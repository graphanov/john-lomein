from __future__ import annotations

import base64
import copy
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_attestor as attestor,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture as capture,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_source_revalidation_binding
    as source_revalidation_binding,
)


class PersonaQualificationAttestorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.private_bytes = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.public_bytes = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def test_default_config_avoids_macos_etc_symlink(self) -> None:
        expected_prefix = "/private/etc/" if sys.platform == "darwin" else "/etc/"
        self.assertTrue(
            str(attestor.DEFAULT_CONFIG_PATH).startswith(expected_prefix)
        )

    def test_authority_metadata_check_is_native_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            path = Path(temporary).resolve() / "state.json"
            path.write_text("{}\n", encoding="utf-8")
            attestor._reject_acl_or_xattrs(
                path,
                field="authority_probe",
            )
            if sys.platform == "darwin":
                subprocess.run(
                    [
                        "/usr/bin/xattr",
                        "-w",
                        "user.john-audit",
                        "unsafe",
                        str(path),
                    ],
                    check=True,
                    capture_output=True,
                )
            elif hasattr(os, "setxattr"):
                os.setxattr(path, b"user.john-audit", b"unsafe")
            else:
                self.skipTest("native xattr mutation unavailable")
            with self.assertRaises(
                attestor.QualificationAttestorError
            ) as caught:
                attestor._reject_acl_or_xattrs(
                    path,
                    field="authority_probe",
                )
            self.assertEqual(
                caught.exception.code,
                "authority_probe_extended_metadata_unsupported",
            )

    def config(self, root: Path = Path("/safe/operator")) -> dict[str, object]:
        return {
            "schema_version": 1,
            "instance_slug": "john-example",
            "qualification_public_root": str(root / "evidence-public"),
            "qualification_private_root": str(root / "evidence-private"),
            "expected_evidence_uid": 501,
            "attestor_key_id": "john-example-persona-ed25519-1",
            "private_key_path": str(root / "keys" / "private.pem"),
            "public_key_path": str(root / "keys" / "public.pem"),
            "public_key_sha256": attestor.public_key_fingerprint(self.public_bytes),
            "head_path": str(root / "state" / "head.json"),
        }

    def evidence(
        self,
        *,
        run_id: str = "run-001",
        summary: str = "1" * 64,
        binding: str = "2" * 64,
        qualified_at: int = 100,
        verified_at: int = 110,
        expires_at: int = 1000,
        observed_uid: int = 501,
        verifier_uid: int = 502,
        capture_creator_uid: int | None = None,
        capture_export_gid: int = 505,
        capture_adopted_at: int | None = None,
        revalidated_at: int | None = None,
        verifier_output: str = "f" * 64,
    ) -> dict[str, object]:
        if capture_creator_uid is None:
            capture_creator_uid = verifier_uid + 1
        if capture_adopted_at is None:
            capture_adopted_at = verified_at - 1
        if revalidated_at is None:
            revalidated_at = verified_at + 1
        evidence = {
            "run_id": run_id,
            "summary_sha256": summary,
            "binding_sha256": binding,
            "status": "qualified",
            "qualified_at_unix": qualified_at,
            "expires_at_unix": expires_at,
            "verifier_version": "john-lomein.persona.operator-verifier.v1",
            "verifier_uid": verifier_uid,
            "verifier_bundle_sha256": "3" * 64,
            "verification_policy_sha256": "4" * 64,
            "capture_manifest_sha256": "5" * 64,
            "capture_plan_sha256": "7" * 64,
            "operator_policy_sha256": "6" * 64,
            "claim_strength": "operator_verified_local_conformance",
            "public_reputation_eligible": False,
            "verified_at_unix": verified_at,
            "observed_evidence_uid": observed_uid,
            "capture_creator_uid": capture_creator_uid,
            "capture_export_gid": capture_export_gid,
            "capture_adopted_uid": 0,
            "capture_adoption_receipt_sha256": "8" * 64,
            "capture_adoption_policy_sha256": "9" * 64,
            "capture_object_identity_sha256": "a" * 64,
            "capture_content_inventory_sha256": "b" * 64,
            "capture_adopted_at_unix": capture_adopted_at,
            "capture_request_sha256": "c" * 64,
            "capture_boundary_policy_sha256": "d" * 64,
            "capture_helper_activation_policy_sha256": "e" * 64,
        }
        receipt = {
            "schema_version": (
                source_revalidation_binding
                .SOURCE_REVALIDATION_RECEIPT_SCHEMA
            ),
            "status": (
                source_revalidation_binding.SOURCE_REVALIDATION_STATUS
            ),
            "capture_adoption_receipt_sha256": evidence[
                "capture_adoption_receipt_sha256"
            ],
            "capture_object_identity_sha256": evidence[
                "capture_object_identity_sha256"
            ],
            "capture_plan_sha256": evidence["capture_plan_sha256"],
            "capture_manifest_sha256": evidence[
                "capture_manifest_sha256"
            ],
            "verifier_output_sha256": verifier_output,
            "revalidator_uid": 0,
            "revalidated_at_unix": revalidated_at,
        }
        return {
            **evidence,
            "post_verifier_live_source_revalidation_receipt": receipt,
            "post_verifier_live_source_revalidation_receipt_sha256": (
                source_revalidation_binding
                .source_revalidation_receipt_sha256(receipt)
            ),
        }

    def envelope(
        self,
        *,
        config: dict[str, object] | None = None,
        evidence: dict[str, object] | None = None,
        sequence: int = 1,
        previous_attestation_sha256: str | None = None,
    ) -> dict[str, object]:
        payload = attestor.build_attestation_payload(
            self.config() if config is None else config,
            self.evidence() if evidence is None else evidence,
            public_key_bytes=self.public_bytes,
            chain_sequence=sequence,
            previous_attestation_sha256=previous_attestation_sha256,
        )
        return attestor.sign_attestation_payload(
            payload,
            private_key_bytes=self.private_bytes,
            public_key_bytes=self.public_bytes,
        )

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(attestor.QualificationAttestorError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def plan_head(self, current, proposed, **kwargs):
        return attestor.plan_verified_head_transition(
            self.config(),
            current,
            proposed,
            public_key_bytes=self.public_bytes,
            **kwargs,
        )

    def attestation_path(
        self,
        *,
        run_id: str = "run-001",
        summary: str = "1" * 64,
        sequence: int = 1,
        root: Path = Path("/safe/operator"),
    ) -> str:
        return str(
            root
            / "state"
            / "attestations"
            / f"{sequence:016d}.{run_id}.{summary}.json"
        )

    def test_config_is_strict_and_separates_evidence_from_control_paths(self) -> None:
        config = self.config()
        self.assertEqual(attestor.normalize_config(config), config)

        unknown = {**config, "unknown_field": "0" * 64}
        self.assert_code("config_fields_invalid", attestor.normalize_config, unknown)

        relative = {**config, "head_path": "state/head.json"}
        self.assert_code("head_path_invalid", attestor.normalize_config, relative)

        controlled = {
            **config,
            "head_path": "/safe/operator/evidence-public/head.json",
        }
        self.assert_code(
            "attestor_control_path_inside_evidence_root",
            attestor.normalize_config,
            controlled,
        )

        overlapping = {
            **config,
            "qualification_private_root": "/safe/operator/evidence-public/private",
        }
        self.assert_code(
            "qualification_roots_overlap",
            attestor.normalize_config,
            overlapping,
        )
        collision = {**config, "head_path": config["public_key_path"]}
        self.assert_code(
            "attestor_control_paths_overlap",
            attestor.normalize_config,
            collision,
        )
        boolean_schema = {**config, "schema_version": True}
        self.assert_code(
            "config_schema_unsupported",
            attestor.normalize_config,
            boolean_schema,
        )
        unicode_alias = {
            **config,
            "qualification_public_root": "/safe/\u00e9",
            "qualification_private_root": "/safe/e\u0301/private",
        }
        self.assert_code(
            "qualification_roots_overlap",
            attestor.normalize_config,
            unicode_alias,
        )
        for reserved in (
            {**config, "head_path": "/safe/operator/state/attestations"},
            {
                **config,
                "private_key_path": (
                    "/safe/operator/state/attestations/private.pem"
                ),
            },
            {
                **config,
                "public_key_path": "/safe/operator/state/.head.json.lock",
            },
            {
                **config,
                "private_key_path": (
                    "/safe/operator/state/"
                    ".head.json.00000000000000000000000000000000.tmp"
                ),
            },
        ):
            with self.subTest(reserved=reserved):
                self.assert_code(
                    "attestor_publication_namespace_overlap",
                    attestor.normalize_config,
                    reserved,
                )

    def test_capture_manifest_file_size_includes_trailing_newline(self) -> None:
        with mock.patch.object(
            capture,
            "_canonical_json",
            return_value=b"x" * (capture.MAX_MANIFEST_BYTES - 1),
        ):
            self.assertEqual(
                len(capture._capture_manifest_file_bytes({})),
                capture.MAX_MANIFEST_BYTES,
            )
        with mock.patch.object(
            capture,
            "_canonical_json",
            return_value=b"x" * capture.MAX_MANIFEST_BYTES,
        ):
            with self.assertRaises(
                capture.QualificationCaptureError
            ) as caught:
                capture._capture_manifest_file_bytes({})
            self.assertEqual(
                caught.exception.code,
                "capture_manifest_too_large",
            )

    def test_installed_bundle_verification_is_complete_and_bounded(self) -> None:
        self.assertEqual(
            attestor.OPERATOR_POLICY_SCHEMA,
            "john-lomein.persona-qualification-operator-policy.v3",
        )
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            root = Path(temporary).resolve()
            installation_uid = os.geteuid()
            evidence_uid = installation_uid if installation_uid > 0 else 1
            verifier_uid = evidence_uid + 1
            verifier_gid = os.getegid() if os.getegid() > 0 else 1
            capture_uid = verifier_uid + 1
            capture_export_gid = verifier_gid + 1
            config = {
                **self.config(root),
                "expected_evidence_uid": evidence_uid,
            }
            bundle_root = root / "installed" / "bundle"
            bundle_root.mkdir(parents=True, mode=0o755)
            python_path = bundle_root / "python"
            entrypoint_path = bundle_root / "verifier.py"
            python_bytes = b"\x7fELF-test-python\n"
            entrypoint_bytes = b"raise SystemExit(0)\n"
            python_path.write_bytes(python_bytes)
            entrypoint_path.write_bytes(entrypoint_bytes)
            python_path.chmod(0o550)
            entrypoint_path.chmod(0o440)
            bundle_root.chmod(0o550)
            if installation_uid == 0:
                for installed_path in (
                    bundle_root,
                    python_path,
                    entrypoint_path,
                ):
                    os.chown(installed_path, 0, verifier_gid)

            instance_path = root / "instance.yaml"
            instance_bytes = b"schema_version: 3\n"
            instance_path.write_bytes(instance_bytes)
            instance_path.chmod(0o600)
            if evidence_uid != installation_uid:
                os.chown(instance_path, evidence_uid, os.getegid())

            file_entries = []
            for relative, content, mode in (
                ("python", python_bytes, 0o550),
                ("verifier.py", entrypoint_bytes, 0o440),
            ):
                file_entries.append(
                    {
                        "path": relative,
                        "sha256": attestor.sha256_bytes(content),
                        "size": len(content),
                        "mode": mode,
                    }
                )
            manifest = {
                "schema_version": (
                    attestor.VERIFIER_BUNDLE_MANIFEST_SCHEMA_VERSION
                ),
                "verifier_version": (
                    "john-lomein.persona.operator-verifier.v1"
                ),
                "bundle_root": str(bundle_root),
                "entrypoint_path": str(entrypoint_path),
                "root_mode": 0o550,
                "directories": [],
                "files": file_entries,
            }
            manifest_bytes = attestor.canonical_json(manifest) + b"\n"
            manifest_path = root / "installed" / "bundle-manifest.json"
            manifest_path.write_bytes(manifest_bytes)
            manifest_path.chmod(0o600)
            binding = {
                "schema_version": attestor.INSTALLED_BINDING_SCHEMA_VERSION,
                "instance_manifest_path": str(instance_path),
                "instance_manifest_sha256": attestor.sha256_bytes(
                    instance_bytes
                ),
                "capture_uid": capture_uid,
                "capture_export_gid": capture_export_gid,
                "verifier_uid": verifier_uid,
                "verifier_gid": verifier_gid,
                "verifier_python_path": str(python_path),
                "verifier_python_sha256": attestor.sha256_bytes(
                    python_bytes
                ),
                "verifier_bundle_root": str(bundle_root),
                "verifier_manifest_path": str(manifest_path),
                "verifier_manifest_sha256": attestor.sha256_bytes(
                    manifest_bytes
                ),
                "verifier_entrypoint_path": str(entrypoint_path),
                "verifier_version": manifest["verifier_version"],
                "verifier_timeout_seconds": 60,
                "capture_parent_path": str(root / "captures"),
                "evidence_home_path": str(root / "evidence-home"),
                "runtime_identity_path": str(root / "runtime"),
                "checkout_identity_path": str(root / "checkout"),
            }
            capture_selection_sha256 = "a" * 64
            with mock.patch.object(
                attestor,
                "INSTALLATION_OWNER_UID",
                installation_uid,
            ):
                verified = attestor.verify_installed_verifier_bundle(
                    config,
                    binding,
                    capture_selection_sha256=capture_selection_sha256,
                )
                self.assertEqual(
                    verified["verifier_bundle_sha256"],
                    binding["verifier_manifest_sha256"],
                )
                self.assertEqual(
                    verified["operator_policy"][
                        "verification_execution_policy_sha256"
                    ],
                    attestor.sha256_json(
                        attestor.VERIFICATION_EXECUTION_POLICY
                    ),
                )
                self.assertEqual(
                    verified["operator_policy"][
                        "capture_selection_sha256"
                    ],
                    capture_selection_sha256,
                )
                self.assertEqual(
                    {
                        field: verified["operator_policy"][field]
                        for field in (
                            "expected_capture_uid",
                            "expected_capture_export_gid",
                            "expected_adopted_uid",
                            "capture_adoption_binding_schema",
                            "capture_adoption_required",
                        )
                    },
                    {
                        "expected_capture_uid": capture_uid,
                        "expected_capture_export_gid": capture_export_gid,
                        "expected_adopted_uid": 0,
                        "capture_adoption_binding_schema": (
                            "john-lomein.persona-qualification-"
                            "capture-adoption-binding.v1"
                        ),
                        "capture_adoption_required": True,
                    },
                )
                self.assertEqual(
                    verified["verification_policy_sha256"],
                    attestor.sha256_json(
                        {
                            "installed_binding": binding,
                            "execution_policy": (
                                attestor.VERIFICATION_EXECUTION_POLICY
                            ),
                            "capture_selection_sha256": (
                                capture_selection_sha256
                            ),
                        }
                    ),
                )
                changed_selection = (
                    attestor.verify_installed_verifier_bundle(
                        config,
                        binding,
                        capture_selection_sha256="b" * 64,
                    )
                )
                self.assertNotEqual(
                    changed_selection["verification_policy_sha256"],
                    verified["verification_policy_sha256"],
                )
                self.assertNotEqual(
                    changed_selection["operator_policy_sha256"],
                    verified["operator_policy_sha256"],
                )
                self.assert_code(
                    "capture_selection_sha256_invalid",
                    attestor.verify_installed_verifier_bundle,
                    config,
                    binding,
                    capture_selection_sha256="A" * 64,
                )
                self.assertEqual(
                    attestor.VERIFICATION_EXECUTION_POLICY[
                        "native_dependency_closure"
                    ],
                    "not-claimed-by-repository-primitive",
                )
                with mock.patch.object(
                    attestor,
                    "MAX_VERIFIER_BUNDLE_ENTRIES",
                    1,
                ):
                    self.assert_code(
                        "verifier_bundle_entry_count_exceeded",
                        attestor.verify_installed_verifier_bundle,
                        config,
                        binding,
                        capture_selection_sha256=(
                            capture_selection_sha256
                        ),
                    )

                extra = bundle_root / "extra"
                nested = extra / "nested"
                bundle_root.chmod(0o750)
                nested.mkdir(parents=True, mode=0o755)
                extra.chmod(0o550)
                nested.chmod(0o550)
                if installation_uid == 0:
                    os.chown(extra, 0, verifier_gid)
                    os.chown(nested, 0, verifier_gid)
                bundle_root.chmod(0o550)
                self.assert_code(
                    "verifier_bundle_directory_inventory_mismatch",
                    attestor.verify_installed_verifier_bundle,
                    config,
                    binding,
                    capture_selection_sha256=capture_selection_sha256,
                )
                with mock.patch.object(
                    attestor,
                    "MAX_VERIFIER_BUNDLE_DIRECTORIES",
                    1,
                ):
                    self.assert_code(
                        "verifier_bundle_directory_count_exceeded",
                        attestor.verify_installed_verifier_bundle,
                        config,
                        binding,
                        capture_selection_sha256=(
                            capture_selection_sha256
                        ),
                    )
                with mock.patch.object(
                    attestor,
                    "MAX_VERIFIER_BUNDLE_DEPTH",
                    1,
                ):
                    self.assert_code(
                        "verifier_bundle_depth_exceeded",
                        attestor.verify_installed_verifier_bundle,
                        config,
                        binding,
                        capture_selection_sha256=(
                            capture_selection_sha256
                        ),
                    )

            reserved_binding = {
                **binding,
                "capture_parent_path": str(
                    Path(config["head_path"]).parent / "attestations"
                ),
            }
            self.assert_code(
                "verifier_control_inside_publication_namespace",
                attestor.normalize_installed_verifier_binding,
                reserved_binding,
                config=config,
            )
            nested.chmod(0o700)
            extra.chmod(0o700)
            bundle_root.chmod(0o700)

    def test_payload_and_signature_have_exact_canonical_contract(self) -> None:
        self.assertEqual(
            attestor.VERIFICATION_EXECUTION_POLICY_SCHEMA,
            (
                "john-lomein.persona-qualification-"
                "verification-execution-policy.v5"
            ),
        )
        self.assertIs(
            attestor.VERIFICATION_EXECUTION_POLICY[
                "post_verifier_live_source_revalidation"
            ],
            True,
        )
        self.assertEqual(
            attestor.VERIFICATION_EXECUTION_POLICY[
                "post_verifier_live_source_"
                "revalidation_receipt_schema"
            ],
            source_revalidation_binding
            .SOURCE_REVALIDATION_RECEIPT_SCHEMA,
        )
        self.assertEqual(
            attestor.VERIFICATION_EXECUTION_POLICY[
                "post_verifier_live_source_revalidation_order"
            ],
            [
                "verifier_process_reaped",
                "verifier_output_canonicalized_and_adoption_bound",
                "live_sources_revalidated_against_adopted_manifest",
                "private_key_opened",
            ],
        )
        payload = attestor.build_attestation_payload(
            self.config(),
            self.evidence(),
            public_key_bytes=self.public_bytes,
            chain_sequence=1,
            previous_attestation_sha256=None,
        )
        self.assertEqual(
            set(payload),
            {
                "schema_version",
                "purpose",
                "scope",
                "attestor",
                "instance",
                "chain",
                "qualification",
                "verification",
            },
        )
        self.assertEqual(payload["schema_version"], 5)
        self.assertEqual(
            payload["chain"],
            {"sequence": 1, "previous_attestation_sha256": None},
        )
        self.assertEqual(
            payload["qualification"],
            {
                "run_id": "run-001",
                "summary_sha256": "1" * 64,
                "binding_sha256": "2" * 64,
                "status": "qualified",
                "qualified_at_unix": 100,
                "expires_at_unix": 1000,
                "evidence_class": "private-raw-public-aggregate",
            },
        )
        self.assertEqual(payload["verification"]["expected_evidence_uid"], 501)
        self.assertEqual(payload["verification"]["observed_evidence_uid"], 501)
        self.assertEqual(payload["verification"]["verifier_uid"], 502)
        self.assertEqual(
            set(payload["verification"]),
            {
                "verifier_version",
                "verifier_uid",
                "verifier_bundle_sha256",
                "verification_policy_sha256",
                "capture_manifest_sha256",
                "capture_plan_sha256",
                "operator_policy_sha256",
                "claim_strength",
                "public_reputation_eligible",
                "verified_at_unix",
                "expected_evidence_uid",
                "observed_evidence_uid",
                "capture_creator_uid",
                "capture_export_gid",
                "capture_adopted_uid",
                "capture_adoption_receipt_sha256",
                "capture_adoption_policy_sha256",
                "capture_object_identity_sha256",
                "capture_content_inventory_sha256",
                "capture_adopted_at_unix",
                "capture_request_sha256",
                "capture_boundary_policy_sha256",
                "capture_helper_activation_policy_sha256",
                "post_verifier_live_source_revalidation_receipt",
                (
                    "post_verifier_live_source_"
                    "revalidation_receipt_sha256"
                ),
                "result",
            },
        )
        self.assertEqual(
            {
                field: payload["verification"][field]
                for field in (
                    "capture_creator_uid",
                    "capture_export_gid",
                    "capture_adopted_uid",
                    "capture_adoption_receipt_sha256",
                    "capture_adoption_policy_sha256",
                    "capture_object_identity_sha256",
                    "capture_content_inventory_sha256",
                    "capture_adopted_at_unix",
                    "capture_request_sha256",
                    "capture_boundary_policy_sha256",
                    "capture_helper_activation_policy_sha256",
                )
            },
            {
                "capture_creator_uid": 503,
                "capture_export_gid": 505,
                "capture_adopted_uid": 0,
                "capture_adoption_receipt_sha256": "8" * 64,
                "capture_adoption_policy_sha256": "9" * 64,
                "capture_object_identity_sha256": "a" * 64,
                "capture_content_inventory_sha256": "b" * 64,
                "capture_adopted_at_unix": 109,
                "capture_request_sha256": "c" * 64,
                "capture_boundary_policy_sha256": "d" * 64,
                "capture_helper_activation_policy_sha256": "e" * 64,
            },
        )
        self.assertEqual(
            payload["verification"]["claim_strength"],
            "operator_verified_local_conformance",
        )
        self.assertFalse(
            payload["verification"]["public_reputation_eligible"]
        )
        receipt = payload["verification"][
            "post_verifier_live_source_revalidation_receipt"
        ]
        self.assertEqual(receipt["revalidated_at_unix"], 111)
        self.assertEqual(receipt["revalidator_uid"], 0)
        self.assertEqual(
            payload["verification"][
                "post_verifier_live_source_"
                "revalidation_receipt_sha256"
            ],
            source_revalidation_binding
            .source_revalidation_receipt_sha256(receipt),
        )
        self.assertRegex(payload["attestor"]["public_key_sha256"], r"^[0-9a-f]{64}$")

        envelope = attestor.sign_attestation_payload(
            payload,
            private_key_bytes=self.private_bytes,
            public_key_bytes=self.public_bytes,
        )
        signature = envelope["signature"]["value_base64"]
        self.assertEqual(len(signature), 86)
        self.assertNotIn("=", signature)
        self.assertEqual(
            attestor.canonical_json(envelope),
            json.dumps(
                envelope,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode(),
        )
        verified = attestor.verify_attestation_envelope(
            envelope,
            public_key_bytes=self.public_bytes,
            expected_key_id="john-example-persona-ed25519-1",
            expected_public_key_sha256=attestor.public_key_fingerprint(
                self.public_bytes
            ),
            expected_instance_slug="john-example",
            now_unix=200,
        )
        self.assertEqual(verified, envelope)
        self.assert_code(
            "attestation_verification_in_future",
            attestor.verify_attestation_envelope,
            envelope,
            public_key_bytes=self.public_bytes,
            expected_key_id="john-example-persona-ed25519-1",
            expected_public_key_sha256=attestor.public_key_fingerprint(
                self.public_bytes
            ),
            now_unix=109,
        )
        self.assert_code(
            "attestation_expired",
            attestor.verify_attestation_envelope,
            envelope,
            public_key_bytes=self.public_bytes,
            expected_key_id="john-example-persona-ed25519-1",
            expected_public_key_sha256=attestor.public_key_fingerprint(
                self.public_bytes
            ),
            now_unix=1000,
        )

    def test_raw_verifier_evidence_is_distinct_from_final_signable_evidence(
        self,
    ) -> None:
        evidence = self.evidence()
        raw = {
            field: evidence[field]
            for field in attestor.VERIFIER_EVIDENCE_FIELDS
        }
        self.assertEqual(
            attestor.normalize_verifier_evidence(
                raw,
                expected_evidence_uid=501,
            ),
            raw,
        )
        self.assert_code(
            "verified_evidence_fields_invalid",
            attestor.normalize_verified_evidence,
            raw,
            expected_evidence_uid=501,
        )
        self.assertEqual(
            set(
                attestor.normalize_verified_evidence(
                    evidence,
                    expected_evidence_uid=501,
                )
            ),
            attestor.VERIFIED_EVIDENCE_FIELDS,
        )

    def test_final_evidence_requires_exact_root_receipt_binding(self) -> None:
        evidence = self.evidence()
        wrong_digest = copy.deepcopy(evidence)
        wrong_digest[
            "post_verifier_live_source_revalidation_receipt_sha256"
        ] = "0" * 64
        self.assert_code(
            "source_revalidation_receipt_digest_mismatch",
            attestor.normalize_verified_evidence,
            wrong_digest,
            expected_evidence_uid=501,
        )

        wrong_manifest = copy.deepcopy(evidence)
        receipt = wrong_manifest[
            "post_verifier_live_source_revalidation_receipt"
        ]
        receipt["capture_manifest_sha256"] = "0" * 64
        wrong_manifest[
            "post_verifier_live_source_revalidation_receipt_sha256"
        ] = (
            source_revalidation_binding
            .source_revalidation_receipt_sha256(receipt)
        )
        self.assert_code(
            (
                "source_revalidation_receipt_"
                "capture_manifest_sha256_mismatch"
            ),
            attestor.normalize_verified_evidence,
            wrong_manifest,
            expected_evidence_uid=501,
        )

        bad_time = copy.deepcopy(evidence)
        receipt = bad_time[
            "post_verifier_live_source_revalidation_receipt"
        ]
        receipt["revalidated_at_unix"] = 109
        bad_time[
            "post_verifier_live_source_revalidation_receipt_sha256"
        ] = (
            source_revalidation_binding
            .source_revalidation_receipt_sha256(receipt)
        )
        self.assert_code(
            "source_revalidation_receipt_time_invalid",
            attestor.normalize_verified_evidence,
            bad_time,
            expected_evidence_uid=501,
        )

    def test_historical_v4_is_readable_but_never_signable(self) -> None:
        current = attestor.build_attestation_payload(
            self.config(),
            self.evidence(),
            public_key_bytes=self.public_bytes,
            chain_sequence=1,
            previous_attestation_sha256=None,
        )
        historical = copy.deepcopy(current)
        historical["schema_version"] = (
            attestor.HISTORICAL_PAYLOAD_SCHEMA_VERSION
        )
        historical["verification"].pop(
            "post_verifier_live_source_revalidation_receipt"
        )
        historical["verification"].pop(
            "post_verifier_live_source_revalidation_receipt_sha256"
        )
        self.assertEqual(attestor.normalize_payload(historical), historical)
        self.assertEqual(
            attestor.effective_verified_at_unix(historical),
            110,
        )
        self.assert_code(
            "payload_schema_not_signable",
            attestor.normalize_payload,
            historical,
            require_current=True,
        )
        self.assert_code(
            "payload_schema_not_signable",
            attestor.sign_attestation_payload,
            historical,
            private_key_bytes=self.private_bytes,
            public_key_bytes=self.public_bytes,
        )

        signature = self.private_key.sign(
            attestor.canonical_json(historical)
        )
        historical_envelope = {
            "schema_version": attestor.ENVELOPE_SCHEMA_VERSION,
            "payload": historical,
            "signature": {
                "algorithm": attestor.ALGORITHM,
                "key_id": historical["attestor"]["key_id"],
                "value_base64": base64.urlsafe_b64encode(signature)
                .decode("ascii")
                .rstrip("="),
            },
        }
        self.assertEqual(
            attestor.verify_attestation_envelope(
                historical_envelope,
                public_key_bytes=self.public_bytes,
                expected_key_id=historical["attestor"]["key_id"],
                expected_public_key_sha256=(
                    attestor.public_key_fingerprint(self.public_bytes)
                ),
                expected_instance_slug="john-example",
                now_unix=200,
            ),
            historical_envelope,
        )
        historical_evidence = attestor._verified_evidence_from_payload(
            historical,
            expected_evidence_uid=501,
        )
        self.assertEqual(
            set(historical_evidence),
            attestor.VERIFIER_EVIDENCE_FIELDS,
        )

        historical_head = attestor._verified_head_for_envelope(
            attestor.normalize_config(self.config()),
            historical_envelope,
            updated_at_unix=120,
        )
        next_envelope = self.envelope(
            evidence=self.evidence(
                run_id="run-002",
                summary="7" * 64,
                binding="8" * 64,
                qualified_at=200,
                verified_at=210,
                expires_at=1200,
            ),
            sequence=2,
            previous_attestation_sha256=attestor.sha256_json(
                historical_envelope
            ),
        )
        next_head, changed = self.plan_head(
            historical_head,
            next_envelope,
            attestation_path=self.attestation_path(
                run_id="run-002",
                summary="7" * 64,
                sequence=2,
            ),
            updated_at_unix=220,
            current_envelope=historical_envelope,
        )
        self.assertTrue(changed)
        self.assertEqual(next_head["chain_sequence"], 2)

    def test_signature_tampering_wrong_key_and_noncanonical_encoding_fail(self) -> None:
        envelope = self.envelope()
        tampered = copy.deepcopy(envelope)
        tampered["payload"]["qualification"]["summary_sha256"] = "3" * 64
        self.assert_code(
            "attestation_signature_invalid",
            attestor.verify_attestation_envelope,
            tampered,
            public_key_bytes=self.public_bytes,
            expected_key_id="john-example-persona-ed25519-1",
            expected_public_key_sha256=attestor.public_key_fingerprint(
                self.public_bytes
            ),
            now_unix=200,
        )

        for field, changed_value in (
            ("capture_creator_uid", 504),
            ("capture_export_gid", 506),
            ("capture_adoption_receipt_sha256", "f" * 64),
            ("capture_adoption_policy_sha256", "f" * 64),
            ("capture_object_identity_sha256", "f" * 64),
            ("capture_content_inventory_sha256", "f" * 64),
            ("capture_adopted_at_unix", 108),
            ("capture_request_sha256", "f" * 64),
            ("capture_boundary_policy_sha256", "f" * 64),
            ("capture_helper_activation_policy_sha256", "f" * 64),
        ):
            with self.subTest(adoption_field=field):
                tampered_adoption = copy.deepcopy(envelope)
                tampered_adoption["payload"]["verification"][field] = (
                    changed_value
                )
                receipt_field = {
                    "capture_adoption_receipt_sha256": (
                        "capture_adoption_receipt_sha256"
                    ),
                    "capture_object_identity_sha256": (
                        "capture_object_identity_sha256"
                    ),
                }.get(field)
                if receipt_field is not None:
                    receipt = tampered_adoption["payload"][
                        "verification"
                    ][
                        "post_verifier_live_source_"
                        "revalidation_receipt"
                    ]
                    receipt[receipt_field] = changed_value
                    tampered_adoption["payload"]["verification"][
                        "post_verifier_live_source_"
                        "revalidation_receipt_sha256"
                    ] = (
                        source_revalidation_binding
                        .source_revalidation_receipt_sha256(receipt)
                    )
                self.assert_code(
                    "attestation_signature_invalid",
                    attestor.verify_attestation_envelope,
                    tampered_adoption,
                    public_key_bytes=self.public_bytes,
                    expected_key_id=(
                        "john-example-persona-ed25519-1"
                    ),
                    expected_public_key_sha256=(
                        attestor.public_key_fingerprint(
                            self.public_bytes
                        )
                    ),
                    now_unix=200,
                )

        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.assert_code(
            "public_key_fingerprint_mismatch",
            attestor.verify_attestation_envelope,
            envelope,
            public_key_bytes=other,
            expected_key_id="john-example-persona-ed25519-1",
            expected_public_key_sha256=attestor.public_key_fingerprint(
                self.public_bytes
            ),
            now_unix=200,
        )

        padded = copy.deepcopy(envelope)
        padded["signature"]["value_base64"] += "=="
        self.assert_code("signature_encoding_invalid", attestor.normalize_envelope, padded)

    def test_payload_rejects_uid_status_expiry_and_extra_fields(self) -> None:
        for mutation, code in (
            ({"observed_evidence_uid": 502}, "verification_evidence_uid_mismatch"),
            ({"verifier_uid": 501}, "verification_identity_not_separate"),
            (
                {"capture_creator_uid": 501},
                "verification_capture_adoption_identity_invalid",
            ),
            (
                {"capture_creator_uid": 502},
                "verification_capture_adoption_identity_invalid",
            ),
            (
                {"capture_adopted_uid": 1},
                "verification_capture_adoption_identity_invalid",
            ),
            (
                {"capture_adopted_at_unix": 111},
                "verification_capture_adoption_identity_invalid",
            ),
            (
                {"capture_export_gid": 0},
                "verified_evidence_capture_export_gid_invalid",
            ),
            ({"status": "failed"}, "verified_evidence_not_qualified"),
            ({"verified_at_unix": 1000}, "verification_timing_invalid"),
        ):
            evidence = {**self.evidence(), **mutation}
            self.assert_code(
                code,
                attestor.build_attestation_payload,
                self.config(),
                evidence,
                public_key_bytes=self.public_bytes,
                chain_sequence=1,
                previous_attestation_sha256=None,
            )
        evidence = {**self.evidence(), "raw_response": "secret"}
        self.assert_code(
            "verified_evidence_fields_invalid",
            attestor.build_attestation_payload,
            self.config(),
            evidence,
            public_key_bytes=self.public_bytes,
            chain_sequence=1,
            previous_attestation_sha256=None,
        )

    def test_head_binding_idempotency_conflict_and_rollback(self) -> None:
        envelope = self.envelope()
        initial = attestor.initial_head("john-example", updated_at_unix=0)
        path = self.attestation_path()
        first, changed = self.plan_head(
            initial,
            envelope,
            attestation_path=path,
            updated_at_unix=120,
        )
        self.assertTrue(changed)
        self.assertEqual(first["state"], "verified")
        self.assertRegex(first["attestation_sha256"], r"^[0-9a-f]{64}$")
        attestor.verify_published_attestation_head(
            self.config(),
            first,
            envelope,
            public_key_bytes=self.public_bytes,
            now_unix=120,
        )
        self.assert_code(
            "head_update_in_future",
            attestor.verify_published_attestation_head,
            self.config(),
            {**first, "updated_at_unix": 121},
            envelope,
            public_key_bytes=self.public_bytes,
            now_unix=120,
        )
        self.assert_code(
            "attestation_path_not_canonical",
            self.plan_head,
            initial,
            envelope,
            attestation_path="/tmp/copied-attestation.json",
            updated_at_unix=120,
        )
        copied_head = {**first, "attestation_path": "/tmp/copied-attestation.json"}
        self.assert_code(
            "attestation_path_not_canonical",
            attestor.verify_published_attestation_head,
            self.config(),
            copied_head,
            envelope,
            public_key_bytes=self.public_bytes,
            now_unix=120,
        )
        tampered_head = {**first, "binding_sha256": "8" * 64}
        self.assert_code(
            "head_attestation_binding_mismatch",
            attestor.verify_published_attestation_head,
            self.config(),
            tampered_head,
            envelope,
            public_key_bytes=self.public_bytes,
            now_unix=120,
        )

        same, changed = self.plan_head(
            first,
            envelope,
            attestation_path=path,
            updated_at_unix=120,
            current_envelope=envelope,
        )
        self.assertFalse(changed)
        self.assertEqual(same, first)

        different_summary = self.envelope(
            evidence=self.evidence(summary="9" * 64, verified_at=121),
            sequence=2,
            previous_attestation_sha256=attestor.sha256_json(envelope),
        )
        self.assert_code(
            "same_run_different_attestation_rejected",
            self.plan_head,
            first,
            different_summary,
            attestation_path=self.attestation_path(
                summary="9" * 64,
                sequence=2,
            ),
            updated_at_unix=122,
            current_envelope=envelope,
        )

        rollback = self.envelope(
            evidence=self.evidence(
                run_id="run-002",
                qualified_at=99,
                verified_at=130,
                expires_at=1200,
            ),
            sequence=2,
            previous_attestation_sha256=attestor.sha256_json(envelope),
        )
        self.assert_code(
            "qualification_rollback_rejected",
            self.plan_head,
            first,
            rollback,
            attestation_path=self.attestation_path(
                run_id="run-002",
                sequence=2,
            ),
            updated_at_unix=131,
            current_envelope=envelope,
        )

        invalid = attestor.normalize_head(
            {
                "schema_version": 2,
                "state": "invalid",
                "instance_slug": "john-example",
                "updated_at_unix": 120,
                "reason": "operator_review_required",
            }
        )
        self.assert_code(
            "invalid_head_requires_operator_recovery",
            self.plan_head,
            invalid,
            envelope,
            attestation_path=path,
            updated_at_unix=121,
        )
        invalid_signature = copy.deepcopy(envelope)
        invalid_signature["signature"]["value_base64"] = "A" * 86
        self.assert_code(
            "attestation_signature_invalid",
            self.plan_head,
            initial,
            invalid_signature,
            attestation_path=path,
            updated_at_unix=120,
        )

    def test_single_flight_transaction_holds_one_lock_through_commit(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            (root / "state").mkdir(mode=0o700)
            config = self.config(root)
            events: list[str] = []
            lock_descriptor = -1
            original_flock = attestor.fcntl.flock
            original_reconcile = attestor._reconcile_head_with_archive
            original_usage = attestor._attestation_archive_usage
            original_sign = attestor.sign_attestation_payload
            original_publish = attestor._publish_immutable_at
            original_replace = attestor._replace_json_at

            def assert_lock_live() -> None:
                self.assertGreaterEqual(lock_descriptor, 0)
                os.fstat(lock_descriptor)

            def lock_probe(descriptor, operation):
                nonlocal lock_descriptor
                self.assertEqual(operation, attestor.fcntl.LOCK_EX)
                self.assertEqual(lock_descriptor, -1)
                original_flock(descriptor, operation)
                lock_descriptor = descriptor
                events.append("lock")

            def reconcile_probe(*args, **kwargs):
                assert_lock_live()
                events.append("reconcile")
                return original_reconcile(*args, **kwargs)

            def usage_probe(*args, **kwargs):
                assert_lock_live()
                events.append("capacity")
                return original_usage(*args, **kwargs)

            def private_key_loader():
                assert_lock_live()
                events.append("key")
                return self.private_bytes

            def sign_probe(*args, **kwargs):
                assert_lock_live()
                events.append("sign")
                return original_sign(*args, **kwargs)

            def publish_probe(*args, **kwargs):
                assert_lock_live()
                events.append("archive")
                return original_publish(*args, **kwargs)

            def replace_probe(*args, **kwargs):
                assert_lock_live()
                events.append("head")
                return original_replace(*args, **kwargs)

            with (
                mock.patch.object(
                    attestor.fcntl,
                    "flock",
                    side_effect=lock_probe,
                ) as flock,
                mock.patch.object(
                    attestor,
                    "_reconcile_head_with_archive",
                    side_effect=reconcile_probe,
                ),
                mock.patch.object(
                    attestor,
                    "_attestation_archive_usage",
                    side_effect=usage_probe,
                ),
                mock.patch.object(
                    attestor,
                    "sign_attestation_payload",
                    side_effect=sign_probe,
                ),
                mock.patch.object(
                    attestor,
                    "_publish_immutable_at",
                    side_effect=publish_probe,
                ),
                mock.patch.object(
                    attestor,
                    "_replace_json_at",
                    side_effect=replace_probe,
                ),
                mock.patch.object(
                    attestor,
                    "read_attestation_chain_tip",
                    side_effect=AssertionError("split tip read"),
                ),
                mock.patch.object(
                    attestor,
                    "publish_attestation",
                    side_effect=AssertionError("split publication"),
                ),
            ):
                head, status, envelope = (
                    attestor.sign_and_publish_attestation(
                        config,
                        self.evidence(),
                        public_key_bytes=self.public_bytes,
                        private_key_loader=private_key_loader,
                        updated_at_unix=120,
                        publication_owner_uid=os.geteuid(),
                    )
                )

            self.assertEqual(status, "published")
            self.assertEqual(
                events,
                [
                    "lock",
                    "reconcile",
                    "capacity",
                    "key",
                    "sign",
                    "archive",
                    "head",
                ],
            )
            flock.assert_called_once()
            self.assertEqual(head["attestation_sha256"], attestor.sha256_json(envelope))

    def test_single_flight_concurrent_same_run_signs_once(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            (root / "state").mkdir(mode=0o700)
            config = self.config(root)
            loader_entered = threading.Event()
            second_lock_attempted = threading.Event()
            release_loader = threading.Event()
            counter_lock = threading.Lock()
            private_key_reads = 0
            lock_attempts = 0
            original_flock = attestor.fcntl.flock

            def flock_probe(descriptor, operation):
                nonlocal lock_attempts
                with counter_lock:
                    lock_attempts += 1
                    if lock_attempts == 2:
                        second_lock_attempted.set()
                return original_flock(descriptor, operation)

            def private_key_loader():
                nonlocal private_key_reads
                with counter_lock:
                    private_key_reads += 1
                loader_entered.set()
                if not release_loader.wait(timeout=5):
                    raise AssertionError("concurrent transaction did not progress")
                return self.private_bytes

            def transact():
                return attestor.sign_and_publish_attestation(
                    config,
                    self.evidence(),
                    public_key_bytes=self.public_bytes,
                    private_key_loader=private_key_loader,
                    updated_at_unix=120,
                    publication_owner_uid=os.geteuid(),
                )

            with (
                mock.patch.object(
                    attestor.fcntl,
                    "flock",
                    side_effect=flock_probe,
                ),
                ThreadPoolExecutor(max_workers=2) as executor,
            ):
                first = executor.submit(transact)
                self.assertTrue(loader_entered.wait(timeout=5))
                second = executor.submit(transact)
                self.assertTrue(second_lock_attempted.wait(timeout=5))
                release_loader.set()
                results = [first.result(timeout=5), second.result(timeout=5)]

            self.assertEqual(private_key_reads, 1)
            self.assertEqual(lock_attempts, 2)
            self.assertEqual(
                sorted(result[1] for result in results),
                ["idempotent", "published"],
            )
            self.assertEqual(results[0][0], results[1][0])
            self.assertEqual(results[0][2], results[1][2])

    def test_single_flight_repairs_crash_after_archive_before_head(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            (root / "state").mkdir(mode=0o700)
            config = self.config(root)
            private_key_reads = 0

            def private_key_loader():
                nonlocal private_key_reads
                private_key_reads += 1
                return self.private_bytes

            with mock.patch.object(
                attestor,
                "_replace_json_at",
                side_effect=RuntimeError("simulated process loss"),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "simulated process loss",
                ):
                    attestor.sign_and_publish_attestation(
                        config,
                        self.evidence(),
                        public_key_bytes=self.public_bytes,
                        private_key_loader=private_key_loader,
                        updated_at_unix=120,
                        publication_owner_uid=os.geteuid(),
                    )

            archive_paths = list(
                (root / "state" / "attestations").glob("*.json")
            )
            self.assertEqual(len(archive_paths), 1)
            self.assertFalse(Path(config["head_path"]).exists())

            repaired_head, status, repaired_envelope = (
                attestor.sign_and_publish_attestation(
                    config,
                    self.evidence(),
                    public_key_bytes=self.public_bytes,
                    private_key_loader=lambda: (_ for _ in ()).throw(
                        AssertionError(
                            "private key reopened during crash recovery"
                        )
                    ),
                    updated_at_unix=121,
                    publication_owner_uid=os.geteuid(),
                )
            )
            self.assertEqual(status, "idempotent")
            self.assertEqual(private_key_reads, 1)
            self.assertEqual(
                repaired_envelope,
                json.loads(archive_paths[0].read_text(encoding="utf-8")),
            )
            self.assertEqual(
                repaired_head,
                json.loads(
                    Path(config["head_path"]).read_text(encoding="utf-8")
                ),
            )

    def test_single_flight_replay_conflict_and_capacity_precede_key(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            (root / "state").mkdir(mode=0o700)
            config = self.config(root)
            first_head, status, first_envelope = (
                attestor.sign_and_publish_attestation(
                    config,
                    self.evidence(),
                    public_key_bytes=self.public_bytes,
                    private_key_loader=lambda: self.private_bytes,
                    updated_at_unix=120,
                    publication_owner_uid=os.geteuid(),
                )
            )
            self.assertEqual(status, "published")
            private_key_reads = 0

            def forbidden_private_key_loader():
                nonlocal private_key_reads
                private_key_reads += 1
                raise AssertionError("private key accessed before rejection")

            with mock.patch.object(
                attestor,
                "MAX_ATTESTATION_ARCHIVE_FILES",
                1,
            ):
                replay_head, replay_status, replay_envelope = (
                    attestor.sign_and_publish_attestation(
                        config,
                        self.evidence(),
                        public_key_bytes=self.public_bytes,
                        private_key_loader=forbidden_private_key_loader,
                        updated_at_unix=120,
                        publication_owner_uid=os.geteuid(),
                    )
                )
                self.assertEqual(replay_status, "idempotent")
                self.assertEqual(replay_head, first_head)
                self.assertEqual(replay_envelope, first_envelope)

                self.assert_code(
                    "same_run_different_attestation_rejected",
                    attestor.sign_and_publish_attestation,
                    config,
                    self.evidence(summary="9" * 64),
                    public_key_bytes=self.public_bytes,
                    private_key_loader=forbidden_private_key_loader,
                    updated_at_unix=120,
                    publication_owner_uid=os.geteuid(),
                )
                self.assert_code(
                    "attestation_archive_capacity_exceeded",
                    attestor.sign_and_publish_attestation,
                    config,
                    self.evidence(
                        run_id="run-002",
                        summary="7" * 64,
                        binding="8" * 64,
                        qualified_at=200,
                        verified_at=210,
                        expires_at=1200,
                    ),
                    public_key_bytes=self.public_bytes,
                    private_key_loader=forbidden_private_key_loader,
                    updated_at_unix=220,
                    publication_owner_uid=os.geteuid(),
                )
            self.assertEqual(private_key_reads, 0)

    def test_single_flight_equivalent_recapture_repairs_without_key(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            (root / "state").mkdir(mode=0o700)
            config = self.config(root)
            first_head, status, first_envelope = (
                attestor.sign_and_publish_attestation(
                    config,
                    self.evidence(),
                    public_key_bytes=self.public_bytes,
                    private_key_loader=lambda: self.private_bytes,
                    updated_at_unix=120,
                    publication_owner_uid=os.geteuid(),
                )
            )
            self.assertEqual(status, "published")

            recaptured = self.evidence()
            recaptured["capture_manifest_sha256"] = "9" * 64
            recaptured["verified_at_unix"] = 111
            receipt = recaptured[
                "post_verifier_live_source_revalidation_receipt"
            ]
            receipt["capture_manifest_sha256"] = "9" * 64
            receipt["verifier_output_sha256"] = "0" * 64
            receipt["revalidated_at_unix"] = 112
            recaptured[
                "post_verifier_live_source_revalidation_receipt_sha256"
            ] = (
                source_revalidation_binding
                .source_revalidation_receipt_sha256(receipt)
            )
            replay_head, replay_status, replayed_envelope = (
                attestor.sign_and_publish_attestation(
                    config,
                    recaptured,
                    public_key_bytes=self.public_bytes,
                    private_key_loader=lambda: (_ for _ in ()).throw(
                        AssertionError(
                            "private key reopened for equivalent recapture"
                        )
                    ),
                    updated_at_unix=121,
                    publication_owner_uid=os.geteuid(),
                    allow_equivalent_recapture=True,
                )
            )
            self.assertEqual(replay_status, "idempotent_recapture")
            self.assertEqual(replay_head, first_head)
            self.assertEqual(replayed_envelope, first_envelope)

            changed_plan = dict(recaptured)
            changed_plan["capture_plan_sha256"] = "8" * 64
            changed_plan[
                "post_verifier_live_source_revalidation_receipt"
            ] = copy.deepcopy(
                recaptured[
                    "post_verifier_live_source_revalidation_receipt"
                ]
            )
            changed_plan[
                "post_verifier_live_source_revalidation_receipt"
            ]["capture_plan_sha256"] = "8" * 64
            changed_plan[
                "post_verifier_live_source_revalidation_receipt_sha256"
            ] = (
                source_revalidation_binding
                .source_revalidation_receipt_sha256(
                    changed_plan[
                        "post_verifier_live_source_"
                        "revalidation_receipt"
                    ]
                )
            )
            self.assert_code(
                "same_run_different_attestation_rejected",
                attestor.sign_and_publish_attestation,
                config,
                changed_plan,
                public_key_bytes=self.public_bytes,
                private_key_loader=lambda: (_ for _ in ()).throw(
                    AssertionError("private key accessed before rejection")
                ),
                updated_at_unix=122,
                publication_owner_uid=os.geteuid(),
                allow_equivalent_recapture=True,
            )

    def test_single_flight_archived_replay_keeps_authoritative_newer_head(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            (root / "state").mkdir(mode=0o700)
            config = self.config(root)
            _, _, first_envelope = attestor.sign_and_publish_attestation(
                config,
                self.evidence(),
                public_key_bytes=self.public_bytes,
                private_key_loader=lambda: self.private_bytes,
                updated_at_unix=120,
                publication_owner_uid=os.geteuid(),
            )
            second_evidence = self.evidence(
                run_id="run-002",
                summary="7" * 64,
                binding="8" * 64,
                qualified_at=200,
                verified_at=210,
                expires_at=1200,
            )
            second_head, _, _ = attestor.sign_and_publish_attestation(
                config,
                second_evidence,
                public_key_bytes=self.public_bytes,
                private_key_loader=lambda: self.private_bytes,
                updated_at_unix=220,
                publication_owner_uid=os.geteuid(),
            )

            current_head, status, replayed_envelope = (
                attestor.sign_and_publish_attestation(
                    config,
                    self.evidence(),
                    public_key_bytes=self.public_bytes,
                    private_key_loader=lambda: (_ for _ in ()).throw(
                        AssertionError("private key accessed on archived replay")
                    ),
                    updated_at_unix=230,
                    publication_owner_uid=os.geteuid(),
                )
            )
            self.assertEqual(status, "idempotent_archived")
            self.assertEqual(current_head, second_head)
            self.assertEqual(current_head["chain_sequence"], 2)
            self.assertEqual(replayed_envelope, first_envelope)
            self.assertEqual(
                json.loads(Path(config["head_path"]).read_text(encoding="utf-8")),
                second_head,
            )

    def test_atomic_publication_is_immutable_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            state = root / "state"
            state.mkdir(mode=0o700)
            config = self.config(root)
            envelope = self.envelope(config=config)

            head, result = attestor.publish_attestation(
                config,
                envelope,
                public_key_bytes=self.public_bytes,
                updated_at_unix=120,
                publication_owner_uid=os.geteuid(),
            )
            self.assertEqual(result, "published")
            head_path = Path(config["head_path"])
            self.assertEqual(
                stat.S_IMODE(head_path.stat().st_mode),
                0o600,
            )
            attestation_path = Path(head["attestation_path"])
            self.assertTrue(attestation_path.is_file())
            self.assertEqual(stat.S_IMODE(attestation_path.stat().st_mode), 0o600)
            self.assertEqual(
                attestor.sha256_json(
                    json.loads(attestation_path.read_text(encoding="utf-8"))
                ),
                head["attestation_sha256"],
            )

            interrupted_temp = (
                attestation_path.parent
                / f".{attestation_path.name}.{'a' * 32}.tmp"
            )
            os.link(attestation_path, interrupted_temp)
            self.assertEqual(attestation_path.stat().st_nlink, 2)
            head_temp = (
                head_path.parent
                / f".{head_path.name}.{'b' * 32}.tmp"
            )
            head_temp.write_text("{}\n", encoding="utf-8")
            head_temp.chmod(0o600)

            repeated, result = attestor.publish_attestation(
                config,
                envelope,
                public_key_bytes=self.public_bytes,
                updated_at_unix=120,
                publication_owner_uid=os.geteuid(),
            )
            self.assertEqual(result, "idempotent")
            self.assertEqual(repeated, head)
            self.assertFalse(interrupted_temp.exists())
            self.assertFalse(head_temp.exists())
            self.assertEqual(attestation_path.stat().st_nlink, 1)
            self.assertEqual(len(list(attestation_path.parent.glob("*.json"))), 1)

    def test_chain_rejects_genesis_previous_gaps_and_forks(self) -> None:
        first = self.envelope()
        first_head, changed = self.plan_head(
            attestor.initial_head("john-example", updated_at_unix=0),
            first,
            attestation_path=self.attestation_path(),
            updated_at_unix=120,
        )
        self.assertTrue(changed)

        self.assert_code(
            "attestation_chain_genesis_previous_invalid",
            attestor.build_attestation_payload,
            self.config(),
            self.evidence(),
            public_key_bytes=self.public_bytes,
            chain_sequence=1,
            previous_attestation_sha256="9" * 64,
        )

        gap = self.envelope(
            evidence=self.evidence(
                run_id="run-003",
                qualified_at=200,
                verified_at=210,
                expires_at=1200,
            ),
            sequence=3,
            previous_attestation_sha256=attestor.sha256_json(first),
        )
        self.assert_code(
            "attestation_chain_sequence_invalid",
            self.plan_head,
            first_head,
            gap,
            attestation_path=self.attestation_path(
                run_id="run-003",
                sequence=3,
            ),
            updated_at_unix=220,
            current_envelope=first,
        )

        fork = self.envelope(
            evidence=self.evidence(
                run_id="run-002",
                qualified_at=200,
                verified_at=210,
                expires_at=1200,
            ),
            sequence=2,
            previous_attestation_sha256="9" * 64,
        )
        self.assert_code(
            "attestation_chain_previous_mismatch",
            self.plan_head,
            first_head,
            fork,
            attestation_path=self.attestation_path(
                run_id="run-002",
                sequence=2,
            ),
            updated_at_unix=220,
            current_envelope=first,
        )

        case_alias = self.envelope(
            evidence=self.evidence(
                run_id="RUN-001",
                qualified_at=200,
                verified_at=210,
                expires_at=1200,
            ),
            sequence=2,
            previous_attestation_sha256=attestor.sha256_json(first),
        )
        self.assert_code(
            "same_run_different_attestation_rejected",
            self.plan_head,
            first_head,
            case_alias,
            attestation_path=self.attestation_path(
                run_id="RUN-001",
                sequence=2,
            ),
            updated_at_unix=220,
            current_envelope=first,
        )

    def test_archive_reconciliation_blocks_head_deletion_rollback(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            (root / "state").mkdir(mode=0o700)
            config = self.config(root)
            first = self.envelope(config=config)
            first_head, result = attestor.publish_attestation(
                config,
                first,
                public_key_bytes=self.public_bytes,
                updated_at_unix=120,
                publication_owner_uid=os.geteuid(),
            )
            self.assertEqual(result, "published")

            second = self.envelope(
                config=config,
                evidence=self.evidence(
                    run_id="run-002",
                    summary="7" * 64,
                    binding="8" * 64,
                    qualified_at=200,
                    verified_at=210,
                    expires_at=1200,
                ),
                sequence=2,
                previous_attestation_sha256=first_head[
                    "attestation_sha256"
                ],
            )
            second_head, result = attestor.publish_attestation(
                config,
                second,
                public_key_bytes=self.public_bytes,
                updated_at_unix=220,
                publication_owner_uid=os.geteuid(),
            )
            self.assertEqual(result, "published")
            self.assertEqual(second_head["chain_sequence"], 2)

            Path(config["head_path"]).unlink()
            self.assert_code(
                "attestation_chain_sequence_invalid",
                attestor.publish_attestation,
                config,
                first,
                public_key_bytes=self.public_bytes,
                updated_at_unix=230,
                publication_owner_uid=os.geteuid(),
            )
            self.assertFalse(Path(config["head_path"]).exists())

            reconciled, result = attestor.publish_attestation(
                config,
                second,
                public_key_bytes=self.public_bytes,
                updated_at_unix=230,
                publication_owner_uid=os.geteuid(),
            )
            self.assertEqual(result, "reconciled")
            self.assertEqual(reconciled["chain_sequence"], 2)
            self.assertEqual(
                reconciled["attestation_sha256"],
                second_head["attestation_sha256"],
            )
            self.assertTrue(Path(config["head_path"]).is_file())
            Path(config["head_path"]).unlink()
            tip = attestor.read_attestation_chain_tip(
                config,
                public_key_bytes=self.public_bytes,
                publication_owner_uid=os.geteuid(),
            )
            self.assertEqual(tip["next_sequence"], 3)
            self.assertEqual(
                tip["previous_attestation_sha256"],
                second_head["attestation_sha256"],
            )
            self.assertTrue(Path(config["head_path"]).is_file())

    def test_read_only_tip_inspector_never_mutates_publication(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            state = root / "state"
            state.mkdir(mode=0o700)
            config = self.config(root)
            head, result = attestor.publish_attestation(
                config,
                self.envelope(config=config),
                public_key_bytes=self.public_bytes,
                updated_at_unix=120,
                publication_owner_uid=os.geteuid(),
            )
            self.assertEqual(result, "published")

            def publication_snapshot() -> dict[str, tuple[object, ...]]:
                snapshot: dict[str, tuple[object, ...]] = {}
                for path in sorted(state.rglob("*")):
                    info = path.lstat()
                    relative = path.relative_to(state).as_posix()
                    if path.is_file():
                        snapshot[relative] = (
                            "file",
                            stat.S_IMODE(info.st_mode),
                            info.st_dev,
                            info.st_ino,
                            info.st_nlink,
                            path.read_bytes(),
                        )
                    else:
                        snapshot[relative] = (
                            "directory",
                            stat.S_IMODE(info.st_mode),
                            info.st_dev,
                            info.st_ino,
                            info.st_nlink,
                        )
                return snapshot

            before = publication_snapshot()
            with (
                mock.patch.object(
                    attestor,
                    "_repair_head_replacement_temps",
                    side_effect=AssertionError("head repair attempted"),
                ),
                mock.patch.object(
                    attestor,
                    "_repair_interrupted_publications",
                    side_effect=AssertionError("archive repair attempted"),
                ),
                mock.patch.object(
                    attestor,
                    "_repair_interrupted_immutable_link",
                    side_effect=AssertionError("link repair attempted"),
                ),
                mock.patch.object(
                    attestor,
                    "_replace_json_at",
                    side_effect=AssertionError("head replacement attempted"),
                ),
            ):
                tip = attestor.inspect_attestation_chain_tip(
                    config,
                    public_key_bytes=self.public_bytes,
                    publication_owner_uid=os.geteuid(),
                )
            self.assertTrue(tip["read_only"])
            self.assertFalse(tip["head_was_missing"])
            self.assertFalse(tip["head_needs_repair"])
            self.assertEqual(tip["observed_head"], head)
            self.assertEqual(tip["current_head"], head)
            self.assertEqual(
                tip["previous_attestation_sha256"],
                head["attestation_sha256"],
            )
            self.assertEqual(
                tip["archive_index"],
                [
                    {
                        "run_id": "run-001",
                        "chain_sequence": 1,
                        "attestation_sha256": head[
                            "attestation_sha256"
                        ],
                        "verified_evidence_sha256": (
                            attestor.sha256_json(self.evidence())
                        ),
                    }
                ],
            )
            self.assertEqual(publication_snapshot(), before)

    def test_read_only_tip_inspector_reports_but_does_not_repair_head(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            (root / "state").mkdir(mode=0o700)
            config = self.config(root)
            with mock.patch.object(
                attestor,
                "_replace_json_at",
                side_effect=RuntimeError("simulated head loss"),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "simulated head loss",
                ):
                    attestor.publish_attestation(
                        config,
                        self.envelope(config=config),
                        public_key_bytes=self.public_bytes,
                        updated_at_unix=120,
                        publication_owner_uid=os.geteuid(),
                    )
            head_path = Path(config["head_path"])
            self.assertFalse(head_path.exists())
            tip = attestor.inspect_attestation_chain_tip(
                config,
                public_key_bytes=self.public_bytes,
                publication_owner_uid=os.geteuid(),
            )
            self.assertTrue(tip["head_was_missing"])
            self.assertTrue(tip["head_needs_repair"])
            self.assertIsNone(tip["observed_head"])
            self.assertEqual(tip["current_head"]["state"], "verified")
            self.assertIsNotNone(tip["current_envelope"])
            self.assertFalse(head_path.exists())

    def test_read_only_tip_inspector_rejects_repair_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            state = root / "state"
            state.mkdir(mode=0o700)
            config = self.config(root)
            attestor.publish_attestation(
                config,
                self.envelope(config=config),
                public_key_bytes=self.public_bytes,
                updated_at_unix=120,
                publication_owner_uid=os.geteuid(),
            )
            temporary = state / (
                f".{Path(config['head_path']).name}."
                + "a" * 32
                + ".tmp"
            )
            temporary.write_text("{}\n", encoding="utf-8")
            temporary.chmod(0o600)
            self.assert_code(
                "attestation_chain_repair_required",
                attestor.inspect_attestation_chain_tip,
                config,
                public_key_bytes=self.public_bytes,
                publication_owner_uid=os.geteuid(),
            )
            self.assertTrue(temporary.is_file())

    def test_read_only_tip_inspector_does_not_create_missing_lock(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            state = root / "state"
            state.mkdir(mode=0o700)
            config = self.config(root)
            lock = state / ".head.lock"
            self.assert_code(
                "publication_lock_missing",
                attestor.inspect_attestation_chain_tip,
                config,
                public_key_bytes=self.public_bytes,
                publication_owner_uid=os.geteuid(),
            )
            self.assertFalse(lock.exists())

    def test_archive_missing_genesis_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            (root / "state").mkdir(mode=0o700)
            config = self.config(root)
            first = self.envelope(config=config)
            first_head, _ = attestor.publish_attestation(
                config,
                first,
                public_key_bytes=self.public_bytes,
                updated_at_unix=120,
                publication_owner_uid=os.geteuid(),
            )
            second = self.envelope(
                config=config,
                evidence=self.evidence(
                    run_id="run-002",
                    qualified_at=200,
                    verified_at=210,
                    expires_at=1200,
                ),
                sequence=2,
                previous_attestation_sha256=first_head[
                    "attestation_sha256"
                ],
            )
            second_head, _ = attestor.publish_attestation(
                config,
                second,
                public_key_bytes=self.public_bytes,
                updated_at_unix=220,
                publication_owner_uid=os.geteuid(),
            )
            Path(config["head_path"]).unlink()
            Path(first_head["attestation_path"]).unlink()
            self.assert_code(
                "attestation_archive_sequence_invalid",
                attestor.publish_attestation,
                config,
                second,
                public_key_bytes=self.public_bytes,
                updated_at_unix=230,
                publication_owner_uid=os.geteuid(),
            )
            self.assertTrue(Path(second_head["attestation_path"]).is_file())

    def test_archive_rejects_unexpected_entries_and_signed_record_tamper(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            (root / "state").mkdir(mode=0o700)
            config = self.config(root)
            envelope = self.envelope(config=config)
            head, _ = attestor.publish_attestation(
                config,
                envelope,
                public_key_bytes=self.public_bytes,
                updated_at_unix=120,
                publication_owner_uid=os.geteuid(),
            )
            archive = Path(head["attestation_path"]).parent
            unexpected = archive / "unexpected.tmp"
            unexpected.write_text("not an attestation\n", encoding="utf-8")
            unexpected.chmod(0o600)
            self.assert_code(
                "attestation_archive_entry_unsafe",
                attestor.publish_attestation,
                config,
                envelope,
                public_key_bytes=self.public_bytes,
                updated_at_unix=120,
                publication_owner_uid=os.geteuid(),
            )
            unexpected.unlink()

            attestation_path = Path(head["attestation_path"])
            tampered = json.loads(attestation_path.read_text(encoding="utf-8"))
            tampered["payload"]["verification"][
                "capture_manifest_sha256"
            ] = "9" * 64
            receipt = tampered["payload"]["verification"][
                "post_verifier_live_source_revalidation_receipt"
            ]
            receipt["capture_manifest_sha256"] = "9" * 64
            tampered["payload"]["verification"][
                "post_verifier_live_source_revalidation_receipt_sha256"
            ] = (
                source_revalidation_binding
                .source_revalidation_receipt_sha256(receipt)
            )
            attestation_path.write_text(
                json.dumps(tampered, sort_keys=True, separators=(",", ":"))
                + "\n",
                encoding="utf-8",
            )
            attestation_path.chmod(0o600)
            self.assert_code(
                "attestation_signature_invalid",
                attestor.publish_attestation,
                config,
                envelope,
                public_key_bytes=self.public_bytes,
                updated_at_unix=120,
                publication_owner_uid=os.geteuid(),
            )

    def test_publication_binds_configured_key_and_evidence_uid(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            (root / "state").mkdir(mode=0o700)
            config = self.config(root)

            wrong_uid_config = {**config, "expected_evidence_uid": 502}
            wrong_uid_evidence = {
                **self.evidence(),
                "observed_evidence_uid": 502,
                "verifier_uid": 503,
                "capture_creator_uid": 504,
            }
            wrong_uid_envelope = self.envelope(
                config=wrong_uid_config,
                evidence=wrong_uid_evidence,
            )
            self.assert_code(
                "configured_evidence_uid_mismatch",
                attestor.publish_attestation,
                config,
                wrong_uid_envelope,
                public_key_bytes=self.public_bytes,
                updated_at_unix=120,
                publication_owner_uid=os.geteuid(),
            )

            wrong_key_config = {**config, "public_key_sha256": "0" * 64}
            self.assert_code(
                "configured_public_key_fingerprint_mismatch",
                attestor.build_attestation_payload,
                wrong_key_config,
                self.evidence(),
                public_key_bytes=self.public_bytes,
                chain_sequence=1,
                previous_attestation_sha256=None,
            )

    def test_identity_boundary_and_command_arguments_fail_closed(self) -> None:
        self.assert_code(
            "verification_identity_unsupported",
            attestor.assert_verification_identity,
            self.config(),
            process_uid=501,
        )
        self.assert_code(
            "verification_identity_unsupported",
            attestor.assert_verification_identity,
            self.config(),
            process_uid=502,
        )
        self.assertEqual(
            attestor.assert_verification_identity(self.config(), process_uid=0),
            self.config(),
        )

        with (
            mock.patch.object(
                attestor,
                "read_root_owned_config",
                return_value=self.config(),
            ),
            mock.patch.object(
                attestor,
                "assert_verification_identity",
                return_value=self.config(),
            ),
        ):
            self.assert_code(
                "verification_identity_unsupported",
                attestor.attest_configured,
            )

        stderr = StringIO()
        with redirect_stderr(stderr):
            code = attestor.main(["--config", "/tmp/attacker.json"])
        self.assertEqual(code, 2)
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {"status": "invalid", "reason": "command_arguments_unsupported"},
        )


if __name__ == "__main__":
    unittest.main()
