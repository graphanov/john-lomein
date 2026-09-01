#!/usr/bin/env python3
from __future__ import annotations

import ast
import fcntl
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_attestor as attestor_core,
)

INSTALLER = ROOT / "scripts" / "install-protected-persona-qualification.sh"
UNINSTALLER = (
    ROOT / "scripts" / "uninstall-protected-persona-qualification.sh"
)
TEMPLATE = (
    ROOT / "templates" / "persona-qualification-install-config.json.example"
)


def embedded_python_blocks(text: str) -> list[str]:
    return re.findall(r"<<'PY'\n(.*?)\nPY", text, flags=re.DOTALL)


class PersonaQualificationInstallerAssetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.install = INSTALLER.read_text(encoding="utf-8")
        cls.uninstall = UNINSTALLER.read_text(encoding="utf-8")
        cls.template_raw = TEMPLATE.read_bytes()
        cls.template = json.loads(cls.template_raw)
        cls.blocks = embedded_python_blocks(cls.install)

    def test_shell_assets_are_executable_fixed_bash_and_syntax_valid(
        self,
    ) -> None:
        for path in (INSTALLER, UNINSTALLER):
            self.assertTrue(path.stat().st_mode & 0o111)
            self.assertTrue(
                path.read_text(encoding="utf-8").startswith("#!/bin/bash\n")
            )
            subprocess.run(
                ["/bin/bash", "-n", str(path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        for index, block in enumerate(self.blocks):
            compile(block, f"<installer-python-{index}>", "exec")

    def test_operator_cli_platform_and_root_control_are_explicit(self) -> None:
        for option in (
            "--slug",
            "--config",
            "--attestor-private-key",
            "--attestor-public-key",
            "--python",
            "--evidence-user",
        ):
            self.assertIn(option, self.install)
        required = (
            'id -u)" -eq 0',
            'uname -s)" = "Darwin"',
            "macOS LaunchDaemons only",
            'validate_existing_path "$SCRIPT_PATH" 0 file "installer script"',
            'validate_existing_path "$PRODUCT_ROOT" 0 directory',
            'validate_existing_path "$PYTHON" 0 executable',
            "root-controlled source snapshot",
            "has a group/other-writable path component",
            "has an access-control list",
            "must be a singly linked regular file",
            "com.apple.provenance|com.apple.rootless",
        )
        for fragment in required:
            self.assertIn(fragment, self.install)
        transaction = self.install.index("TRANSACTION_STARTED=1")
        first_group_mutation = self.install.index(
            'ensure_group "$SIGNER_GROUP"'
        )
        self.assertLess(transaction, first_group_mutation)
        self.assertNotIn(
            'SIGNER_GID="$(ensure_group',
            self.install,
            msg="identity creation must not run in a subshell that loses rollback state",
        )

    def test_template_is_canonical_strict_and_disabled(self) -> None:
        expected_fields = {
            "schema_version",
            "enabled",
            "instance_slug",
            "instance_manifest_path",
            "runtime_root",
            "checkout_source_path",
            "checkout_identity_path",
            "runtime_source_path",
            "evidence_home_path",
            "qualification_public_root",
            "qualification_private_root",
            "attestor_key_id",
            "verifier_timeout_seconds",
            "capture_limits",
            "capture_lifecycle",
        }
        self.assertEqual(set(self.template), expected_fields)
        self.assertEqual(
            self.template["schema_version"],
            "john-lomein.persona-qualification-install-config.v1",
        )
        self.assertIs(self.template["enabled"], False)
        self.assertEqual(
            self.template["qualification_public_root"],
            f'{self.template["runtime_root"]}/state/persona-qualification',
        )
        self.assertEqual(
            self.template_raw,
            (
                json.dumps(
                    self.template,
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                    allow_nan=False,
                )
                + "\n"
            ).encode(),
        )
        self.assertEqual(
            set(self.template["capture_limits"]),
            {
                "max_files",
                "max_directories",
                "max_bytes",
                "max_file_bytes",
                "max_depth",
            },
        )
        self.assertEqual(
            self.template["capture_lifecycle"]["retention"], "ephemeral"
        )

    def test_preflight_generator_accepts_template_and_rejects_enablement(
        self,
    ) -> None:
        block = next(
            value
            for value in self.blocks
            if "CONFIG_FIELDS =" in value
            and "cryptography 50.0.1" in value
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.json"
            private_path = root / "private.pem"
            public_path = root / "public.pem"
            config.write_bytes(self.template_raw)
            private = Ed25519PrivateKey.generate()
            private_path.write_bytes(
                private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            public_path.write_bytes(
                private.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            command = [
                sys.executable,
                "-c",
                block,
                str(config),
                str(private_path),
                str(public_path),
                "example-repo",
                sys.executable,
                str(ROOT),
            ]
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = dict(
                line.split("\t", 1)
                for line in result.stdout.splitlines()
            )
            self.assertRegex(report["public_key_sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(Path(report["yaml_root"]).is_dir())

            unsafe = dict(self.template)
            unsafe["enabled"] = True
            config.write_text(
                json.dumps(unsafe, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            rejected = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("enabled must remain false", rejected.stderr)

            topology_cases = {
                "manifest_inside_runtime": {
                    "instance_manifest_path": (
                        f'{self.template["runtime_root"]}/instance.yaml'
                    )
                },
                "checkout_identity_inside_runtime": {
                    "checkout_identity_path": (
                        f'{self.template["runtime_root"]}/checkout'
                    )
                },
                "runtime_source_inside_checkout": {
                    "runtime_source_path": (
                        f'{self.template["checkout_source_path"]}/runtime'
                    )
                },
                "checkout_identity_inside_private": {
                    "checkout_identity_path": (
                        f'{self.template["qualification_private_root"]}/checkout'
                    )
                },
            }
            for label, changes in topology_cases.items():
                with self.subTest(topology=label):
                    invalid = {**self.template, **changes}
                    config.write_text(
                        json.dumps(
                            invalid,
                            ensure_ascii=False,
                            sort_keys=True,
                            indent=2,
                            allow_nan=False,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    rejected = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn(
                        "capture selection rejected",
                        rejected.stderr,
                    )

    def test_deterministic_accounts_and_membership_invariants(self) -> None:
        expected_id = hashlib.sha256(b"example-repo").hexdigest()[:12]
        self.assertEqual(len(expected_id), 12)
        required = (
            'SIGNER_USER="_jlqs_$INSTANCE_ID"',
            'CAPTURE_USER="_jlqc_$INSTANCE_ID"',
            'VERIFIER_USER="_jlqv_$INSTANCE_ID"',
            'EXPORT_GROUP="_jlqe_$INSTANCE_ID"',
            "NFSHomeDirectory /var/empty",
            "UserShell /usr/bin/false",
            "Password '*'",
            "IsHidden 1",
            'ensure_export_member "$EVIDENCE_USER"',
            'ensure_export_member "$CAPTURE_USER"',
            "private group is not dedicated to its service identity",
            "evidence export group contains an unrelated user",
            "qualification service users and evidence user must be distinct",
            "next_directory_id /Groups PrimaryGroupID",
            "next_directory_id /Users UniqueID",
            "assert_unique_directory_id /Groups PrimaryGroupID",
            "assert_unique_directory_id /Users UniqueID",
            "has unsafe existing attributes",
            "john-lomein-persona-qualification.install.lock",
            "/usr/bin/lockf -t 0 9",
            "another persona qualification install or uninstall is running",
            'validate_existing_path "$GLOBAL_INSTALL_LOCK" 0 file',
        )
        for fragment in required:
            self.assertIn(fragment, self.install)
        self.assertIn("350..499", self.install)
        self.assertIn("sha256(sys.argv[1].encode", self.install)

    def test_upgrade_trust_identity_continuity_uses_attestor_contract(
        self,
    ) -> None:
        block = next(
            value
            for value in self.blocks
            if "existing attestor trust identity differs" in value
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_config_path = root / "install-config.json"
            existing_config_path = root / "attestor.json"
            install_record_path = root / "install-record.json"
            private_key_path = str(root / "keys" / "private.pem")
            public_key_path = str(root / "keys" / "public.pem")
            head_path = str(root / "state" / "head.json")
            public_key_sha256 = "a" * 64
            install_config_path.write_bytes(self.template_raw)
            existing_config = {
                "schema_version": 1,
                "instance_slug": "example-repo",
                "qualification_public_root": self.template[
                    "qualification_public_root"
                ],
                "qualification_private_root": self.template[
                    "qualification_private_root"
                ],
                "expected_evidence_uid": 501,
                "attestor_key_id": self.template["attestor_key_id"],
                "private_key_path": private_key_path,
                "public_key_path": public_key_path,
                "public_key_sha256": public_key_sha256,
                "head_path": head_path,
            }
            existing_config_path.write_text(
                json.dumps(existing_config, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            install_record = {
                "schema_version": (
                    "john-lomein.persona-qualification-install-record.v1"
                ),
                "instance_slug": "example-repo",
                "identities": {
                    "instance_id": hashlib.sha256(
                        b"example-repo"
                    ).hexdigest()[:12],
                    "evidence": {"user": "runtime-user", "uid": 501},
                    "signer": {"user": "_jlqs_deadbeefcafe"},
                    "capture": {"user": "_jlqc_deadbeefcafe"},
                    "verifier": {"user": "_jlqv_deadbeefcafe"},
                    "export": {"group": "_jlqe_deadbeefcafe"},
                },
            }
            install_record_path.write_text(
                json.dumps(install_record, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            base_args = [
                str(ROOT),
                str(install_config_path),
                str(existing_config_path),
                str(install_record_path),
                "example-repo",
                "runtime-user",
                "501",
                "_jlqs_deadbeefcafe",
                "_jlqc_deadbeefcafe",
                "_jlqv_deadbeefcafe",
                "_jlqe_deadbeefcafe",
                private_key_path,
                public_key_path,
                self.template["qualification_public_root"],
                self.template["qualification_private_root"],
                head_path,
                public_key_sha256,
            ]
            accepted = subprocess.run(
                [sys.executable, "-c", block, *base_args],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            changed_install = dict(self.template)
            changed_install["attestor_key_id"] = "replacement-key"
            install_config_path.write_text(
                json.dumps(changed_install, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            key_id_rejected = subprocess.run(
                [sys.executable, "-c", block, *base_args],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(key_id_rejected.returncode, 0)
            self.assertIn(
                "explicit migration required",
                key_id_rejected.stderr,
            )

            install_config_path.write_bytes(self.template_raw)
            changed_uid_args = list(base_args)
            changed_uid_args[6] = "502"
            uid_rejected = subprocess.run(
                [sys.executable, "-c", block, *changed_uid_args],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(uid_rejected.returncode, 0)
            self.assertIn("explicit migration required", uid_rejected.stderr)

    def test_canonical_paths_and_owner_mode_matrix_are_explicit(self) -> None:
        paths = (
            "/private/etc/john-lomein-persona-qualification.d",
            "/private/etc/john-lomein-persona-qualification-public",
            "/private/var/db/john-lomein-persona-qualification",
            "/usr/local/libexec/john-lomein-persona-qualification",
            "/usr/local/libexec/john-lomein-persona-qualification-instances",
            "/Library/LaunchDaemons",
            "capture-selection.json",
            "public-verifier.json",
            "trust-projection.json",
            "verifier-bundle-manifest.json",
        )
        for path in paths:
            self.assertIn(path, self.install)
        modes = (
            '"$INSTANCE_CONFIG_DIR" root wheel 0700',
            '"$KEYS_DIR" root wheel 0700',
            '"$INSTANCE_PUBLIC_DIR" root wheel 0755',
            '"$DATA_ROOT" root wheel 0711',
            '"$INSTANCE_DATA_DIR" root wheel 0711',
            '"$STATE_DIR" root wheel 0700',
            '"$TRANSACTION_JOURNAL_DIR" root wheel 0700',
            '"$TRANSACTION_JOURNAL_COMPLETED_DIR" root wheel 0700',
            '"$STAGING_DIR" root wheel 0711',
            '"$CAPTURE_DIR" root "$VERIFIER_GROUP" 0710',
            '"$SCRATCH_DIR" "$VERIFIER_USER" "$VERIFIER_GROUP" 0700',
            '"$EXPORT_DIR" "$EVIDENCE_USER" "$EXPORT_GROUP" 0750',
            '"$PRIVATE_KEY_PATH" root wheel 0600',
            '"$PUBLIC_KEY_PATH" root wheel 0444',
            '"$PUBLIC_PIN_PATH" root wheel 0444',
            '"$ATTEST_WRAPPER_PATH" root wheel 0555',
            '"$PLIST_PATH" root wheel 0644',
        )
        for fragment in modes:
            self.assertIn(fragment, self.install)
        self.assertIn(
            'validate_private_file_owner \\\n'
            '  "$INSTANCE_MANIFEST_PATH" "$EVIDENCE_UID" "instance manifest"',
            self.install,
        )
        self.assertIn(
            'die "$label has the wrong owner"',
            self.install,
        )
        self.assertIn(
            "must not grant group or other permissions",
            self.install,
        )

    def test_role_bundles_are_separate_complete_and_content_addressed(
        self,
    ) -> None:
        for role in (
            "capture",
            "verifier",
            "coordinator",
            "public-verifier",
        ):
            self.assertIn(role, self.install)
        self.assertIn('"$BUNDLE_STAGE_ROOT/$role"', self.install)
        self.assertIn(
            '"$BUNDLES_ROOT/$INSTANCE_ID/$role"',
            self.install,
        )
        self.assertIn(
            "john_lomein_persona_qualification_capture_child.py",
            self.install,
        )
        self.assertIn(
            "john_lomein_persona_qualification_capture_protocol.py",
            self.install,
        )
        self.assertIn(
            "john_lomein_persona_qualification_capture_adoption.py",
            self.install,
        )
        self.assertIn(
            "john_lomein_persona_qualification_adoption_binding.py",
            self.install,
        )
        self.assertIn(
            (
                "john_lomein_persona_qualification_"
                "adoption_reconciliation.py"
            ),
            self.install,
        )
        self.assertIn(
            (
                "john_lomein_persona_qualification_"
                "adoption_recovery.py"
            ),
            self.install,
        )
        self.assertIn(
            (
                "john_lomein_persona_qualification_"
                "adoption_result.py"
            ),
            self.install,
        )
        self.assertIn(
            (
                "john_lomein_persona_qualification_"
                "recovered_adoption_evidence.py"
            ),
            self.install,
        )
        self.assertIn(
            "john_lomein_persona_qualification_native_bundle.py",
            self.install,
        )
        self.assertIn(
            "john_lomein_persona_qualification_native_host_evidence.py",
            self.install,
        )
        self.assertIn(
            "john_lomein_persona_qualification_wheel_provenance.py",
            self.install,
        )
        self.assertIn(
            "persona-qualification-native-bundle-manifest.v3.schema.json",
            self.install,
        )
        self.assertIn(
            "john_lomein_persona_qualification_verifier.py",
            self.install,
        )
        self.assertIn(
            "john_lomein_persona_qualification_orchestrator.py",
            self.install,
        )
        self.assertIn(
            "john_lomein_persona_qualification_transaction_journal.py",
            self.install,
        )
        self.assertIn(
            (
                "john_lomein_persona_qualification_"
                "capture_staging_receipts.py"
            ),
            self.install,
        )
        self.assertIn(
            (
                "john_lomein_persona_qualification_"
                "lifecycle_receipts.py"
            ),
            self.install,
        )
        self.assertIn(
            "john_lomein_persona_qualification_public_verifier.py",
            self.install,
        )
        capture_role = self.install.split(
            "# The capture role is deliberately standard-library-only.",
            1,
        )[1].split(
            "# The coordinator role contains authority-ordering code",
            1,
        )[0]
        self.assertIn(
            "john_lomein_persona_qualification_capture_child.py",
            capture_role,
        )
        self.assertNotIn(
            "john_lomein_persona_qualification_capture_helper.py",
            capture_role,
        )
        self.assertNotIn(
            "john_lomein_persona_qualification_capture_selection.py",
            capture_role,
        )
        coordinator_role = self.install.split(
            "# The coordinator role contains authority-ordering code",
            1,
        )[1].split(
            "# Public verification is a separate immutable role.",
            1,
        )[0]
        for name in (
            "john_lomein_persona_qualification_adoption_binding.py",
            (
                "john_lomein_persona_qualification_"
                "adoption_reconciliation.py"
            ),
            (
                "john_lomein_persona_qualification_"
                "adoption_recovery.py"
            ),
            (
                "john_lomein_persona_qualification_"
                "adoption_result.py"
            ),
            (
                "john_lomein_persona_qualification_"
                "recovered_adoption_evidence.py"
            ),
            "john_lomein_persona_qualification_capture_adoption.py",
            "john_lomein_persona_qualification_capture_child.py",
            "john_lomein_persona_qualification_capture_helper.py",
            "john_lomein_persona_qualification_capture_plan.py",
            "john_lomein_persona_qualification_capture_protocol.py",
            "john_lomein_persona_qualification_capture_staging.py",
            (
                "john_lomein_persona_qualification_"
                "capture_staging_receipts.py"
            ),
            (
                "john_lomein_persona_qualification_"
                "lifecycle_receipts.py"
            ),
            "john_lomein_persona_qualification_native_bundle.py",
            "john_lomein_persona_qualification_native_host_evidence.py",
            "john_lomein_persona_qualification_opaque_capture.py",
            "john_lomein_persona_qualification_transaction_journal.py",
            "john_lomein_persona_qualification_wheel_provenance.py",
        ):
            self.assertIn(name, coordinator_role)
        for marker in (
            "# The capture role is deliberately standard-library-only.",
            "# Public verification is a separate immutable role.",
            "# The verifier bundle includes only replay/evaluator assets",
        ):
            self.assertNotEqual(self.install.find(marker), -1)
        capture_role = self.install.split(
            "# The capture role is deliberately standard-library-only.",
            1,
        )[1].split(
            "# The coordinator role contains authority-ordering code",
            1,
        )[0]
        public_role = self.install.split(
            "# Public verification is a separate immutable role.",
            1,
        )[1].split(
            "# The verifier bundle includes only replay/evaluator assets",
            1,
        )[0]
        verifier_role = self.install.split(
            "# The verifier bundle includes only replay/evaluator assets",
            1,
        )[1].split(
            'FINAL_REPORT="$TEMP_DIR/final.tsv"',
            1,
        )[0]
        for role_body in (public_role, verifier_role):
            for pure_adoption_contract in (
                (
                    "john_lomein_persona_qualification_"
                    "adoption_reconciliation.py"
                ),
                (
                    "john_lomein_persona_qualification_"
                    "adoption_result.py"
                ),
                (
                    "john_lomein_persona_qualification_"
                    "recovered_adoption_evidence.py"
                ),
            ):
                self.assertIn(pure_adoption_contract, role_body)
        for role_body in (capture_role, public_role, verifier_role):
            for coordinator_only in (
                "john_lomein_persona_qualification_capture_staging.py",
                (
                    "john_lomein_persona_qualification_"
                    "capture_staging_receipts.py"
                ),
                (
                    "john_lomein_persona_qualification_"
                    "transaction_journal.py"
                ),
                (
                    "john_lomein_persona_qualification_"
                    "adoption_recovery.py"
                ),
                (
                    "john_lomein_persona_qualification_"
                    "lifecycle_receipts.py"
                ),
            ):
                self.assertNotIn(coordinator_only, role_body)
        for pure_adoption_contract in (
            (
                "john_lomein_persona_qualification_"
                "adoption_reconciliation.py"
            ),
            (
                "john_lomein_persona_qualification_"
                "adoption_result.py"
            ),
            (
                "john_lomein_persona_qualification_"
                "recovered_adoption_evidence.py"
            ),
        ):
            self.assertNotIn(pure_adoption_contract, capture_role)
        self.assertIn("vendor/yaml/$yaml_relative", self.install)
        self.assertIn("content-addressed bundle has conflicting bytes", self.install)
        self.assertIn('"bundle_sha256": digest', self.install)
        self.assertIn('"native_dependency_closure": "not-qualified"', self.install)
        self.assertIn(
            "installed bundle contains a hard-linked file",
            self.install,
        )
        self.assertIn(
            "installed bundle contains an unsupported entry",
            self.install,
        )
        self.assertIn(
            'reject_xattrs "$candidate" "$role installed bundle"',
            self.install,
        )

    def test_relocated_role_entrypoints_import_all_packaged_local_dependencies(
        self,
    ) -> None:
        role_sections = {
            "coordinator": self.install.split(
                "# The coordinator role contains authority-ordering code",
                1,
            )[1].split(
                "# Public verification is a separate immutable role.",
                1,
            )[0],
            "public-verifier": self.install.split(
                "# Public verification is a separate immutable role.",
                1,
            )[1].split(
                "# The verifier bundle includes only replay/evaluator assets",
                1,
            )[0],
            "verifier": self.install.split(
                "# The verifier bundle includes only replay/evaluator assets",
                1,
            )[1].split(
                'FINAL_REPORT="$TEMP_DIR/final.tsv"',
                1,
            )[0],
        }
        staged_attestor_names = {
            role: set(
                re.findall(
                    r"\b(?:__init__|"
                    r"john_lomein_persona_qualification_[a-z0-9_]+)"
                    r"\.py\b",
                    section,
                )
            )
            for role, section in role_sections.items()
        }
        staged_attestor_names = {
            role: {
                name
                for name in names
                if (ROOT / "qualification_attestor" / name).is_file()
            }
            for role, names in staged_attestor_names.items()
        }
        entrypoints = {
            "coordinator": (
                ROOT
                / "qualification_attestor"
                / "john_lomein_persona_qualification_orchestrator.py"
            ),
            "public-verifier": (
                ROOT / "scripts" / "john-lomein-persona-trust.py"
            ),
            "verifier": (
                ROOT
                / "qualification_verifier"
                / "john_lomein_persona_qualification_verifier.py"
            ),
        }

        def local_attestor_closure(entrypoint: Path) -> set[str]:
            required: set[str] = set()
            pending = [entrypoint]
            inspected: set[Path] = set()
            while pending:
                source = pending.pop()
                if source in inspected:
                    continue
                inspected.add(source)
                parsed = ast.parse(
                    source.read_text(encoding="utf-8"),
                    filename=str(source),
                )
                for node in ast.walk(parsed):
                    if not (
                        isinstance(node, ast.ImportFrom)
                        and node.module == "qualification_attestor"
                    ):
                        continue
                    for imported in node.names:
                        name = f"{imported.name}.py"
                        candidate = ROOT / "qualification_attestor" / name
                        if candidate.is_file() and name not in required:
                            required.add(name)
                            pending.append(candidate)
            return required

        coordinator_seeds = [
            ROOT / "qualification_attestor" / name
            for name in staged_attestor_names["coordinator"]
            if name != "__init__.py"
        ]
        required_by_role = {
            role: set().union(
                *(
                    local_attestor_closure(seed)
                    for seed in (
                        coordinator_seeds
                        if role == "coordinator"
                        else [entrypoint]
                    )
                )
            )
            for role, entrypoint in entrypoints.items()
        }
        for role, required in required_by_role.items():
            with self.subTest(role=role, check="transitive-local-closure"):
                self.assertIn("__init__.py", staged_attestor_names[role])
                self.assertEqual(
                    required - staged_attestor_names[role],
                    set(),
                    msg=(
                        f"{role} omits transitive qualification_attestor "
                        "dependencies"
                    ),
                )

        def install_crypto_import_sentinel(bundle_root: Path) -> None:
            """Supply names only; native dependency closure remains unclaimed."""

            files = {
                "cryptography/__init__.py": "",
                "cryptography/exceptions.py": (
                    "class InvalidSignature(Exception):\n"
                    "    pass\n"
                    "class UnsupportedAlgorithm(Exception):\n"
                    "    pass\n"
                ),
                "cryptography/hazmat/__init__.py": "",
                "cryptography/hazmat/primitives/__init__.py": (
                    "from . import serialization\n"
                ),
                "cryptography/hazmat/primitives/serialization.py": "",
                "cryptography/hazmat/primitives/asymmetric/__init__.py": "",
                (
                    "cryptography/hazmat/primitives/asymmetric/"
                    "ed25519.py"
                ): (
                    "class Ed25519PrivateKey:\n"
                    "    pass\n"
                    "class Ed25519PublicKey:\n"
                    "    pass\n"
                ),
            }
            for relative, body in files.items():
                destination = bundle_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(body, encoding="utf-8")

        with tempfile.TemporaryDirectory() as temporary:
            isolated_root = Path(temporary)
            working_directory = isolated_root / "outside-bundles"
            working_directory.mkdir()
            role_roots: dict[str, Path] = {}
            for role, names in staged_attestor_names.items():
                role_root = isolated_root / "bundles" / role
                role_roots[role] = role_root
                for name in names:
                    source = ROOT / "qualification_attestor" / name
                    destination = role_root / "qualification_attestor" / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination)

            public_wrapper = (
                role_roots["public-verifier"]
                / "scripts"
                / "john-lomein-persona-trust.py"
            )
            public_wrapper.parent.mkdir(parents=True)
            shutil.copyfile(entrypoints["public-verifier"], public_wrapper)

            verifier_package = role_roots["verifier"] / "qualification_verifier"
            verifier_package.mkdir(parents=True)
            for name in (
                "__init__.py",
                "john_lomein_persona_qualification_verifier.py",
            ):
                shutil.copyfile(
                    ROOT / "qualification_verifier" / name,
                    verifier_package / name,
                )

            # This smoke verifies relocation and complete local module
            # packaging.  The install record separately and deliberately says
            # the external cryptography/native closure is not qualified.
            for role in ("coordinator", "public-verifier"):
                install_crypto_import_sentinel(role_roots[role])

            commands = {
                "coordinator": [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(
                        role_roots["coordinator"]
                        / "qualification_attestor"
                        / "john_lomein_persona_qualification_orchestrator.py"
                    ),
                ],
                "public-verifier": [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(public_wrapper),
                    "reject-after-import",
                ],
                "verifier": [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(
                        verifier_package
                        / "john_lomein_persona_qualification_verifier.py"
                    ),
                    "reject-after-import",
                ],
            }
            for role, command in commands.items():
                with self.subTest(role=role, check="isolated-relocation"):
                    result = subprocess.run(
                        command,
                        cwd=working_directory,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if role == "coordinator":
                        self.assertEqual(result.returncode, 0, result.stderr)
                    else:
                        self.assertEqual(result.returncode, 2, result.stderr)
                        response = json.loads(result.stdout)
                        self.assertEqual(
                            response["reason"],
                            "command_arguments_unsupported",
                        )

    def test_bundle_inventory_digest_is_sorted_and_byte_sensitive(self) -> None:
        block = next(value for value in self.blocks if "def inventory(root, role):" in value)
        parsed = ast.parse(block)
        selected = [
            node
            for node in parsed.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            or (
                isinstance(node, ast.FunctionDef)
                and node.name in {"canonical", "inventory"}
            )
        ]
        namespace: dict[str, object] = {}
        exec(
            compile(ast.Module(body=selected, type_ignores=[]), "<inventory>", "exec"),
            namespace,
        )
        inventory = namespace["inventory"]
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            (bundle / "z").mkdir(parents=True)
            (bundle / "a").mkdir()
            (bundle / "z" / "two").write_bytes(b"two")
            (bundle / "a" / "one").write_bytes(b"one")
            os.chmod(bundle / "z", 0o550)
            os.chmod(bundle / "a", 0o550)
            os.chmod(bundle / "z" / "two", 0o440)
            os.chmod(bundle / "a" / "one", 0o440)
            first, first_digest = inventory(bundle, "verifier")
            second, second_digest = inventory(bundle, "verifier")
            self.assertEqual(first, second)
            self.assertEqual(first_digest, second_digest)
            self.assertEqual(
                [item["path"] for item in first["files"]],
                ["a/one", "z/two"],
            )
            os.chmod(bundle / "z" / "two", 0o640)
            (bundle / "z" / "two").write_bytes(b"changed")
            os.chmod(bundle / "z" / "two", 0o440)
            _, changed_digest = inventory(bundle, "verifier")
            self.assertNotEqual(first_digest, changed_digest)

    def test_transaction_journal_layout_is_secure_idempotent_and_durable(
        self,
    ) -> None:
        block = next(
            value
            for value in self.blocks
            if "transaction journal layout escaped its fixed namespace"
            in value
        )
        with tempfile.TemporaryDirectory() as temporary:
            anchor = Path(temporary) / "instance"
            state = anchor / "state"
            store = state / "transactions"
            completed = store / ".completed"
            lock = store / ".lock"
            completed.mkdir(parents=True)
            anchor.chmod(0o711)
            state.chmod(0o700)
            store.chmod(0o700)
            completed.chmod(0o700)
            args = [
                str(anchor),
                str(state),
                str(store),
                str(completed),
                str(lock),
                str(os.geteuid()),
                str(os.getegid()),
            ]

            created = subprocess.run(
                [sys.executable, "-I", "-B", "-S", "-c", block, *args],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            self.assertEqual(created.stdout, "created\n")
            info = lock.lstat()
            self.assertTrue(info.st_mode & 0o170000 == 0o100000)
            self.assertEqual(info.st_mode & 0o777, 0o600)
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(info.st_size, 0)

            existing = subprocess.run(
                [sys.executable, "-I", "-B", "-S", "-c", block, *args],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(existing.returncode, 0, existing.stderr)
            self.assertEqual(existing.stdout, "existing\n")

            with lock.open("r+b") as held:
                fcntl.flock(
                    held.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
                busy = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        "-S",
                        "-c",
                        block,
                        *args,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertNotEqual(busy.returncode, 0)
                self.assertIn(
                    "transaction journal lock is already held",
                    busy.stderr,
                )

            lock.chmod(0o644)
            unsafe = subprocess.run(
                [sys.executable, "-I", "-B", "-S", "-c", block, *args],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(unsafe.returncode, 0)
            self.assertIn("journal lock metadata is unsafe", unsafe.stderr)

            lock.unlink()
            lock.symlink_to("/dev/null")
            redirected = subprocess.run(
                [sys.executable, "-I", "-B", "-S", "-c", block, *args],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(redirected.returncode, 0)

    def test_final_generator_renders_strict_controls_and_disabled_plist(
        self,
    ) -> None:
        block = next(value for value in self.blocks if "def inventory(root, role):" in value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle_stage = root / "bundles"
            generated = root / "generated"
            for role in (
                "capture",
                "verifier",
                "coordinator",
                "public-verifier",
            ):
                directory_mode = (
                    0o555 if role == "public-verifier" else 0o550
                )
                data_mode = (
                    0o444 if role == "public-verifier" else 0o440
                )
                executable_mode = (
                    0o555 if role == "public-verifier" else 0o550
                )
                role_root = bundle_stage / role
                role_root.mkdir(parents=True)
                (role_root / "python").write_bytes(b"python-binary")
                os.chmod(role_root / "python", executable_mode)
                if role == "verifier":
                    entry = (
                        role_root
                        / "qualification_verifier"
                        / "john_lomein_persona_qualification_verifier.py"
                    )
                    entry.parent.mkdir()
                    entry.write_bytes(b"verifier")
                    os.chmod(entry, 0o440)
                    os.chmod(entry.parent, 0o550)
                else:
                    entry = role_root / "role.py"
                    entry.write_bytes(role.encode())
                    os.chmod(entry, data_mode)
                if role == "coordinator":
                    journal_source = (
                        ROOT
                        / "qualification_attestor"
                        / (
                            "john_lomein_persona_qualification_"
                            "transaction_journal.py"
                        )
                    )
                    journal_target = (
                        role_root
                        / "qualification_attestor"
                        / journal_source.name
                    )
                    journal_target.parent.mkdir()
                    journal_target.write_bytes(journal_source.read_bytes())
                    os.chmod(journal_target, data_mode)
                    os.chmod(journal_target.parent, directory_mode)
                os.chmod(role_root, directory_mode)
            config_path = root / "config.json"
            config_path.write_bytes(self.template_raw)
            p = lambda name: str(root / name)
            args = [
                str(config_path),
                str(bundle_stage),
                str(generated),
                "example-repo",
                "runtime-user",
                "501",
                "_jlqs_deadbeefcafe",
                "401",
                "411",
                "_jlqc_deadbeefcafe",
                "402",
                "412",
                "_jlqv_deadbeefcafe",
                "403",
                "413",
                "_jlqe_deadbeefcafe",
                "414",
                "deadbeefcafe",
                "a" * 64,
                "b" * 64,
                sys.executable,
                self.template["instance_manifest_path"],
                self.template["runtime_root"],
                self.template["checkout_source_path"],
                self.template["checkout_identity_path"],
                self.template["runtime_source_path"],
                self.template["evidence_home_path"],
                self.template["qualification_public_root"],
                self.template["qualification_private_root"],
                p("config-root"),
                p("config-root/example-repo"),
                p("config-root/example-repo/keys"),
                p("public/example-repo"),
                p("data/state"),
                p("data/staging"),
                p("data/captures"),
                p("data/scratch"),
                p("data/export"),
                p("code/bundles"),
                p("code/instances/example-repo"),
                p("config-root/example-repo/attestor.json"),
                p("config-root/example-repo/persona-qualification-verifier.example-repo.json"),
                p("config-root/example-repo/capture-selection.json"),
                p("config-root/example-repo/install-record.json"),
                p("config-root/example-repo/native-closure.json"),
                p("config-root/example-repo/keys/private.pem"),
                p("config-root/example-repo/keys/public.pem"),
                p("config-root/example-repo/verifier-manifest.json"),
                p("config-root/example-repo/capture-manifest.json"),
                p("config-root/example-repo/coordinator-manifest.json"),
                p("config-root/example-repo/public-verifier-manifest.json"),
                p("public/example-repo/public.pem"),
                p("public/example-repo/pin.json"),
                p("public/example-repo/status.json"),
                p("public/example-repo/policy.json"),
                p("public/example-repo/projection.json"),
                p("code/instances/example-repo/attest"),
                p("code/instances/example-repo/trust"),
                p("code/instances/example-repo/doctor"),
                p("bin/trust"),
                p("bin/doctor"),
                "com.john-lomein.persona-qualification.example-repo",
                p("LaunchDaemons/example.plist"),
            ]
            result = subprocess.run(
                [sys.executable, "-c", block, *args],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            bundle_rows = [
                line.split("\t") for line in result.stdout.splitlines()
            ]
            self.assertEqual(len(bundle_rows), 4)
            self.assertEqual(
                {row[1] for row in bundle_rows},
                {"capture", "verifier", "coordinator", "public-verifier"},
            )
            for row in bundle_rows:
                self.assertEqual(
                    Path(row[4]).parts[-3:-1],
                    ("deadbeefcafe", row[1]),
                )
            selection = json.loads(
                (generated / "capture-selection.json").read_text()
            )
            self.assertEqual(
                selection["schema_version"],
                "john-lomein.persona-qualification-capture-selection.v1",
            )
            self.assertEqual(selection["evidence_uid"], 501)
            self.assertEqual(selection["verifier_gid"], 413)
            self.assertNotIn("checkout", selection["source_roots"])
            pin = json.loads((generated / "public-pin.json").read_text())
            self.assertEqual(pin["public_key_sha256"], "a" * 64)
            record = json.loads((generated / "install-record.json").read_text())
            self.assertIs(record["production_activation"], False)
            self.assertEqual(record["activation_receipts"], [])
            self.assertGreaterEqual(len(record["activation_blockers"]), 4)
            self.assertIn(
                "capture_handoff_v2_not_bound_to_installed_launcher",
                record["activation_blockers"],
            )
            self.assertIn(
                "capture_staging_parent_session_lifecycle_missing",
                record["activation_blockers"],
            )
            self.assertIn(
                "lifecycle_root_supervisor_not_implemented",
                record["activation_blockers"],
            )
            self.assertIn(
                "lifecycle_supervisor_installed_bundle_service_missing",
                record["activation_blockers"],
            )
            self.assertIn(
                "lifecycle_supervisor_server_peer_auth_missing",
                record["activation_blockers"],
            )
            self.assertIn(
                "lifecycle_capability_process_boundary_missing",
                record["activation_blockers"],
            )
            self.assertIn(
                "lifecycle_recovered_clearance_consume_authority_missing",
                record["activation_blockers"],
            )
            self.assertIn(
                "lifecycle_remote_error_commit_proof_missing",
                record["activation_blockers"],
            )
            self.assertIn(
                "lifecycle_terminal_retirement_authority_missing",
                record["activation_blockers"],
            )
            self.assertIn(
                "lifecycle_privileged_provider_adapter_missing",
                record["activation_blockers"],
            )
            self.assertIn(
                "lifecycle_privileged_canary_missing",
                record["activation_blockers"],
            )
            self.assertIn(
                "capture_adoption_crash_recovery_missing",
                record["activation_blockers"],
            )
            self.assertIn(
                "adoption_reconciliation_producer_missing",
                record["activation_blockers"],
            )
            self.assertIn(
                (
                    "recovered_adoption_installed_journal_"
                    "mint_integration_missing"
                ),
                record["activation_blockers"],
            )
            self.assertIn(
                "recovered_adoption_downstream_binding_missing",
                record["activation_blockers"],
            )
            self.assertIn(
                "outer_ack_clearance_capability_missing",
                record["activation_blockers"],
            )
            self.assertIn(
                "transaction_journal_runtime_orchestration_missing",
                record["activation_blockers"],
            )
            self.assertIn(
                (
                    "transaction_journal_installed_"
                    "operation_lease_integration_missing"
                ),
                record["activation_blockers"],
            )
            self.assertNotIn(
                "transaction_journal_operation_lease_missing",
                record["activation_blockers"],
            )
            self.assertNotIn(
                "post_verifier_live_source_revalidation_missing",
                record["activation_blockers"],
            )
            self.assertIs(
                attestor_core.VERIFICATION_EXECUTION_POLICY[
                    "post_verifier_live_source_revalidation"
                ],
                True,
            )
            self.assertEqual(
                attestor_core.VERIFICATION_EXECUTION_POLICY[
                    "post_verifier_live_source_revalidation_order"
                ],
                [
                    "verifier_process_reaped",
                    (
                        "verifier_output_canonicalized_"
                        "and_adoption_bound"
                    ),
                    (
                        "live_sources_revalidated_against_"
                        "adopted_manifest"
                    ),
                    "private_key_opened",
                ],
            )
            policy = json.loads((generated / "operator-policy.json").read_text())
            self.assertEqual(
                policy["schema_version"],
                "john-lomein.persona-qualification-operator-policy.v3",
            )
            self.assertEqual(policy["expected_capture_uid"], 402)
            self.assertEqual(policy["expected_capture_export_gid"], 414)
            self.assertEqual(policy["expected_adopted_uid"], 0)
            self.assertIs(policy["capture_adoption_required"], True)
            binding = json.loads(
                (generated / "installed-binding.json").read_text()
            )
            self.assertEqual(binding["schema_version"], 3)
            self.assertEqual(binding["capture_uid"], 402)
            self.assertEqual(binding["capture_export_gid"], 414)
            self.assertEqual(
                binding["verifier_version"],
                "john-lomein.persona.operator-verifier.v4",
            )
            self.assertFalse(
                any(
                    key.startswith("transaction_journal")
                    for key in binding
                ),
                msg="the verifier binding must not receive journal authority",
            )
            journal_control_path = generated / "transaction-journal.json"
            journal_control = json.loads(
                journal_control_path.read_text()
            )
            self.assertEqual(
                journal_control["schema_version"],
                (
                    "john-lomein.persona-qualification-"
                    "transaction-journal-control.v1"
                ),
            )
            self.assertEqual(
                journal_control["journal_record_schema"],
                (
                    "john-lomein.persona-qualification-"
                    "transaction-journal.v5"
                ),
            )
            self.assertEqual(
                journal_control["store_path"],
                p("data/state/transactions"),
            )
            self.assertEqual(
                journal_control["filesystem_anchor_path"],
                p("data"),
            )
            self.assertEqual(
                journal_control["completed_directory_path"],
                p("data/state/transactions/.completed"),
            )
            self.assertEqual(
                journal_control["lock_file_path"],
                p("data/state/transactions/.lock"),
            )
            self.assertEqual(journal_control["store_mode"], 0o700)
            self.assertEqual(
                journal_control["completed_directory_mode"],
                0o700,
            )
            self.assertEqual(journal_control["lock_file_mode"], 0o600)
            self.assertIs(
                journal_control["runtime_orchestration_enabled"],
                False,
            )
            self.assertIs(
                journal_control["production_activation"],
                False,
            )
            self.assertEqual(
                record["controls"]["transaction_journal_store_path"],
                journal_control["store_path"],
            )
            self.assertEqual(
                record["controls"][
                    "transaction_journal_filesystem_anchor_path"
                ],
                journal_control["filesystem_anchor_path"],
            )
            self.assertEqual(
                record["controls"][
                    "transaction_journal_control_sha256"
                ],
                hashlib.sha256(
                    journal_control_path.read_bytes()
                ).hexdigest(),
            )
            self.assertEqual(
                record["controls"][
                    "transaction_journal_control_path"
                ],
                p("config-root/example-repo/transaction-journal.json"),
            )
            coordinator_manifest = json.loads(
                (generated / "coordinator-manifest.json").read_text()
            )
            self.assertEqual(
                journal_control["coordinator_bundle_sha256"],
                coordinator_manifest["bundle_sha256"],
            )
            journal_entries = [
                item
                for item in coordinator_manifest["files"]
                if item["path"].endswith(
                    "john_lomein_persona_qualification_"
                    "transaction_journal.py"
                )
            ]
            self.assertEqual(len(journal_entries), 1)
            self.assertEqual(
                journal_control["journal_module_sha256"],
                journal_entries[0]["sha256"],
            )
            self.assertEqual(
                journal_control["journal_module_path"],
                str(
                    Path(coordinator_manifest["bundle_root"])
                    / journal_entries[0]["path"]
                ),
            )
            expected_execution_digest = hashlib.sha256(
                json.dumps(
                    attestor_core.VERIFICATION_EXECUTION_POLICY,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            self.assertEqual(
                policy["verification_execution_policy_sha256"],
                expected_execution_digest,
            )
            native = json.loads((generated / "native-closure.json").read_text())
            self.assertEqual(native["status"], "not-qualified")
            public_manifest = json.loads(
                (generated / "public-verifier-manifest.json").read_text()
            )
            self.assertEqual(public_manifest["root_mode"], 0o555)
            self.assertTrue(
                all(
                    entry["mode"] == 0o555
                    for entry in public_manifest["directories"]
                )
            )
            self.assertEqual(
                {entry["mode"] for entry in public_manifest["files"]},
                {0o444, 0o555},
            )
            plist = plistlib.loads(
                (generated / "launchdaemon.plist").read_bytes()
            )
            self.assertIs(plist["Disabled"], True)
            self.assertIs(plist["RunAtLoad"], False)
            self.assertIs(plist["KeepAlive"], False)
            self.assertEqual(plist["ProgramArguments"], [args[-7]])
            self.assertEqual(plist["UserName"], "root")
            self.assertIn(
                "protected_persona_qualification_not_activated",
                (generated / "attest").read_text(),
            )
            self.assertIn(
                "transaction_journal_runtime_orchestration_missing",
                (generated / "doctor").read_text(),
            )
            public_status = json.loads(
                (generated / "public-status.json").read_text()
            )
            self.assertIn(
                "transaction_journal_runtime_orchestration_missing",
                public_status["activation_blockers"],
            )

    def test_fixed_wrappers_and_launchdaemon_can_never_activate(self) -> None:
        required = (
            '"$#\\" -ne 0',
            "protected_persona_qualification_not_activated",
            "public_verifier_native_closure_not_qualified",
            '"Disabled": True',
            '"RunAtLoad": False',
            '"KeepAlive": False',
            '"ProgramArguments": [attest_wrapper]',
            '/bin/launchctl disable "system/$LABEL"',
            "unexpectedly became loaded",
        )
        for fragment in required:
            self.assertIn(fragment, self.install)
        self.assertNotIn("/bin/launchctl bootstrap", self.install)
        self.assertNotIn("/bin/launchctl enable", self.install)
        self.assertNotIn("/bin/launchctl kickstart", self.install)
        self.assertNotIn("privileged_canary_passed", self.install)
        self.assertIn('"activation_receipts": []', self.install)
        self.assertIn(
            '[ ! -e "$INSTANCE_CONFIG_DIR/activation" ]', self.install
        )

    def test_upgrade_rollback_covers_files_and_new_identities(self) -> None:
        required = (
            "TRANSACTION_STARTED=0",
            "TRANSACTION_COMMITTED=0",
            "MANAGED_FILES=()",
            "CREATED_USERS=()",
            "CREATED_GROUPS=()",
            "ADDED_EXPORT_MEMBERS=()",
            "CREATED_BUNDLES=()",
            "CREATED_DIRECTORIES=()",
            "CREATED_STATE_FILES=()",
            "restore_managed_file",
            "os.O_NOFOLLOW",
            "rollback source changed during snapshot",
            "rollback source metadata is unsafe",
            'dseditgroup -o edit -d "$member"',
            'dscl . -delete "/Users/$user"',
            'dscl . -delete "/Groups/$group"',
            "rollback was incomplete; installation remains disabled",
            "Deleting a",
            "group while an owned directory or bundle remains",
            "key rotation is unsupported",
        )
        for fragment in required:
            self.assertIn(fragment, self.install)

    def test_uninstall_removes_only_invocation_and_preserves_evidence(
        self,
    ) -> None:
        required = (
            "usage: uninstall-protected-persona-qualification.sh --slug SLUG",
            'id -u)" -eq 0',
            'uname -s)" = "Darwin"',
            'launchctl bootout "system/$LABEL"',
            'launchctl disable "system/$LABEL"',
            'launchctl print "system/$LABEL"',
            "john-lomein-persona-qualification.install.lock",
            "/usr/bin/lockf -t 0 9",
            'validate_root_file "$PLIST_PATH"',
            "validate_root_directory_chain",
            'remove_root_file "$PLIST_PATH"',
            'remove_root_file "$ATTEST_WRAPPER_PATH"',
            'remove_root_file "$TRUST_WRAPPER_PATH"',
            'remove_root_file "$DOCTOR_WRAPPER_PATH"',
            'remove_root_file "$PUBLIC_TRUST_COMMAND"',
            'remove_root_file "$PUBLIC_DOCTOR_COMMAND"',
            "preserved service identities",
            "preserved configs, keys, manifests, and activation history",
            "preserved signed archive and raw-state namespace",
            "preserved public key, pin, policy, and trust projection",
            "preserved content-addressed role bundles",
        )
        for fragment in required:
            self.assertIn(fragment, self.uninstall)
        self.assertNotIn("rm -rf", self.uninstall)
        self.assertNotIn("dscl . -delete", self.uninstall)
        self.assertNotIn("dseditgroup -o edit -d", self.uninstall)


if __name__ == "__main__":
    unittest.main()
