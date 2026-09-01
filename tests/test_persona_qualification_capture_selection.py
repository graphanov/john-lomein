from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_plan as capture_plan,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_selection as selection,
)


class PersonaQualificationCaptureSelectionTests(unittest.TestCase):
    RUN_ID = "run-current-001"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.root = Path(self.temporary.name).resolve()
        self.owner_uid = os.geteuid()
        self.evidence_uid = self.owner_uid if self.owner_uid > 0 else 1
        self.verifier_gid = os.getegid() if os.getegid() > 0 else 2
        self.evidence_home = self.root / "evidence-home"
        self.checkout = self.evidence_home / "checkout"
        self.runtime = self.evidence_home / "runtime"
        self.private = self.evidence_home / "private"
        self.instance = self.evidence_home / "instance.yaml"
        self.public = (
            self.runtime / "state" / "persona-qualification"
        )
        for path in (
            self.evidence_home,
            self.checkout,
            self.runtime,
            self.private,
            self.public,
        ):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.chmod(0o700)
        self.instance.write_bytes(b"instance:\n  slug: john-example\n")
        self.instance.chmod(0o600)
        self._adopt_evidence_paths()
        self.status = self._terminal_status()
        self._write_status(self.status)

    def tearDown(self) -> None:
        if self.owner_uid == 0:
            for directory, directories, files in os.walk(
                self.root,
                topdown=False,
            ):
                for name in files:
                    path = Path(directory) / name
                    with self.subTest(cleanup=path):
                        try:
                            os.chown(path, 0, -1)
                            path.chmod(0o600)
                        except OSError:
                            pass
                for name in directories:
                    path = Path(directory) / name
                    try:
                        os.chown(path, 0, -1)
                        path.chmod(0o700)
                    except OSError:
                        pass
        self.temporary.cleanup()

    def _adopt_evidence_paths(self) -> None:
        if self.owner_uid != 0:
            return
        for directory, directories, files in os.walk(self.evidence_home):
            path = Path(directory)
            os.chown(path, self.evidence_uid, -1)
            path.chmod(0o700)
            for name in directories:
                child = path / name
                os.chown(child, self.evidence_uid, -1)
                child.chmod(0o700)
            for name in files:
                child = path / name
                os.chown(child, self.evidence_uid, -1)
                child.chmod(0o600)

    @staticmethod
    def _canonical_json(value: object) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    @staticmethod
    def _retained_json(value: object) -> bytes:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")

    def _self_digest(self, value: dict) -> dict:
        result = copy.deepcopy(value)
        result["record_digest"] = hashlib.sha256(
            self._canonical_json(result)
        ).hexdigest()
        return result

    def _terminal_status(self) -> dict:
        return self._self_digest(
            {
                "schema_version": selection.QUALIFICATION_STATUS_SCHEMA,
                "status": "qualified",
                "reason": "all-distinct-candidates-qualified",
                "run_id": self.RUN_ID,
                "binding_digest": "1" * 64,
                "candidates": [
                    {
                        "id": "candidate-01-aaaaaaaaaaaa",
                        "slots": ["primary"],
                        "status": "qualified",
                    },
                    {
                        "id": "candidate-02-bbbbbbbbbbbb",
                        "slots": ["fallback"],
                        "status": "qualified",
                    },
                ],
                "summary_sha256": "2" * 64,
                "started_at_unix": 100,
                "run_deadline_unix": 300,
                "qualified_at_unix": 200,
                "expires_at_unix": 1_000,
                "evidence_class": "local_model_conformance",
                "public_reputation_eligible": False,
            }
        )

    def _write_status(
        self,
        value: dict,
        *,
        canonical_retained: bool = True,
    ) -> None:
        path = self.public / "status.json"
        raw = (
            self._retained_json(value)
            if canonical_retained
            else self._canonical_json(value) + b"\n"
        )
        path.write_bytes(raw)
        path.chmod(0o600)
        if self.owner_uid == 0:
            os.chown(path, self.evidence_uid, -1)

    def policy(self) -> dict:
        return {
            "schema_version": selection.CAPTURE_SELECTION_SCHEMA,
            "instance_slug": "john-example",
            "evidence_uid": self.evidence_uid,
            "verifier_gid": self.verifier_gid,
            "source_roots": {
                "instance_manifest": str(self.instance),
                "runtime": str(self.runtime),
                "qualification_public": str(self.public),
                "qualification_private": str(self.private),
            },
            "path_identities": {
                "evidence_home": str(self.evidence_home),
                "checkout_source": str(self.checkout),
                "runtime_source": str(self.runtime),
                "checkout": str(self.checkout),
                "runtime": str(self.runtime),
            },
            "role_profiles": dict(selection.ROLE_PROFILES),
            "limits": {
                "max_files": 1_024,
                "max_directories": 1_024,
                "max_bytes": 64 * 1024 * 1024,
                "max_file_bytes": 8 * 1024 * 1024,
                "max_depth": 32,
            },
            "lifecycle": {
                "retention": "ephemeral",
                "max_capture_slots": 4,
                "max_orphan_age_seconds": 900,
            },
        }

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(selection.CaptureSelectionError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_schema_normalization_and_activation_are_strict(self) -> None:
        policy = self.policy()
        schema = json.loads(
            (
                ROOT
                / "qualification_attestor"
                / "schemas"
                / "persona-qualification-capture-selection.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(policy, schema)
        self.assertEqual(
            selection.normalize_capture_selection(policy),
            policy,
        )
        self.assertRegex(
            selection.capture_selection_sha256(policy),
            r"^[0-9a-f]{64}$",
        )
        self.assertIs(selection.PRODUCTION_ACTIVATION, False)
        self.assertNotIn("yaml", selection.__dict__)

        self.assert_code(
            "capture_selection_fields_invalid",
            selection.normalize_capture_selection,
            {**policy, "run_id": self.RUN_ID},
        )
        drifted = copy.deepcopy(policy)
        drifted["role_profiles"]["maintainer"] = "attacker-profile"
        self.assert_code(
            "capture_selection_role_profiles_mismatch",
            selection.normalize_capture_selection,
            drifted,
        )

    def test_layout_unicode_and_aliases_fail_closed(self) -> None:
        wrong_public = copy.deepcopy(self.policy())
        wrong_public["source_roots"]["qualification_public"] = str(
            self.runtime / "other"
        )
        self.assert_code(
            "capture_selection_public_root_layout_mismatch",
            selection.normalize_capture_selection,
            wrong_public,
        )

        wrong_identity = copy.deepcopy(self.policy())
        wrong_identity["path_identities"]["runtime"] = str(
            self.evidence_home / "other-runtime"
        )
        self.assert_code(
            "capture_selection_runtime_identity_mismatch",
            selection.normalize_capture_selection,
            wrong_identity,
        )

        checkout_alias = copy.deepcopy(self.policy())
        checkout_alias["path_identities"]["checkout_source"] = str(
            self.runtime
        ).upper()
        self.assert_code(
            "capture_selection_checkout_runtime_overlap",
            selection.normalize_capture_selection,
            checkout_alias,
        )

        private_overlap = copy.deepcopy(self.policy())
        private_overlap["source_roots"]["qualification_private"] = str(
            self.runtime / "private"
        )
        self.assert_code(
            "capture_selection_source_roots_overlap",
            selection.normalize_capture_selection,
            private_overlap,
        )

        private_runtime_source_overlap = copy.deepcopy(self.policy())
        private_runtime_source_overlap["path_identities"][
            "runtime_source"
        ] = str(self.private)
        self.assert_code(
            "capture_selection_private_runtime_overlap",
            selection.normalize_capture_selection,
            private_runtime_source_overlap,
        )

        decomposed = copy.deepcopy(self.policy())
        decomposed["path_identities"]["checkout_source"] = (
            str(self.evidence_home) + "/e\u0301"
        )
        self.assert_code(
            "capture_selection_checkout_source_identity_invalid",
            selection.normalize_capture_selection,
            decomposed,
        )

    def test_root_owned_selection_read_is_no_follow_and_byte_bound(self) -> None:
        config = self.root / "control"
        config.mkdir(mode=0o700)
        config.chmod(0o700)
        path = config / "capture-selection.json"
        path.write_bytes(self._retained_json(self.policy()))
        path.chmod(0o600)

        normalized, digest = (
            selection.read_installed_capture_selection(
                path,
                expected_owner_uid=self.owner_uid,
            )
        )
        self.assertEqual(normalized, self.policy())
        self.assertEqual(
            digest,
            selection.capture_selection_sha256(self.policy()),
        )

        path.chmod(0o644)
        self.assert_code(
            "capture_selection_file_unsafe",
            selection.read_installed_capture_selection,
            path,
            expected_owner_uid=self.owner_uid,
        )
        path.chmod(0o600)
        hardlink = config / "capture-selection-hardlink.json"
        os.link(path, hardlink)
        self.assert_code(
            "capture_selection_file_unsafe",
            selection.read_installed_capture_selection,
            path,
            expected_owner_uid=self.owner_uid,
        )
        hardlink.unlink()

        config.chmod(0o770)
        self.assert_code(
            "capture_selection_parent_unsafe",
            selection.read_installed_capture_selection,
            path,
            expected_owner_uid=self.owner_uid,
        )
        config.chmod(0o700)

        path.write_bytes(
            b'{"schema_version":"one","schema_version":"two"}\n'
        )
        path.chmod(0o600)
        self.assert_code(
            "capture_selection_duplicate_json_field",
            selection.read_installed_capture_selection,
            path,
            expected_owner_uid=self.owner_uid,
        )

    def test_fixed_status_selector_requires_exact_terminal_record(self) -> None:
        selected = selection.read_current_qualified_status(self.policy())
        self.assertEqual(selected, self.status)
        self.assertEqual(
            selection.select_current_run(self.policy()),
            self.RUN_ID,
        )

        tampered = copy.deepcopy(self.status)
        tampered["summary_sha256"] = "3" * 64
        self._write_status(tampered)
        self.assert_code(
            "qualification_status_self_digest_invalid",
            selection.read_current_qualified_status,
            self.policy(),
        )

        extra = self._terminal_status()
        extra["selected_path"] = "/attacker"
        extra = self._self_digest(
            {key: value for key, value in extra.items() if key != "record_digest"}
        )
        self._write_status(extra)
        self.assert_code(
            "qualification_status_fields_invalid",
            selection.read_current_qualified_status,
            self.policy(),
        )

        failed = self._terminal_status()
        failed["status"] = "failed"
        failed = self._self_digest(
            {
                key: value
                for key, value in failed.items()
                if key != "record_digest"
            }
        )
        self._write_status(failed)
        self.assert_code(
            "qualification_status_not_terminal_qualified",
            selection.read_current_qualified_status,
            self.policy(),
        )

        candidate_failed = self._terminal_status()
        candidate_failed["candidates"][0]["status"] = "failed"
        candidate_failed = self._self_digest(
            {
                key: value
                for key, value in candidate_failed.items()
                if key != "record_digest"
            }
        )
        self._write_status(candidate_failed)
        self.assert_code(
            "qualification_status_candidate_invalid",
            selection.read_current_qualified_status,
            self.policy(),
        )

        status_path = self.public / "status.json"
        status_path.write_bytes(
            b'{"schema_version":"one","schema_version":"two"}\n'
        )
        status_path.chmod(0o600)
        if self.owner_uid == 0:
            os.chown(status_path, self.evidence_uid, -1)
        self.assert_code(
            "qualification_status_duplicate_json_field",
            selection.read_current_qualified_status,
            self.policy(),
        )

    def test_status_encoding_mode_hardlink_and_symlink_are_rejected(self) -> None:
        self._write_status(self.status, canonical_retained=False)
        self.assert_code(
            "qualification_status_encoding_not_canonical",
            selection.read_current_qualified_status,
            self.policy(),
        )

        self._write_status(self.status)
        status_path = self.public / "status.json"
        status_path.chmod(0o640)
        self.assert_code(
            "qualification_status_file_unsafe",
            selection.read_current_qualified_status,
            self.policy(),
        )

        status_path.chmod(0o600)
        alias = self.public / "status-hardlink.json"
        os.link(status_path, alias)
        self.assert_code(
            "qualification_status_file_unsafe",
            selection.read_current_qualified_status,
            self.policy(),
        )
        alias.unlink()

        real = self.public / "status-real.json"
        status_path.rename(real)
        status_path.symlink_to(real.name)
        with self.assertRaises(selection.CaptureSelectionError):
            selection.read_current_qualified_status(self.policy())

    def test_sparse_plan_is_exact_deterministic_and_current_run_only(self) -> None:
        # These historical and unrelated paths must never be selected.
        historical = self.public / "reports" / "run-historical"
        historical.mkdir(parents=True, mode=0o700)
        old_private = self.private / "run-historical"
        old_private.mkdir(mode=0o700)
        unrelated = self.runtime / "unrelated-secrets"
        unrelated.mkdir(mode=0o700)
        (self.checkout / "large-repository.bin").write_bytes(b"x" * 128)
        if self.owner_uid == 0:
            self._adopt_evidence_paths()

        plan = selection.compile_current_run_capture_plan(self.policy())
        self.assertEqual(
            capture_plan.normalize_capture_plan(plan),
            plan,
        )
        self.assertEqual(len(plan["sources"]), 17)
        self.assertEqual(
            [item["destination_path"] for item in plan["sources"]],
            sorted(item["destination_path"] for item in plan["sources"]),
        )
        tree_sources = [
            item for item in plan["sources"] if item["kind"] == "tree"
        ]
        self.assertEqual(
            {
                item["source_path"] for item in tree_sources
            },
            {
                str(self.private / self.RUN_ID),
                str(self.public / "reports" / self.RUN_ID),
            },
        )
        self.assertFalse(
            any(
                item["source_path"] in {str(self.checkout), str(self.runtime)}
                for item in plan["sources"]
            )
        )
        serialized = json.dumps(plan, sort_keys=True)
        self.assertNotIn("run-historical", serialized)
        self.assertNotIn("unrelated-secrets", serialized)
        self.assertNotIn("large-repository.bin", serialized)

    def test_pure_concrete_plan_validator_reconstructs_exact_policy(self) -> None:
        expected = selection.compile_concrete_capture_plan(
            self.policy(),
            self.RUN_ID,
        )
        normalized, digest = selection.validate_concrete_capture_plan(
            self.policy(),
            copy.deepcopy(expected),
            self.RUN_ID,
        )
        self.assertEqual(normalized, expected)
        self.assertEqual(
            digest,
            capture_plan.capture_plan_sha256(expected),
        )

        injected = copy.deepcopy(expected)
        injected["sources"].append(
            {
                "source_id": "checkout",
                "source_class": "checkout",
                "kind": "tree",
                "source_path": str(self.checkout),
                "destination_path": "checkout",
            }
        )
        self.assert_code(
            "capture_selection_concrete_plan_mismatch",
            selection.validate_concrete_capture_plan,
            self.policy(),
            injected,
            self.RUN_ID,
        )
        self.assert_code(
            "capture_selection_run_id_invalid",
            selection.compile_concrete_capture_plan,
            self.policy(),
            "../other-run",
        )


if __name__ == "__main__":
    unittest.main()
