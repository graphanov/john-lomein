from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (
    john_lomein_persona_qualification_capture_plan as capture_plan,
)


class PersonaQualificationCapturePlanTests(unittest.TestCase):
    def plan(self, root: Path = Path("/safe/evidence")) -> dict:
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
                    "source_path": str(root / "instance.yaml"),
                    "destination_path": "instance/instance.yaml",
                },
                {
                    "source_id": "private",
                    "source_class": "qualification_private",
                    "kind": "tree",
                    "source_path": str(root / "private"),
                    "destination_path": "private",
                },
                {
                    "source_id": "public",
                    "source_class": "qualification_public",
                    "kind": "tree",
                    "source_path": str(root / "public"),
                    "destination_path": "runtime/evidence",
                },
            ],
            "limits": {
                "max_files": 1024,
                "max_directories": 1024,
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
        with self.assertRaises(capture_plan.CapturePlanError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_normalization_is_strict_canonical_and_opaque(self) -> None:
        plan = self.plan()
        schema = json.loads(
            (
                ROOT
                / "qualification_attestor"
                / "schemas"
                / "persona-qualification-capture-plan.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(plan, schema)
        self.assertEqual(capture_plan.normalize_capture_plan(plan), plan)
        digest = capture_plan.capture_plan_sha256(plan)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertNotIn("yaml", capture_plan.__dict__)
        self.assertEqual(
            capture_plan.normalize_capture_plan(
                json.loads(json.dumps(plan))
            ),
            plan,
        )

        unknown = {**plan, "command": ["/attacker"]}
        self.assert_code(
            "capture_plan_fields_invalid",
            capture_plan.normalize_capture_plan,
            unknown,
        )
        retained = copy.deepcopy(plan)
        retained["lifecycle"]["retention"] = "forever"
        self.assert_code(
            "capture_plan_retention_unsupported",
            capture_plan.normalize_capture_plan,
            retained,
        )
        excessive = copy.deepcopy(plan)
        excessive["limits"]["max_bytes"] = (
            capture_plan.MAX_CAPTURE_BYTES + 1
        )
        self.assert_code(
            "capture_plan_max_bytes_invalid",
            capture_plan.normalize_capture_plan,
            excessive,
        )

    def test_aliases_overlaps_and_order_fail_closed(self) -> None:
        plan = self.plan()
        reordered = copy.deepcopy(plan)
        reordered["sources"].reverse()
        self.assert_code(
            "capture_plan_sources_not_sorted",
            capture_plan.normalize_capture_plan,
            reordered,
        )
        duplicate = copy.deepcopy(plan)
        duplicate["sources"][1]["source_id"] = "INSTANCE"
        self.assert_code(
            "capture_plan_source_id_duplicate",
            capture_plan.normalize_capture_plan,
            duplicate,
        )
        source_overlap = copy.deepcopy(plan)
        source_overlap["sources"][1]["source_path"] = (
            source_overlap["sources"][0]["source_path"] + "/child"
        )
        self.assert_code(
            "capture_plan_source_paths_overlap",
            capture_plan.normalize_capture_plan,
            source_overlap,
        )
        destination_overlap = copy.deepcopy(plan)
        destination_overlap["sources"][1]["destination_path"] = (
            "instance/instance.yaml/child"
        )
        self.assert_code(
            "capture_plan_destination_paths_overlap",
            capture_plan.normalize_capture_plan,
            destination_overlap,
        )
        unicode_alias = copy.deepcopy(plan)
        unicode_alias["sources"][0]["source_path"] = "/safe/\u00e9"
        unicode_alias["sources"][1]["source_path"] = (
            "/safe/e\u0301/child"
        )
        self.assert_code(
            "capture_plan_source_paths_overlap",
            capture_plan.normalize_capture_plan,
            unicode_alias,
        )

    def test_installed_plan_read_binds_exact_safe_bytes(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            root = Path(temporary).resolve()
            plan = self.plan(root / "evidence")
            plan["evidence_uid"] = max(os.geteuid(), 1)
            plan["verifier_gid"] = max(os.getegid(), 1)
            path = root / "capture-plan.json"
            path.write_text(
                json.dumps(
                    plan,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            if sys.platform == "darwin":
                subprocess.run(
                    ["/usr/bin/xattr", "-c", str(path)],
                    check=True,
                    capture_output=True,
                )
            normalized, digest = capture_plan.read_installed_capture_plan(
                path,
                expected_owner_uid=os.geteuid(),
            )
            self.assertEqual(normalized, plan)
            self.assertEqual(
                digest,
                capture_plan.capture_plan_sha256(plan),
            )

            path.chmod(0o644)
            self.assert_code(
                "capture_plan_file_unsafe",
                capture_plan.read_installed_capture_plan,
                path,
                expected_owner_uid=os.geteuid(),
            )
            path.chmod(0o600)
            hardlink = root / "capture-plan-hardlink.json"
            os.link(path, hardlink)
            self.assert_code(
                "capture_plan_file_unsafe",
                capture_plan.read_installed_capture_plan,
                path,
                expected_owner_uid=os.geteuid(),
            )
            hardlink.unlink()
            if sys.platform == "darwin":
                subprocess.run(
                    [
                        "/usr/bin/xattr",
                        "-w",
                        "com.john-lomein.parent-test",
                        "unsafe",
                        str(root),
                    ],
                    check=True,
                    capture_output=True,
                )
                self.assert_code(
                    "capture_plan_parent_extended_metadata_unsupported",
                    capture_plan.read_installed_capture_plan,
                    path,
                    expected_owner_uid=os.geteuid(),
                )
                subprocess.run(
                    [
                        "/usr/bin/xattr",
                        "-d",
                        "com.john-lomein.parent-test",
                        str(root),
                    ],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    [
                        "/bin/chmod",
                        "+a",
                        "everyone allow add_file,delete_child",
                        str(root),
                    ],
                    check=True,
                    capture_output=True,
                )
                self.assert_code(
                    "capture_plan_parent_acl_grants_unsupported",
                    capture_plan.read_installed_capture_plan,
                    path,
                    expected_owner_uid=os.geteuid(),
                )
                subprocess.run(
                    ["/bin/chmod", "-N", str(root)],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    [
                        "/usr/bin/xattr",
                        "-w",
                        "com.john-lomein.test",
                        "unsafe",
                        str(path),
                    ],
                    check=True,
                    capture_output=True,
                )
                self.assert_code(
                    "capture_plan_extended_metadata_unsupported",
                    capture_plan.read_installed_capture_plan,
                    path,
                    expected_owner_uid=os.geteuid(),
                )
                subprocess.run(
                    [
                        "/usr/bin/xattr",
                        "-d",
                        "com.john-lomein.test",
                        str(path),
                    ],
                    check=True,
                    capture_output=True,
                )

            path.write_bytes(
                b'{"schema_version":"one","schema_version":"two"}\n'
            )
            path.chmod(0o600)
            if sys.platform == "darwin":
                subprocess.run(
                    ["/usr/bin/xattr", "-c", str(path)],
                    check=True,
                    capture_output=True,
                )
            self.assert_code(
                "capture_plan_duplicate_json_field",
                capture_plan.read_installed_capture_plan,
                path,
                expected_owner_uid=os.geteuid(),
            )


if __name__ == "__main__":
    unittest.main()
