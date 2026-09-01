from __future__ import annotations

import ast
import json
import os
import struct
import subprocess
import sys
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_child as capture_child,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_helper as helper,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_plan as capture_plan,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_protocol as protocol,
)


class PersonaQualificationCaptureProtocolTests(unittest.TestCase):
    maxDiff = None

    def _plan(self) -> dict[str, object]:
        return capture_plan.normalize_capture_plan(
            {
                "schema_version": capture_plan.CAPTURE_PLAN_SCHEMA,
                "instance_slug": "john-example",
                "evidence_uid": 501,
                "verifier_gid": 502,
                "sources": [
                    {
                        "source_id": "instance",
                        "source_class": "instance_manifest",
                        "kind": "file",
                        "source_path": (
                            "/srv/john-lomein/export/instance.yaml"
                        ),
                        "destination_path": "instance/instance.yaml",
                    }
                ],
                "limits": {
                    "max_files": 32,
                    "max_directories": 32,
                    "max_bytes": 1024 * 1024,
                    "max_file_bytes": 256 * 1024,
                    "max_depth": 16,
                },
                "lifecycle": {
                    "retention": "ephemeral",
                    "max_capture_slots": 4,
                    "max_orphan_age_seconds": 60,
                },
            }
        )

    def _qualification_import_closure(self, module_name: str) -> list[str]:
        code = (
            "import json,sys;"
            f"sys.path.insert(0,{str(ROOT)!r});"
            f"import qualification_attestor.{module_name};"
            "print(json.dumps(sorted(name for name in sys.modules "
            "if name == 'qualification_attestor' or "
            "name.startswith('qualification_attestor.'))))"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", code],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout)

    def test_shared_protocol_has_only_standard_library_dependencies(
        self,
    ) -> None:
        source = Path(protocol.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.partition(".")[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.partition(".")[0])
        self.assertTrue(
            imported_roots <= (set(sys.stdlib_module_names) | {"__future__"}),
            imported_roots,
        )
        self.assertNotIn("qualification_attestor", imported_roots)
        self.assertFalse(hasattr(protocol, "PRODUCTION_ACTIVATION"))

    def test_runtime_role_import_closures_are_exact_and_disjoint(
        self,
    ) -> None:
        protocol_name = (
            "john_lomein_persona_qualification_capture_protocol"
        )
        plan_name = "john_lomein_persona_qualification_capture_plan"
        opaque_name = (
            "john_lomein_persona_qualification_opaque_capture"
        )
        helper_name = (
            "john_lomein_persona_qualification_capture_helper"
        )
        source_revalidation_name = (
            "john_lomein_persona_qualification_"
            "source_revalidation_binding"
        )
        staging_name = (
            "john_lomein_persona_qualification_capture_staging"
        )
        staging_receipts_name = (
            "john_lomein_persona_qualification_capture_staging_receipts"
        )
        child_name = "john_lomein_persona_qualification_capture_child"
        package = "qualification_attestor"
        self.assertEqual(
            self._qualification_import_closure(child_name),
            [
                package,
                f"{package}.{child_name}",
                f"{package}.{plan_name}",
                f"{package}.{protocol_name}",
                f"{package}.{opaque_name}",
            ],
        )
        self.assertEqual(
            self._qualification_import_closure(helper_name),
            [
                package,
                f"{package}.{helper_name}",
                f"{package}.{plan_name}",
                f"{package}.{protocol_name}",
                f"{package}.{staging_name}",
                f"{package}.{staging_receipts_name}",
                f"{package}.{opaque_name}",
                f"{package}.{source_revalidation_name}",
            ],
        )

    def test_top_level_roles_do_not_import_each_other(self) -> None:
        def top_level_qualification_imports(module: object) -> set[str]:
            tree = ast.parse(
                Path(module.__file__).read_text(encoding="utf-8")
            )
            names: set[str] = set()
            for node in tree.body:
                if (
                    isinstance(node, ast.ImportFrom)
                    and node.module == "qualification_attestor"
                ):
                    names.update(alias.name for alias in node.names)
            return names

        self.assertEqual(
            top_level_qualification_imports(capture_child),
            {
                "john_lomein_persona_qualification_capture_plan",
                "john_lomein_persona_qualification_capture_protocol",
                "john_lomein_persona_qualification_opaque_capture",
            },
        )
        self.assertEqual(
            top_level_qualification_imports(helper),
            {
                "john_lomein_persona_qualification_capture_plan",
                "john_lomein_persona_qualification_capture_protocol",
                "john_lomein_persona_qualification_opaque_capture",
                (
                    "john_lomein_persona_qualification_"
                    "source_revalidation_binding"
                ),
                "john_lomein_persona_qualification_capture_staging",
            },
        )
        self.assertNotIn("capture_child", helper.__dict__)
        self.assertNotIn("capture_helper", capture_child.__dict__)

    def test_coordinator_reexports_the_single_wire_implementation(
        self,
    ) -> None:
        self.assertIs(helper.CaptureHelperError, protocol.CaptureHelperError)
        self.assertIs(helper._ProtocolMachine, protocol.ProtocolMachine)
        self.assertIs(helper._canonical_json, protocol.canonical_json)
        self.assertIs(helper._read_frame, protocol.read_frame)
        self.assertIs(helper._write_frame, protocol.write_frame)
        self.assertIs(
            helper.COMMAND_TRANSITIONS,
            protocol.COMMAND_TRANSITIONS,
        )
        self.assertEqual(
            protocol.MAX_INITIALIZATION_FRAME_BYTES,
            capture_plan.MAX_PLAN_BYTES + (32 * 1024),
        )

    def test_v1_framing_and_state_bytes_are_unchanged(self) -> None:
        session = "1" * 64
        command = {
            "schema_version": protocol.PROTOCOL_SCHEMA,
            "session_id": session,
            "sequence": 1,
            "command": "begin_verification",
            "artifact_sha256": None,
            "reason_code": None,
        }
        payload = (
            b'{"artifact_sha256":null,"command":"begin_verification",'
            b'"reason_code":null,"schema_version":"john-lomein.persona.'
            b'capture-helper-protocol.v1","sequence":1,"session_id":"'
            + (b"1" * 64)
            + b'"}'
        )
        self.assertEqual(
            protocol.encode_frame(
                command,
                maximum_bytes=protocol.MAX_CONTROL_FRAME_BYTES,
            ),
            struct.pack("!I", len(payload)) + payload,
        )
        machine = protocol.ProtocolMachine(session)
        self.assertEqual(
            machine.accept(command),
            ("begin_verification", None, None),
        )

    def test_framing_round_trip_and_public_error_type(self) -> None:
        read_fd, write_fd = os.pipe()
        value = protocol.error_record(
            session="2" * 64,
            sequence=3,
            error_code="capture_helper_test_error",
        )
        try:
            protocol.write_frame(
                write_fd,
                value,
                maximum_bytes=protocol.MAX_EVENT_FRAME_BYTES,
            )
            self.assertEqual(
                protocol.read_frame(
                    read_fd,
                    maximum_bytes=protocol.MAX_EVENT_FRAME_BYTES,
                    deadline=time.monotonic() + 1,
                ),
                value,
            )
        finally:
            os.close(read_fd)
            os.close(write_fd)
        with self.assertRaises(helper.CaptureHelperError) as caught:
            protocol.ProtocolMachine("not-a-session")
        self.assertEqual(
            caught.exception.code,
            "capture_helper_session_id_invalid",
        )

    def test_child_is_a_distinct_isolated_entrypoint_and_stays_disabled(
        self,
    ) -> None:
        entrypoint = Path(capture_child.__file__)
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(entrypoint)],
            check=False,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")
        self.assertNotEqual(Path(helper.__file__), entrypoint)
        self.assertEqual(helper.CHILD_ARGUMENT, capture_child.CHILD_ARGUMENT)
        self.assertIs(helper.PRODUCTION_ACTIVATION, False)
        self.assertIs(helper.CAPTURE_ADOPTION_IMPLEMENTED, False)
        self.assertIs(capture_child.PRODUCTION_ACTIVATION, False)
        with self.assertRaises(helper.CaptureHelperError) as caught:
            helper._main([helper.CHILD_ARGUMENT])
        self.assertEqual(
            caught.exception.code,
            "capture_helper_direct_invocation_disabled",
        )

    def test_child_owns_plan_and_identity_initialization_semantics(
        self,
    ) -> None:
        plan = self._plan()
        plan_sha256 = capture_plan.capture_plan_sha256(plan)
        initialization = {
            "schema_version": protocol.PROTOCOL_SCHEMA,
            "session_id": "3" * 64,
            "sequence": 0,
            "command": "initialize",
            "capture_plan": plan,
            "capture_plan_sha256": plan_sha256,
            "destination_parent": "/var/lib/john-lomein/captures",
            "helper_uid": 501,
            "helper_gid": 502,
            "timeout_seconds": 120,
        }
        self.assertEqual(
            capture_child.normalize_initialization(initialization),
            (
                "3" * 64,
                plan,
                plan_sha256,
                Path("/var/lib/john-lomein/captures"),
                501,
                502,
                120,
            ),
        )
        with self.assertRaises(helper.CaptureHelperError) as caught:
            capture_child.normalize_initialization(
                {**initialization, "helper_gid": 503}
            )
        self.assertEqual(
            caught.exception.code,
            "capture_helper_initialization_identity_mismatch",
        )


if __name__ == "__main__":
    unittest.main()
