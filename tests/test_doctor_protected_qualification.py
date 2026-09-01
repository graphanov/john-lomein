from __future__ import annotations

import importlib.util
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "john_lomein_doctor_instance",
    ROOT / "scripts" / "doctor-instance.py",
)
assert SPEC is not None and SPEC.loader is not None
doctor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(doctor)


class ProtectedQualificationDoctorTests(unittest.TestCase):
    def setUp(self) -> None:
        doctor.FAIL.clear()
        doctor.WARN.clear()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.command_root = Path(self.temporary.name)
        self.command = (
            self.command_root
            / "john-lomein-persona-qualification-doctor-example-repo"
        )

    def _install(self, payload: str, *, exit_code: int) -> None:
        self.command.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' '{payload}'\n"
            f"exit {exit_code}\n",
            encoding="utf-8",
        )
        self.command.chmod(0o555)

    def _root_owned_lstat(self):
        real_lstat = Path.lstat
        command = self.command

        def fake_lstat(path: Path):
            observed = real_lstat(path)
            if path == command:
                return types.SimpleNamespace(
                    st_mode=observed.st_mode,
                    st_uid=0,
                    st_gid=0,
                    st_nlink=observed.st_nlink,
                )
            return observed

        return mock.patch.object(Path, "lstat", fake_lstat)

    def test_missing_installed_doctor_is_visible(self) -> None:
        doctor.protected_qualification_doctor(
            "example-repo",
            self.command_root,
        )
        self.assertEqual(doctor.FAIL, [])
        self.assertEqual(
            doctor.WARN,
            [
                "protected persona qualification doctor is not installed; "
                "operator attestation remains unavailable"
            ],
        )

    def test_canonical_disabled_report_is_a_warning(self) -> None:
        payload = (
            '{"activation_blockers":["native_dependency_closure_not_qualified"],'
            '"instance_slug":"example-repo","production_activation":false,'
            '"schema_version":"john-lomein.persona-qualification-doctor.v1",'
            '"status":"disabled"}'
        )
        self._install(payload, exit_code=1)
        with self._root_owned_lstat():
            doctor.protected_qualification_doctor(
                "example-repo",
                self.command_root,
            )
        self.assertEqual(doctor.FAIL, [])
        self.assertEqual(len(doctor.WARN), 1)
        self.assertIn("installed but disabled", doctor.WARN[0])

    def test_journal_runtime_blocker_is_reported_without_activation(
        self,
    ) -> None:
        payload = (
            '{"activation_blockers":['
            '"transaction_journal_runtime_orchestration_missing"],'
            '"instance_slug":"example-repo","production_activation":false,'
            '"schema_version":"john-lomein.persona-qualification-doctor.v1",'
            '"status":"disabled"}'
        )
        self._install(payload, exit_code=1)
        with self._root_owned_lstat():
            doctor.protected_qualification_doctor(
                "example-repo",
                self.command_root,
            )
        self.assertEqual(doctor.FAIL, [])
        self.assertEqual(len(doctor.WARN), 1)
        self.assertIn(
            "transaction_journal_runtime_orchestration_missing",
            doctor.WARN[0],
        )

    def test_noncanonical_or_inconsistent_report_fails(self) -> None:
        cases = (
            (
                '{"status":"disabled"}',
                1,
                "report is invalid",
            ),
            (
                '{"activation_blockers":[],"instance_slug":"example-repo",'
                '"production_activation":true,'
                '"schema_version":"john-lomein.persona-qualification-doctor.v1",'
                '"status":"active"}',
                1,
                "state is inconsistent",
            ),
        )
        for payload, exit_code, reason in cases:
            with self.subTest(reason=reason):
                doctor.FAIL.clear()
                doctor.WARN.clear()
                if self.command.exists():
                    self.command.chmod(0o700)
                    self.command.unlink()
                self._install(payload, exit_code=exit_code)
                with self._root_owned_lstat():
                    doctor.protected_qualification_doctor(
                        "example-repo",
                        self.command_root,
                    )
                self.assertEqual(doctor.WARN, [])
                self.assertEqual(len(doctor.FAIL), 1)
                self.assertIn(reason, doctor.FAIL[0])

    def test_metadata_must_be_root_owned_immutable_regular_file(self) -> None:
        self._install("{}", exit_code=1)
        self.command.chmod(0o755)
        doctor.protected_qualification_doctor(
            "example-repo",
            self.command_root,
        )
        self.assertEqual(doctor.WARN, [])
        self.assertEqual(len(doctor.FAIL), 1)
        self.assertIn("root:wheel 0555 single-link", doctor.FAIL[0])


if __name__ == "__main__":
    unittest.main()
