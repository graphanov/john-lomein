from __future__ import annotations

import copy
import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_verifier import (  # noqa: E402
    john_lomein_persona_qualification_verifier as verifier,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_plan as capture_plan,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_selection as capture_selection,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_binding as adoption_binding,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_opaque_capture as opaque_capture,
)


def _adoption_receipt(
    *,
    snapshot_root: str,
    selection_sha256: str,
    plan_sha256: str,
    manifest_sha256: str,
    capture_uid: int,
    export_gid: int,
    verifier_uid: int,
    verifier_gid: int,
) -> dict[str, object]:
    return {
        "schema_version": adoption_binding.ADOPTION_RECEIPT_SCHEMA,
        "status": adoption_binding.ADOPTION_STATUS,
        "session_id": "f" * 64,
        "capture_adoption_policy_sha256": "a" * 64,
        "capture_selection_sha256": selection_sha256,
        "capture_plan_sha256": plan_sha256,
        "capture_manifest_sha256": manifest_sha256,
        "capture_boundary_policy_sha256": "b" * 64,
        "helper_activation_policy_sha256": "c" * 64,
        "request_sha256": "d" * 64,
        "capture_uid": capture_uid,
        "capture_gid": export_gid,
        "adopted_uid": 0,
        "verifier_uid": verifier_uid,
        "verifier_gid": verifier_gid,
        "final_name": Path(snapshot_root).name,
        "object_identity_sha256": "e" * 64,
        "provisional_stat_sha256": "1" * 64,
        "adopted_stat_sha256": "2" * 64,
        "content_inventory_sha256": "3" * 64,
        "file_count": 1,
        "directory_count": 1,
        "total_bytes": 1,
        "child_pid": 12_345,
        "child_exit_status": 0,
        "child_stderr_sha256": adoption_binding.EMPTY_SHA256,
        "process_group_reaped": True,
        "staging_namespace_revoked": True,
        "same_filesystem": True,
        "rename_noreplace": True,
        "rename_primitive": "renameatx_np_excl",
        "adopted_at_unix": 100,
    }


class FakeRunner:
    VERIFY_SCHEMA = "john-lomein.persona-qualification-verification.v1"

    def __init__(self, public_root: Path, result: dict, exit_code: int = 0):
        self.public_root = public_root
        self.result = result
        self.exit_code = exit_code
        self.PERSONA_EVAL = SimpleNamespace(
            DEFAULT_SCENARIOS=ROOT / "evals" / "persona" / "scenarios.json",
            DEFAULT_RUBRIC=ROOT / "evals" / "persona" / "rubric.json",
        )

    def load_instance(self, path: Path):
        return {
            "path": path,
            "slug": "qualification-test",
            "hermes_home": self.public_root.parents[1],
        }

    def _public_root(self, instance):
        return self.public_root

    def verify_qualification(self, arguments):
        return copy.deepcopy(self.result), self.exit_code

    def verify_qualification_from_opaque_snapshot(self, **arguments):
        self.opaque_arguments = arguments
        return copy.deepcopy(self.result), self.exit_code


class PersonaQualificationVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.instance = self.base / "instance.yaml"
        self.private = self.base / "private"
        self.public = self.base / "runtime" / "state" / "persona-qualification"
        self.instance.write_text("{}\n", encoding="utf-8")
        self.private.mkdir(mode=0o700)
        self.public.mkdir(parents=True, mode=0o700)
        self.result = {
            "schema_version": FakeRunner.VERIFY_SCHEMA,
            "valid": True,
            "current": True,
            "status": "qualified",
            "reason": "all-distinct-candidates-qualified",
            "candidates": [
                {"id": "candidate-01", "reproducible": True},
            ],
            "attestation_projection": {
                "schema_version": (
                    "john-lomein.persona-qualification-"
                    "attestation-projection.v1"
                ),
                "run_id": "run-001",
                "summary_sha256": "1" * 64,
                "binding_sha256": "2" * 64,
                "qualified_at_unix": 100,
                "expires_at_unix": 1000,
            },
            "public_reputation_eligible": False,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def verify(self, *, result=None, exit_code=0, **overrides):
        arguments = {
            "instance_manifest": self.instance,
            "private_root": self.private,
            "expected_public_root": self.public,
            "expected_instance_slug": "qualification-test",
            "expected_evidence_uid": 501,
            "verified_at_unix": 200,
            "process_uid": 501,
            "runner": FakeRunner(
                self.public,
                self.result if result is None else result,
                exit_code=exit_code,
            ),
        }
        arguments.update(overrides)
        return verifier.verify_configured_evidence(**arguments)

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(verifier.QualificationVerifierError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_emits_only_strict_attestable_evidence(self) -> None:
        self.assertEqual(
            self.verify(),
            {
                "run_id": "run-001",
                "summary_sha256": "1" * 64,
                "binding_sha256": "2" * 64,
                "status": "qualified",
                "qualified_at_unix": 100,
                "expires_at_unix": 1000,
                "verifier_version": (
                    "john-lomein.persona.operator-verifier.v1"
                ),
                "verified_at_unix": 200,
                "observed_evidence_uid": 501,
            },
        )

    def test_identity_must_equal_nonroot_evidence_uid(self) -> None:
        self.assert_code(
            "verifier_identity_mismatch",
            self.verify,
            process_uid=0,
        )
        self.assert_code(
            "verifier_identity_mismatch",
            self.verify,
            process_uid=502,
        )

    def test_public_root_and_instance_are_config_bound(self) -> None:
        other = self.base / "other-public"
        other.mkdir(mode=0o700)
        self.assert_code(
            "qualification_public_root_mismatch",
            self.verify,
            expected_public_root=other,
        )
        self.assert_code(
            "instance_slug_mismatch",
            self.verify,
            expected_instance_slug="other-instance",
        )

    def test_only_current_reproduced_qualified_result_is_attestable(self) -> None:
        for mutation in (
            {"valid": False},
            {"current": False},
            {"status": "stale"},
            {"reason": "qualification-expired"},
            {"public_reputation_eligible": True},
        ):
            with self.subTest(mutation=mutation):
                result = {**self.result, **mutation}
                self.assert_code(
                    "qualification_not_attestable",
                    self.verify,
                    result=result,
                )
        self.assert_code(
            "qualification_not_attestable",
            self.verify,
            exit_code=4,
        )

    def test_projection_is_strict_fresh_and_digest_bound(self) -> None:
        extra = copy.deepcopy(self.result)
        extra["attestation_projection"]["private_path"] = "/private/evidence"
        self.assert_code(
            "attestation_projection_fields_invalid",
            self.verify,
            result=extra,
        )

        expired = copy.deepcopy(self.result)
        expired["attestation_projection"]["expires_at_unix"] = 200
        self.assert_code(
            "attestation_projection_timing_invalid",
            self.verify,
            result=expired,
        )

        malformed = copy.deepcopy(self.result)
        malformed["attestation_projection"]["summary_sha256"] = "not-a-digest"
        self.assert_code(
            "projection_summary_sha256_invalid",
            self.verify,
            result=malformed,
        )

    def test_every_candidate_must_be_reproducible(self) -> None:
        result = copy.deepcopy(self.result)
        result["candidates"][0]["reproducible"] = False
        self.assert_code(
            "qualification_candidates_not_reproducible",
            self.verify,
            result=result,
        )

    def test_sealed_verifier_identity_is_distinct_and_group_confined(self) -> None:
        self.assertEqual(
            verifier._validate_sealed_verifier_identity(
                expected_verifier_uid=502,
                expected_verifier_gid=503,
                expected_evidence_uid=501,
                process_uid=502,
                process_gid=503,
                process_groups=[503],
            ),
            (502, 503),
        )
        self.assert_code(
            "verifier_identity_aliasing",
            verifier._validate_sealed_verifier_identity,
            expected_verifier_uid=501,
            expected_verifier_gid=503,
            expected_evidence_uid=501,
            process_uid=501,
            process_gid=503,
            process_groups=[503],
        )
        # UID and GID numbers are separate namespaces; equal numeric values do
        # not identify the same principal.
        self.assertEqual(
            verifier._validate_sealed_verifier_identity(
                expected_verifier_uid=502,
                expected_verifier_gid=501,
                expected_evidence_uid=501,
                process_uid=502,
                process_gid=501,
                process_groups=[501],
            ),
            (502, 501),
        )
        self.assertEqual(
            verifier._validate_sealed_verifier_identity(
                expected_verifier_uid=502,
                expected_verifier_gid=502,
                expected_evidence_uid=501,
                process_uid=502,
                process_gid=502,
                process_groups=[502],
            ),
            (502, 502),
        )
        self.assert_code(
            "verifier_supplementary_groups_forbidden",
            verifier._validate_sealed_verifier_identity,
            expected_verifier_uid=502,
            expected_verifier_gid=503,
            expected_evidence_uid=501,
            process_uid=502,
            process_gid=503,
            process_groups=[503, 504],
        )
        self.assert_code(
            "verifier_group_mismatch",
            verifier._validate_sealed_verifier_identity,
            expected_verifier_uid=502,
            expected_verifier_gid=503,
            expected_evidence_uid=501,
            process_uid=502,
            process_gid=504,
            process_groups=[],
        )
        self.assert_code(
            "verifier_saved_identity_mismatch",
            verifier._validate_sealed_verifier_identity,
            expected_verifier_uid=502,
            expected_verifier_gid=503,
            expected_evidence_uid=501,
            process_uid=502,
            process_gid=503,
            process_groups=[503],
            process_res_uids=[502, 502, 0],
        )
        self.assert_code(
            "verifier_saved_group_mismatch",
            verifier._validate_sealed_verifier_identity,
            expected_verifier_uid=502,
            expected_verifier_gid=503,
            expected_evidence_uid=501,
            process_uid=502,
            process_gid=503,
            process_groups=[503],
            process_res_gids=[503, 503, 0],
        )

    def test_installed_verifier_has_no_path_bearing_cli(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = verifier.main(
                ["--snapshot-root", "/caller/chosen/capture"]
            )
        self.assertEqual(status, 2)
        self.assertEqual(
            json.loads(output.getvalue()),
            {
                "schema_version": verifier.OUTPUT_SCHEMA,
                "status": "invalid",
                "reason": "command_arguments_unsupported",
            },
        )

    def test_sealed_request_is_strict_and_canonical(self) -> None:
        selection = {
            "schema_version": capture_selection.CAPTURE_SELECTION_SCHEMA,
            "instance_slug": "qualification-test",
            "evidence_uid": 501,
            "verifier_gid": 503,
            "source_roots": {
                "instance_manifest": "/operator/control/instance.yaml",
                "qualification_private": "/operator/private",
                "qualification_public": (
                    "/operator/runtime/state/persona-qualification"
                ),
                "runtime": "/operator/runtime",
            },
            "path_identities": {
                "checkout": "/operator/checkout",
                "checkout_source": "/operator/checkout-source",
                "evidence_home": "/operator/evidence",
                "runtime": "/operator/runtime",
                "runtime_source": "/operator/runtime-source",
            },
            "role_profiles": dict(capture_selection.ROLE_PROFILES),
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
        snapshot_root = "/trusted/opaque-capture-" + "a" * 32
        selection_sha256 = (
            capture_selection.capture_selection_sha256(selection)
        )
        receipt = _adoption_receipt(
            snapshot_root=snapshot_root,
            selection_sha256=selection_sha256,
            plan_sha256="6" * 64,
            manifest_sha256="1" * 64,
            capture_uid=504,
            export_gid=505,
            verifier_uid=502,
            verifier_gid=503,
        )
        request = {
            "schema_version": verifier.REQUEST_SCHEMA,
            "snapshot_root": snapshot_root,
            "capture_manifest_sha256": "1" * 64,
            "capture_plan_sha256": "6" * 64,
            "capture_selection": selection,
            "capture_selection_sha256": selection_sha256,
            "capture_adoption_receipt": receipt,
            "capture_adoption_receipt_sha256": (
                adoption_binding.adoption_receipt_sha256(receipt)
            ),
            "capture_session_id": receipt["session_id"],
            "capture_request_sha256": receipt["request_sha256"],
            "capture_boundary_policy_sha256": receipt[
                "capture_boundary_policy_sha256"
            ],
            "capture_helper_activation_policy_sha256": receipt[
                "helper_activation_policy_sha256"
            ],
            "capture_uid": 504,
            "capture_export_gid": 505,
            "adopted_uid": 0,
            "instance_manifest_path": "/operator/control/instance.yaml",
            "instance_manifest_sha256": "5" * 64,
            "qualification_private_root": "/operator/private",
            "qualification_public_root": "/operator/runtime/state/persona-qualification",
            "evidence_home_path": "/operator/evidence",
            "checkout_identity_path": "/operator/checkout",
            "runtime_identity_path": "/operator/runtime",
            "instance_slug": "qualification-test",
            "evidence_uid": 501,
            "verifier_uid": 502,
            "verifier_gid": 503,
            "verifier_bundle_sha256": "2" * 64,
            "verification_policy_sha256": "3" * 64,
            "operator_policy_sha256": "4" * 64,
            "verified_at_unix": 200,
        }
        self.assertEqual(
            verifier.normalize_sealed_request(copy.deepcopy(request)),
            request,
        )
        for mutation in (
            {**request, "extra": True},
            {key: value for key, value in request.items() if key != "snapshot_root"},
            {**request, "schema_version": "unsupported"},
            {**request, "snapshot_root": "relative/capture"},
            {**request, "evidence_uid": True},
            {
                **request,
                "capture_selection_sha256": "0" * 64,
            },
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(
                    verifier.QualificationVerifierError
                ):
                    verifier.normalize_sealed_request(mutation)

    def test_linux_privilege_check_does_not_require_procfs(self) -> None:
        def prctl(option, argument2=0, *_arguments):
            if option == verifier._PR_GET_NO_NEW_PRIVS:
                return 1
            return 0

        with (
            mock.patch.object(
                verifier,
                "_linux_capability_words",
                return_value=(0, 0, 0, 0, 0, 0),
            ),
            mock.patch.object(verifier, "_linux_prctl", side_effect=prctl),
            mock.patch.object(
                verifier.Path,
                "read_text",
                side_effect=AssertionError("procfs must not be read"),
            ),
        ):
            verifier._assert_linux_privilege_confinement()

    def test_linux_privilege_check_rejects_every_privilege_surface(self) -> None:
        with mock.patch.object(
            verifier,
            "_linux_capability_words",
            return_value=(0, 1, 0, 0, 0, 0),
        ):
            self.assert_code(
                "verifier_capability_residue",
                verifier._assert_linux_privilege_confinement,
            )

        def bounding_residue(option, argument2=0, *_arguments):
            if option == verifier._PR_CAPBSET_READ and argument2 == 7:
                return 1
            return 0

        with (
            mock.patch.object(
                verifier,
                "_linux_capability_words",
                return_value=(0, 0, 0, 0, 0, 0),
            ),
            mock.patch.object(
                verifier,
                "_linux_prctl",
                side_effect=bounding_residue,
            ),
        ):
            self.assert_code(
                "verifier_capability_residue",
                verifier._assert_linux_privilege_confinement,
            )

        def ambient_residue(option, argument2=0, *_arguments):
            if (
                option == verifier._PR_CAP_AMBIENT
                and argument2 == verifier._PR_CAP_AMBIENT_IS_SET
            ):
                return 1
            return 0

        with (
            mock.patch.object(
                verifier,
                "_linux_capability_words",
                return_value=(0, 0, 0, 0, 0, 0),
            ),
            mock.patch.object(
                verifier,
                "_linux_prctl",
                side_effect=ambient_residue,
            ),
        ):
            self.assert_code(
                "verifier_capability_residue",
                verifier._assert_linux_privilege_confinement,
            )

        def no_new_privs_missing(option, _argument2=0, *_arguments):
            if option == verifier._PR_GET_NO_NEW_PRIVS:
                return 0
            return 0

        with (
            mock.patch.object(
                verifier,
                "_linux_capability_words",
                return_value=(0, 0, 0, 0, 0, 0),
            ),
            mock.patch.object(
                verifier,
                "_linux_prctl",
                side_effect=no_new_privs_missing,
            ),
        ):
            self.assert_code(
                "verifier_no_new_privs_missing",
                verifier._assert_linux_privilege_confinement,
            )


class OpaquePersonaQualificationVerifierTests(unittest.TestCase):
    RUN_ID = "run-opaque-001"
    HISTORICAL_RUN_ID = "run-historical-000"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.capture_uid = os.geteuid()
        self.evidence_uid = self.capture_uid if self.capture_uid > 0 else 1
        self.verifier_gid = os.getegid() if os.getegid() > 0 else 1
        self.verifier_uid = (
            self.evidence_uid + 10_000
            if self.evidence_uid + 10_000 != self.evidence_uid
            else self.evidence_uid + 1
        )
        self.evidence_home = self.root / "evidence-home"
        self.checkout_source = self.evidence_home / "checkout-source"
        self.checkout_identity = self.evidence_home / "checkout-identity"
        self.runtime_source = self.evidence_home / "runtime-source-identity"
        self.runtime = self.evidence_home / "runtime"
        self.private = self.evidence_home / "qualification-private"
        self.instance = self.evidence_home / "instance.yaml"
        self.public = self.runtime / "state" / "persona-qualification"
        self.captures = self.root / "captures"
        self.lease = None

        for path in (
            self.evidence_home,
            self.checkout_source,
            self.checkout_identity,
            self.runtime_source,
            self.runtime,
            self.private,
        ):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.captures.mkdir(mode=0o710)
        instance_bytes = (
            "instance:\n"
            "  slug: qualification-test\n"
            "target:\n"
            f"  local_checkout: {self.checkout_source}\n"
            "runtime:\n"
            f"  hermes_home: {self.runtime_source}\n"
        ).encode("utf-8")
        self._write_file(
            self.instance,
            instance_bytes,
        )
        self._write_file(self.runtime / "instance.yaml", instance_bytes)
        for role, profile in capture_selection.ROLE_PROFILES.items():
            profile_root = self.runtime / "profiles" / profile
            self._write_file(
                profile_root / "SOUL.md",
                f"# {role}\nSparse verifier fixture.\n".encode(),
            )
            self._write_file(
                profile_root / "config.yaml",
                f"profile: {profile}\n".encode(),
            )
        self._write_json(
            self.runtime / "state" / "john-lomein-persona.json",
            {"schema_version": "fixture.v1", "installed": True},
        )
        self.status = self._self_digest({
            "schema_version": verifier.QUALIFICATION_STATUS_SCHEMA,
            "status": "qualified",
            "reason": "all-distinct-candidates-qualified",
            "run_id": self.RUN_ID,
            "binding_digest": "a" * 64,
            "candidates": [
                {
                    "id": "candidate-01",
                    "slots": ["primary"],
                    "status": "qualified",
                }
            ],
            "summary_sha256": "b" * 64,
            "started_at_unix": 50,
            "run_deadline_unix": 150,
            "qualified_at_unix": 100,
            "expires_at_unix": 1000,
            "evidence_class": "local_model_conformance",
            "public_reputation_eligible": False,
        })
        self._write_status(self.status)
        self._write_json(
            self.public / "latest.json",
            {
                "schema_version": (
                    "john-lomein.persona-qualification-latest.v1"
                ),
                "run_id": self.RUN_ID,
            },
        )
        self._write_json(
            self.public / "reports" / self.RUN_ID / "summary.json",
            {"run_id": self.RUN_ID},
        )
        self._write_json(
            self.private / self.RUN_ID / "run-manifest.json",
            {"run_id": self.RUN_ID},
        )

        # Broad source trees deliberately contain material that must never be
        # copied by the sparse selector.
        self._write_file(
            self.checkout_source / ".git" / "config",
            b"[credential]\nhelper = forbidden\n",
        )
        self._write_file(
            self.checkout_source / "auth" / "token",
            b"checkout-secret\n",
        )
        self._write_file(
            self.checkout_identity / "working-tree.txt",
            b"identity-only checkout bytes\n",
        )
        self._write_json(
            self.runtime / "auth" / "provider-token.json",
            {"token": "runtime-secret"},
        )
        self._write_file(
            self.runtime / "logs" / "qualification.log",
            b"private log\n",
        )
        self._write_json(
            self.runtime / "state" / "learning" / "memory.json",
            {"memory": "not qualification evidence"},
        )
        self._write_file(
            self.runtime / "worktrees" / "other" / "HEAD",
            b"not selected\n",
        )
        self._write_file(
            self.runtime_source / "logs" / "source.log",
            b"runtime source identity only\n",
        )
        self._write_json(
            self.public
            / "reports"
            / self.HISTORICAL_RUN_ID
            / "summary.json",
            {"run_id": self.HISTORICAL_RUN_ID},
        )
        self._write_json(
            self.private
            / self.HISTORICAL_RUN_ID
            / "run-manifest.json",
            {"run_id": self.HISTORICAL_RUN_ID},
        )
        self._adopt_source_tree()
        self.captures.chmod(0o710)
        os.chown(self.captures, self.capture_uid, self.verifier_gid)

        self.result = {
            "schema_version": FakeRunner.VERIFY_SCHEMA,
            "valid": True,
            "current": True,
            "status": "qualified",
            "reason": "all-distinct-candidates-qualified",
            "candidates": [
                {"id": "candidate-01", "reproducible": True},
            ],
            "attestation_projection": {
                "schema_version": (
                    "john-lomein.persona-qualification-"
                    "attestation-projection.v1"
                ),
                "run_id": self.RUN_ID,
                "summary_sha256": "1" * 64,
                "binding_sha256": "2" * 64,
                "qualified_at_unix": 100,
                "expires_at_unix": 1000,
            },
            "public_reputation_eligible": False,
        }

    def tearDown(self) -> None:
        if self.lease is not None and self.lease.active:
            self.lease.cleanup()
        for directory, directories, _files in os.walk(
            self.root,
            topdown=True,
        ):
            with contextlib.suppress(OSError):
                Path(directory).chmod(0o700)
            for name in directories:
                with contextlib.suppress(OSError):
                    (Path(directory) / name).chmod(0o700)
        self.temporary.cleanup()

    def _write_file(self, path: Path, raw: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw)
        path.chmod(0o600)

    def _write_json(self, path: Path, value: object) -> None:
        self._write_file(
            path,
            (
                json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
        )

    @staticmethod
    def _canonical_json(value: object) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    def _self_digest(self, value: dict) -> dict:
        result = copy.deepcopy(value)
        result["record_digest"] = hashlib.sha256(
            self._canonical_json(result)
        ).hexdigest()
        return result

    def _write_status(
        self,
        value: dict,
        *,
        canonical_retained: bool = True,
    ) -> None:
        raw = (
            (
                json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
            if canonical_retained
            else self._canonical_json(value) + b"\n"
        )
        self._write_file(self.public / "status.json", raw)

    def _adopt_source_tree(self) -> None:
        for directory, directories, files in os.walk(self.evidence_home):
            current = Path(directory)
            current.chmod(0o700)
            os.chown(current, self.evidence_uid, os.getegid())
            for name in directories:
                child = current / name
                child.chmod(0o700)
                os.chown(child, self.evidence_uid, os.getegid())
            for name in files:
                child = current / name
                child.chmod(0o600)
                os.chown(child, self.evidence_uid, os.getegid())

    def selection(self) -> dict:
        return {
            "schema_version": capture_selection.CAPTURE_SELECTION_SCHEMA,
            "instance_slug": "qualification-test",
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
                "checkout_source": str(self.checkout_source),
                "runtime_source": str(self.runtime_source),
                "checkout": str(self.checkout_identity),
                "runtime": str(self.runtime),
            },
            "role_profiles": dict(capture_selection.ROLE_PROFILES),
            "limits": {
                "max_files": 128,
                "max_directories": 128,
                "max_bytes": 4 * 1024 * 1024,
                "max_file_bytes": 1024 * 1024,
                "max_depth": 32,
            },
            "lifecycle": {
                "retention": "ephemeral",
                "max_capture_slots": 8,
                "max_orphan_age_seconds": 60,
            },
        }

    def plan(self) -> dict:
        return capture_selection.compile_current_run_capture_plan(
            self.selection()
        )

    def capture(self, *, plan: dict | None = None):
        selected = self.plan() if plan is None else plan
        self.lease = opaque_capture._capture_opaque_snapshot_from_plan(
            plan=selected,
            plan_sha256=capture_plan.capture_plan_sha256(selected),
            destination_parent=self.captures,
            capture_uid=self.capture_uid,
        )
        return self.lease

    def _verification_arguments(
        self,
        lease,
        *,
        result=None,
        **overrides,
    ):
        runner = FakeRunner(
            self.public,
            self.result if result is None else result,
        )
        selection = self.selection()
        arguments = {
            "snapshot_root": lease.snapshot_root,
            "expected_capture_manifest_sha256": (
                lease.capture_manifest_sha256
            ),
            "expected_capture_plan_sha256": lease.capture_plan_sha256,
            "capture_selection": selection,
            "expected_capture_selection_sha256": (
                capture_selection.capture_selection_sha256(selection)
            ),
            "instance_manifest": self.instance,
            "expected_instance_manifest_sha256": hashlib.sha256(
                self.instance.read_bytes()
            ).hexdigest(),
            "private_root": self.private,
            "expected_public_root": self.public,
            "evidence_home": self.evidence_home,
            "checkout_identity": self.checkout_identity,
            "runtime_identity": self.runtime,
            "expected_instance_slug": "qualification-test",
            "expected_evidence_uid": self.evidence_uid,
            "expected_verifier_uid": self.verifier_uid,
            "expected_verifier_gid": self.verifier_gid,
            "verifier_bundle_sha256": "3" * 64,
            "verification_policy_sha256": "4" * 64,
            "operator_policy_sha256": "5" * 64,
            "verified_at_unix": 200,
            "process_uid": self.verifier_uid,
            "process_gid": self.verifier_gid,
            "process_groups": [self.verifier_gid],
            "snapshot_owner_uid": self.capture_uid,
            "runner": runner,
        }
        arguments.update(overrides)
        return arguments, runner

    def verify_lease(self, lease, *, result=None, **overrides):
        arguments, runner = self._verification_arguments(
            lease,
            result=result,
            **overrides,
        )
        return verifier.verify_opaque_snapshot_evidence(**arguments), runner

    def verify(self, *, plan: dict | None = None, result=None, **overrides):
        lease = self.capture(plan=plan)
        return self.verify_lease(lease, result=result, **overrides)

    def _release_capture(self) -> None:
        if self.lease is not None and self.lease.active:
            self.lease.cleanup()
        self.lease = None

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(verifier.QualificationVerifierError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_real_opaque_capture_is_reconstructed_verified_and_bound(self):
        evidence, runner = self.verify()
        self.assertEqual(evidence["run_id"], self.RUN_ID)
        self.assertEqual(
            evidence["verifier_version"],
            "john-lomein.persona.operator-verifier.v4",
        )
        self.assertEqual(
            evidence["capture_plan_sha256"],
            self.lease.capture_plan_sha256,
        )
        self.assertEqual(
            evidence["capture_manifest_sha256"],
            self.lease.capture_manifest_sha256,
        )
        self.assertEqual(
            evidence["observed_evidence_uid"],
            self.evidence_uid,
        )
        self.assertEqual(evidence["verifier_uid"], self.verifier_uid)
        self.assertEqual(
            runner.opaque_arguments["source_path_identities"],
            {
                "evidence_home": str(self.evidence_home),
                "checkout_source": str(self.checkout_source),
                "runtime_source": str(self.runtime_source),
                "checkout": str(self.checkout_identity),
                "runtime": str(self.runtime),
            },
        )
        self.assertNotIn(
            "source_checkout_root",
            runner.opaque_arguments,
        )
        expected_files = {
            "instance/instance.yaml",
            f"private/{self.RUN_ID}/run-manifest.json",
            "runtime/instance.yaml",
            "runtime/state/john-lomein-persona.json",
            "runtime/state/persona-qualification/latest.json",
            "runtime/state/persona-qualification/status.json",
            (
                "runtime/state/persona-qualification/reports/"
                f"{self.RUN_ID}/summary.json"
            ),
        }
        for profile in capture_selection.ROLE_PROFILES.values():
            expected_files.update(
                {
                    f"runtime/profiles/{profile}/SOUL.md",
                    f"runtime/profiles/{profile}/config.yaml",
                }
            )
        manifest = self.lease.manifest
        self.assertEqual(
            {entry["path"] for entry in manifest["files"]},
            expected_files,
        )
        self.assertEqual(len(manifest["sources"]), 17)
        self.assertFalse((self.lease.snapshot_root / "checkout").exists())
        captured_inventory = json.dumps(
            {
                "sources": manifest["sources"],
                "files": manifest["files"],
            },
            sort_keys=True,
        )
        for forbidden in (
            "/.git/",
            "/auth/",
            "/logs/",
            "/learning/",
            "/worktrees/",
            self.HISTORICAL_RUN_ID,
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, captured_inventory)
        public_output = json.dumps(evidence, sort_keys=True)
        self.assertNotIn(str(self.root), public_output)

    def test_runner_never_dereferences_identity_only_checkout(self):
        lease = self.capture()
        shutil.rmtree(self.checkout_source)
        shutil.rmtree(self.checkout_identity)
        installed_runner = verifier._load_runner()
        with (
            mock.patch.object(
                installed_runner,
                "load_instance",
                return_value={"slug": "qualification-test"},
            ),
            mock.patch.object(
                installed_runner,
                "verify_qualification",
                return_value=(copy.deepcopy(self.result), 0),
            ),
        ):
            result, exit_code = (
                installed_runner.verify_qualification_from_opaque_snapshot(
                    snapshot_root=lease.snapshot_root,
                    source_manifest_path=self.instance,
                    source_runtime_root=self.runtime,
                    source_private_root=self.private,
                    source_path_identities=self.selection()[
                        "path_identities"
                    ],
                    expected_run_id=self.RUN_ID,
                    expected_instance_slug="qualification-test",
                    expected_evidence_uid=self.evidence_uid,
                    snapshot_owner_uid=self.capture_uid,
                    verifier_gid=self.verifier_gid,
                    scenarios_path=(
                        installed_runner.PERSONA_EVAL.DEFAULT_SCENARIOS
                    ),
                    rubric_path=(
                        installed_runner.PERSONA_EVAL.DEFAULT_RUBRIC
                    ),
                )
            )
        self.assertEqual(exit_code, 0)
        self.assertEqual(
            result["attestation_projection"]["run_id"],
            self.RUN_ID,
        )
        self.assertFalse((lease.snapshot_root / "checkout").exists())

    def test_plan_digest_sparse_layout_and_source_paths_are_strict(self):
        lease = self.capture()
        base, _runner = self._verification_arguments(
            lease,
            expected_capture_plan_sha256="0" * 64,
        )
        self.assert_code(
            "opaque_capture_plan_digest_mismatch",
            verifier.verify_opaque_snapshot_evidence,
            **base,
        )
        self._release_capture()

        wrong_role = self.plan()
        profile_source = next(
            item
            for item in wrong_role["sources"]
            if item["source_id"] == "profile-maintainer-soul"
        )
        profile_source["source_class"] = "deployed_soul:attacker"
        self.assert_code(
            "capture_selection_concrete_plan_mismatch",
            self.verify,
            plan=wrong_role,
        )
        self._release_capture()

        injected_checkout = self.plan()
        injected_checkout["sources"].append(
            {
                "source_id": "checkout",
                "source_class": "checkout",
                "kind": "tree",
                "source_path": str(self.checkout_source),
                "destination_path": "checkout",
            }
        )
        injected_checkout["sources"].sort(
            key=lambda item: item["destination_path"]
        )
        self.assert_code(
            "capture_selection_concrete_plan_mismatch",
            self.verify,
            plan=injected_checkout,
        )
        self._release_capture()

        attacker_profile = self.runtime / "attacker-SOUL.md"
        self._write_file(attacker_profile, b"attacker profile\n")
        if os.geteuid() == 0:
            os.chown(attacker_profile, self.evidence_uid, os.getegid())
        wrong_source_path = self.plan()
        next(
            item
            for item in wrong_source_path["sources"]
            if item["source_id"] == "profile-maintainer-soul"
        )["source_path"] = str(attacker_profile)
        self.assert_code(
            "capture_selection_concrete_plan_mismatch",
            self.verify,
            plan=wrong_source_path,
        )
        self._release_capture()

    def test_inventory_status_and_run_id_tamper_fail_closed(self):
        lease = self.capture()
        status_path = (
            lease.snapshot_root
            / "runtime"
            / "state"
            / "persona-qualification"
            / "status.json"
        )
        status_path.chmod(0o640)
        with status_path.open("ab") as handle:
            handle.write(b" ")
        status_path.chmod(0o440)
        arguments, _runner = self._verification_arguments(lease)
        self.assert_code(
            "opaque_capture_sealed_inventory_mismatch",
            verifier.verify_opaque_snapshot_evidence,
            **arguments,
        )
        self._release_capture()

        selected_plan = self.plan()
        invalid_status = copy.deepcopy(self.status)
        invalid_status["summary_sha256"] = "9" * 64
        self._write_status(invalid_status)
        lease = self.capture(plan=selected_plan)
        arguments, _runner = self._verification_arguments(lease)
        self.assert_code(
            "qualification_status_self_digest_invalid",
            verifier.verify_opaque_snapshot_evidence,
            **arguments,
        )
        self._release_capture()
        self._write_status(self.status)

        mismatched = copy.deepcopy(self.result)
        mismatched["attestation_projection"]["run_id"] = "different-run"
        self.assert_code(
            "qualification_opaque_run_id_mismatch",
            self.verify,
            result=mismatched,
        )
        self._release_capture()

    def test_capture_selection_and_digest_tamper_fail_closed(self):
        lease = self.capture()
        selected = self.selection()
        stale_digest_selection = copy.deepcopy(selected)
        stale_digest_selection["limits"]["max_files"] -= 1
        arguments, _runner = self._verification_arguments(
            lease,
            capture_selection=stale_digest_selection,
        )
        self.assert_code(
            "capture_selection_digest_mismatch",
            verifier.verify_opaque_snapshot_evidence,
            **arguments,
        )

        rebound_selection = copy.deepcopy(selected)
        rebound_selection["source_roots"]["qualification_private"] = str(
            self.root / "attacker-private"
        )
        arguments, _runner = self._verification_arguments(
            lease,
            capture_selection=rebound_selection,
            expected_capture_selection_sha256=(
                capture_selection.capture_selection_sha256(
                    rebound_selection
                )
            ),
        )
        self.assert_code(
            "capture_selection_source_roots_mismatch",
            verifier.verify_opaque_snapshot_evidence,
            **arguments,
        )

        role_drift = copy.deepcopy(selected)
        role_drift["role_profiles"]["maintainer"] = "attacker-profile"
        arguments, _runner = self._verification_arguments(
            lease,
            capture_selection=role_drift,
        )
        self.assert_code(
            "capture_selection_role_profiles_mismatch",
            verifier.verify_opaque_snapshot_evidence,
            **arguments,
        )
        self._release_capture()

    def test_request_v4_rejects_missing_or_tampered_adoption_bindings(self):
        selection = self.selection()
        snapshot_root = "/trusted/opaque-capture-" + "b" * 32
        selection_sha256 = (
            capture_selection.capture_selection_sha256(selection)
        )
        capture_uid = self.evidence_uid + 1
        export_gid = self.verifier_gid + 1
        receipt = _adoption_receipt(
            snapshot_root=snapshot_root,
            selection_sha256=selection_sha256,
            plan_sha256="2" * 64,
            manifest_sha256="1" * 64,
            capture_uid=capture_uid,
            export_gid=export_gid,
            verifier_uid=self.verifier_uid,
            verifier_gid=self.verifier_gid,
        )
        request = {
            "schema_version": verifier.REQUEST_SCHEMA,
            "snapshot_root": snapshot_root,
            "capture_manifest_sha256": "1" * 64,
            "capture_plan_sha256": "2" * 64,
            "capture_selection": selection,
            "capture_selection_sha256": selection_sha256,
            "capture_adoption_receipt": receipt,
            "capture_adoption_receipt_sha256": (
                adoption_binding.adoption_receipt_sha256(receipt)
            ),
            "capture_session_id": receipt["session_id"],
            "capture_request_sha256": receipt["request_sha256"],
            "capture_boundary_policy_sha256": receipt[
                "capture_boundary_policy_sha256"
            ],
            "capture_helper_activation_policy_sha256": receipt[
                "helper_activation_policy_sha256"
            ],
            "capture_uid": capture_uid,
            "capture_export_gid": export_gid,
            "adopted_uid": 0,
            "instance_manifest_path": str(self.instance),
            "instance_manifest_sha256": "3" * 64,
            "qualification_private_root": str(self.private),
            "qualification_public_root": str(self.public),
            "evidence_home_path": str(self.evidence_home),
            "checkout_identity_path": str(self.checkout_identity),
            "runtime_identity_path": str(self.runtime),
            "instance_slug": "qualification-test",
            "evidence_uid": self.evidence_uid,
            "verifier_uid": self.verifier_uid,
            "verifier_gid": self.verifier_gid,
            "verifier_bundle_sha256": "4" * 64,
            "verification_policy_sha256": "5" * 64,
            "operator_policy_sha256": "6" * 64,
            "verified_at_unix": 200,
        }
        self.assertEqual(
            verifier.normalize_sealed_request(copy.deepcopy(request)),
            request,
        )
        for mutation in (
            {
                key: value
                for key, value in request.items()
                if key != "capture_plan_sha256"
            },
            {
                key: value
                for key, value in request.items()
                if key != "capture_selection"
            },
            {
                key: value
                for key, value in request.items()
                if key != "capture_selection_sha256"
            },
            {
                key: value
                for key, value in request.items()
                if key != "evidence_home_path"
            },
            {
                **request,
                "schema_version": (
                    "john-lomein.persona.operator-verifier-request.v1"
                ),
            },
            {**request, "evidence_home_path": "~/operator"},
            {
                **request,
                "capture_selection_sha256": "0" * 64,
            },
            {
                **request,
                "checkout_identity_path": "relative/checkout",
            },
            {
                **request,
                "runtime_identity_path": "relative/runtime",
            },
            {
                **request,
                "adopted_uid": 1,
            },
            {
                **request,
                "capture_uid": self.evidence_uid,
            },
            {
                **request,
                "capture_uid": self.verifier_uid,
            },
            {
                **request,
                "capture_export_gid": self.verifier_gid,
            },
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(
                    verifier.QualificationVerifierError
                ):
                    verifier.normalize_sealed_request(mutation)

    def test_metadata_policy_is_descriptor_based_and_narrow(self):
        self.assertNotIn("listxattr", verifier._reject_fd_metadata.__code__.co_names)
        source = verifier._reject_fd_metadata.__code__.co_consts
        self.assertIn(b"security.selinux", source)
        self.assertIn(
            b"com.apple.provenance",
            source,
        )
        self.assertIn(
            b"com.apple.rootless",
            source,
        )
        probe = self.root / "metadata-probe"
        probe.write_bytes(b"probe")
        attribute = (
            "com.john-lomein.verifier-test"
            if sys.platform == "darwin"
            else "user.john_lomein_verifier_test"
        )
        try:
            os.setxattr(probe, attribute, b"forbidden")
        except (AttributeError, OSError):
            return
        descriptor = os.open(probe, os.O_RDONLY)
        try:
            self.assert_code(
                "metadata_probe_extended_metadata_unsupported",
                verifier._reject_fd_metadata,
                descriptor,
                field="metadata_probe",
            )
        finally:
            os.close(descriptor)
            with contextlib.suppress(OSError):
                os.removexattr(probe, attribute)


if __name__ == "__main__":
    unittest.main()
