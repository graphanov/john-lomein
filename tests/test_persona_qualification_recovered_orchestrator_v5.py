from __future__ import annotations

import copy
import inspect
import json
import os
import pickle
import platform
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from types import MethodType, SimpleNamespace
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import test_persona_qualification_adoption_recovery_v2 as recovery_v2_tests  # noqa: E402
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_binding
    as adoption_binding,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_recovery
    as adoption_recovery,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_attestor as core,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_adoption
    as capture_adoption,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_plan as capture_plan,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_selection
    as capture_selection,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_opaque_capture
    as opaque_capture,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_orchestrator as orchestrator,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_sandbox as sandbox,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_transaction_journal as journal,
)


class _Clock:
    def __init__(self, *values: int) -> None:
        self._values = iter(values)

    def __call__(self) -> int:
        return next(self._values)


class RecoveredOrchestratorV5Tests(unittest.TestCase):
    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(
            core.QualificationAttestorError
        ) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def _selection(
        self,
        root: Path,
        *,
        evidence_uid: int,
        verifier_gid: int,
        limits: dict[str, int],
    ) -> dict:
        runtime = root / "runtime"
        return {
            "schema_version": (
                capture_selection.CAPTURE_SELECTION_SCHEMA
            ),
            "instance_slug": "john-test",
            "evidence_uid": evidence_uid,
            "verifier_gid": verifier_gid,
            "source_roots": {
                "instance_manifest": str(
                    root / "control" / "instance.yaml"
                ),
                "runtime": str(runtime),
                "qualification_public": str(
                    runtime / "state" / "persona-qualification"
                ),
                "qualification_private": str(root / "private"),
            },
            "path_identities": {
                "evidence_home": str(root / "evidence"),
                "checkout_source": str(
                    root / "sources" / "checkout"
                ),
                "runtime_source": str(
                    root / "sources" / "runtime"
                ),
                "checkout": str(root / "checkout"),
                "runtime": str(runtime),
            },
            "role_profiles": dict(capture_selection.ROLE_PROFILES),
            "limits": dict(limits),
            "lifecycle": {
                "retention": "ephemeral",
                "max_capture_slots": 8,
                "max_orphan_age_seconds": 60,
            },
        }

    def _patch_recovered_control_digests(
        self,
        support: (
            recovery_v2_tests
            .PersonaQualificationAdoptionRecoveryV2Tests
        ),
        *,
        selection_sha256: str,
        plan_sha256: str,
    ) -> None:
        original = support.journal_fixture.details_for

        def details_for(_fixture, session, state):
            details = original(session, state)
            if state == "capture_ready":
                details["capture_selection_sha256"] = (
                    selection_sha256
                )
                details["capture_plan_sha256"] = plan_sha256
                event = dict(details)
                binding = dict(
                    event.pop("lifecycle_operation_binding")
                )
                binding["supervisor_event_evidence_sha256"] = (
                    journal._capture_event_evidence_sha256(event)
                )
                details["lifecycle_operation_binding"] = binding
            return details

        support.journal_fixture.details_for = MethodType(
            details_for, support.journal_fixture
        )

    def _prepared(
        self,
        fixture: SimpleNamespace,
        *,
        selection: dict,
        plan: dict,
    ) -> tuple[
        orchestrator.PreparedQualificationTransaction,
        orchestrator.PreparedRecoveredQualificationTransaction,
    ]:
        root = fixture.final_parent.parent / "recovered-controls"
        public_key = Ed25519PrivateKey.generate().public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        runtime = Path(selection["source_roots"]["runtime"])
        config = {
            "schema_version": 1,
            "instance_slug": selection["instance_slug"],
            "qualification_public_root": selection[
                "source_roots"
            ]["qualification_public"],
            "qualification_private_root": selection[
                "source_roots"
            ]["qualification_private"],
            "expected_evidence_uid": selection["evidence_uid"],
            "attestor_key_id": "qualification-key",
            "private_key_path": str(root / "keys" / "private.pem"),
            "public_key_path": str(root / "keys" / "public.pem"),
            "public_key_sha256": core.public_key_fingerprint(
                public_bytes
            ),
            "head_path": str(root / "state" / "head.json"),
        }
        bundle = root / "bundle"
        base_binding = {
            "schema_version": core.INSTALLED_BINDING_SCHEMA_VERSION,
            "instance_manifest_path": selection[
                "source_roots"
            ]["instance_manifest"],
            "instance_manifest_sha256": "1" * 64,
            "capture_uid": fixture.owner_uid,
            "capture_export_gid": fixture.export_gid,
            "verifier_uid": selection["evidence_uid"] + 1,
            "verifier_gid": fixture.verifier_gid,
            "verifier_python_path": str(bundle / "python"),
            "verifier_python_sha256": "2" * 64,
            "verifier_bundle_root": str(bundle),
            "verifier_manifest_path": str(
                root / "verifier-manifest.json"
            ),
            "verifier_manifest_sha256": "3" * 64,
            "verifier_entrypoint_path": str(
                bundle / "qualification-verifier.py"
            ),
            "verifier_version": (
                "john-lomein.persona.operator-verifier.v4"
            ),
            "verifier_timeout_seconds": 300,
            "capture_parent_path": str(fixture.final_parent),
            "evidence_home_path": selection[
                "path_identities"
            ]["evidence_home"],
            "runtime_identity_path": str(runtime),
            "checkout_identity_path": selection[
                "path_identities"
            ]["checkout"],
        }
        selection_sha256 = (
            capture_selection.capture_selection_sha256(selection)
        )
        operator_policy = {
            "schema_version": core.OPERATOR_POLICY_SCHEMA,
            "instance_slug": config["instance_slug"],
            "expected_evidence_uid": config[
                "expected_evidence_uid"
            ],
            "expected_capture_uid": fixture.owner_uid,
            "expected_capture_export_gid": fixture.export_gid,
            "expected_adopted_uid": 0,
            "capture_adoption_binding_schema": (
                adoption_binding.ADOPTION_BINDING_SCHEMA
            ),
            "capture_adoption_required": True,
            "instance_manifest_sha256": "1" * 64,
            "verifier_uid": base_binding["verifier_uid"],
            "verifier_gid": fixture.verifier_gid,
            "verifier_python_sha256": "2" * 64,
            "verifier_bundle_sha256": "3" * 64,
            "verifier_version": base_binding["verifier_version"],
            "verifier_timeout_seconds": 300,
            "verification_execution_policy_sha256": core.sha256_json(
                core.VERIFICATION_EXECUTION_POLICY
            ),
            "capture_selection_sha256": selection_sha256,
            "claim_strength": core.CLAIM_STRENGTH,
            "public_reputation_eligible": False,
        }
        binding = {
            **base_binding,
            "verifier_bundle_sha256": "3" * 64,
            "verification_policy_sha256": "4" * 64,
            "operator_policy": operator_policy,
            "operator_policy_sha256": core.sha256_json(
                operator_policy
            ),
        }
        sandbox_policy = sandbox.QualificationSandboxPolicy(
            system=platform.system(),
            kernel_release=platform.release(),
            backend_path=root / "sandbox-backend",
            backend_sha256="5" * 64,
            bundle_root=bundle,
            bundle_sha256="3" * 64,
            capture_parent=fixture.final_parent,
            capture_root=fixture.capture_root,
            python_path=bundle / "python",
            entrypoint_path=bundle / "qualification-verifier.py",
            scratch_root=root / "scratch",
            activation_receipt_path=root / "activation.json",
            verifier_uid=base_binding["verifier_uid"],
            verifier_gid=fixture.verifier_gid,
            timeout_seconds=300,
        )
        prepared = orchestrator.prepare_transaction(
            config=config,
            verified_binding=binding,
            capture_selection=selection,
            capture_plan_sha256=capture_plan.capture_plan_sha256(
                plan
            ),
            sandbox_policy=sandbox_policy,
            public_key_bytes=public_bytes,
            public_projection_path=root / "observer" / "trust.json",
        )
        return prepared, orchestrator.prepare_recovered_transaction(
            prepared,
            capture_plan=plan,
        )

    def _fixture(self) -> SimpleNamespace:
        support = (
            recovery_v2_tests
            .PersonaQualificationAdoptionRecoveryV2Tests("runTest")
        )
        support.setUp()
        self.addCleanup(support.doCleanups)
        owner_uid = os.geteuid()
        if owner_uid <= 0:
            self.skipTest(
                "journal verifier-v5 identity contract needs a "
                "positive dedicated capture uid"
            )
        verifier_gid = os.getegid()
        if verifier_gid == 0:
            verifier_gid = 1
        limits = {
            "max_files": 10,
            "max_directories": 10,
            "max_bytes": 10_000,
            "max_file_bytes": 1_000,
            "max_depth": 8,
        }
        selection = self._selection(
            support.journal_fixture.root / "verifier-contract",
            evidence_uid=60_001,
            verifier_gid=verifier_gid,
            limits=limits,
        )
        plan = capture_selection.compile_concrete_capture_plan(
            selection, "run-001"
        )
        self._patch_recovered_control_digests(
            support,
            selection_sha256=(
                capture_selection.capture_selection_sha256(
                    selection
                )
            ),
            plan_sha256=capture_plan.capture_plan_sha256(plan),
        )
        prepared_holder: dict[str, object] = {}
        original_build = support._build_real_recovered_head

        def build_with_prepared_control(_support):
            prepared, recovered_prepared = self._prepared(
                support.object_fixture,
                selection=selection,
                plan=plan,
            )
            prepared_holder["prepared"] = prepared
            prepared_holder["recovered_prepared"] = (
                recovered_prepared
            )
            journal_fixture = support.journal_fixture

            def reserve_with_control(
                _journal_fixture,
                store,
                *,
                marker="1",
                fault_hook=None,
            ):
                return store._reserve_session_for_test(
                    instance_slug="john-test",
                    control_sha256=prepared.control_sha256,
                    handoff_policy_sha256=(
                        journal_fixture.digest("handoff")
                    ),
                    recorded_at_unix=1,
                    session_id=marker * 64,
                    fault_hook=fault_hook,
                )

            journal_fixture.reserve = MethodType(
                reserve_with_control, journal_fixture
            )
            return original_build()

        support._build_real_recovered_head = MethodType(
            build_with_prepared_control, support
        )
        object_fixture = support._make_object_fixture()
        self.assertEqual(object_fixture.verifier_gid, verifier_gid)
        lease = support._recover(object_fixture)
        self.addCleanup(
            lambda: lease.close() if lease.active else None
        )
        support._commit(object_fixture, lease)
        prepared = prepared_holder["prepared"]
        recovered_prepared = prepared_holder[
            "recovered_prepared"
        ]
        return SimpleNamespace(
            support=support,
            object=object_fixture,
            lease=lease,
            session=object_fixture.session,
            selection=selection,
            plan=plan,
            prepared=prepared,
            recovered_prepared=recovered_prepared,
        )

    def _output(self, fixture: SimpleNamespace, request: dict) -> dict:
        recovered = fixture.lease.capture_adoption_result["evidence"]
        provenance = fixture.lease.capture_adoption_provenance
        return {
            "schema_version": journal.VERIFIER_OUTPUT_V4_SCHEMA,
            "status": "verified",
            "evidence": {
                "run_id": "run-001",
                "summary_sha256": "6" * 64,
                "binding_sha256": "7" * 64,
                "status": "qualified",
                "qualified_at_unix": request[
                    "verified_at_unix"
                ]
                - 1,
                "expires_at_unix": request[
                    "verified_at_unix"
                ]
                + 1_000,
                "verifier_version": journal.VERIFIER_V5_VERSION,
                "verifier_uid": request["verifier_uid"],
                "verifier_bundle_sha256": request[
                    "verifier_bundle_sha256"
                ],
                "verification_policy_sha256": request[
                    "verification_policy_sha256"
                ],
                "capture_manifest_sha256": request[
                    "capture_manifest_sha256"
                ],
                "capture_plan_sha256": request[
                    "capture_plan_sha256"
                ],
                "operator_policy_sha256": request[
                    "operator_policy_sha256"
                ],
                "claim_strength": journal.VERIFIER_CLAIM_STRENGTH,
                "public_reputation_eligible": False,
                "verified_at_unix": request["verified_at_unix"],
                "observed_evidence_uid": request["evidence_uid"],
                "capture_creator_uid": request["capture_uid"],
                "capture_export_gid": request[
                    "capture_export_gid"
                ],
                "capture_adopted_uid": 0,
                "capture_adoption_policy_sha256": recovered[
                    "capture_adoption_policy_sha256"
                ],
                "capture_object_identity_sha256": recovered[
                    "capture_object_identity_sha256"
                ],
                "capture_content_inventory_sha256": recovered[
                    "reconciled_content_inventory_sha256"
                ],
                "capture_request_sha256": recovered[
                    "capture_request_sha256"
                ],
                "capture_boundary_policy_sha256": recovered[
                    "capture_boundary_policy_sha256"
                ],
                "capture_helper_activation_policy_sha256": recovered[
                    "helper_activation_policy_sha256"
                ],
                "capture_adoption_provenance": provenance,
                "capture_adoption_provenance_sha256": (
                    fixture.lease.capture_adoption_provenance_sha256
                ),
            },
        }

    def _launcher(self, fixture: SimpleNamespace, events: list[str]):
        def launch(request):
            events.append("verifier")
            fixture.request = copy.deepcopy(request)
            output = self._output(fixture, request)
            return SimpleNamespace(
                stdout=core.canonical_json(output) + b"\n",
                stderr=b"",
                returncode=0,
            )

        return launch

    def _run(
        self,
        fixture: SimpleNamespace,
        *,
        events: list[str] | None = None,
        launcher=None,
        controls=None,
    ) -> dict:
        observed_events = [] if events is None else events

        def revalidate(snapshot_root, **kwargs):
            observed_events.append("live-source")
            self.assertEqual(
                snapshot_root, fixture.object.capture_root
            )
            self.assertEqual(kwargs["plan"], fixture.plan)
            self.assertEqual(
                kwargs["expected_plan_sha256"],
                fixture.prepared.capture_plan_sha256,
            )
            self.assertEqual(kwargs["expected_capture_uid"], 0)
            self.assertEqual(
                kwargs["expected_manifest_capture_uid"],
                fixture.object.owner_uid,
            )
            self.assertEqual(
                kwargs["expected_directory_mode"],
                capture_adoption.ADOPTED_DIRECTORY_MODE,
            )
            self.assertEqual(
                kwargs["source_directory_mode"],
                opaque_capture.EXPORT_SOURCE_DIRECTORY_MODE,
            )
            return {}

        selected_launcher = (
            self._launcher(fixture, observed_events)
            if launcher is None
            else launcher
        )
        selected_controls = (
            lambda: fixture.prepared.control_sha256
            if controls is None
            else controls
        )
        with (
            mock.patch.object(orchestrator.os, "getuid", return_value=0),
            mock.patch.object(orchestrator.os, "geteuid", return_value=0),
            mock.patch.object(
                orchestrator.opaque_capture,
                "revalidate_live_opaque_sources",
                side_effect=revalidate,
            ),
        ):
            ack_time = (
                fixture.session.latest_record.recorded_at_unix
            )
            return orchestrator.run_recovered_adoption_verifier_v5(
                fixture.recovered_prepared,
                fixture.lease,
                fixture.session,
                verifier_v5_launcher=selected_launcher,
                revalidate_controls=selected_controls,
                clock=_Clock(ack_time + 1, ack_time + 2),
            )

    def test_full_route_orders_real_reread_and_returns_clearance_v6(
        self,
    ) -> None:
        fixture = self._fixture()
        events: list[str] = []
        evidence = self._run(fixture, events=events)
        self.assertEqual(events, ["verifier", "live-source"])
        self.assertEqual(
            fixture.request["snapshot_root"],
            str(
                Path(
                    fixture.prepared.binding[
                        "capture_parent_path"
                    ]
                )
                / fixture.object.final_name
            ),
        )
        self.assertEqual(
            fixture.session.state,
            "live_revalidation_receipt_complete",
        )
        self.assertEqual(
            evidence["capture_adoption_provenance"]["kind"],
            "recovered_adoption",
        )
        self.assertFalse(evidence["public_reputation_eligible"])
        envelope = (
            fixture.session
            .recover_recovered_verified_evidence_v6()
            .recovered_verifier_source_evidence
        )
        self.assertIs(
            envelope[
                "source_revalidation_effect_"
                "completed_under_acked_head"
            ],
            True,
        )
        receipt = envelope["source_revalidation_receipt_v2"]
        self.assertEqual(
            receipt["revalidated_at_unix"],
            next(
                record.recorded_at_unix
                for record in fixture.session.records
                if record.state == "staging_tombstone_acked"
            )
            + 2,
        )
        self.assertNotIn(
            str(fixture.object.capture_root),
            core.canonical_json(
                [record.to_dict() for record in fixture.session.records]
            ).decode("ascii"),
        )

    def test_post_commit_interrupt_resumes_without_relaunch_or_reread(
        self,
    ) -> None:
        fixture = self._fixture()
        events: list[str] = []
        interruption = KeyboardInterrupt("after durable commit")
        with mock.patch.object(
            journal.TransactionJournalSession,
            "advance_recovered_verifier_source_evidence",
            side_effect=interruption,
        ):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self._run(fixture, events=events)
        self.assertIs(caught.exception, interruption)
        self.assertEqual(events, ["verifier", "live-source"])
        self.assertEqual(
            fixture.session.state, "verifier_output_bound"
        )
        evidence = (
            orchestrator.resume_recovered_adoption_verifier_v5(
                fixture.recovered_prepared,
                fixture.session,
            )
        )
        self.assertEqual(
            fixture.session.state,
            "live_revalidation_receipt_complete",
        )
        self.assertEqual(evidence["run_id"], "run-001")
        self.assertEqual(events, ["verifier", "live-source"])

    def test_precommit_async_failure_cancels_reservation_and_preserves(
        self,
    ) -> None:
        fixture = self._fixture()
        interruption = KeyboardInterrupt("during verifier")

        def interrupted(_request):
            raise interruption

        with self.assertRaises(KeyboardInterrupt) as caught:
            self._run(fixture, launcher=interrupted)
        self.assertIs(caught.exception, interruption)
        self.assertEqual(
            fixture.session.state, "staging_tombstone_acked"
        )
        operation = (
            fixture.session.begin_recovered_verifier_source_evidence()
        )
        operation.cancel()

    def test_cleanup_interrupt_never_pins_reservation_or_hides_primary(
        self,
    ) -> None:
        for primary_kind in ("ordinary", "base-exception"):
            with self.subTest(primary_kind=primary_kind):
                fixture = self._fixture()
                events: list[str] = []
                primary_escape = KeyboardInterrupt(
                    "primary verifier escape"
                )
                cleanup_escape = KeyboardInterrupt(
                    "cancel release escape"
                )

                def launcher(request):
                    events.append("verifier")
                    if primary_kind == "base-exception":
                        raise primary_escape
                    output = self._output(fixture, request)
                    output["evidence"][
                        "capture_plan_sha256"
                    ] = "f" * 64
                    return SimpleNamespace(
                        stdout=core.canonical_json(output) + b"\n",
                        stderr=b"",
                        returncode=0,
                    )

                with mock.patch.object(
                    journal.TransactionJournalSession,
                    (
                        "_release_cancelled_recovered_"
                        "verifier_operation"
                    ),
                    side_effect=cleanup_escape,
                ):
                    try:
                        self._run(
                            fixture,
                            events=events,
                            launcher=launcher,
                        )
                    except BaseException as caught:
                        expected = (
                            primary_escape
                            if primary_kind == "base-exception"
                            else cleanup_escape
                        )
                        self.assertIs(caught, expected)
                    else:
                        self.fail("cleanup escape was swallowed")

                self.assertEqual(events, ["verifier"])
                self.assertEqual(
                    fixture.session.state,
                    "staging_tombstone_acked",
                )
                replacement = (
                    fixture.session
                    .begin_recovered_verifier_source_evidence()
                )
                replacement.cancel()

    def test_hostile_output_stops_before_reread_and_releases_reservation(
        self,
    ) -> None:
        fixture = self._fixture()
        events: list[str] = []

        def hostile(request):
            events.append("verifier")
            output = self._output(fixture, request)
            output["evidence"]["capture_plan_sha256"] = "f" * 64
            return SimpleNamespace(
                stdout=core.canonical_json(output) + b"\n",
                stderr=b"",
                returncode=0,
            )

        self.assert_code(
            "recovered_verifier_v5_output_capture_plan_sha256_mismatch",
            self._run,
            fixture,
            events=events,
            launcher=hostile,
        )
        self.assertEqual(events, ["verifier"])
        operation = (
            fixture.session.begin_recovered_verifier_source_evidence()
        )
        operation.cancel()

    def test_hostile_output_run_id_stops_before_reread_and_commit(
        self,
    ) -> None:
        fixture = self._fixture()
        events: list[str] = []

        def hostile(request):
            events.append("verifier")
            output = self._output(fixture, request)
            output["evidence"]["run_id"] = "different-run"
            return SimpleNamespace(
                stdout=core.canonical_json(output) + b"\n",
                stderr=b"",
                returncode=0,
            )

        self.assert_code(
            "recovered_verifier_v5_output_run_id_mismatch",
            self._run,
            fixture,
            events=events,
            launcher=hostile,
        )
        self.assertEqual(events, ["verifier"])
        self.assertEqual(
            fixture.session.state, "staging_tombstone_acked"
        )
        operation = (
            fixture.session.begin_recovered_verifier_source_evidence()
        )
        operation.cancel()

    def test_api_has_no_raw_authority_and_default_is_fail_closed(
        self,
    ) -> None:
        fixture = self._fixture()
        parameters = set(
            inspect.signature(
                orchestrator.run_recovered_adoption_verifier_v5
            ).parameters
        )
        self.assertTrue(
            {
                "snapshot_root",
                "capture_plan",
                "capture_adoption_provenance",
                "verifier_output_v4",
                "source_revalidation_receipt_v2",
                "verified_evidence_v6",
            }.isdisjoint(parameters)
        )
        self.assertEqual(
            tuple(
                inspect.signature(
                    orchestrator
                    .resume_recovered_adoption_verifier_v5
                ).parameters
            ),
            ("prepared_recovered", "journal_session"),
        )
        self.assertFalse(
            orchestrator.RECOVERED_VERIFIER_V5_PRODUCTION_ACTIVATION
        )
        self.assert_code(
            "recovered_verifier_v5_not_installed",
            orchestrator.run_recovered_adoption_verifier_v5,
            fixture.recovered_prepared,
            fixture.lease,
            fixture.session,
            revalidate_controls=(
                lambda: fixture.prepared.control_sha256
            ),
        )
        self.assertEqual(
            fixture.session.state, "staging_tombstone_acked"
        )
        self.assert_code(
            "transaction_journal_recovered_verifier_"
            "evidence_head_state_invalid",
            orchestrator.resume_recovered_adoption_verifier_v5,
            fixture.recovered_prepared,
            fixture.session,
        )

    def test_prepared_plan_is_sealed_and_digest_bound(self) -> None:
        fixture = self._fixture()
        with self.assertRaises(TypeError):
            copy.copy(fixture.recovered_prepared)
        with self.assertRaises(TypeError):
            copy.deepcopy(fixture.recovered_prepared)
        with self.assertRaises(TypeError):
            pickle.dumps(fixture.recovered_prepared)
        with self.assertRaises(TypeError):
            orchestrator.PreparedRecoveredQualificationTransaction(
                _token=object(),
                prepared=fixture.prepared,
                capture_plan=fixture.plan,
            )
        changed = copy.deepcopy(fixture.plan)
        changed["sources"][0]["source_path"] = str(
            fixture.object.final_parent / "caller-selected"
        )
        self.assert_code(
            "capture_selection_concrete_plan_mismatch",
            orchestrator.prepare_recovered_transaction,
            fixture.prepared,
            capture_plan=changed,
        )

    def test_prepared_wrapper_deep_snapshots_mutable_prepared_fields(
        self,
    ) -> None:
        fixture = self._fixture()
        snapshot, _plan = fixture.recovered_prepared._contents()
        expected_slug = snapshot.config["instance_slug"]
        expected_bundle = snapshot.binding[
            "verifier_bundle_sha256"
        ]
        expected_profile = snapshot.capture_selection[
            "role_profiles"
        ]["maintainer"]

        fixture.prepared.config["instance_slug"] = "caller-mutation"
        fixture.prepared.binding["verifier_bundle_sha256"] = "f" * 64
        fixture.prepared.capture_selection["role_profiles"][
            "maintainer"
        ] = "caller-profile"

        observed, _plan = fixture.recovered_prepared._contents()
        self.assertEqual(observed.config["instance_slug"], expected_slug)
        self.assertEqual(
            observed.binding["verifier_bundle_sha256"],
            expected_bundle,
        )
        self.assertEqual(
            observed.capture_selection["role_profiles"][
                "maintainer"
            ],
            expected_profile,
        )

    def test_mutated_or_forged_prepared_controls_cannot_be_sealed(
        self,
    ) -> None:
        fixture = self._fixture()
        mutations = []

        changed = copy.deepcopy(fixture.prepared)
        changed.binding["verifier_bundle_sha256"] = "f" * 64
        mutations.append(
            ("bundle", changed, "operator_policy_binding_mismatch")
        )

        changed = copy.deepcopy(fixture.prepared)
        changed.binding["verification_policy_sha256"] = "f" * 64
        mutations.append(
            (
                "verification-policy",
                changed,
                "recovered_transaction_prepared_recomputation_mismatch",
            )
        )

        changed = copy.deepcopy(fixture.prepared)
        changed.operator_policy["verifier_bundle_sha256"] = "f" * 64
        mutations.append(
            (
                "operator-policy",
                changed,
                "operator_policy_digest_mismatch",
            )
        )

        mutations.append(
            (
                "forged-control",
                replace(
                    fixture.prepared,
                    control_sha256="f" * 64,
                ),
                "recovered_transaction_prepared_recomputation_mismatch",
            )
        )

        for label, prepared, code in mutations:
            with self.subTest(label=label):
                self.assert_code(
                    code,
                    orchestrator.prepare_recovered_transaction,
                    prepared,
                    capture_plan=fixture.plan,
                )

    def test_same_instance_wrong_control_cannot_resume_clearance(
        self,
    ) -> None:
        fixture = self._fixture()
        self._run(fixture)
        wrong = replace(
            fixture.prepared,
            control_sha256="f" * 64,
        )
        self.assert_code(
            "recovered_transaction_prepared_recomputation_mismatch",
            orchestrator.prepare_recovered_transaction,
            wrong,
            capture_plan=fixture.plan,
        )
        self.assertEqual(
            fixture.session.state,
            "live_revalidation_receipt_complete",
        )

    def test_request_is_normalized_and_time_bound_before_launch(
        self,
    ) -> None:
        fixture = self._fixture()
        launches: list[dict] = []
        original = (
            orchestrator._build_recovered_verifier_request_v5
        )

        def caller_path(*args, **kwargs):
            request = original(*args, **kwargs)
            request["snapshot_root"] = str(
                fixture.object.final_parent
                / ("opaque-capture-" + "b" * 32)
            )
            return request

        with (
            mock.patch.object(orchestrator.os, "getuid", return_value=0),
            mock.patch.object(
                orchestrator.os, "geteuid", return_value=0
            ),
            mock.patch.object(
                orchestrator,
                "_build_recovered_verifier_request_v5",
                side_effect=caller_path,
            ),
        ):
            self.assert_code(
                "transaction_journal_recovered_verifier_"
                "snapshot_result_name_mismatch",
                orchestrator.run_recovered_adoption_verifier_v5,
                fixture.recovered_prepared,
                fixture.lease,
                fixture.session,
                verifier_v5_launcher=(
                    lambda request: launches.append(request)
                ),
                revalidate_controls=(
                    lambda: fixture.prepared.control_sha256
                ),
                clock=_Clock(
                    fixture.session.latest_record.recorded_at_unix
                    + 1
                ),
            )
        self.assertEqual(launches, [])
        operation = (
            fixture.session.begin_recovered_verifier_source_evidence()
        )
        operation.cancel()

        fixture = self._fixture()
        ack_time = fixture.session.latest_record.recorded_at_unix
        with (
            mock.patch.object(orchestrator.os, "getuid", return_value=0),
            mock.patch.object(
                orchestrator.os, "geteuid", return_value=0
            ),
        ):
            self.assert_code(
                "recovered_verifier_v5_clock_precedes_ack",
                orchestrator.run_recovered_adoption_verifier_v5,
                fixture.recovered_prepared,
                fixture.lease,
                fixture.session,
                verifier_v5_launcher=(
                    lambda request: launches.append(request)
                ),
                revalidate_controls=(
                    lambda: fixture.prepared.control_sha256
                ),
                clock=_Clock(ack_time - 1),
            )
        self.assertEqual(launches, [])
        operation = (
            fixture.session.begin_recovered_verifier_source_evidence()
        )
        operation.cancel()

    def test_noncanonical_and_trailing_verifier_output_never_reread(
        self,
    ) -> None:
        for mode in ("pretty", "trailing"):
            with self.subTest(mode=mode):
                fixture = self._fixture()
                events: list[str] = []

                def malformed(request):
                    events.append("verifier")
                    output = self._output(fixture, request)
                    if mode == "pretty":
                        stdout = (
                            json.dumps(
                                output,
                                ensure_ascii=True,
                                allow_nan=False,
                                indent=2,
                                sort_keys=True,
                            ).encode("ascii")
                            + b"\n"
                        )
                    else:
                        stdout = (
                            core.canonical_json(output)
                            + b"\ntrailing"
                        )
                    return SimpleNamespace(
                        stdout=stdout,
                        stderr=b"",
                        returncode=0,
                    )

                with self.assertRaises(
                    core.QualificationAttestorError
                ) as caught:
                    self._run(
                        fixture,
                        events=events,
                        launcher=malformed,
                    )
                if mode == "pretty":
                    self.assertEqual(
                        caught.exception.code,
                        "recovered_verifier_v5_output_noncanonical",
                    )
                else:
                    self.assertIn(
                        "recovered_verifier_v5_output",
                        caught.exception.code,
                    )
                self.assertEqual(events, ["verifier"])
                operation = (
                    fixture.session
                    .begin_recovered_verifier_source_evidence()
                )
                operation.cancel()

    def test_launcher_cannot_mutate_normalized_request_in_place(
        self,
    ) -> None:
        fixture = self._fixture()
        events: list[str] = []

        def mutating(request):
            events.append("verifier")
            output = self._output(fixture, request)
            request["snapshot_root"] = str(
                fixture.object.final_parent
                / ("opaque-capture-" + "c" * 32)
            )
            return SimpleNamespace(
                stdout=core.canonical_json(output) + b"\n",
                stderr=b"",
                returncode=0,
            )

        self.assert_code(
            "recovered_verifier_v5_launcher_mutated_request",
            self._run,
            fixture,
            events=events,
            launcher=mutating,
        )
        self.assertEqual(events, ["verifier"])
        self.assertEqual(
            fixture.session.state, "staging_tombstone_acked"
        )
        operation = (
            fixture.session.begin_recovered_verifier_source_evidence()
        )
        operation.cancel()

    def test_revalidation_clock_rollback_cannot_mint_evidence(
        self,
    ) -> None:
        fixture = self._fixture()
        events: list[str] = []
        ack_time = fixture.session.latest_record.recorded_at_unix

        def reread(*_args, **_kwargs):
            events.append("live-source")
            return {}

        with (
            mock.patch.object(orchestrator.os, "getuid", return_value=0),
            mock.patch.object(
                orchestrator.os, "geteuid", return_value=0
            ),
            mock.patch.object(
                orchestrator.opaque_capture,
                "revalidate_live_opaque_sources",
                side_effect=reread,
            ),
        ):
            self.assert_code(
                "qualification_clock_rollback",
                orchestrator.run_recovered_adoption_verifier_v5,
                fixture.recovered_prepared,
                fixture.lease,
                fixture.session,
                verifier_v5_launcher=self._launcher(
                    fixture, events
                ),
                revalidate_controls=(
                    lambda: fixture.prepared.control_sha256
                ),
                clock=_Clock(ack_time + 2, ack_time + 1),
            )
        self.assertEqual(events, ["verifier", "live-source"])
        self.assertEqual(
            fixture.session.state, "staging_tombstone_acked"
        )
        operation = (
            fixture.session.begin_recovered_verifier_source_evidence()
        )
        operation.cancel()


if __name__ == "__main__":
    unittest.main()
