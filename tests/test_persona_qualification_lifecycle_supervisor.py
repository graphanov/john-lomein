from __future__ import annotations

import hashlib
import inspect
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (
    john_lomein_persona_qualification_lifecycle_receipts
    as lifecycle,
)
from qualification_attestor import (
    john_lomein_persona_qualification_lifecycle_supervisor
    as supervisor,
)


class SimulatedCrash(RuntimeError):
    pass


class PersonaQualificationLifecycleSupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.store_path = self.root / "lifecycle"
        self.store_path.mkdir(mode=0o700)
        self.store_path.chmod(0o700)
        lock = self.store_path / ".lock"
        lock.touch(mode=0o600)
        lock.chmod(0o600)
        self.boot = self.digest("boot-1")
        self.epoch = self.digest("epoch-1")
        self.instance_slug = "john-test"
        self.instance_control = self.digest("instance-control")
        self.stores: list[supervisor.LifecycleSupervisorStore] = []
        self.addCleanup(self.close_stores)

    def digest(self, label: str) -> str:
        return hashlib.sha256(label.encode("ascii")).hexdigest()

    def close_stores(self) -> None:
        for store in reversed(self.stores):
            if store.active:
                store.close()

    def open_store(
        self,
        *,
        boot: str | None = None,
        epoch: str | None = None,
        store_path: Path | None = None,
    ) -> supervisor.LifecycleSupervisorStore:
        store = supervisor._open_lifecycle_supervisor_store_for_test(
            self.store_path if store_path is None else store_path,
            instance_slug=self.instance_slug,
            instance_control_sha256=self.instance_control,
            host_boot_id_sha256=self.boot if boot is None else boot,
            supervisor_epoch_id=self.epoch if epoch is None else epoch,
        )
        self.stores.append(store)
        return store

    def activation(
        self,
        *,
        provider: str = "linux_cgroup_v2",
        boot: str | None = None,
    ) -> dict:
        return {
            "schema_version": lifecycle.ACTIVATION_RECEIPT_SCHEMA,
            "status": lifecycle.ACTIVATION_STATUS,
            "system": "Linux",
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": provider,
            "supervisor_policy_sha256": self.digest(
                "supervisor-policy"
            ),
            "supervisor_bundle_sha256": self.digest(
                "supervisor-bundle"
            ),
            "helper_activation_policy_sha256": self.digest("helper"),
            "lifecycle_canary_sha256": self.digest("canary"),
            "host_boot_measurement": "linux_boot_id",
            "host_boot_id_sha256": (
                self.boot if boot is None else boot
            ),
            "assertions": {
                name: True for name in lifecycle.ACTIVATION_ASSERTIONS
            },
            "production_activation": False,
        }

    def start_kwargs(
        self,
        *,
        provider: str = "linux_cgroup_v2",
        session_marker: str = "1",
        incarnation_marker: str = "2",
        boot: str | None = None,
        operation: str = "start-operation",
    ) -> dict:
        activation = self.activation(provider=provider, boot=boot)
        return {
            "capture_session_id": session_marker * 64,
            "scope_incarnation_id": incarnation_marker * 64,
            "activation_receipt": activation,
            "activation_receipt_sha256": (
                lifecycle.activation_receipt_sha256(activation)
            ),
            "staging_transaction_intent_sha256": self.digest(
                "staging-intent"
            ),
            "staging_exposure_receipt_sha256": self.digest(
                "staging-exposure"
            ),
            "child_launch_intent_record_revision": 4,
            "child_launch_intent_record_sha256": self.digest(
                "launch-intent"
            ),
            "handoff_policy_sha256": self.digest("handoff"),
            "helper_activation_policy_sha256": self.digest("helper"),
            "capture_uid": 501,
            "export_gid": 502,
            "operation_id_sha256": self.digest(operation),
            "recorded_at_unix": 1,
        }

    def start_session(
        self,
        store: supervisor.LifecycleSupervisorStore,
        **overrides,
    ) -> supervisor.LifecycleSupervisorSession:
        kwargs = self.start_kwargs()
        kwargs.update(overrides)
        return store.start_session(**kwargs)

    def record_started(
        self,
        session: supervisor.LifecycleSupervisorSession,
        *,
        operation: str = "scope-started-operation",
        recorded_at: int = 2,
    ) -> supervisor.LifecycleSupervisorRecord:
        return session.record_scope_started(
            provider_start_observation_sha256=self.digest(
                "provider-start-observation"
            ),
            operation_id_sha256=self.digest(operation),
            recorded_at_unix=recorded_at,
        )

    def record_capture(
        self,
        session: supervisor.LifecycleSupervisorSession,
        started: supervisor.LifecycleSupervisorRecord,
        *,
        origin: str = "capture_ready",
        operation: str = "capture-operation",
        recorded_at: int = 3,
    ) -> supervisor.LifecycleSupervisorRecord:
        return session.record_capture_event(
            effect_origin_state=origin,
            effect_origin_record_revision=(
                6 if origin == "capture_ready" else 5
            ),
            effect_origin_record_sha256=self.digest(
                f"{origin}-outer-record"
            ),
            expected_scope_started_receipt_sha256=started.details[
                "scope_started_receipt_sha256"
            ],
            operation_id_sha256=self.digest(operation),
            recorded_at_unix=recorded_at,
        )

    def record_clearance(
        self,
        session: supervisor.LifecycleSupervisorSession,
        *,
        operation: str = "clearance-operation",
        recorded_at: int = 4,
    ) -> supervisor.LifecycleSupervisorRecord:
        capture = next(
            (
                record
                for record in session.records
                if record.state == "capture_event"
            ),
            None,
        )
        started = next(
            (
                record
                for record in session.records
                if record.state == "scope_started"
            ),
            None,
        )
        if capture is None:
            start = session.records[0]
            origin = "child_launch_intent"
            origin_revision = start.details[
                "child_launch_intent_record_revision"
            ]
            origin_digest = start.details[
                "child_launch_intent_record_sha256"
            ]
            start_digest = None
            mode = "terminate_and_clear"
        else:
            origin = capture.details["effect_origin_state"]
            origin_revision = capture.details[
                "effect_origin_record_revision"
            ]
            origin_digest = capture.details[
                "effect_origin_record_sha256"
            ]
            start_digest = started.details[
                "scope_started_receipt_sha256"
            ]
            mode = (
                "wait_clean_then_terminate_on_deadline"
                if origin == "capture_ready"
                else "terminate_and_clear"
            )
        return session.record_clearance_intent(
            effect_origin_state=origin,
            effect_origin_record_revision=origin_revision,
            effect_origin_record_sha256=origin_digest,
            expected_scope_started_receipt_sha256=start_digest,
            clearance_mode=mode,
            outer_clearance_intent_record_revision=7,
            outer_clearance_intent_record_sha256=self.digest(
                "outer-clearance-intent"
            ),
            operation_id_sha256=self.digest(operation),
            recorded_at_unix=recorded_at,
        )

    def observe(
        self,
        session: supervisor.LifecycleSupervisorSession,
        *,
        kind: str,
        stderr_bytes: int | None = None,
        stderr_sha256: str | None = None,
        operation: str = "observation-operation",
        recorded_at: int = 5,
    ) -> supervisor.LifecycleSupervisorRecord:
        return session.record_provider_observation(
            observation_kind=kind,
            provider_observation_sha256=self.digest(
                f"provider-{kind}"
            ),
            stderr_bytes=stderr_bytes,
            stderr_sha256=stderr_sha256,
            operation_id_sha256=self.digest(operation),
            recorded_at_unix=recorded_at,
        )

    def settle(
        self,
        session: supervisor.LifecycleSupervisorSession,
        observation: supervisor.LifecycleSupervisorRecord,
        *,
        operation: str = "settle-operation",
        recorded_at: int = 6,
    ) -> supervisor.LifecycleSupervisorRecord:
        return session.record_settled_bundle(
            expected_provider_observation_record_sha256=(
                observation.record_sha256
            ),
            operation_id_sha256=self.digest(operation),
            recorded_at_unix=recorded_at,
        )

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(
            supervisor.LifecycleSupervisorError
        ) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def assert_no_forbidden_authority(self, value) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                parts = set(key.lower().split("_"))
                self.assertFalse(
                    parts & supervisor.FORBIDDEN_FIELD_PARTS,
                    key,
                )
                self.assert_no_forbidden_authority(child)
        elif isinstance(value, list):
            for child in value:
                self.assert_no_forbidden_authority(child)

    def test_clean_capture_builds_exact_normalized_bundle(self) -> None:
        store = self.open_store()
        session = self.start_session(store)
        started = self.record_started(session)
        self.record_capture(session, started)
        self.record_clearance(session)
        observation = self.observe(
            session,
            kind="clean_exit",
            stderr_bytes=0,
            stderr_sha256=lifecycle.EMPTY_SHA256,
        )
        settled = self.settle(session, observation)

        self.assertEqual(
            [record.state for record in session.records],
            [
                "start_intent",
                "scope_started",
                "capture_event",
                "clearance_intent",
                "provider_observation",
                "settled_bundle",
            ],
        )
        bundle = settled.details["clearance_bundle"]
        self.assertEqual(
            lifecycle.normalize_clearance_bundle(bundle), bundle
        )
        self.assertTrue(
            bundle["scope_empty_receipt"]["adoption_eligible"]
        )
        self.assertEqual(
            bundle["scope_empty_receipt"][
                "completion_disposition"
            ],
            "clean_exit",
        )
        self.assert_no_forbidden_authority(
            [record.to_dict() for record in session.records]
        )

        previous = supervisor.ZERO_SHA256
        raw_operation = self.digest("same-operation")
        bound = {
            supervisor._bound_operation_id(
                raw_operation,
                state=state,
                session_id=session.capture_session_id,
                incarnation_id=session.scope_incarnation_id,
            )
            for state in (
                "start_intent",
                "scope_started",
                "capture_event",
            )
        }
        self.assertEqual(len(bound), 3)
        for revision, record in enumerate(session.records, start=1):
            value = record.to_dict()
            self.assertEqual(value["revision"], revision)
            self.assertEqual(
                value["previous_record_sha256"], previous
            )
            self.assertNotEqual(
                value["operation_id_sha256"],
                self.digest(
                    {
                        1: "start-operation",
                        2: "scope-started-operation",
                        3: "capture-operation",
                        4: "clearance-operation",
                        5: "observation-operation",
                        6: "settle-operation",
                    }[revision]
                ),
            )
            self.assertEqual(
                value["operation_request_sha256"],
                self.digest(
                    {
                        1: "start-operation",
                        2: "scope-started-operation",
                        3: "capture-operation",
                        4: "clearance-operation",
                        5: "observation-operation",
                        6: "settle-operation",
                    }[revision]
                ),
            )
            previous = record.record_sha256

        session_dir = next(
            child
            for child in self.store_path.iterdir()
            if child.name.startswith("session-")
        )
        self.assertEqual(
            stat.S_IMODE(session_dir.stat().st_mode), 0o700
        )
        for child in session_dir.iterdir():
            self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o400)

    def test_never_started_same_boot_is_no_effect_clearance(self) -> None:
        store = self.open_store()
        session = self.start_session(store)
        self.record_clearance(session, recorded_at=2)
        observation = self.observe(
            session, kind="scope_absent", recorded_at=3
        )
        settled = self.settle(
            session, observation, recorded_at=4
        )
        empty = settled.details["clearance_bundle"][
            "scope_empty_receipt"
        ]
        self.assertEqual(
            empty["completion_disposition"], "never_started"
        )
        self.assertEqual(
            empty["clearance_basis"],
            lifecycle.NO_EFFECT_CLEARANCE_BASIS,
        )
        self.assertIsNone(empty["scope_started_receipt_sha256"])

    def test_never_started_after_reboot_is_derived_on_replay(self) -> None:
        first = self.open_store()
        session = self.start_session(first)
        session.close()
        first.close()

        reboot = self.digest("boot-2")
        restarted = self.open_store(
            boot=reboot, epoch=self.digest("epoch-2")
        )
        recovered = restarted.load_incomplete_sessions()[0]
        self.assertEqual(
            recovered.recovery_status()["action"],
            "request_clearance",
        )
        self.record_clearance(recovered, recorded_at=2)
        observation = self.observe(
            recovered, kind="scope_absent", recorded_at=3
        )
        settled = self.settle(
            recovered, observation, recorded_at=4
        )
        empty = settled.details["clearance_bundle"][
            "scope_empty_receipt"
        ]
        self.assertEqual(
            empty["completion_disposition"],
            "never_started_after_reboot",
        )
        self.assertEqual(
            empty["clearance_host_boot_id_sha256"], reboot
        )

    def test_reboot_with_reused_supervisor_epoch_routes_to_attention(
        self,
    ) -> None:
        first = self.open_store()
        session = self.start_session(first)
        session.close()
        first.close()

        restarted = self.open_store(
            boot=self.digest("boot-2"), epoch=self.epoch
        )
        recovered = restarted.load_incomplete_sessions()[0]
        self.record_clearance(recovered, recorded_at=2)
        attention = self.observe(
            recovered, kind="scope_absent", recorded_at=3
        )
        self.assertEqual(attention.state, "operator_attention")
        self.assertEqual(
            attention.details["reason_code"],
            supervisor.HOST_EPOCH_INCOHERENT_REASON,
        )

    def test_started_scope_after_host_reboot_derives_host_reboot(self) -> None:
        first = self.open_store()
        session = self.start_session(first)
        started = self.record_started(session)
        self.record_capture(
            session, started, origin="child_running"
        )
        self.record_clearance(session)
        session.close()
        first.close()

        restarted = self.open_store(
            boot=self.digest("boot-2"),
            epoch=self.digest("epoch-2"),
        )
        recovered = restarted.load_incomplete_sessions()[0]
        observation = self.observe(
            recovered, kind="scope_absent"
        )
        settled = self.settle(recovered, observation)
        empty = settled.details["clearance_bundle"][
            "scope_empty_receipt"
        ]
        self.assertEqual(
            empty["completion_disposition"], "host_reboot"
        )
        self.assertEqual(
            empty["clearance_basis"],
            lifecycle.REBOOT_CLEARANCE_BASIS,
        )

    def test_restart_safe_provider_can_derive_unobserved_exit(self) -> None:
        first = self.open_store()
        session = self.start_session(first)
        started = self.record_started(session)
        self.record_capture(
            session, started, origin="child_running"
        )
        self.record_clearance(session)
        session.close()
        first.close()

        restarted = self.open_store(
            epoch=self.digest("epoch-2")
        )
        recovered = restarted.load_incomplete_sessions()[0]
        observation = self.observe(
            recovered, kind="scope_empty_unobserved"
        )
        empty = observation.details["scope_empty_receipt"]
        self.assertEqual(
            empty["completion_disposition"],
            "exit_unobserved_after_restart",
        )
        self.assertIsNone(empty["stderr_bytes"])
        self.assertFalse(empty["adoption_eligible"])

    def test_restart_safe_provider_can_record_forced_termination(self) -> None:
        first = self.open_store()
        session = self.start_session(first)
        started = self.record_started(session)
        self.record_capture(
            session, started, origin="child_running"
        )
        self.record_clearance(session)
        session.close()
        first.close()

        restarted = self.open_store(
            epoch=self.digest("epoch-2")
        )
        recovered = restarted.load_incomplete_sessions()[0]
        observation = self.observe(
            recovered,
            kind="forced_scope_empty",
            stderr_bytes=7,
            stderr_sha256=self.digest("seven-stderr-bytes"),
        )
        empty = observation.details["scope_empty_receipt"]
        self.assertEqual(
            empty["completion_disposition"],
            "forced_termination",
        )
        self.assertEqual(empty["stderr_bytes"], 7)

    def test_direct_wait_same_boot_restart_is_durable_attention(self) -> None:
        first = self.open_store()
        session = self.start_session(
            first,
            **self.start_kwargs(provider="direct_waitid_deny_fork"),
        )
        started = self.record_started(session)
        self.record_capture(
            session, started, origin="child_running"
        )
        self.record_clearance(session)
        session.close()
        first.close()

        restarted = self.open_store(
            epoch=self.digest("epoch-2")
        )
        recovered = restarted.load_incomplete_sessions()[0]
        status = recovered.recovery_status()
        self.assertEqual(status["action"], "operator_attention")
        self.assertNotIn("clearance_bundle", status)
        attention = self.observe(
            recovered,
            kind="forced_scope_empty",
            stderr_bytes=0,
            stderr_sha256=lifecycle.EMPTY_SHA256,
        )
        self.assertEqual(attention.state, "operator_attention")
        self.assertEqual(
            attention.details["reason_code"],
            supervisor.DIRECT_WAIT_RESTART_REASON,
        )
        self.assertIsNone(
            next(
                (
                    record
                    for record in recovered.records
                    if record.state == "provider_observation"
                ),
                None,
            )
        )

    def test_direct_wait_host_reboot_can_prove_reboot_clearance(self) -> None:
        first = self.open_store()
        session = self.start_session(
            first,
            **self.start_kwargs(provider="direct_waitid_deny_fork"),
        )
        started = self.record_started(session)
        self.record_capture(
            session, started, origin="child_running"
        )
        self.record_clearance(session)
        session.close()
        first.close()

        restarted = self.open_store(
            boot=self.digest("boot-2"),
            epoch=self.digest("epoch-2"),
        )
        recovered = restarted.load_incomplete_sessions()[0]
        observation = self.observe(
            recovered, kind="scope_absent"
        )
        self.assertEqual(observation.state, "provider_observation")
        self.assertEqual(
            observation.details["scope_empty_receipt"][
                "completion_disposition"
            ],
            "host_reboot",
        )

    def test_exit_claim_after_restart_routes_to_attention(self) -> None:
        first = self.open_store()
        session = self.start_session(first)
        started = self.record_started(session)
        self.record_capture(session, started)
        self.record_clearance(session)
        session.close()
        first.close()

        restarted = self.open_store(
            epoch=self.digest("epoch-2")
        )
        recovered = restarted.load_incomplete_sessions()[0]
        attention = self.observe(
            recovered,
            kind="clean_exit",
            stderr_bytes=0,
            stderr_sha256=lifecycle.EMPTY_SHA256,
        )
        self.assertEqual(attention.state, "operator_attention")
        self.assertEqual(
            attention.details["reason_code"],
            supervisor.EXIT_EPOCH_REASON,
        )

    def test_same_epoch_absence_cannot_masquerade_as_unobserved_exit(
        self,
    ) -> None:
        store = self.open_store()
        session = self.start_session(store)
        started = self.record_started(session)
        self.record_capture(
            session, started, origin="child_running"
        )
        self.record_clearance(session)
        attention = self.observe(session, kind="scope_absent")
        self.assertEqual(attention.state, "operator_attention")
        self.assertEqual(
            attention.details["reason_code"],
            supervisor.ABSENCE_EPOCH_REASON,
        )

    def test_scope_start_cannot_be_minted_after_epoch_or_boot_change(
        self,
    ) -> None:
        first = self.open_store()
        session = self.start_session(first)
        session.close()
        first.close()
        restarted = self.open_store(
            epoch=self.digest("epoch-2")
        )
        recovered = restarted.load_incomplete_sessions()[0]
        self.assert_code(
            "lifecycle_supervisor_start_epoch_changed",
            recovered.record_scope_started,
            provider_start_observation_sha256=self.digest(
                "provider-start"
            ),
            operation_id_sha256=self.digest("late-start"),
            recorded_at_unix=2,
        )

    def test_exact_retries_are_idempotent_after_later_states(self) -> None:
        store = self.open_store()
        kwargs = self.start_kwargs()
        session = store.start_session(**kwargs)
        self.assertIs(store.start_session(**kwargs), session)
        started = self.record_started(session)
        capture = self.record_capture(session, started)
        retried_started = self.record_started(session)
        retried_capture = self.record_capture(session, started)
        self.assertEqual(
            retried_started.record_sha256, started.record_sha256
        )
        self.assertEqual(
            retried_capture.record_sha256, capture.record_sha256
        )
        self.assertEqual(len(session.records), 3)

    def test_concurrent_exact_start_admission_returns_one_lease(
        self,
    ) -> None:
        store = self.open_store()
        kwargs = self.start_kwargs()
        first_inside_admission = threading.Event()
        release_first = threading.Event()
        second_invoked = threading.Event()
        second_done = threading.Event()
        results: list[supervisor.LifecycleSupervisorSession] = []
        failures: list[BaseException] = []

        def hold_first(phase: str) -> None:
            if phase == "after_session_mkdir":
                first_inside_admission.set()
                if not release_first.wait(2):
                    raise RuntimeError("test start admission timed out")

        def run_first() -> None:
            try:
                results.append(
                    store._start_session_for_test(
                        fault_hook=hold_first, **kwargs
                    )
                )
            except BaseException as exc:
                failures.append(exc)

        def run_second() -> None:
            second_invoked.set()
            try:
                results.append(store.start_session(**kwargs))
            except BaseException as exc:
                failures.append(exc)
            finally:
                second_done.set()

        first = threading.Thread(target=run_first)
        second = threading.Thread(target=run_second)
        first.start()
        self.assertTrue(first_inside_admission.wait(2))
        second.start()
        self.assertTrue(second_invoked.wait(2))
        self.assertFalse(second_done.wait(0.05))
        release_first.set()
        first.join(2)
        second.join(2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(results), 2)
        self.assertIs(results[0], results[1])
        self.assertEqual(len(results[0].records), 1)
        session_directories = [
            child
            for child in self.store_path.iterdir()
            if child.name.startswith("session-")
        ]
        self.assertEqual(len(session_directories), 1)
        self.assertEqual(
            len(list(session_directories[0].iterdir())), 1
        )

    def test_concurrent_incarnation_admission_cannot_split_session(
        self,
    ) -> None:
        store = self.open_store()
        first_kwargs = self.start_kwargs()
        competing_kwargs = self.start_kwargs(
            incarnation_marker="3", operation="competing-start"
        )
        first_inside_admission = threading.Event()
        release_first = threading.Event()
        competing_invoked = threading.Event()
        competing_done = threading.Event()
        results: list[supervisor.LifecycleSupervisorSession] = []
        failures: list[BaseException] = []

        def hold_first(phase: str) -> None:
            if phase == "after_session_mkdir":
                first_inside_admission.set()
                if not release_first.wait(2):
                    raise RuntimeError(
                        "test incarnation admission timed out"
                    )

        def run_first() -> None:
            try:
                results.append(
                    store._start_session_for_test(
                        fault_hook=hold_first, **first_kwargs
                    )
                )
            except BaseException as exc:
                failures.append(exc)

        def run_competing() -> None:
            competing_invoked.set()
            try:
                store.start_session(**competing_kwargs)
            except BaseException as exc:
                failures.append(exc)
            finally:
                competing_done.set()

        first = threading.Thread(target=run_first)
        competing = threading.Thread(target=run_competing)
        first.start()
        self.assertTrue(first_inside_admission.wait(2))
        competing.start()
        self.assertTrue(competing_invoked.wait(2))
        self.assertFalse(competing_done.wait(0.05))
        release_first.set()
        first.join(2)
        competing.join(2)

        self.assertFalse(first.is_alive())
        self.assertFalse(competing.is_alive())
        self.assertEqual(len(results), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(
            failures[0], supervisor.LifecycleSupervisorError
        )
        self.assertEqual(
            failures[0].code,
            "lifecycle_supervisor_session_incarnation_conflict",
        )
        self.assertEqual(
            len(
                [
                    child
                    for child in self.store_path.iterdir()
                    if child.name.startswith("session-")
                ]
            ),
            1,
        )

    def test_concurrent_exact_append_commits_one_revision(self) -> None:
        store = self.open_store()
        session = self.start_session(store)
        first_inside_append = threading.Event()
        release_first = threading.Event()
        second_invoked = threading.Event()
        second_done = threading.Event()
        results: list[supervisor.LifecycleSupervisorRecord] = []
        failures: list[BaseException] = []

        def hold_first(phase: str) -> None:
            if phase == "after_temp_open":
                first_inside_append.set()
                if not release_first.wait(2):
                    raise RuntimeError("test scope append timed out")

        def run_first() -> None:
            try:
                results.append(
                    session._record_scope_started_for_test(
                        provider_start_observation_sha256=self.digest(
                            "provider-start-observation"
                        ),
                        operation_id_sha256=self.digest(
                            "scope-started-operation"
                        ),
                        recorded_at_unix=2,
                        fault_hook=hold_first,
                    )
                )
            except BaseException as exc:
                failures.append(exc)

        def run_second() -> None:
            second_invoked.set()
            try:
                results.append(self.record_started(session))
            except BaseException as exc:
                failures.append(exc)
            finally:
                second_done.set()

        first = threading.Thread(target=run_first)
        second = threading.Thread(target=run_second)
        first.start()
        self.assertTrue(first_inside_append.wait(2))
        second.start()
        self.assertTrue(second_invoked.wait(2))
        self.assertFalse(second_done.wait(0.05))
        release_first.set()
        first.join(2)
        second.join(2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(
            results[0].record_sha256, results[1].record_sha256
        )
        self.assertEqual(
            [record.revision for record in session.records], [1, 2]
        )
        session_directory = next(
            child
            for child in self.store_path.iterdir()
            if child.name.startswith("session-")
        )
        self.assertEqual(len(list(session_directory.iterdir())), 2)

    def test_concurrent_divergent_append_cannot_fork_revision(
        self,
    ) -> None:
        store = self.open_store()
        session = self.start_session(store)
        first_inside_append = threading.Event()
        release_first = threading.Event()
        competing_invoked = threading.Event()
        competing_done = threading.Event()
        results: list[supervisor.LifecycleSupervisorRecord] = []
        failures: list[BaseException] = []

        def hold_first(phase: str) -> None:
            if phase == "after_temp_open":
                first_inside_append.set()
                if not release_first.wait(2):
                    raise RuntimeError(
                        "test divergent append timed out"
                    )

        def run_first() -> None:
            try:
                results.append(
                    session._record_scope_started_for_test(
                        provider_start_observation_sha256=self.digest(
                            "provider-start-observation"
                        ),
                        operation_id_sha256=self.digest(
                            "scope-started-operation"
                        ),
                        recorded_at_unix=2,
                        fault_hook=hold_first,
                    )
                )
            except BaseException as exc:
                failures.append(exc)

        def run_competing() -> None:
            competing_invoked.set()
            try:
                session.record_scope_started(
                    provider_start_observation_sha256=self.digest(
                        "competing-provider-start"
                    ),
                    operation_id_sha256=self.digest(
                        "competing-scope-started-operation"
                    ),
                    recorded_at_unix=2,
                )
            except BaseException as exc:
                failures.append(exc)
            finally:
                competing_done.set()

        first = threading.Thread(target=run_first)
        competing = threading.Thread(target=run_competing)
        first.start()
        self.assertTrue(first_inside_append.wait(2))
        competing.start()
        self.assertTrue(competing_invoked.wait(2))
        self.assertFalse(competing_done.wait(0.05))
        release_first.set()
        first.join(2)
        competing.join(2)

        self.assertFalse(first.is_alive())
        self.assertFalse(competing.is_alive())
        self.assertEqual(len(results), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(
            failures[0], supervisor.LifecycleSupervisorError
        )
        self.assertEqual(
            failures[0].code,
            "lifecycle_supervisor_transition_conflict",
        )
        self.assertEqual(
            [record.revision for record in session.records], [1, 2]
        )
        session_directory = next(
            child
            for child in self.store_path.iterdir()
            if child.name.startswith("session-")
        )
        self.assertEqual(len(list(session_directory.iterdir())), 2)

    def test_independent_scopes_do_not_share_the_append_lock(self) -> None:
        store = self.open_store()
        first_session = self.start_session(store)
        second_session = self.start_session(
            store,
            capture_session_id="3" * 64,
            scope_incarnation_id="4" * 64,
            operation_id_sha256=self.digest("second-start"),
        )
        first_inside_append = threading.Event()
        release_first = threading.Event()
        second_done = threading.Event()
        failures: list[BaseException] = []

        def hold_first(phase: str) -> None:
            if phase == "after_temp_open":
                first_inside_append.set()
                if not release_first.wait(2):
                    raise RuntimeError(
                        "test independent scope append timed out"
                    )

        def run_first() -> None:
            try:
                first_session._record_scope_started_for_test(
                    provider_start_observation_sha256=self.digest(
                        "provider-start-observation"
                    ),
                    operation_id_sha256=self.digest(
                        "scope-started-operation"
                    ),
                    recorded_at_unix=2,
                    fault_hook=hold_first,
                )
            except BaseException as exc:
                failures.append(exc)

        def run_second() -> None:
            try:
                self.record_started(
                    second_session,
                    operation="second-scope-started",
                )
            except BaseException as exc:
                failures.append(exc)
            finally:
                second_done.set()

        first = threading.Thread(target=run_first)
        second = threading.Thread(target=run_second)
        first.start()
        self.assertTrue(first_inside_append.wait(2))
        second.start()
        self.assertTrue(second_done.wait(2))
        release_first.set()
        first.join(2)
        second.join(2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(first_session.state, "scope_started")
        self.assertEqual(second_session.state, "scope_started")

    def test_recovery_head_waits_for_inflight_commit(self) -> None:
        store = self.open_store()
        session = self.start_session(store)
        committed_name = threading.Event()
        release_append = threading.Event()
        recovery_invoked = threading.Event()
        recovery_done = threading.Event()
        records: list[supervisor.LifecycleSupervisorRecord] = []
        statuses: list[dict] = []
        failures: list[BaseException] = []

        def hold_after_commit(phase: str) -> None:
            if phase == "after_noreplace_commit":
                committed_name.set()
                if not release_append.wait(2):
                    raise RuntimeError("test recovery proof timed out")

        def run_append() -> None:
            try:
                records.append(
                    session._record_scope_started_for_test(
                        provider_start_observation_sha256=self.digest(
                            "provider-start-observation"
                        ),
                        operation_id_sha256=self.digest(
                            "scope-started-operation"
                        ),
                        recorded_at_unix=2,
                        fault_hook=hold_after_commit,
                    )
                )
            except BaseException as exc:
                failures.append(exc)

        def run_recovery() -> None:
            recovery_invoked.set()
            try:
                statuses.append(session.recovery_status())
            except BaseException as exc:
                failures.append(exc)
            finally:
                recovery_done.set()

        append_thread = threading.Thread(target=run_append)
        recovery_thread = threading.Thread(target=run_recovery)
        append_thread.start()
        self.assertTrue(committed_name.wait(2))
        recovery_thread.start()
        self.assertTrue(recovery_invoked.wait(2))
        self.assertFalse(recovery_done.wait(0.05))
        release_append.set()
        append_thread.join(2)
        recovery_thread.join(2)

        self.assertFalse(append_thread.is_alive())
        self.assertFalse(recovery_thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(records), 1)
        self.assertEqual(len(statuses), 1)
        self.assertEqual(statuses[0]["state"], "scope_started")
        self.assertEqual(
            statuses[0]["ledger_head_sha256"],
            records[0].record_sha256,
        )

    def test_divergent_retry_and_incarnation_reuse_conflict(self) -> None:
        store = self.open_store()
        kwargs = self.start_kwargs()
        session = store.start_session(**kwargs)
        self.record_started(session)
        self.assert_code(
            "lifecycle_supervisor_idempotency_conflict",
            session.record_scope_started,
            provider_start_observation_sha256=self.digest(
                "different-observation"
            ),
            operation_id_sha256=self.digest(
                "scope-started-operation"
            ),
            recorded_at_unix=2,
        )
        conflicting = self.start_kwargs(incarnation_marker="3")
        self.assert_code(
            "lifecycle_supervisor_session_incarnation_conflict",
            store.start_session,
            **conflicting,
        )

    def test_incarnation_is_protocol_derived_and_never_regenerated(
        self,
    ) -> None:
        self.assertEqual(
            supervisor.SCOPE_INCARNATION_ID_CONTRACT,
            "protocol_derived_stable_digest",
        )
        first = self.open_store()
        kwargs = self.start_kwargs(incarnation_marker="a")
        session = first.start_session(**kwargs)
        exact_incarnation = session.scope_incarnation_id
        session.close()
        first.close()

        restarted = self.open_store()
        recovered = restarted.load_incomplete_sessions()[0]
        self.assertEqual(
            recovered.scope_incarnation_id, exact_incarnation
        )
        self.assertEqual(
            recovered.records[0].to_dict()["scope_incarnation_id"],
            exact_incarnation,
        )
        self.assertNotIn(
            "generate_scope_incarnation_id",
            dir(supervisor),
        )

    def test_replay_resumes_from_durable_provider_observation_only(
        self,
    ) -> None:
        first = self.open_store()
        session = self.start_session(first)
        started = self.record_started(session)
        self.record_capture(session, started)
        self.record_clearance(session)
        observation = self.observe(
            session,
            kind="clean_exit",
            stderr_bytes=0,
            stderr_sha256=lifecycle.EMPTY_SHA256,
        )
        observation_digest = observation.record_sha256
        session.close()
        first.close()

        restarted = self.open_store()
        recovered = restarted.load_incomplete_sessions()[0]
        status = recovered.recovery_status()
        self.assertEqual(status["action"], "settle_bundle")
        self.assertNotIn("clearance_bundle", status)
        settled = recovered.record_settled_bundle(
            expected_provider_observation_record_sha256=(
                observation_digest
            ),
            operation_id_sha256=self.digest("settle-operation"),
            recorded_at_unix=6,
        )
        self.assertEqual(settled.state, "settled_bundle")

    def test_lost_terminal_response_replays_through_exact_start(
        self,
    ) -> None:
        first = self.open_store()
        kwargs = self.start_kwargs()
        session = first.start_session(**kwargs)
        started = self.record_started(session)
        self.record_capture(session, started)
        self.record_clearance(session)
        observation = self.observe(
            session,
            kind="clean_exit",
            stderr_bytes=0,
            stderr_sha256=lifecycle.EMPTY_SHA256,
        )
        settled = self.settle(session, observation)
        terminal_digest = settled.record_sha256
        observation_digest = observation.record_sha256
        session.close()
        first.close()

        restarted = self.open_store()
        self.assertEqual(
            restarted.load_incomplete_sessions(), ()
        )
        replayed = restarted.start_session(**kwargs)
        self.assertEqual(replayed.state, "settled_bundle")
        self.assertEqual(
            replayed.recovery_status()["action"], "complete"
        )
        retried = replayed.record_settled_bundle(
            expected_provider_observation_record_sha256=(
                observation_digest
            ),
            operation_id_sha256=self.digest("settle-operation"),
            recorded_at_unix=999,
        )
        self.assertEqual(retried.record_sha256, terminal_digest)
        self.assertEqual(len(replayed.records), 6)

    def test_lost_start_response_recovers_late_started_receipt(
        self,
    ) -> None:
        """Outer launch intent may survive after start receipt is durable."""

        first = self.open_store()
        session = self.start_session(first)
        started = self.record_started(session)
        started_digest = started.details[
            "scope_started_receipt_sha256"
        ]
        session.close()
        first.close()

        restarted = self.open_store(
            epoch=self.digest("epoch-2")
        )
        recovered = restarted.load_incomplete_sessions()[0]
        start = recovered.records[0]
        clearance = recovered.record_clearance_intent(
            effect_origin_state="child_launch_intent",
            effect_origin_record_revision=start.details[
                "child_launch_intent_record_revision"
            ],
            effect_origin_record_sha256=start.details[
                "child_launch_intent_record_sha256"
            ],
            expected_scope_started_receipt_sha256=None,
            clearance_mode="terminate_and_clear",
            outer_clearance_intent_record_revision=5,
            outer_clearance_intent_record_sha256=self.digest(
                "lost-response-clearance"
            ),
            operation_id_sha256=self.digest(
                "lost-response-clearance-operation"
            ),
            recorded_at_unix=3,
        )
        self.assertIsNone(
            clearance.details["clearance_intent_receipt"][
                "scope_started_receipt_sha256"
            ]
        )
        observation = self.observe(
            recovered,
            kind="forced_scope_empty",
            stderr_bytes=0,
            stderr_sha256=lifecycle.EMPTY_SHA256,
            recorded_at=4,
        )
        settled = self.settle(
            recovered, observation, recorded_at=5
        )
        bundle = settled.details["clearance_bundle"]
        self.assertEqual(
            bundle["scope_started_receipt_sha256"], started_digest
        )
        self.assertEqual(
            bundle["scope_empty_receipt"][
                "scope_started_receipt_sha256"
            ],
            started_digest,
        )
        self.assertEqual(
            bundle["scope_empty_receipt"][
                "completion_disposition"
            ],
            "forced_termination",
        )

    def test_outer_record_revisions_are_strict_and_cross_bound(
        self,
    ) -> None:
        store = self.open_store()
        bad_start = self.start_kwargs()
        bad_start["child_launch_intent_record_revision"] = 0
        self.assert_code(
            "lifecycle_supervisor_child_launch_intent_"
            "record_revision_invalid",
            store.start_session,
            **bad_start,
        )

        session = self.start_session(store)
        started = self.record_started(session)
        self.assert_code(
            "lifecycle_supervisor_capture_start_binding_changed",
            session.record_capture_event,
            effect_origin_state="capture_ready",
            effect_origin_record_revision=4,
            effect_origin_record_sha256=self.digest(
                "capture_ready-outer-record"
            ),
            expected_scope_started_receipt_sha256=started.details[
                "scope_started_receipt_sha256"
            ],
            operation_id_sha256=self.digest("bad-capture-revision"),
            recorded_at_unix=3,
        )
        capture = self.record_capture(session, started)
        self.assert_code(
            "lifecycle_supervisor_effect_origin_expectation_mismatch",
            session.record_clearance_intent,
            effect_origin_state="capture_ready",
            effect_origin_record_revision=5,
            effect_origin_record_sha256=capture.details[
                "effect_origin_record_sha256"
            ],
            expected_scope_started_receipt_sha256=started.details[
                "scope_started_receipt_sha256"
            ],
            clearance_mode=(
                "wait_clean_then_terminate_on_deadline"
            ),
            outer_clearance_intent_record_revision=7,
            outer_clearance_intent_record_sha256=self.digest(
                "outer-clearance-intent"
            ),
            operation_id_sha256=self.digest("bad-origin-revision"),
            recorded_at_unix=4,
        )
        self.assert_code(
            "lifecycle_supervisor_clearance_revision_order_invalid",
            session.record_clearance_intent,
            effect_origin_state="capture_ready",
            effect_origin_record_revision=6,
            effect_origin_record_sha256=capture.details[
                "effect_origin_record_sha256"
            ],
            expected_scope_started_receipt_sha256=started.details[
                "scope_started_receipt_sha256"
            ],
            clearance_mode=(
                "wait_clean_then_terminate_on_deadline"
            ),
            outer_clearance_intent_record_revision=6,
            outer_clearance_intent_record_sha256=self.digest(
                "outer-clearance-intent"
            ),
            operation_id_sha256=self.digest(
                "bad-clearance-revision"
            ),
            recorded_at_unix=4,
        )

    def test_ready_wait_does_not_advance_ledger_before_outer_event(
        self,
    ) -> None:
        store = self.open_store()
        session = self.start_session(store)
        started = self.record_started(session)

        # The helper READY event is observed here, but it has no durable
        # outer-journal coordinate and therefore causes no ledger append.
        self.assertEqual(session.state, "scope_started")
        self.assertEqual(
            session.recovery_status()["action"], "request_clearance"
        )

        capture = self.record_capture(
            session, started, origin="capture_ready"
        )
        self.assertEqual(capture.state, "capture_event")
        clearance = self.record_clearance(session)
        self.assertEqual(clearance.state, "clearance_intent")

    def test_abnormal_pre_ready_binds_child_running_at_clearance(
        self,
    ) -> None:
        store = self.open_store()
        session = self.start_session(store)
        started = self.record_started(session)
        capture = self.record_capture(
            session, started, origin="child_running"
        )
        clearance = self.record_clearance(session)
        intent = clearance.details["clearance_intent_receipt"]
        self.assertEqual(
            capture.details["effect_origin_record_revision"], 5
        )
        self.assertEqual(intent["effect_origin_state"], "child_running")
        self.assertEqual(intent["clearance_mode"], "terminate_and_clear")

    def test_stale_fsynced_temp_is_removed_without_advancing_state(
        self,
    ) -> None:
        first = self.open_store()
        session = self.start_session(first)

        def crash(phase: str) -> None:
            if phase == "after_temp_metadata_fsync":
                raise SimulatedCrash(phase)

        with self.assertRaises(SimulatedCrash):
            session._record_scope_started_for_test(
                provider_start_observation_sha256=self.digest(
                    "provider-start-observation"
                ),
                operation_id_sha256=self.digest(
                    "scope-started-operation"
                ),
                recorded_at_unix=2,
                fault_hook=crash,
            )
        session_dir = next(
            child
            for child in self.store_path.iterdir()
            if child.name.startswith("session-")
        )
        self.assertTrue(
            any(child.name.startswith(".tmp-") for child in session_dir.iterdir())
        )
        session.close()
        first.close()

        restarted = self.open_store()
        recovered = restarted.load_incomplete_sessions()[0]
        self.assertEqual(recovered.state, "start_intent")
        self.assertFalse(
            any(child.name.startswith(".tmp-") for child in session_dir.iterdir())
        )

    def test_retry_after_noreplace_commit_recovers_exact_record(
        self,
    ) -> None:
        first = self.open_store()
        session = self.start_session(first)

        def crash(phase: str) -> None:
            if phase == "after_noreplace_commit":
                raise SimulatedCrash(phase)

        with self.assertRaises(SimulatedCrash):
            session._record_scope_started_for_test(
                provider_start_observation_sha256=self.digest(
                    "provider-start-observation"
                ),
                operation_id_sha256=self.digest(
                    "scope-started-operation"
                ),
                recorded_at_unix=2,
                fault_hook=crash,
            )
        self.assertEqual(session.state, "start_intent")
        session.close()
        first.close()

        restarted = self.open_store()
        recovered = restarted.load_incomplete_sessions()[0]
        self.assertEqual(recovered.state, "scope_started")
        count = len(recovered.records)
        retry = self.record_started(recovered)
        self.assertEqual(retry.state, "scope_started")
        self.assertEqual(len(recovered.records), count)

    def test_duplicate_key_record_is_rejected_as_operator_attention(
        self,
    ) -> None:
        first = self.open_store()
        session = self.start_session(first)
        session_dir = next(
            child
            for child in self.store_path.iterdir()
            if child.name.startswith("session-")
        )
        record_path = next(session_dir.iterdir())
        raw = record_path.read_bytes()
        record_path.chmod(0o600)
        record_path.write_bytes(b'{"revision":1,' + raw[1:])
        record_path.chmod(0o400)
        session.close()
        first.close()

        with self.assertRaises(
            supervisor.LifecycleSupervisorError
        ) as caught:
            self.open_store()
        self.assertEqual(
            caught.exception.code,
            "lifecycle_supervisor_record_encoding_invalid",
        )
        self.assertTrue(caught.exception.operator_attention)

    def test_store_permissions_symlinks_and_exclusive_lock_fail_closed(
        self,
    ) -> None:
        first = self.open_store()
        self.assert_code(
            "lifecycle_supervisor_store_busy",
            supervisor._open_lifecycle_supervisor_store_for_test,
            self.store_path,
            instance_slug=self.instance_slug,
            instance_control_sha256=self.instance_control,
            host_boot_id_sha256=self.boot,
            supervisor_epoch_id=self.epoch,
        )
        first.close()

        self.store_path.chmod(0o770)
        self.assert_code(
            "lifecycle_supervisor_store_unsafe",
            supervisor._open_lifecycle_supervisor_store_for_test,
            self.store_path,
            instance_slug=self.instance_slug,
            instance_control_sha256=self.instance_control,
            host_boot_id_sha256=self.boot,
            supervisor_epoch_id=self.epoch,
        )
        self.store_path.chmod(0o700)

        lock = self.store_path / ".lock"
        lock.unlink()
        target = self.root / "not-lock"
        target.touch(mode=0o600)
        lock.symlink_to(target)
        self.assert_code(
            "lifecycle_supervisor_lock_file_unreadable",
            supervisor._open_lifecycle_supervisor_store_for_test,
            self.store_path,
            instance_slug=self.instance_slug,
            instance_control_sha256=self.instance_control,
            host_boot_id_sha256=self.boot,
            supervisor_epoch_id=self.epoch,
        )

    def test_provider_input_rejects_authority_fields_and_bad_stderr(
        self,
    ) -> None:
        base = {
            "observation_kind": "scope_absent",
            "provider_observation_sha256": self.digest("observation"),
            "observed_supervisor_epoch_id": self.epoch,
            "observed_host_boot_id_sha256": self.boot,
            "stderr_bytes": None,
            "stderr_sha256": None,
        }
        self.assert_code(
            "lifecycle_supervisor_forbidden_authority_field",
            supervisor._normalize_observation,
            {**base, "pid": 123},
        )
        base["stderr_bytes"] = 1
        base["stderr_sha256"] = self.digest("stderr")
        self.assert_code(
            "lifecycle_supervisor_observation_stderr_invalid",
            supervisor._normalize_observation,
            base,
        )

    def test_replay_rejects_operation_domain_binding_mutation(
        self,
    ) -> None:
        store = self.open_store()
        session = self.start_session(store)
        value = session.records[0].to_dict()
        value["operation_id_sha256"] = self.digest(
            "not-the-domain-bound-operation"
        )
        self.assert_code(
            "lifecycle_supervisor_operation_domain_binding_invalid",
            supervisor.LifecycleSupervisorRecord,
            value,
        )

    def test_session_api_has_no_process_or_filesystem_authority(
        self,
    ) -> None:
        forbidden = {"path", "pid", "pgid", "signal", "argv", "command"}
        for name in (
            "record_scope_started",
            "record_capture_event",
            "record_clearance_intent",
            "record_provider_observation",
            "record_settled_bundle",
            "recovery_status",
        ):
            parameters = set(
                inspect.signature(
                    getattr(
                        supervisor.LifecycleSupervisorSession, name
                    )
                ).parameters
            )
            self.assertFalse(parameters & forbidden, (name, parameters))
        self.assertFalse(supervisor.PRODUCTION_ACTIVATION)

    def test_scope_and_record_objects_are_not_caller_constructible(
        self,
    ) -> None:
        store = self.open_store()
        session = self.start_session(store)
        started = self.record_started(session)
        self.assert_code(
            "lifecycle_supervisor_scope_started_expectation_mismatch",
            session.record_capture_event,
            effect_origin_state="capture_ready",
            effect_origin_record_revision=6,
            effect_origin_record_sha256=self.digest("capture"),
            expected_scope_started_receipt_sha256=self.digest("wrong"),
            operation_id_sha256=self.digest("capture-op"),
            recorded_at_unix=2,
        )
        with self.assertRaises(TypeError):
            supervisor.LifecycleSupervisorSession(
                _token=object(),
                store=store,
                directory_fd=-1,
                directory_name="no",
                records=(),
                session_id="1" * 64,
                incarnation_id="2" * 64,
            )

    def test_public_open_requires_root_identity(self) -> None:
        with mock.patch.object(os, "geteuid", return_value=501):
            self.assert_code(
                "lifecycle_supervisor_requires_root",
                supervisor.open_lifecycle_supervisor_store,
                self.store_path,
                instance_slug=self.instance_slug,
                instance_control_sha256=self.instance_control,
                host_boot_id_sha256=self.boot,
                supervisor_epoch_id=self.epoch,
            )

    def test_store_rejects_history_for_another_instance_or_control(
        self,
    ) -> None:
        first = self.open_store()
        session = self.start_session(first)
        session.close()
        first.close()

        with self.assertRaises(
            supervisor.LifecycleSupervisorError
        ) as wrong_instance:
            supervisor._open_lifecycle_supervisor_store_for_test(
                self.store_path,
                instance_slug="somebody-else",
                instance_control_sha256=self.instance_control,
                host_boot_id_sha256=self.boot,
                supervisor_epoch_id=self.epoch,
            )
        self.assertEqual(
            wrong_instance.exception.code,
            "lifecycle_supervisor_instance_control_mismatch",
        )
        self.assertTrue(wrong_instance.exception.operator_attention)

        with self.assertRaises(
            supervisor.LifecycleSupervisorError
        ) as wrong_control:
            supervisor._open_lifecycle_supervisor_store_for_test(
                self.store_path,
                instance_slug=self.instance_slug,
                instance_control_sha256=self.digest("other-control"),
                host_boot_id_sha256=self.boot,
                supervisor_epoch_id=self.epoch,
            )
        self.assertEqual(
            wrong_control.exception.code,
            "lifecycle_supervisor_instance_control_mismatch",
        )

    def test_terminal_retirement_remains_an_explicit_blocker(
        self,
    ) -> None:
        self.assertFalse(supervisor.PRODUCTION_ACTIVATION)
        self.assertIn(
            "lifecycle_terminal_retirement_authority_missing",
            supervisor.PRODUCTION_BLOCKERS,
        )
        self.assertNotIn(
            "retire_terminal_session",
            dir(supervisor.LifecycleSupervisorStore),
        )

    def test_empty_crash_directory_is_reaped_before_replay(self) -> None:
        empty = self.store_path / (
            f"session-{'3' * 64}-{'4' * 64}"
        )
        empty.mkdir(mode=0o700)
        empty.chmod(0o700)
        store = self.open_store()
        self.assertFalse(empty.exists())
        self.assertEqual(store.load_incomplete_sessions(), ())

    def test_noncanonical_record_is_rejected(self) -> None:
        first = self.open_store()
        session = self.start_session(first)
        session_dir = next(
            child
            for child in self.store_path.iterdir()
            if child.name.startswith("session-")
        )
        record_path = next(session_dir.iterdir())
        value = json.loads(record_path.read_text("ascii"))
        record_path.chmod(0o600)
        record_path.write_text(
            json.dumps(value, indent=1, sort_keys=True) + "\n",
            encoding="ascii",
        )
        record_path.chmod(0o400)
        session.close()
        first.close()
        with self.assertRaises(
            supervisor.LifecycleSupervisorError
        ) as caught:
            self.open_store()
        self.assertTrue(caught.exception.operator_attention)


if __name__ == "__main__":
    unittest.main()
