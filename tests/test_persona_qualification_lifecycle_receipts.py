from __future__ import annotations

import copy
import hashlib
import pickle
import sys
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (
    john_lomein_persona_qualification_lifecycle_receipts as lifecycle,
)


class LifecycleReceiptFixture:
    @staticmethod
    def digest(label: str) -> str:
        return hashlib.sha256(label.encode("ascii")).hexdigest()

    def __init__(
        self,
        *,
        system: str = "Linux",
        provider: str = "linux_cgroup_v2",
        origin: str = "capture_ready",
        disposition: str = "clean_exit",
        clearance_mode: str | None = None,
    ) -> None:
        self.session_id = self.digest("capture-session")
        self.scope_id = (
            f"jlq-{lifecycle.LIFECYCLE_BACKEND}-{self.session_id}"
        )
        self.incarnation = self.digest("scope-incarnation")
        self.start_epoch = self.digest("start-supervisor-epoch")
        self.clearance_epoch = (
            self.start_epoch
            if (
                disposition in {"clean_exit", "abnormal_exit"}
                or (
                    provider == "direct_waitid_deny_fork"
                    and disposition != "host_reboot"
                )
            )
            else self.digest("clearance-supervisor-epoch")
        )
        self.start_boot = self.digest("start-host-boot")
        self.clearance_boot = (
            self.digest("clearance-host-boot")
            if disposition
            in {"host_reboot", "never_started_after_reboot"}
            else self.start_boot
        )
        self.staging_intent = self.digest("staging-intent")
        self.staging_exposure = self.digest("staging-exposure")
        self.launch_intent = self.digest("child-launch-intent")
        self.origin_record = (
            self.launch_intent
            if origin == "child_launch_intent"
            else self.digest(f"{origin}-record")
        )
        self.handoff_policy = self.digest("handoff-policy")
        self.helper_policy = self.digest("helper-policy")
        self.outer_clearance = self.digest("outer-clearance-intent")

        boot_measurement = {
            "Linux": "linux_boot_id",
            "Darwin": "darwin_boot_session_uuid",
        }[system]
        self.activation = {
            "schema_version": lifecycle.ACTIVATION_RECEIPT_SCHEMA,
            "status": lifecycle.ACTIVATION_STATUS,
            "system": system,
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": provider,
            "supervisor_policy_sha256": self.digest(
                "supervisor-policy"
            ),
            "supervisor_bundle_sha256": self.digest(
                "supervisor-bundle"
            ),
            "helper_activation_policy_sha256": self.helper_policy,
            "lifecycle_canary_sha256": self.digest(
                "lifecycle-canary"
            ),
            "host_boot_measurement": boot_measurement,
            "host_boot_id_sha256": self.start_boot,
            "assertions": {
                name: True
                for name in lifecycle.ACTIVATION_ASSERTIONS
            },
            "production_activation": False,
        }
        activation_digest = lifecycle.activation_receipt_sha256(
            self.activation
        )
        self.started = {
            "schema_version": lifecycle.SCOPE_STARTED_RECEIPT_SCHEMA,
            "status": lifecycle.SCOPE_STARTED_STATUS,
            "capture_session_id": self.session_id,
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": provider,
            "lifecycle_scope_id": self.scope_id,
            "scope_incarnation_id": self.incarnation,
            "supervisor_epoch_id": self.start_epoch,
            "host_boot_id_sha256": self.start_boot,
            "staging_transaction_intent_sha256": self.staging_intent,
            "staging_exposure_receipt_sha256": self.staging_exposure,
            "child_launch_intent_record_sha256": self.launch_intent,
            "handoff_policy_sha256": self.handoff_policy,
            "helper_activation_policy_sha256": self.helper_policy,
            "capture_uid": 4201,
            "export_gid": 4202,
            "lifecycle_activation_receipt_sha256": activation_digest,
        }
        started_digest = lifecycle.scope_started_receipt_sha256(
            self.started
        )
        no_start = disposition in {
            "never_started",
            "never_started_after_reboot",
        }
        if clearance_mode is None:
            clearance_mode = (
                "wait_clean_then_terminate_on_deadline"
                if origin == "capture_ready"
                else "terminate_and_clear"
            )
        self.intent = {
            "schema_version": (
                lifecycle.CLEARANCE_INTENT_RECEIPT_SCHEMA
            ),
            "status": lifecycle.CLEARANCE_INTENT_STATUS,
            "capture_session_id": self.session_id,
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": provider,
            "lifecycle_scope_id": self.scope_id,
            "scope_incarnation_id": self.incarnation,
            "lifecycle_activation_receipt_sha256": activation_digest,
            "child_launch_intent_record_sha256": self.launch_intent,
            "effect_origin_state": origin,
            "effect_origin_record_sha256": self.origin_record,
            "scope_started_receipt_sha256": (
                None
                if origin == "child_launch_intent"
                else started_digest
            ),
            "clearance_mode": clearance_mode,
            "outer_clearance_intent_record_sha256": (
                self.outer_clearance
            ),
        }
        intent_digest = lifecycle.clearance_intent_receipt_sha256(
            self.intent
        )
        basis = {
            "never_started": "supervisor_ledger_no_effect",
            "never_started_after_reboot": "host_boot_epoch_changed",
            "host_reboot": "host_boot_epoch_changed",
        }.get(
            disposition,
            {
                "linux_cgroup_v2": (
                    "linux_cgroup_kill_populated_zero"
                ),
                "systemd_transient_scope": (
                    "systemd_control_group_empty"
                ),
                "darwin_launchd_job": (
                    "launchd_job_absent_fork_denied"
                ),
                "direct_waitid_deny_fork": (
                    "direct_waitid_pinned_single_process"
                ),
            }[provider],
        )
        process_observed = disposition in {
            "clean_exit",
            "abnormal_exit",
            "forced_termination",
        }
        stderr_bytes = 0 if process_observed else None
        stderr_digest = (
            lifecycle.EMPTY_SHA256 if process_observed else None
        )
        adoption_eligible = (
            disposition == "clean_exit" and origin == "capture_ready"
        )
        self.empty = {
            "schema_version": lifecycle.SCOPE_EMPTY_RECEIPT_SCHEMA,
            "status": lifecycle.SCOPE_EMPTY_STATUS,
            "capture_session_id": self.session_id,
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": provider,
            "lifecycle_scope_id": self.scope_id,
            "scope_incarnation_id": self.incarnation,
            "lifecycle_activation_receipt_sha256": activation_digest,
            "child_launch_intent_record_sha256": self.launch_intent,
            "effect_origin_state": origin,
            "effect_origin_record_sha256": self.origin_record,
            "scope_started_receipt_sha256": (
                None if no_start else started_digest
            ),
            "clearance_intent_receipt_sha256": intent_digest,
            "outer_clearance_intent_record_sha256": (
                self.outer_clearance
            ),
            "clearance_mode": clearance_mode,
            "start_supervisor_epoch_id": (
                None if no_start else self.start_epoch
            ),
            "clearance_supervisor_epoch_id": self.clearance_epoch,
            "start_host_boot_id_sha256": (
                None if no_start else self.start_boot
            ),
            "clearance_host_boot_id_sha256": self.clearance_boot,
            "clearance_basis": basis,
            "completion_disposition": disposition,
            "stderr_bytes": stderr_bytes,
            "stderr_sha256": stderr_digest,
            "adoption_eligible": adoption_eligible,
        }
        self.bundle = self.rebuild_bundle(
            include_start=not no_start
        )

    def rebuild_bundle(
        self,
        *,
        include_start: bool = True,
    ) -> dict[str, Any]:
        return {
            "schema_version": lifecycle.CLEARANCE_BUNDLE_SCHEMA,
            "status": lifecycle.CLEARANCE_BUNDLE_STATUS,
            "activation_receipt": copy.deepcopy(self.activation),
            "activation_receipt_sha256": (
                lifecycle.activation_receipt_sha256(self.activation)
            ),
            "scope_started_receipt": (
                copy.deepcopy(self.started) if include_start else None
            ),
            "scope_started_receipt_sha256": (
                lifecycle.scope_started_receipt_sha256(self.started)
                if include_start
                else None
            ),
            "clearance_intent_receipt": copy.deepcopy(self.intent),
            "clearance_intent_receipt_sha256": (
                lifecycle.clearance_intent_receipt_sha256(self.intent)
            ),
            "scope_empty_receipt": copy.deepcopy(self.empty),
            "scope_empty_receipt_sha256": (
                lifecycle.scope_empty_receipt_sha256(self.empty)
            ),
        }


class LifecycleReceiptTest(unittest.TestCase):
    def assert_code(
        self,
        code: str,
        function: Any,
        value: Mapping[str, Any],
    ) -> None:
        with self.assertRaises(lifecycle.LifecycleReceiptError) as raised:
            function(value)
        self.assertEqual(raised.exception.code, code)

    def test_clean_linux_bundle_is_canonical_and_hash_stable(self) -> None:
        fixture = LifecycleReceiptFixture()
        normalized = lifecycle.normalize_clearance_bundle(fixture.bundle)
        self.assertEqual(normalized, fixture.bundle)
        self.assertTrue(
            normalized["scope_empty_receipt"]["adoption_eligible"]
        )
        self.assertEqual(
            lifecycle.clearance_bundle_sha256(fixture.bundle),
            lifecycle.clearance_bundle_sha256(normalized),
        )

    def test_all_provider_and_normal_basis_pairs(self) -> None:
        cases = (
            ("Linux", "linux_cgroup_v2"),
            ("Linux", "systemd_transient_scope"),
            ("Linux", "direct_waitid_deny_fork"),
            ("Darwin", "darwin_launchd_job"),
            ("Darwin", "direct_waitid_deny_fork"),
        )
        for system, provider in cases:
            with self.subTest(system=system, provider=provider):
                fixture = LifecycleReceiptFixture(
                    system=system,
                    provider=provider,
                )
                lifecycle.normalize_clearance_bundle(fixture.bundle)

    def test_all_dispositions_are_strict_and_path_free(self) -> None:
        cases = (
            ("never_started", "child_launch_intent"),
            (
                "never_started_after_reboot",
                "child_launch_intent",
            ),
            ("clean_exit", "capture_ready"),
            ("abnormal_exit", "child_running"),
            ("forced_termination", "child_launch_intent"),
            ("exit_unobserved_after_restart", "child_running"),
            ("host_reboot", "capture_ready"),
        )
        for disposition, origin in cases:
            with self.subTest(disposition=disposition, origin=origin):
                fixture = LifecycleReceiptFixture(
                    disposition=disposition,
                    origin=origin,
                )
                normalized = lifecycle.normalize_clearance_bundle(
                    fixture.bundle
                )
                empty = normalized["scope_empty_receipt"]
                self.assertEqual(
                    empty["completion_disposition"], disposition
                )
                self.assertEqual(
                    empty["adoption_eligible"],
                    disposition == "clean_exit"
                    and origin == "capture_ready",
                )

    def test_activation_rejects_incomplete_claims_and_wrong_provider(
        self,
    ) -> None:
        fixture = LifecycleReceiptFixture()
        mutations: tuple[tuple[str, Any], ...] = (
            (
                "lifecycle_activation_assertion_not_proven",
                lambda value: value["assertions"].__setitem__(
                    "fork_denied", False
                ),
            ),
            (
                "lifecycle_activation_assertions_invalid",
                lambda value: value["assertions"].pop(
                    "wrapper_scope_contained"
                ),
            ),
            (
                "lifecycle_activation_must_remain_disabled",
                lambda value: value.__setitem__(
                    "production_activation", True
                ),
            ),
            (
                "lifecycle_activation_provider_system_mismatch",
                lambda value: value.__setitem__(
                    "lifecycle_provider", "darwin_launchd_job"
                ),
            ),
            (
                "lifecycle_activation_boot_measurement_mismatch",
                lambda value: value.__setitem__(
                    "host_boot_measurement",
                    "darwin_boot_session_uuid",
                ),
            ),
        )
        for expected, mutate in mutations:
            with self.subTest(expected=expected):
                candidate = copy.deepcopy(fixture.activation)
                mutate(candidate)
                self.assert_code(
                    expected,
                    lifecycle.normalize_activation_receipt,
                    candidate,
                )

    def test_every_receipt_rejects_pid_pgid_path_and_key_fields(
        self,
    ) -> None:
        fixture = LifecycleReceiptFixture()
        cases = (
            (
                lifecycle.normalize_activation_receipt,
                fixture.activation,
            ),
            (
                lifecycle.normalize_scope_started_receipt,
                fixture.started,
            ),
            (
                lifecycle.normalize_clearance_intent_receipt,
                fixture.intent,
            ),
            (
                lifecycle.normalize_scope_empty_receipt,
                fixture.empty,
            ),
            (
                lifecycle.normalize_clearance_bundle,
                fixture.bundle,
            ),
        )
        for function, valid in cases:
            for forbidden in (
                "child_pid",
                "leader_pgid",
                "cgroup_path",
                "signing_key_sha256",
            ):
                with self.subTest(
                    function=function.__name__, forbidden=forbidden
                ):
                    candidate = copy.deepcopy(valid)
                    candidate[forbidden] = fixture.digest(forbidden)
                    self.assert_code(
                        "lifecycle_receipt_forbidden_field",
                        function,
                        candidate,
                    )

    def test_scope_start_rejects_unsafe_identity_and_scope_binding(
        self,
    ) -> None:
        fixture = LifecycleReceiptFixture()
        mutations = (
            (
                "lifecycle_receipt_scope_id_invalid",
                "lifecycle_scope_id",
                "jlq-root_supervisor-" + fixture.digest("other"),
            ),
            (
                "lifecycle_scope_incarnation_id_invalid",
                "scope_incarnation_id",
                "bad",
            ),
            ("lifecycle_capture_uid_invalid", "capture_uid", True),
            ("lifecycle_export_gid_invalid", "export_gid", 0),
            (
                "lifecycle_child_launch_intent_record_sha256_invalid",
                "child_launch_intent_record_sha256",
                "bad",
            ),
        )
        for expected, field, replacement in mutations:
            with self.subTest(field=field):
                candidate = copy.deepcopy(fixture.started)
                candidate[field] = replacement
                self.assert_code(
                    expected,
                    lifecycle.normalize_scope_started_receipt,
                    candidate,
                )

    def test_clearance_intent_requires_start_after_launch_state(
        self,
    ) -> None:
        fixture = LifecycleReceiptFixture()
        candidate = copy.deepcopy(fixture.intent)
        candidate["scope_started_receipt_sha256"] = None
        self.assert_code(
            "lifecycle_clearance_intent_start_missing",
            lifecycle.normalize_clearance_intent_receipt,
            candidate,
        )

        candidate = copy.deepcopy(fixture.intent)
        candidate["effect_origin_state"] = "child_running"
        candidate["clearance_mode"] = (
            "wait_clean_then_terminate_on_deadline"
        )
        self.assert_code(
            "lifecycle_clearance_mode_origin_mismatch",
            lifecycle.normalize_clearance_intent_receipt,
            candidate,
        )

        never = LifecycleReceiptFixture(
            disposition="never_started",
            origin="child_launch_intent",
        )
        recovered_start = LifecycleReceiptFixture(
            disposition="forced_termination",
            origin="child_launch_intent",
        )
        candidate = copy.deepcopy(recovered_start.intent)
        candidate["scope_started_receipt_sha256"] = (
            lifecycle.scope_started_receipt_sha256(
                recovered_start.started
            )
        )
        self.assert_code(
            "lifecycle_clearance_recovered_start_must_be_deferred",
            lifecycle.normalize_clearance_intent_receipt,
            candidate,
        )

        candidate = copy.deepcopy(never.intent)
        candidate["effect_origin_record_sha256"] = never.digest(
            "not-launch"
        )
        self.assert_code(
            "lifecycle_clearance_origin_record_mismatch",
            lifecycle.normalize_clearance_intent_receipt,
            candidate,
        )

    def test_provider_basis_pairing_is_exact(self) -> None:
        fixture = LifecycleReceiptFixture()
        for invalid_basis in (
            "systemd_control_group_empty",
            "launchd_job_absent_fork_denied",
            "direct_waitid_pinned_single_process",
            "supervisor_ledger_no_effect",
            "host_boot_epoch_changed",
        ):
            with self.subTest(invalid_basis=invalid_basis):
                candidate = copy.deepcopy(fixture.empty)
                candidate["clearance_basis"] = invalid_basis
                self.assert_code(
                    "lifecycle_normal_clearance_structure_invalid",
                    lifecycle.normalize_scope_empty_receipt,
                    candidate,
                )

    def test_never_started_structure_is_exact(self) -> None:
        fixture = LifecycleReceiptFixture(
            disposition="never_started",
            origin="child_launch_intent",
        )
        valid = fixture.empty
        lifecycle.normalize_scope_empty_receipt(valid)
        mutations = (
            ("scope_started_receipt_sha256", fixture.digest("start")),
            ("start_supervisor_epoch_id", fixture.digest("epoch")),
            ("start_host_boot_id_sha256", fixture.digest("boot")),
            ("effect_origin_state", "capture_ready"),
            ("clearance_basis", "linux_cgroup_kill_populated_zero"),
        )
        for field, replacement in mutations:
            with self.subTest(field=field):
                candidate = copy.deepcopy(valid)
                candidate[field] = replacement
                self.assert_code(
                    "lifecycle_never_started_structure_invalid",
                    lifecycle.normalize_scope_empty_receipt,
                    candidate,
                )

    def test_reboot_requires_changed_boot_and_never_allows_adoption(
        self,
    ) -> None:
        fixture = LifecycleReceiptFixture(
            disposition="host_reboot",
            origin="capture_ready",
        )
        lifecycle.normalize_scope_empty_receipt(fixture.empty)
        candidate = copy.deepcopy(fixture.empty)
        candidate["clearance_host_boot_id_sha256"] = fixture.start_boot
        self.assert_code(
            "lifecycle_reboot_structure_invalid",
            lifecycle.normalize_scope_empty_receipt,
            candidate,
        )
        candidate = copy.deepcopy(fixture.empty)
        candidate["adoption_eligible"] = True
        self.assert_code(
            "lifecycle_adoption_eligibility_invalid",
            lifecycle.normalize_scope_empty_receipt,
            candidate,
        )
        candidate = copy.deepcopy(fixture.empty)
        candidate["clearance_supervisor_epoch_id"] = (
            fixture.start_epoch
        )
        self.assert_code(
            "lifecycle_reboot_structure_invalid",
            lifecycle.normalize_scope_empty_receipt,
            candidate,
        )

    def test_direct_wait_cannot_cross_supervisor_epoch(self) -> None:
        fixture = LifecycleReceiptFixture(
            provider="direct_waitid_deny_fork"
        )
        candidate = copy.deepcopy(fixture.empty)
        candidate["clearance_supervisor_epoch_id"] = fixture.digest(
            "new-supervisor"
        )
        self.assert_code(
            "lifecycle_direct_wait_epoch_changed",
            lifecycle.normalize_scope_empty_receipt,
            candidate,
        )

    def test_clearance_mode_is_bound_to_adoption_eligibility(
        self,
    ) -> None:
        fixture = LifecycleReceiptFixture()
        candidate = copy.deepcopy(fixture.empty)
        candidate["clearance_mode"] = "terminate_and_clear"
        self.assert_code(
            "lifecycle_adoption_eligibility_invalid",
            lifecycle.normalize_scope_empty_receipt,
            candidate,
        )

        candidate = copy.deepcopy(fixture.bundle)
        intent = candidate["clearance_intent_receipt"]
        intent["clearance_mode"] = "terminate_and_clear"
        intent_digest = lifecycle.clearance_intent_receipt_sha256(
            intent
        )
        candidate["clearance_intent_receipt_sha256"] = intent_digest
        empty = candidate["scope_empty_receipt"]
        empty["clearance_intent_receipt_sha256"] = intent_digest
        candidate["scope_empty_receipt_sha256"] = (
            lifecycle.scope_empty_receipt_sha256(empty)
        )
        self.assert_code(
            "lifecycle_bundle_clearance_binding_changed",
            lifecycle.normalize_clearance_bundle,
            candidate,
        )

    def test_exit_status_requires_continuous_observer_epoch(
        self,
    ) -> None:
        for disposition in ("clean_exit", "abnormal_exit"):
            with self.subTest(disposition=disposition):
                fixture = LifecycleReceiptFixture(
                    disposition=disposition,
                    origin="capture_ready",
                )
                candidate = copy.deepcopy(fixture.empty)
                candidate["clearance_supervisor_epoch_id"] = (
                    fixture.digest("replacement-clearance-epoch")
                )
                self.assert_code(
                    "lifecycle_exit_observer_epoch_changed",
                    lifecycle.normalize_scope_empty_receipt,
                    candidate,
                )

        unobserved = LifecycleReceiptFixture(
            disposition="exit_unobserved_after_restart",
            origin="child_running",
        )
        lifecycle.normalize_clearance_bundle(unobserved.bundle)
        candidate = copy.deepcopy(unobserved.empty)
        candidate["clearance_supervisor_epoch_id"] = (
            unobserved.start_epoch
        )
        self.assert_code(
            "lifecycle_unobserved_exit_structure_invalid",
            lifecycle.normalize_scope_empty_receipt,
            candidate,
        )

    def test_activation_boot_is_bound_to_execution_epoch(self) -> None:
        def rebind_activation_boot(
            bundle: dict[str, Any],
            boot_digest: str,
        ) -> None:
            activation = bundle["activation_receipt"]
            activation["host_boot_id_sha256"] = boot_digest
            activation_digest = lifecycle.activation_receipt_sha256(
                activation
            )
            bundle["activation_receipt_sha256"] = activation_digest
            started = bundle["scope_started_receipt"]
            assert started is not None
            started["lifecycle_activation_receipt_sha256"] = (
                activation_digest
            )
            started_digest = lifecycle.scope_started_receipt_sha256(
                started
            )
            bundle["scope_started_receipt_sha256"] = started_digest
            intent = bundle["clearance_intent_receipt"]
            intent["lifecycle_activation_receipt_sha256"] = (
                activation_digest
            )
            intent["scope_started_receipt_sha256"] = started_digest
            intent_digest = lifecycle.clearance_intent_receipt_sha256(
                intent
            )
            bundle["clearance_intent_receipt_sha256"] = intent_digest
            empty = bundle["scope_empty_receipt"]
            empty["lifecycle_activation_receipt_sha256"] = (
                activation_digest
            )
            empty["scope_started_receipt_sha256"] = started_digest
            empty["clearance_intent_receipt_sha256"] = intent_digest
            bundle["scope_empty_receipt_sha256"] = (
                lifecycle.scope_empty_receipt_sha256(empty)
            )

        for disposition in ("clean_exit", "host_reboot"):
            with self.subTest(disposition=disposition):
                fixture = LifecycleReceiptFixture(
                    disposition=disposition,
                    origin="capture_ready",
                )
                candidate = copy.deepcopy(fixture.bundle)
                replacement_boot = (
                    fixture.clearance_boot
                    if disposition == "host_reboot"
                    else fixture.digest("stale-activation-boot")
                )
                rebind_activation_boot(candidate, replacement_boot)
                self.assert_code(
                    (
                        "lifecycle_bundle_"
                        "activation_boot_binding_changed"
                    ),
                    lifecycle.normalize_clearance_bundle,
                    candidate,
                )

        no_effect = LifecycleReceiptFixture(
            disposition="never_started_after_reboot",
            origin="child_launch_intent",
        )
        lifecycle.normalize_clearance_bundle(no_effect.bundle)
        candidate = copy.deepcopy(no_effect.bundle)
        empty = candidate["scope_empty_receipt"]
        empty["clearance_host_boot_id_sha256"] = (
            no_effect.start_boot
        )
        candidate["scope_empty_receipt_sha256"] = (
            lifecycle.scope_empty_receipt_sha256(empty)
        )
        self.assert_code(
            "lifecycle_bundle_activation_boot_binding_changed",
            lifecycle.normalize_clearance_bundle,
            candidate,
        )

    def test_stderr_and_adoption_eligibility_are_derived(self) -> None:
        fixture = LifecycleReceiptFixture()
        candidate = copy.deepcopy(fixture.empty)
        candidate["stderr_bytes"] = 1
        candidate["stderr_sha256"] = fixture.digest("stderr")
        self.assert_code(
            "lifecycle_clean_exit_stderr_not_empty",
            lifecycle.normalize_scope_empty_receipt,
            candidate,
        )
        candidate = copy.deepcopy(fixture.empty)
        candidate["adoption_eligible"] = False
        self.assert_code(
            "lifecycle_adoption_eligibility_invalid",
            lifecycle.normalize_scope_empty_receipt,
            candidate,
        )
        abnormal = LifecycleReceiptFixture(
            disposition="abnormal_exit",
            origin="capture_ready",
        )
        candidate = copy.deepcopy(abnormal.empty)
        candidate["adoption_eligible"] = True
        self.assert_code(
            "lifecycle_adoption_eligibility_invalid",
            lifecycle.normalize_scope_empty_receipt,
            candidate,
        )
        for disposition, stderr_bytes, stderr_sha256 in (
            (
                "abnormal_exit",
                0,
                fixture.digest("fabricated-nonempty-stderr"),
            ),
            (
                "forced_termination",
                1,
                lifecycle.EMPTY_SHA256,
            ),
        ):
            with self.subTest(
                disposition=disposition,
                stderr_bytes=stderr_bytes,
            ):
                inconsistent = LifecycleReceiptFixture(
                    disposition=disposition,
                    origin="child_running",
                )
                candidate = copy.deepcopy(inconsistent.empty)
                candidate["stderr_bytes"] = stderr_bytes
                candidate["stderr_sha256"] = stderr_sha256
                self.assert_code(
                    "lifecycle_stderr_length_digest_incoherent",
                    lifecycle.normalize_scope_empty_receipt,
                    candidate,
                )
        reboot = LifecycleReceiptFixture(
            disposition="host_reboot",
            origin="capture_ready",
        )
        candidate = copy.deepcopy(reboot.empty)
        candidate["stderr_bytes"] = 0
        candidate["stderr_sha256"] = lifecycle.EMPTY_SHA256
        self.assert_code(
            "lifecycle_stderr_not_applicable_invalid",
            lifecycle.normalize_scope_empty_receipt,
            candidate,
        )

    def test_zero_digest_sentinel_is_never_evidence(self) -> None:
        fixture = LifecycleReceiptFixture()
        cases = (
            (
                lifecycle.normalize_activation_receipt,
                fixture.activation,
                "supervisor_policy_sha256",
                (
                    "lifecycle_activation_"
                    "supervisor_policy_sha256_invalid"
                ),
            ),
            (
                lifecycle.normalize_scope_started_receipt,
                fixture.started,
                "scope_incarnation_id",
                "lifecycle_scope_incarnation_id_invalid",
            ),
            (
                lifecycle.normalize_clearance_intent_receipt,
                fixture.intent,
                "outer_clearance_intent_record_sha256",
                (
                    "lifecycle_outer_clearance_"
                    "intent_record_sha256_invalid"
                ),
            ),
            (
                lifecycle.normalize_scope_empty_receipt,
                fixture.empty,
                "clearance_supervisor_epoch_id",
                "lifecycle_clearance_supervisor_epoch_id_invalid",
            ),
            (
                lifecycle.normalize_clearance_bundle,
                fixture.bundle,
                "activation_receipt_sha256",
                (
                    "lifecycle_bundle_"
                    "activation_receipt_sha256_invalid"
                ),
            ),
        )
        for function, source, field, code in cases:
            with self.subTest(function=function.__name__, field=field):
                candidate = copy.deepcopy(source)
                candidate[field] = lifecycle.ZERO_SHA256
                self.assert_code(code, function, candidate)

        zero_session = copy.deepcopy(fixture.started)
        zero_session["capture_session_id"] = lifecycle.ZERO_SHA256
        self.assert_code(
            "lifecycle_receipt_capture_session_id_invalid",
            lifecycle.normalize_scope_started_receipt,
            zero_session,
        )

    def test_bundle_rejects_every_digest_substitution(self) -> None:
        fixture = LifecycleReceiptFixture()
        fields = (
            "activation_receipt_sha256",
            "scope_started_receipt_sha256",
            "clearance_intent_receipt_sha256",
            "scope_empty_receipt_sha256",
        )
        expected = (
            "lifecycle_bundle_activation_digest_mismatch",
            "lifecycle_bundle_start_digest_mismatch",
            "lifecycle_bundle_intent_digest_mismatch",
            "lifecycle_bundle_empty_digest_mismatch",
        )
        for field, code in zip(fields, expected, strict=True):
            with self.subTest(field=field):
                candidate = copy.deepcopy(fixture.bundle)
                candidate[field] = fixture.digest(f"substitute-{field}")
                self.assert_code(
                    code,
                    lifecycle.normalize_clearance_bundle,
                    candidate,
                )

    def test_bundle_rejects_cross_object_binding_changes(self) -> None:
        fixture = LifecycleReceiptFixture()

        candidate = copy.deepcopy(fixture.bundle)
        candidate["scope_empty_receipt"][
            "scope_incarnation_id"
        ] = fixture.digest("other-incarnation")
        candidate["scope_empty_receipt_sha256"] = (
            lifecycle.scope_empty_receipt_sha256(
                candidate["scope_empty_receipt"]
            )
        )
        self.assert_code(
            "lifecycle_bundle_scope_binding_changed",
            lifecycle.normalize_clearance_bundle,
            candidate,
        )

        candidate = copy.deepcopy(fixture.bundle)
        candidate["scope_empty_receipt"][
            "outer_clearance_intent_record_sha256"
        ] = fixture.digest("other-outer-intent")
        candidate["scope_empty_receipt_sha256"] = (
            lifecycle.scope_empty_receipt_sha256(
                candidate["scope_empty_receipt"]
            )
        )
        self.assert_code(
            "lifecycle_bundle_clearance_binding_changed",
            lifecycle.normalize_clearance_bundle,
            candidate,
        )

        candidate = copy.deepcopy(fixture.bundle)
        candidate["scope_empty_receipt"][
            "scope_started_receipt_sha256"
        ] = fixture.digest("other-start")
        candidate["scope_empty_receipt_sha256"] = (
            lifecycle.scope_empty_receipt_sha256(
                candidate["scope_empty_receipt"]
            )
        )
        self.assert_code(
            "lifecycle_bundle_start_binding_changed",
            lifecycle.normalize_clearance_bundle,
            candidate,
        )

        candidate = copy.deepcopy(fixture.bundle)
        other_epoch = fixture.digest("other-start-epoch")
        candidate["scope_empty_receipt"][
            "start_supervisor_epoch_id"
        ] = other_epoch
        candidate["scope_empty_receipt"][
            "clearance_supervisor_epoch_id"
        ] = other_epoch
        candidate["scope_empty_receipt_sha256"] = (
            lifecycle.scope_empty_receipt_sha256(
                candidate["scope_empty_receipt"]
            )
        )
        self.assert_code(
            "lifecycle_bundle_start_observation_changed",
            lifecycle.normalize_clearance_bundle,
            candidate,
        )

    def test_bundle_rejects_missing_or_unexpected_start_receipt(
        self,
    ) -> None:
        fixture = LifecycleReceiptFixture()
        candidate = copy.deepcopy(fixture.bundle)
        candidate["scope_started_receipt"] = None
        candidate["scope_started_receipt_sha256"] = None
        self.assert_code(
            "lifecycle_bundle_start_binding_changed",
            lifecycle.normalize_clearance_bundle,
            candidate,
        )

    def test_launch_intent_recovery_can_discover_a_durable_start(
        self,
    ) -> None:
        fixture = LifecycleReceiptFixture(
            disposition="forced_termination",
            origin="child_launch_intent",
        )
        fixture.intent["scope_started_receipt_sha256"] = None
        fixture.empty["clearance_intent_receipt_sha256"] = (
            lifecycle.clearance_intent_receipt_sha256(fixture.intent)
        )
        fixture.bundle = fixture.rebuild_bundle()
        normalized = lifecycle.normalize_clearance_bundle(
            fixture.bundle
        )
        self.assertIsNone(
            normalized["clearance_intent_receipt"][
                "scope_started_receipt_sha256"
            ]
        )
        self.assertEqual(
            normalized["scope_empty_receipt"][
                "scope_started_receipt_sha256"
            ],
            normalized["scope_started_receipt_sha256"],
        )

        never = LifecycleReceiptFixture(
            disposition="never_started",
            origin="child_launch_intent",
        )
        candidate = copy.deepcopy(never.bundle)
        candidate["scope_started_receipt"] = copy.deepcopy(
            never.started
        )
        candidate["scope_started_receipt_sha256"] = (
            lifecycle.scope_started_receipt_sha256(never.started)
        )
        self.assert_code(
            "lifecycle_bundle_start_binding_changed",
            lifecycle.normalize_clearance_bundle,
            candidate,
        )

    def test_proof_is_gated_nonserializable_and_single_consumption(
        self,
    ) -> None:
        fixture = LifecycleReceiptFixture()
        self.assertFalse(lifecycle.PRODUCTION_ACTIVATION)
        self.assert_code(
            "lifecycle_scope_clearance_production_disabled",
            lifecycle.mint_scope_clearance_proof,
            fixture.bundle,
        )
        with self.assertRaises(TypeError):
            lifecycle.ScopeClearanceProof(
                _token=object(),
                bundle=fixture.bundle,
            )
        proof = lifecycle._mint_scope_clearance_proof_for_test(
            fixture.bundle
        )
        self.assertTrue(proof.active)
        self.assertTrue(proof.adoption_eligible)
        self.assertEqual(
            proof.capture_session_id, fixture.session_id
        )
        for operation in (
            lambda: copy.copy(proof),
            lambda: copy.deepcopy(proof),
            lambda: pickle.dumps(proof),
        ):
            with self.assertRaises(TypeError):
                operation()
        self.assertEqual(
            proof.consume(
                capture_session_id=fixture.session_id,
                purpose="capture_adoption",
            ),
            (
                fixture.session_id,
                lifecycle.scope_empty_receipt_sha256(fixture.empty),
            ),
        )
        self.assertFalse(proof.active)
        with self.assertRaises(lifecycle.LifecycleReceiptError) as raised:
            proof.consume(
                capture_session_id=fixture.session_id,
                purpose="staging_cleanup",
            )
        self.assertEqual(
            raised.exception.code,
            "lifecycle_scope_clearance_proof_consumed",
        )

    def test_noneligible_proof_cannot_adopt_but_can_clean_once(
        self,
    ) -> None:
        fixture = LifecycleReceiptFixture(
            disposition="forced_termination",
            origin="capture_ready",
        )
        proof = lifecycle._mint_scope_clearance_proof_for_test(
            fixture.bundle
        )
        with self.assertRaises(lifecycle.LifecycleReceiptError) as raised:
            proof.consume(
                capture_session_id=fixture.session_id,
                purpose="capture_adoption",
            )
        self.assertEqual(
            raised.exception.code,
            "lifecycle_scope_clearance_proof_adoption_forbidden",
        )
        self.assertTrue(proof.active)
        proof.consume(
            capture_session_id=fixture.session_id,
            purpose="staging_cleanup",
        )
        self.assertFalse(proof.active)


if __name__ == "__main__":
    unittest.main()
