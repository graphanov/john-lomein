from __future__ import annotations

import ast
import copy
import hashlib
import struct
import sys
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (
    john_lomein_persona_qualification_lifecycle_receipts as lifecycle,
)
from qualification_attestor import (
    john_lomein_persona_qualification_lifecycle_supervisor_protocol
    as protocol,
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class Fixture:
    def __init__(
        self,
        *,
        disposition: str = "clean_exit",
        origin: str = "capture_ready",
        changed_epoch: bool = False,
    ) -> None:
        self.session = digest("capture-session")
        self.scope = f"jlq-root_supervisor-{self.session}"
        self.incarnation = digest("scope-incarnation")
        self.client_incarnation = digest("client-incarnation")
        self.client_nonce = digest("client-nonce")
        self.server_nonce = digest("server-nonce")
        self.protocol_session = digest("protocol-session")
        self.supervisor_incarnation = digest(
            "supervisor-incarnation"
        )
        self.start_epoch = digest("start-epoch")
        self.clearance_epoch = (
            digest("clearance-epoch")
            if changed_epoch
            else self.start_epoch
        )
        self.boot = digest("host-boot")
        self.policy = digest("supervisor-policy")
        self.bundle_digest = digest("supervisor-bundle")
        self.helper_policy = digest("helper-policy")
        self.canary = digest("lifecycle-canary")
        self.staging_intent = digest("staging-intent")
        self.staging_exposure = digest("staging-exposure")
        self.launch = digest("child-launch-intent")
        self.handoff = digest("handoff-policy")
        self.origin_record = (
            self.launch
            if origin == "child_launch_intent"
            else digest(f"{origin}-outer-record")
        )
        self.origin_revision = {
            "child_launch_intent": 7,
            "child_running": 8,
            "capture_ready": 9,
        }[origin]
        self.outer_clearance = digest("outer-clearance-intent")
        self.capture_event_evidence = {
            "provisional_name": "opaque-capture-a1b2c3d4",
            "capture_object_identity_sha256": digest(
                "capture-object-identity"
            ),
            "capture_selection_sha256": digest("capture-selection"),
            "capture_plan_sha256": digest("capture-plan"),
            "capture_manifest_sha256": digest("capture-manifest"),
            "capture_boundary_policy_sha256": digest(
                "capture-boundary-policy"
            ),
            "helper_activation_policy_sha256": self.helper_policy,
            "request_sha256": digest("capture-request"),
        }
        self.capture_event_evidence_digest = (
            protocol.capture_event_evidence_sha256(
                self.capture_event_evidence
            )
        )

        self.activation = {
            "schema_version": lifecycle.ACTIVATION_RECEIPT_SCHEMA,
            "status": lifecycle.ACTIVATION_STATUS,
            "system": "Linux",
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": "linux_cgroup_v2",
            "supervisor_policy_sha256": self.policy,
            "supervisor_bundle_sha256": self.bundle_digest,
            "helper_activation_policy_sha256": self.helper_policy,
            "lifecycle_canary_sha256": self.canary,
            "host_boot_measurement": "linux_boot_id",
            "host_boot_id_sha256": self.boot,
            "assertions": {
                name: True
                for name in lifecycle.ACTIVATION_ASSERTIONS
            },
            "production_activation": False,
        }
        self.activation_digest = (
            lifecycle.activation_receipt_sha256(self.activation)
        )
        self.incarnation = protocol.derive_scope_incarnation_id(
            instance_slug="widget-production",
            capture_session_id=self.session,
            child_launch_intent_record_sha256=self.launch,
            lifecycle_activation_receipt_sha256=(
                self.activation_digest
            ),
        )
        self.start_authorization = (
            protocol.derive_scope_start_authorization_sha256(
                instance_slug="widget-production",
                capture_session_id=self.session,
                scope_incarnation_id=self.incarnation,
                child_launch_intent_record_revision=7,
                child_launch_intent_record_sha256=self.launch,
                staging_transaction_intent_sha256=(
                    self.staging_intent
                ),
                staging_exposure_receipt_sha256=(
                    self.staging_exposure
                ),
                handoff_policy_sha256=self.handoff,
                helper_activation_policy_sha256=self.helper_policy,
                lifecycle_provider="linux_cgroup_v2",
                capture_uid=4201,
                export_gid=4202,
                lifecycle_activation_receipt_sha256=(
                    self.activation_digest
                ),
                activation_host_boot_id_sha256=self.boot,
            )
        )
        self.started = {
            "schema_version": lifecycle.SCOPE_STARTED_RECEIPT_SCHEMA,
            "status": lifecycle.SCOPE_STARTED_STATUS,
            "capture_session_id": self.session,
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": "linux_cgroup_v2",
            "lifecycle_scope_id": self.scope,
            "scope_incarnation_id": self.incarnation,
            "supervisor_epoch_id": self.start_epoch,
            "host_boot_id_sha256": self.boot,
            "staging_transaction_intent_sha256": self.staging_intent,
            "staging_exposure_receipt_sha256": self.staging_exposure,
            "child_launch_intent_record_sha256": self.launch,
            "handoff_policy_sha256": self.handoff,
            "helper_activation_policy_sha256": self.helper_policy,
            "capture_uid": 4201,
            "export_gid": 4202,
            "lifecycle_activation_receipt_sha256": (
                self.activation_digest
            ),
        }
        self.started_digest = lifecycle.scope_started_receipt_sha256(
            self.started
        )
        mode = (
            "wait_clean_then_terminate_on_deadline"
            if origin == "capture_ready"
            else "terminate_and_clear"
        )
        self.intent = {
            "schema_version": (
                lifecycle.CLEARANCE_INTENT_RECEIPT_SCHEMA
            ),
            "status": lifecycle.CLEARANCE_INTENT_STATUS,
            "capture_session_id": self.session,
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": "linux_cgroup_v2",
            "lifecycle_scope_id": self.scope,
            "scope_incarnation_id": self.incarnation,
            "lifecycle_activation_receipt_sha256": (
                self.activation_digest
            ),
            "child_launch_intent_record_sha256": self.launch,
            "effect_origin_state": origin,
            "effect_origin_record_sha256": self.origin_record,
            "scope_started_receipt_sha256": (
                None
                if origin == "child_launch_intent"
                else self.started_digest
            ),
            "clearance_mode": mode,
            "outer_clearance_intent_record_sha256": (
                self.outer_clearance
            ),
        }
        self.intent_digest = (
            lifecycle.clearance_intent_receipt_sha256(self.intent)
        )
        no_start = disposition in {
            "never_started",
            "never_started_after_reboot",
        }
        process_observed = disposition in {
            "clean_exit",
            "abnormal_exit",
            "forced_termination",
        }
        basis = {
            "never_started": "supervisor_ledger_no_effect",
            "never_started_after_reboot": "host_boot_epoch_changed",
            "host_reboot": "host_boot_epoch_changed",
        }.get(disposition, "linux_cgroup_kill_populated_zero")
        self.empty = {
            "schema_version": lifecycle.SCOPE_EMPTY_RECEIPT_SCHEMA,
            "status": lifecycle.SCOPE_EMPTY_STATUS,
            "capture_session_id": self.session,
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": "linux_cgroup_v2",
            "lifecycle_scope_id": self.scope,
            "scope_incarnation_id": self.incarnation,
            "lifecycle_activation_receipt_sha256": (
                self.activation_digest
            ),
            "child_launch_intent_record_sha256": self.launch,
            "effect_origin_state": origin,
            "effect_origin_record_sha256": self.origin_record,
            "scope_started_receipt_sha256": (
                None if no_start else self.started_digest
            ),
            "clearance_intent_receipt_sha256": self.intent_digest,
            "outer_clearance_intent_record_sha256": (
                self.outer_clearance
            ),
            "clearance_mode": mode,
            "start_supervisor_epoch_id": (
                None if no_start else self.start_epoch
            ),
            "clearance_supervisor_epoch_id": self.clearance_epoch,
            "start_host_boot_id_sha256": (
                None if no_start else self.boot
            ),
            "clearance_host_boot_id_sha256": self.boot,
            "clearance_basis": basis,
            "completion_disposition": disposition,
            "stderr_bytes": 0 if process_observed else None,
            "stderr_sha256": (
                lifecycle.EMPTY_SHA256 if process_observed else None
            ),
            "adoption_eligible": (
                disposition == "clean_exit"
                and origin == "capture_ready"
                and not changed_epoch
            ),
        }
        self.clearance_bundle = {
            "schema_version": lifecycle.CLEARANCE_BUNDLE_SCHEMA,
            "status": lifecycle.CLEARANCE_BUNDLE_STATUS,
            "activation_receipt": copy.deepcopy(self.activation),
            "activation_receipt_sha256": self.activation_digest,
            "scope_started_receipt": (
                None if no_start else copy.deepcopy(self.started)
            ),
            "scope_started_receipt_sha256": (
                None if no_start else self.started_digest
            ),
            "clearance_intent_receipt": copy.deepcopy(self.intent),
            "clearance_intent_receipt_sha256": self.intent_digest,
            "scope_empty_receipt": copy.deepcopy(self.empty),
            "scope_empty_receipt_sha256": (
                lifecycle.scope_empty_receipt_sha256(self.empty)
            ),
        }

        self.client_hello = protocol.build_client_hello(
            instance_slug="widget-production",
            request_id="jlqreq-" + ("1" * 32),
            client_incarnation_id=self.client_incarnation,
            client_nonce=self.client_nonce,
            expected_supervisor_policy_sha256=self.policy,
            expected_supervisor_bundle_sha256=self.bundle_digest,
            expected_helper_activation_policy_sha256=(
                self.helper_policy
            ),
            expected_lifecycle_canary_sha256=self.canary,
        )
        self.server_hello = protocol.build_server_hello(
            self.client_hello,
            server_nonce=self.server_nonce,
            protocol_session_id=self.protocol_session,
            supervisor_incarnation_id=self.supervisor_incarnation,
            supervisor_epoch_id=self.clearance_epoch,
            host_boot_id_sha256=self.boot,
            supervisor_policy_sha256=self.policy,
            supervisor_bundle_sha256=self.bundle_digest,
            helper_activation_policy_sha256=self.helper_policy,
            lifecycle_canary_sha256=self.canary,
            activation_receipt_sha256=self.activation_digest,
        )

    def payload(self, operation: str) -> dict[str, Any]:
        if operation == "get_activation":
            return {
                "expected_activation_receipt_sha256": (
                    self.activation_digest
                ),
                "expected_supervisor_policy_sha256": self.policy,
                "expected_supervisor_bundle_sha256": (
                    self.bundle_digest
                ),
                "expected_helper_activation_policy_sha256": (
                    self.helper_policy
                ),
                "expected_lifecycle_canary_sha256": self.canary,
            }
        if operation == "start_scope":
            return {
                "capture_session_id": self.session,
                "lifecycle_scope_id": self.scope,
                "scope_incarnation_id": self.incarnation,
                "child_launch_intent_record_revision": 7,
                "child_launch_intent_record_sha256": self.launch,
                "staging_transaction_intent_sha256": (
                    self.staging_intent
                ),
                "staging_exposure_receipt_sha256": (
                    self.staging_exposure
                ),
                "handoff_policy_sha256": self.handoff,
                "helper_activation_policy_sha256": self.helper_policy,
                "lifecycle_provider": "linux_cgroup_v2",
                "capture_uid": 4201,
                "export_gid": 4202,
                "lifecycle_activation_receipt_sha256": (
                    self.activation_digest
                ),
            }
        if operation == "await_capture_event":
            return {
                "capture_session_id": self.session,
                "lifecycle_scope_id": self.scope,
                "scope_incarnation_id": self.incarnation,
                "scope_started_receipt_sha256": self.started_digest,
                "child_launch_intent_record_sha256": self.launch,
                "outer_journal_record_state": "child_running",
                "outer_journal_record_revision": 8,
                "outer_journal_record_sha256": digest(
                    "child-running-outer"
                ),
                "expected_ledger_head_sha256": digest(
                    "started-ledger-head"
                ),
                "after_event_sequence": 0,
                "timeout_seconds": 30,
            }
        if operation == "request_clearance":
            return {
                "capture_session_id": self.session,
                "lifecycle_scope_id": self.scope,
                "scope_incarnation_id": self.incarnation,
                "lifecycle_activation_receipt_sha256": (
                    self.activation_digest
                ),
                "child_launch_intent_record_sha256": self.launch,
                "effect_origin_state": self.intent[
                    "effect_origin_state"
                ],
                "effect_origin_record_revision": self.origin_revision,
                "effect_origin_record_sha256": self.origin_record,
                "scope_started_receipt_sha256": self.intent[
                    "scope_started_receipt_sha256"
                ],
                "clearance_mode": self.intent["clearance_mode"],
                "lifecycle_clearance_intent_record_revision": 10,
                "lifecycle_clearance_intent_record_sha256": (
                    self.outer_clearance
                ),
                "expected_ledger_head_sha256": digest(
                    "capture-event-ledger-head"
                ),
                "timeout_seconds": 30,
            }
        if operation == "recover_scope":
            return {
                "capture_session_id": self.session,
                "lifecycle_scope_id": self.scope,
                "scope_incarnation_id": self.incarnation,
                "lifecycle_activation_receipt_sha256": (
                    self.activation_digest
                ),
                "child_launch_intent_record_revision": 7,
                "child_launch_intent_record_sha256": self.launch,
                "outer_journal_record_state": (
                    "lifecycle_clearance_intent"
                ),
                "outer_journal_record_revision": 10,
                "outer_journal_record_sha256": self.outer_clearance,
                "expected_scope_started_receipt_sha256": (
                    self.started_digest
                ),
                "expected_scope_start_authorization_sha256": (
                    self.start_authorization
                ),
                "expected_effect_origin_state": self.intent[
                    "effect_origin_state"
                ],
                "expected_effect_origin_record_revision": (
                    self.origin_revision
                ),
                "expected_effect_origin_record_sha256": (
                    self.origin_record
                ),
                "expected_clearance_intent_record_revision": 10,
                "expected_clearance_intent_record_sha256": (
                    self.outer_clearance
                ),
                "expected_clearance_mode": self.intent[
                    "clearance_mode"
                ],
                "expected_ledger_head_sha256": None,
                "recovery_reason": "supervisor_restart",
            }
        raise AssertionError(operation)

    def result(self, operation: str) -> dict[str, Any]:
        if operation == "get_activation":
            return {
                "activation_receipt": copy.deepcopy(self.activation),
                "activation_receipt_sha256": self.activation_digest,
            }
        if operation == "start_scope":
            return {
                "scope_started_receipt": copy.deepcopy(self.started),
                "scope_started_receipt_sha256": self.started_digest,
                "ledger_head_sha256": digest("started-ledger-head"),
            }
        if operation == "await_capture_event":
            return {
                "capture_session_id": self.session,
                "lifecycle_scope_id": self.scope,
                "scope_incarnation_id": self.incarnation,
                "scope_started_receipt_sha256": self.started_digest,
                "event_sequence": 1,
                "event": "capture_ready",
                "event_record_sha256": digest("capture-event-record"),
                "event_evidence_sha256": (
                    self.capture_event_evidence_digest
                ),
                "ledger_head_sha256": digest(
                    "capture-event-ledger-head"
                ),
            }
        if operation == "request_clearance":
            return {
                "clearance_bundle": copy.deepcopy(
                    self.clearance_bundle
                ),
                "clearance_bundle_sha256": (
                    lifecycle.clearance_bundle_sha256(
                        self.clearance_bundle
                    )
                ),
                "ledger_head_sha256": digest("settled-ledger-head"),
            }
        if operation == "recover_scope":
            return {
                "recovery_state": "settled_bundle",
                "capture_session_id": self.session,
                "lifecycle_scope_id": self.scope,
                "scope_incarnation_id": self.incarnation,
                "ledger_head_sha256": digest("settled-ledger-head"),
                "scope_started_receipt": copy.deepcopy(self.started),
                "scope_started_receipt_sha256": self.started_digest,
                "effect_origin_state": self.intent[
                    "effect_origin_state"
                ],
                "effect_origin_record_revision": self.origin_revision,
                "effect_origin_record_sha256": self.origin_record,
                "event_sequence": None,
                "event": None,
                "event_record_sha256": None,
                "event_evidence_sha256": None,
                "clearance_bundle": copy.deepcopy(
                    self.clearance_bundle
                ),
                "clearance_bundle_sha256": (
                    lifecycle.clearance_bundle_sha256(
                        self.clearance_bundle
                    )
                ),
            }
        raise AssertionError(operation)


class LifecycleSupervisorProtocolTest(unittest.TestCase):
    def assert_code(
        self,
        code: str,
        function: Any,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        with self.assertRaises(
            protocol.LifecycleSupervisorProtocolError
        ) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)

    def request(
        self,
        fixture: Fixture,
        operation: str,
        *,
        sequence: int = 1,
    ) -> dict[str, Any]:
        return protocol.build_request(
            fixture.server_hello,
            request_id="jlqreq-" + f"{sequence:032x}",
            sequence=sequence,
            operation=operation,
            payload=fixture.payload(operation),
        )

    def test_production_is_disabled_and_runtime_is_stdlib_only(self) -> None:
        self.assertIs(protocol.PRODUCTION_ACTIVATION, False)
        source_path = (
            ROOT
            / "qualification_attestor"
            / (
                "john_lomein_persona_qualification_"
                "lifecycle_supervisor_protocol.py"
            )
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            (node.module or "").split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module != "__future__"
        }
        self.assertEqual(
            imported,
            {
                "collections",
                "hashlib",
                "hmac",
                "json",
                "qualification_attestor",
                "re",
                "struct",
                "typing",
            },
        )
        receipt_path = (
            ROOT
            / "qualification_attestor"
            / "john_lomein_persona_qualification_lifecycle_receipts.py"
        )
        receipt_tree = ast.parse(
            receipt_path.read_text(encoding="utf-8")
        )
        receipt_imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(receipt_tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            (node.module or "").split(".", 1)[0]
            for node in ast.walk(receipt_tree)
            if isinstance(node, ast.ImportFrom)
            and node.module != "__future__"
        }
        self.assertEqual(
            receipt_imports,
            {"collections", "hashlib", "hmac", "json", "re", "typing"},
        )

    def test_handshake_is_exact_and_measurement_bound(self) -> None:
        fixture = Fixture()
        self.assertEqual(
            protocol.validate_server_hello(
                fixture.client_hello, fixture.server_hello
            ),
            fixture.server_hello,
        )
        mutations = {
            "client nonce": ("client_nonce", digest("wrong-client")),
            "instance": ("instance_slug", "other-production"),
            "policy": (
                "supervisor_policy_sha256",
                digest("wrong-policy"),
            ),
            "hello digest": (
                "client_hello_sha256",
                digest("wrong-hello"),
            ),
            "activation flag": ("production_activation", True),
        }
        for label, (field, value) in mutations.items():
            with self.subTest(label=label):
                changed = copy.deepcopy(fixture.server_hello)
                changed[field] = value
                with self.assertRaises(
                    protocol.LifecycleSupervisorProtocolError
                ):
                    protocol.validate_server_hello(
                        fixture.client_hello, changed
                    )

    def test_handshake_nonce_domains_cannot_collide(self) -> None:
        fixture = Fixture()
        changed = copy.deepcopy(fixture.server_hello)
        changed["server_nonce"] = changed["client_nonce"]
        self.assert_code(
            "lifecycle_supervisor_handshake_domain_collision",
            protocol.normalize_server_hello,
            changed,
        )

    def test_frames_are_canonical_bounded_and_incremental(self) -> None:
        fixture = Fixture()
        frame = protocol.encode_frame(fixture.client_hello)
        self.assertEqual(protocol.decode_frame(frame), fixture.client_hello)
        decoder = protocol.FrameDecoder()
        messages: list[dict[str, Any]] = []
        for byte in frame:
            messages.extend(decoder.feed(bytes((byte,))))
        decoder.finish()
        self.assertEqual(messages, [fixture.client_hello])

        payload = frame[4:]
        noncanonical = struct.pack("!I", len(payload) + 1) + payload + b" "
        self.assert_code(
            "lifecycle_supervisor_json_noncanonical",
            protocol.decode_frame,
            noncanonical,
        )
        self.assert_code(
            "lifecycle_supervisor_frame_length_mismatch",
            protocol.decode_frame,
            frame + b"x",
        )
        oversized = struct.pack("!I", protocol.MAX_FRAME_BYTES + 1)
        oversized += b"{}"
        self.assert_code(
            "lifecycle_supervisor_frame_size_invalid",
            protocol.decode_frame,
            oversized,
        )

    def test_duplicate_keys_and_non_objects_are_rejected(self) -> None:
        duplicate = b'{"a":1,"a":2}'
        frame = struct.pack("!I", len(duplicate)) + duplicate
        self.assert_code(
            "lifecycle_supervisor_json_duplicate_key",
            protocol.decode_frame,
            frame,
        )
        array = b"[]"
        self.assert_code(
            "lifecycle_supervisor_message_invalid",
            protocol.decode_frame,
            struct.pack("!I", len(array)) + array,
        )

    def test_all_operation_payloads_and_results_are_exact(self) -> None:
        fixture = Fixture()
        for sequence, operation in enumerate(
            sorted(protocol.OPERATIONS), 1
        ):
            with self.subTest(operation=operation):
                payload = fixture.payload(operation)
                result = fixture.result(operation)
                self.assertEqual(
                    protocol.normalize_operation_payload(
                        operation, payload
                    ),
                    payload,
                )
                self.assertEqual(
                    protocol.normalize_operation_result(
                        operation, result
                    ),
                    result,
                )
                request = self.request(
                    fixture, operation, sequence=sequence
                )
                response = protocol.build_success_response(
                    request, result=result
                )
                self.assertEqual(
                    protocol.validate_response_for_request(
                        fixture.client_hello,
                        fixture.server_hello,
                        request,
                        response,
                    ),
                    response,
                )

    def test_capture_event_evidence_has_one_domain_separated_digest(
        self,
    ) -> None:
        fixture = Fixture()
        expected = protocol.sha256_json(
            {
                "schema_version": (
                    protocol.CAPTURE_EVENT_EVIDENCE_SCHEMA
                ),
                "capture_ready": fixture.capture_event_evidence,
            }
        )
        self.assertEqual(
            fixture.capture_event_evidence_digest, expected
        )
        self.assertEqual(
            protocol.capture_event_evidence_sha256(
                dict(
                    reversed(
                        tuple(fixture.capture_event_evidence.items())
                    )
                )
            ),
            expected,
        )

        changed = copy.deepcopy(fixture.capture_event_evidence)
        changed["capture_manifest_sha256"] = digest(
            "different-capture-manifest"
        )
        self.assertNotEqual(
            protocol.capture_event_evidence_sha256(changed),
            expected,
        )
        for mutation in ("missing", "extra"):
            with self.subTest(mutation=mutation):
                malformed = copy.deepcopy(
                    fixture.capture_event_evidence
                )
                if mutation == "missing":
                    malformed.pop("request_sha256")
                else:
                    malformed["capture_size"] = 1
                self.assert_code(
                    (
                        "lifecycle_supervisor_capture_event_"
                        "evidence_fields_invalid"
                    ),
                    protocol.capture_event_evidence_sha256,
                    malformed,
                )
        malformed = copy.deepcopy(fixture.capture_event_evidence)
        malformed["provisional_name"] = "../capture"
        self.assert_code(
            (
                "lifecycle_supervisor_capture_event_"
                "provisional_name_invalid"
            ),
            protocol.capture_event_evidence_sha256,
            malformed,
        )
        malformed = copy.deepcopy(fixture.capture_event_evidence)
        malformed["capture_plan_sha256"] = protocol.ZERO_SHA256
        self.assert_code(
            (
                "lifecycle_supervisor_capture_event_"
                "capture_plan_sha256_invalid"
            ),
            protocol.capture_event_evidence_sha256,
            malformed,
        )

    def test_await_capture_event_evidence_nullness_is_exact(
        self,
    ) -> None:
        fixture = Fixture()
        request = self.request(fixture, "await_capture_event")
        cases = (
            ("capture_ready", fixture.capture_event_evidence_digest),
            ("child_exited", None),
            ("capture_deadline_exceeded", None),
        )
        for event, evidence in cases:
            with self.subTest(event=event):
                result = fixture.result("await_capture_event")
                result["event"] = event
                result["event_evidence_sha256"] = evidence
                self.assertEqual(
                    protocol.normalize_operation_result(
                        "await_capture_event", result
                    ),
                    result,
                )
                response = protocol.build_success_response(
                    request, result=result
                )
                self.assertEqual(
                    protocol.validate_response_for_request(
                        fixture.client_hello,
                        fixture.server_hello,
                        request,
                        protocol.decode_frame(
                            protocol.encode_frame(response)
                        ),
                    ),
                    response,
                )

        wrong_nullness = (
            ("capture_ready", None),
            ("child_exited", fixture.capture_event_evidence_digest),
            (
                "capture_deadline_exceeded",
                fixture.capture_event_evidence_digest,
            ),
        )
        for event, evidence in wrong_nullness:
            with self.subTest(event=event, wrong_nullness=True):
                result = fixture.result("await_capture_event")
                result["event"] = event
                result["event_evidence_sha256"] = evidence
                self.assert_code(
                    (
                        "lifecycle_supervisor_capture_event_"
                        "evidence_shape_invalid"
                    ),
                    protocol.normalize_operation_result,
                    "await_capture_event",
                    result,
                )

        for mutation in ("missing", "extra"):
            with self.subTest(mutation=mutation):
                result = fixture.result("await_capture_event")
                if mutation == "missing":
                    result.pop("event_evidence_sha256")
                else:
                    result["capture_evidence"] = "forbidden"
                self.assert_code(
                    (
                        "lifecycle_supervisor_await_capture_event_"
                        "result_fields_invalid"
                    ),
                    protocol.normalize_operation_result,
                    "await_capture_event",
                    result,
                )
        invalid = fixture.result("await_capture_event")
        invalid["event_evidence_sha256"] = protocol.ZERO_SHA256
        self.assert_code(
            (
                "lifecycle_supervisor_capture_event_"
                "evidence_sha256_invalid"
            ),
            protocol.normalize_operation_result,
            "await_capture_event",
            invalid,
        )

    def test_recovery_capture_event_tuple_is_all_or_none(
        self,
    ) -> None:
        fixture = Fixture(origin="child_running")
        payload = fixture.payload("recover_scope")
        payload.update(
            {
                "outer_journal_record_state": "child_running",
                "outer_journal_record_revision": 8,
                "outer_journal_record_sha256": fixture.origin_record,
                "expected_clearance_intent_record_revision": None,
                "expected_clearance_intent_record_sha256": None,
                "expected_clearance_mode": None,
            }
        )
        request = protocol.build_request(
            fixture.server_hello,
            request_id="jlqreq-" + ("9" * 32),
            sequence=1,
            operation="recover_scope",
            payload=payload,
        )
        cases = (
            ("capture_ready", fixture.capture_event_evidence_digest),
            ("child_exited", None),
            ("capture_deadline_exceeded", None),
        )
        for event, evidence in cases:
            with self.subTest(event=event):
                result = fixture.result("recover_scope")
                result.update(
                    {
                        "recovery_state": "capture_event",
                        "event_sequence": 4,
                        "event": event,
                        "event_record_sha256": digest(
                            f"recovered-{event}-record"
                        ),
                        "event_evidence_sha256": evidence,
                        "clearance_bundle": None,
                        "clearance_bundle_sha256": None,
                    }
                )
                normalized = protocol.normalize_operation_result(
                    "recover_scope", result
                )
                self.assertEqual(normalized, result)
                response = protocol.build_success_response(
                    request, result=result
                )
                guard = protocol.ClientExchangeGuard(
                    fixture.client_hello, fixture.server_hello
                )
                guarded_request = guard.build_request(
                    request_id="jlqreq-" + ("8" * 32),
                    operation="recover_scope",
                    payload=payload,
                )
                guarded_response = protocol.build_success_response(
                    guarded_request, result=result
                )
                self.assertEqual(
                    guard.accept_response(guarded_response),
                    guarded_response,
                )
                self.assertEqual(
                    protocol.validate_response_for_request(
                        fixture.client_hello,
                        fixture.server_hello,
                        request,
                        response,
                    ),
                    response,
                )

        absent = fixture.result("recover_scope")
        for field in (
            "event_sequence",
            "event",
            "event_record_sha256",
            "event_evidence_sha256",
        ):
            self.assertIsNone(absent[field])
            with self.subTest(field=field, unexpected=True):
                malformed = copy.deepcopy(absent)
                malformed[field] = (
                    1
                    if field == "event_sequence"
                    else (
                        "capture_ready"
                        if field == "event"
                        else digest(f"unexpected-{field}")
                    )
                )
                self.assert_code(
                    (
                        "lifecycle_supervisor_recovery_"
                        "event_shape_invalid"
                    ),
                    protocol.normalize_operation_result,
                    "recover_scope",
                    malformed,
                )

        capture_event = fixture.result("recover_scope")
        capture_event.update(
            {
                "recovery_state": "capture_event",
                "event_sequence": 4,
                "event": "capture_ready",
                "event_record_sha256": digest(
                    "recovered-capture-event-record"
                ),
                "event_evidence_sha256": (
                    fixture.capture_event_evidence_digest
                ),
                "clearance_bundle": None,
                "clearance_bundle_sha256": None,
            }
        )
        for field in (
            "event_sequence",
            "event",
            "event_record_sha256",
        ):
            with self.subTest(field=field, partial=True):
                malformed = copy.deepcopy(capture_event)
                malformed[field] = None
                self.assert_code(
                    (
                        "lifecycle_supervisor_recovery_"
                        "event_shape_invalid"
                    ),
                    protocol.normalize_operation_result,
                    "recover_scope",
                    malformed,
                )
        capture_event["event_evidence_sha256"] = None
        self.assert_code(
            (
                "lifecycle_supervisor_capture_event_"
                "evidence_shape_invalid"
            ),
            protocol.normalize_operation_result,
            "recover_scope",
            capture_event,
        )

        for mutation in ("missing", "extra"):
            with self.subTest(mutation=mutation):
                malformed = fixture.result("recover_scope")
                if mutation == "missing":
                    malformed.pop("event_record_sha256")
                else:
                    malformed["recovered_event"] = {}
                self.assert_code(
                    (
                        "lifecycle_supervisor_recover_scope_"
                        "result_fields_invalid"
                    ),
                    protocol.normalize_operation_result,
                    "recover_scope",
                    malformed,
                )

    def test_lifecycle_receipts_have_one_canonical_grammar(self) -> None:
        fixture = Fixture()
        self.assertEqual(
            protocol.ACTIVATION_RECEIPT_SCHEMA,
            lifecycle.ACTIVATION_RECEIPT_SCHEMA,
        )
        self.assertEqual(
            protocol.SCOPE_STARTED_RECEIPT_SCHEMA,
            lifecycle.SCOPE_STARTED_RECEIPT_SCHEMA,
        )
        self.assertEqual(
            protocol.CLEARANCE_BUNDLE_SCHEMA,
            lifecycle.CLEARANCE_BUNDLE_SCHEMA,
        )
        activation = protocol.normalize_operation_result(
            "get_activation", fixture.result("get_activation")
        )
        self.assertEqual(
            activation["activation_receipt"],
            lifecycle.normalize_activation_receipt(
                fixture.activation
            ),
        )
        started = protocol.normalize_operation_result(
            "start_scope", fixture.result("start_scope")
        )
        self.assertEqual(
            started["scope_started_receipt"],
            lifecycle.normalize_scope_started_receipt(
                fixture.started
            ),
        )
        clearance = protocol.normalize_operation_result(
            "request_clearance",
            fixture.result("request_clearance"),
        )
        self.assertEqual(
            clearance["clearance_bundle"],
            lifecycle.normalize_clearance_bundle(
                fixture.clearance_bundle
            ),
        )

        invalid = fixture.result("start_scope")
        invalid["scope_started_receipt"]["capture_uid"] = True
        self.assert_code(
            "lifecycle_supervisor_lifecycle_receipt_invalid",
            protocol.normalize_operation_result,
            "start_scope",
            invalid,
        )

    def test_start_response_provider_is_bound_to_launch_activation(
        self,
    ) -> None:
        fixture = Fixture()
        request = self.request(fixture, "start_scope")
        result = fixture.result("start_scope")
        result["scope_started_receipt"][
            "lifecycle_provider"
        ] = "direct_waitid_deny_fork"
        result["scope_started_receipt_sha256"] = (
            lifecycle.scope_started_receipt_sha256(
                result["scope_started_receipt"]
            )
        )
        response = protocol.build_success_response(
            request, result=result
        )
        self.assert_code(
            "lifecycle_supervisor_scope_started_binding_mismatch",
            protocol.validate_response_for_request,
            fixture.client_hello,
            fixture.server_hello,
            request,
            response,
        )

    def test_start_clearance_and_recovery_require_outer_revisions(self) -> None:
        fixture = Fixture()
        cases = (
            (
                "start_scope",
                "child_launch_intent_record_revision",
            ),
            (
                "request_clearance",
                "lifecycle_clearance_intent_record_revision",
            ),
            ("recover_scope", "outer_journal_record_revision"),
        )
        for operation, field in cases:
            with self.subTest(operation=operation):
                payload = fixture.payload(operation)
                del payload[field]
                with self.assertRaises(
                    protocol.LifecycleSupervisorProtocolError
                ):
                    protocol.normalize_operation_payload(
                        operation, payload
                    )
                payload = fixture.payload(operation)
                payload[field] = 0
                with self.assertRaises(
                    protocol.LifecycleSupervisorProtocolError
                ):
                    protocol.normalize_operation_payload(
                        operation, payload
                    )

    def test_clearance_revisions_are_strictly_ordered(self) -> None:
        fixture = Fixture()
        payload = fixture.payload("request_clearance")
        payload["effect_origin_record_revision"] = payload[
            "lifecycle_clearance_intent_record_revision"
        ]
        self.assert_code(
            "lifecycle_supervisor_clearance_revision_order_invalid",
            protocol.normalize_operation_payload,
            "request_clearance",
            payload,
        )

    def test_protocol_has_no_process_path_or_command_authority(self) -> None:
        fixture = Fixture()
        forbidden = (
            ("pid", 123),
            ("signal", 9),
            ("executable_path", "/bin/sh"),
            ("argv", ["sh", "-c", "do something"]),
            ("command", "kill"),
            ("environment", {"TOKEN": "secret"}),
        )
        for operation in protocol.OPERATIONS:
            for field, value in forbidden:
                with self.subTest(operation=operation, field=field):
                    payload = fixture.payload(operation)
                    payload[field] = value
                    self.assert_code(
                        "lifecycle_supervisor_forbidden_authority_field",
                        protocol.normalize_operation_payload,
                        operation,
                        payload,
                    )

    def test_capture_event_cannot_expose_raw_stderr(self) -> None:
        fixture = Fixture()
        result = fixture.result("await_capture_event")
        result["stderr"] = "secret output"
        with self.assertRaises(
            protocol.LifecycleSupervisorProtocolError
        ):
            protocol.normalize_operation_result(
                "await_capture_event", result
            )

    def test_request_is_bound_to_full_handshake(self) -> None:
        fixture = Fixture()
        request = self.request(fixture, "start_scope")
        protocol.validate_request_for_handshake(
            fixture.client_hello,
            fixture.server_hello,
            request,
        )
        fields = (
            "instance_slug",
            "protocol_session_id",
            "client_incarnation_id",
            "supervisor_incarnation_id",
            "client_nonce",
            "server_nonce",
            "server_hello_sha256",
            "supervisor_epoch_id",
            "host_boot_id_sha256",
        )
        for field in fields:
            with self.subTest(field=field):
                changed = copy.deepcopy(request)
                changed[field] = (
                    "other-production"
                    if field == "instance_slug"
                    else digest(f"wrong-{field}")
                )
                self.assert_code(
                    "lifecycle_supervisor_request_handshake_binding_mismatch",
                    protocol.validate_request_for_handshake,
                    fixture.client_hello,
                    fixture.server_hello,
                    changed,
                )

    def test_scope_incarnation_is_durable_and_protocol_enforced(
        self,
    ) -> None:
        fixture = Fixture()
        expected = protocol.sha256_json(
            {
                "schema_version": (
                    protocol.SCOPE_INCARNATION_DERIVATION_SCHEMA
                ),
                "instance_slug": "widget-production",
                "capture_session_id": fixture.session,
                "child_launch_intent_record_sha256": fixture.launch,
                "lifecycle_activation_receipt_sha256": (
                    fixture.activation_digest
                ),
            }
        )
        self.assertEqual(fixture.incarnation, expected)
        self.assertEqual(
            protocol.derive_scope_incarnation_id(
                instance_slug="widget-production",
                capture_session_id=fixture.session,
                child_launch_intent_record_sha256=fixture.launch,
                lifecycle_activation_receipt_sha256=(
                    fixture.activation_digest
                ),
            ),
            expected,
        )
        self.assertNotEqual(
            protocol.derive_scope_incarnation_id(
                instance_slug="widget-production",
                capture_session_id=fixture.session,
                child_launch_intent_record_sha256=digest(
                    "other-launch"
                ),
                lifecycle_activation_receipt_sha256=(
                    fixture.activation_digest
                ),
            ),
            expected,
        )

        for sequence, operation in enumerate(
            (
                "start_scope",
                "await_capture_event",
                "request_clearance",
                "recover_scope",
            ),
            1,
        ):
            with self.subTest(operation=operation):
                request = self.request(
                    fixture, operation, sequence=sequence
                )
                protocol.validate_request_for_handshake(
                    fixture.client_hello,
                    fixture.server_hello,
                    request,
                )
                request["payload"]["scope_incarnation_id"] = digest(
                    f"random-process-state-{operation}"
                )
                self.assert_code(
                    (
                        "lifecycle_supervisor_scope_incarnation_"
                        "derivation_mismatch"
                    ),
                    protocol.validate_request_for_handshake,
                    fixture.client_hello,
                    fixture.server_hello,
                    request,
                )

    def test_reboot_authenticates_current_server_but_recovers_old_scope(
        self,
    ) -> None:
        fixture = Fixture()
        rotated_activation = digest("activation-after-host-reboot")
        rotated_server = protocol.build_server_hello(
            fixture.client_hello,
            server_nonce=digest("server-nonce-after-reboot"),
            protocol_session_id=digest(
                "protocol-session-after-reboot"
            ),
            supervisor_incarnation_id=digest(
                "supervisor-incarnation-after-reboot"
            ),
            supervisor_epoch_id=digest(
                "supervisor-epoch-after-reboot"
            ),
            host_boot_id_sha256=digest("host-boot-after-reboot"),
            supervisor_policy_sha256=fixture.policy,
            supervisor_bundle_sha256=fixture.bundle_digest,
            helper_activation_policy_sha256=fixture.helper_policy,
            lifecycle_canary_sha256=fixture.canary,
            activation_receipt_sha256=rotated_activation,
        )
        self.assertNotEqual(
            rotated_server["activation_receipt_sha256"],
            fixture.activation_digest,
        )

        for sequence, operation in enumerate(
            ("recover_scope", "request_clearance"), 1
        ):
            with self.subTest(operation=operation):
                request = protocol.build_request(
                    rotated_server,
                    request_id="jlqreq-" + f"{sequence:032x}",
                    sequence=sequence,
                    operation=operation,
                    payload=fixture.payload(operation),
                )
                self.assertEqual(
                    protocol.validate_request_for_handshake(
                        fixture.client_hello,
                        rotated_server,
                        request,
                    ),
                    request,
                )
                response = protocol.build_success_response(
                    request,
                    result=fixture.result(operation),
                )
                self.assertEqual(
                    protocol.validate_response_for_request(
                        fixture.client_hello,
                        rotated_server,
                        request,
                        response,
                    ),
                    response,
                )

        stale_start = protocol.build_request(
            rotated_server,
            request_id="jlqreq-" + ("a" * 32),
            sequence=3,
            operation="start_scope",
            payload=fixture.payload("start_scope"),
        )
        self.assert_code(
            "lifecycle_supervisor_request_measurement_mismatch",
            protocol.validate_request_for_handshake,
            fixture.client_hello,
            rotated_server,
            stale_start,
        )
        stale_await = protocol.build_request(
            rotated_server,
            request_id="jlqreq-" + ("b" * 32),
            sequence=4,
            operation="await_capture_event",
            payload=fixture.payload("await_capture_event"),
        )
        self.assert_code(
            (
                "lifecycle_supervisor_scope_incarnation_"
                "derivation_mismatch"
            ),
            protocol.validate_request_for_handshake,
            fixture.client_hello,
            rotated_server,
            stale_await,
        )

    def test_recovery_reconciles_discovered_start_and_exact_origin(
        self,
    ) -> None:
        fixture = Fixture()
        payload = fixture.payload("recover_scope")
        payload.update(
            {
                "outer_journal_record_state": "child_launch_intent",
                "outer_journal_record_revision": 7,
                "outer_journal_record_sha256": fixture.launch,
                "expected_scope_started_receipt_sha256": None,
                "expected_effect_origin_state": "child_launch_intent",
                "expected_effect_origin_record_revision": 7,
                "expected_effect_origin_record_sha256": fixture.launch,
                "expected_clearance_intent_record_revision": None,
                "expected_clearance_intent_record_sha256": None,
                "expected_clearance_mode": None,
            }
        )
        request = protocol.build_request(
            fixture.server_hello,
            request_id="jlqreq-" + ("c" * 32),
            sequence=1,
            operation="recover_scope",
            payload=payload,
        )
        discovered = fixture.result("recover_scope")
        discovered.update(
            {
                "recovery_state": "scope_started",
                "effect_origin_state": "child_launch_intent",
                "effect_origin_record_revision": 7,
                "effect_origin_record_sha256": fixture.launch,
                "clearance_bundle": None,
                "clearance_bundle_sha256": None,
            }
        )
        response = protocol.build_success_response(
            request, result=discovered
        )
        protocol.validate_response_for_request(
            fixture.client_hello,
            fixture.server_hello,
            request,
            response,
        )

        changed = copy.deepcopy(discovered)
        changed["scope_started_receipt"][
            "staging_transaction_intent_sha256"
        ] = digest("alternate-staging-intent")
        changed["scope_started_receipt_sha256"] = (
            lifecycle.scope_started_receipt_sha256(
                changed["scope_started_receipt"]
            )
        )
        changed_response = protocol.build_success_response(
            request, result=changed
        )
        self.assert_code(
            (
                "lifecycle_supervisor_recovery_start_"
                "authorization_mismatch"
            ),
            protocol.validate_response_for_request,
            fixture.client_hello,
            fixture.server_hello,
            request,
            changed_response,
        )

        advanced_request = self.request(fixture, "recover_scope")
        wrong_origin = fixture.result("recover_scope")
        wrong_origin.update(
            {
                "recovery_state": "clearance_intent",
                "effect_origin_record_sha256": digest(
                    "alternate-capture-ready"
                ),
                "clearance_bundle": None,
                "clearance_bundle_sha256": None,
            }
        )
        wrong_origin_response = protocol.build_success_response(
            advanced_request, result=wrong_origin
        )
        self.assert_code(
            "lifecycle_supervisor_recovery_outer_binding_mismatch",
            protocol.validate_response_for_request,
            fixture.client_hello,
            fixture.server_hello,
            advanced_request,
            wrong_origin_response,
        )

    def test_recovery_cannot_erase_a_known_started_receipt(self) -> None:
        fixture = Fixture()
        request = self.request(fixture, "recover_scope")
        result = fixture.result("recover_scope")
        result.update(
            {
                "recovery_state": "clearance_intent",
                "scope_started_receipt": None,
                "scope_started_receipt_sha256": None,
                "clearance_bundle": None,
                "clearance_bundle_sha256": None,
            }
        )
        response = protocol.build_success_response(
            request, result=result
        )
        self.assert_code(
            "lifecycle_supervisor_recovery_started_binding_mismatch",
            protocol.validate_response_for_request,
            fixture.client_hello,
            fixture.server_hello,
            request,
            response,
        )

    def test_settled_recovery_can_discover_a_lost_start_response(
        self,
    ) -> None:
        fixture = Fixture(origin="child_launch_intent")
        payload = fixture.payload("recover_scope")
        payload["expected_scope_started_receipt_sha256"] = None
        request = protocol.build_request(
            fixture.server_hello,
            request_id="jlqreq-" + ("d" * 32),
            sequence=1,
            operation="recover_scope",
            payload=payload,
        )
        result = fixture.result("recover_scope")
        self.assertIsNone(
            result["clearance_bundle"]["clearance_intent_receipt"][
                "scope_started_receipt_sha256"
            ]
        )
        self.assertIsNotNone(result["scope_started_receipt"])
        response = protocol.build_success_response(
            request, result=result
        )
        self.assertEqual(
            protocol.validate_response_for_request(
                fixture.client_hello,
                fixture.server_hello,
                request,
                response,
            ),
            response,
        )

    def test_response_is_strictly_correlated_to_request(self) -> None:
        fixture = Fixture()
        request = self.request(fixture, "await_capture_event")
        response = protocol.build_success_response(
            request,
            result=fixture.result("await_capture_event"),
        )
        changes = {
            "request_id": "jlqreq-" + ("e" * 32),
            "sequence": 2,
            "operation": "get_activation",
            "request_sha256": digest("wrong-request"),
            "server_nonce": digest("wrong-server-nonce"),
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(response)
                changed[field] = value
                with self.assertRaises(
                    protocol.LifecycleSupervisorProtocolError
                ):
                    protocol.validate_response_for_request(
                        fixture.client_hello,
                        fixture.server_hello,
                        request,
                        changed,
                    )

    def test_remote_error_operation_outcome_matrix_is_exact(
        self,
    ) -> None:
        final = protocol.ERROR_OUTCOME_FINAL_NO_EFFECT
        retry = protocol.ERROR_OUTCOME_RETRYABLE_NO_EFFECT
        recover = protocol.ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED
        attention = (
            protocol.ERROR_OUTCOME_OPERATOR_ATTENTION_REQUIRED
        )
        expected = {
            "get_activation": {
                "activation_mismatch": {final},
                "activation_unavailable": {retry},
                "deadline_exceeded": {retry},
                "instance_unknown": {final},
                "operation_unsupported": {final},
                "peer_unauthorized": {final},
                "production_disabled": {final},
                "provider_failure": {retry},
                "provider_unavailable": {retry},
                "replay_rejected": {final},
                "request_out_of_order": {final},
                "supervisor_restarting": {retry},
            },
            "start_scope": {
                "activation_mismatch": {final},
                "activation_unavailable": {retry},
                "deadline_exceeded": {retry, recover},
                "instance_unknown": {final},
                "journal_binding_mismatch": {attention},
                "operation_unsupported": {final},
                "peer_unauthorized": {final},
                "production_disabled": {final},
                "provider_failure": {recover},
                "provider_unavailable": {retry, recover},
                "recovery_attention_required": {attention},
                "replay_rejected": {final, recover},
                "request_out_of_order": {final},
                "scope_incarnation_mismatch": {final},
                "scope_not_found": {recover},
                "scope_state_conflict": {recover, attention},
                "session_conflict": {recover, attention},
                "supervisor_restarting": {retry, recover},
            },
            "await_capture_event": {
                "activation_mismatch": {attention},
                "activation_unavailable": {retry},
                "deadline_exceeded": {retry, recover},
                "instance_unknown": {attention},
                "journal_binding_mismatch": {attention},
                "operation_unsupported": {attention},
                "peer_unauthorized": {attention},
                "production_disabled": {attention},
                "provider_failure": {recover},
                "provider_unavailable": {retry, recover},
                "recovery_attention_required": {attention},
                "replay_rejected": {recover},
                "request_out_of_order": {recover},
                "scope_incarnation_mismatch": {attention},
                "scope_not_found": {recover},
                "scope_state_conflict": {recover, attention},
                "session_conflict": {recover, attention},
                "supervisor_restarting": {retry, recover},
            },
            "request_clearance": {
                "activation_mismatch": {attention},
                "activation_unavailable": {retry},
                "deadline_exceeded": {retry, recover},
                "instance_unknown": {attention},
                "journal_binding_mismatch": {attention},
                "operation_unsupported": {attention},
                "peer_unauthorized": {attention},
                "production_disabled": {attention},
                "provider_failure": {recover},
                "provider_unavailable": {retry, recover},
                "recovery_attention_required": {attention},
                "replay_rejected": {recover},
                "request_out_of_order": {recover},
                "scope_incarnation_mismatch": {attention},
                "scope_not_found": {recover},
                "scope_state_conflict": {recover, attention},
                "session_conflict": {recover, attention},
                "supervisor_restarting": {retry, recover},
            },
            "recover_scope": {
                "activation_mismatch": {attention},
                "activation_unavailable": {retry},
                "deadline_exceeded": {retry, recover},
                "instance_unknown": {attention},
                "journal_binding_mismatch": {attention},
                "operation_unsupported": {attention},
                "peer_unauthorized": {attention},
                "production_disabled": {attention},
                "provider_failure": {recover},
                "provider_unavailable": {retry, recover},
                "recovery_attention_required": {attention},
                "replay_rejected": {recover},
                "request_out_of_order": {recover},
                "scope_incarnation_mismatch": {attention},
                "scope_not_found": {final, attention},
                "scope_state_conflict": {recover, attention},
                "session_conflict": {recover, attention},
                "supervisor_restarting": {retry, recover},
            },
        }
        all_codes = set().union(
            *(
                set(outcomes_by_code)
                for outcomes_by_code in expected.values()
            )
        )
        all_outcomes = set(protocol.ERROR_OUTCOMES)
        fixture = Fixture()
        known_recovery_payload = fixture.payload("recover_scope")
        known_recovery_payload["expected_ledger_head_sha256"] = digest(
            "known-recovery-head"
        )
        known_recovery_request = protocol.build_request(
            fixture.server_hello,
            request_id="jlqreq-" + ("8" * 32),
            sequence=1,
            operation="recover_scope",
            payload=known_recovery_payload,
        )

        for operation, outcomes_by_code in expected.items():
            request = self.request(fixture, operation)
            expected_head = (
                None
                if operation in {"get_activation", "start_scope"}
                else request["payload"][
                    "expected_ledger_head_sha256"
                ]
            )
            for error_code in all_codes:
                permitted = outcomes_by_code.get(error_code, set())
                for error_outcome in all_outcomes:
                    with self.subTest(
                        operation=operation,
                        error_code=error_code,
                        error_outcome=error_outcome,
                    ):
                        case_request = request
                        case_expected_head = expected_head
                        if (
                            operation == "recover_scope"
                            and error_code == "scope_not_found"
                            and error_outcome == attention
                        ):
                            case_request = known_recovery_request
                            case_expected_head = (
                                known_recovery_payload[
                                    "expected_ledger_head_sha256"
                                ]
                            )
                        observed_head = (
                            case_expected_head
                            if error_outcome in {final, retry}
                            else digest(
                                f"{operation}-{error_code}-"
                                f"{error_outcome}"
                            )
                        )
                        if error_outcome in permitted:
                            response = protocol.build_error_response(
                                case_request,
                                error_code=error_code,
                                error_outcome=error_outcome,
                                observed_ledger_head_sha256=(
                                    observed_head
                                ),
                            )
                            self.assertEqual(
                                protocol.validate_response_for_request(
                                    fixture.client_hello,
                                    fixture.server_hello,
                                    case_request,
                                    response,
                                ),
                                response,
                            )
                            continue
                        code = (
                            "lifecycle_supervisor_remote_error_"
                            "operation_invalid"
                            if error_code not in outcomes_by_code
                            else (
                                "lifecycle_supervisor_remote_error_"
                                "outcome_invalid"
                            )
                        )
                        self.assert_code(
                            code,
                            protocol.build_error_response,
                            case_request,
                            error_code=error_code,
                            error_outcome=error_outcome,
                            observed_ledger_head_sha256=observed_head,
                        )

        request = self.request(fixture, "start_scope")
        self.assert_code(
            "lifecycle_supervisor_remote_error_code_invalid",
            protocol.build_error_response,
            request,
            error_code="surprise_error",
            error_outcome=final,
            observed_ledger_head_sha256=None,
        )

    def test_no_effect_errors_bind_the_request_ledger_head(
        self,
    ) -> None:
        fixture = Fixture()
        final = protocol.ERROR_OUTCOME_FINAL_NO_EFFECT
        retry = protocol.ERROR_OUTCOME_RETRYABLE_NO_EFFECT
        cases = [
            (operation, "activation_unavailable", retry)
            for operation in protocol.OPERATIONS
        ] + [
            ("get_activation", "activation_mismatch", final),
            ("start_scope", "activation_mismatch", final),
            ("recover_scope", "scope_not_found", final),
        ]
        for operation, error_code, error_outcome in cases:
            request = self.request(fixture, operation)
            expected_head = (
                None
                if operation in {"get_activation", "start_scope"}
                else request["payload"][
                    "expected_ledger_head_sha256"
                ]
            )
            with self.subTest(
                operation=operation,
                error_code=error_code,
                error_outcome=error_outcome,
            ):
                response = protocol.build_error_response(
                    request,
                    error_code=error_code,
                    error_outcome=error_outcome,
                    observed_ledger_head_sha256=expected_head,
                )
                changed = copy.deepcopy(response)
                changed["observed_ledger_head_sha256"] = digest(
                    f"wrong-{operation}-{error_outcome}"
                )
                code = (
                    "lifecycle_supervisor_remote_error_"
                    "ledger_head_invalid"
                    if operation
                    in {"get_activation", "start_scope"}
                    else (
                        "lifecycle_supervisor_remote_error_"
                        "ledger_head_mismatch"
                    )
                )
                self.assert_code(
                    code,
                    protocol.validate_response_for_request,
                    fixture.client_hello,
                    fixture.server_hello,
                    request,
                    changed,
                )

    def test_recover_scope_not_found_depends_on_known_head(
        self,
    ) -> None:
        fixture = Fixture()
        final = protocol.ERROR_OUTCOME_FINAL_NO_EFFECT
        attention = (
            protocol.ERROR_OUTCOME_OPERATOR_ATTENTION_REQUIRED
        )
        unknown_request = self.request(fixture, "recover_scope")
        response = protocol.build_error_response(
            unknown_request,
            error_code="scope_not_found",
            error_outcome=final,
            observed_ledger_head_sha256=None,
        )
        self.assertEqual(
            protocol.validate_response_for_request(
                fixture.client_hello,
                fixture.server_hello,
                unknown_request,
                response,
            ),
            response,
        )
        self.assert_code(
            "lifecycle_supervisor_remote_error_outcome_invalid",
            protocol.build_error_response,
            unknown_request,
            error_code="scope_not_found",
            error_outcome=attention,
            observed_ledger_head_sha256=None,
        )

        payload = fixture.payload("recover_scope")
        payload["expected_ledger_head_sha256"] = digest(
            "known-recovery-head"
        )
        request = protocol.build_request(
            fixture.server_hello,
            request_id="jlqreq-" + ("9" * 32),
            sequence=1,
            operation="recover_scope",
            payload=payload,
        )
        self.assert_code(
            "lifecycle_supervisor_remote_error_outcome_invalid",
            protocol.build_error_response,
            request,
            error_code="scope_not_found",
            error_outcome=(
                protocol.ERROR_OUTCOME_FINAL_NO_EFFECT
            ),
            observed_ledger_head_sha256=payload[
                "expected_ledger_head_sha256"
            ],
        )
        for observed_head in (
            None,
            digest("last-readable-recovery-head"),
        ):
            with self.subTest(observed_head=observed_head):
                response = protocol.build_error_response(
                    request,
                    error_code="scope_not_found",
                    error_outcome=attention,
                    observed_ledger_head_sha256=observed_head,
                )
                self.assertEqual(
                    protocol.validate_response_for_request(
                        fixture.client_hello,
                        fixture.server_hello,
                        request,
                        response,
                    ),
                    response,
                )

    def test_effectful_failures_cannot_claim_no_effect(
        self,
    ) -> None:
        fixture = Fixture()
        final = protocol.ERROR_OUTCOME_FINAL_NO_EFFECT
        attention = (
            protocol.ERROR_OUTCOME_OPERATOR_ATTENTION_REQUIRED
        )
        recover = protocol.ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED
        attention_codes = (
            "activation_mismatch",
            "instance_unknown",
            "operation_unsupported",
            "peer_unauthorized",
            "production_disabled",
            "scope_incarnation_mismatch",
        )
        recovery_codes = (
            "replay_rejected",
            "request_out_of_order",
        )
        for operation in (
            "await_capture_event",
            "request_clearance",
            "recover_scope",
        ):
            request = self.request(fixture, operation)
            for error_code in attention_codes:
                with self.subTest(
                    operation=operation,
                    error_code=error_code,
                ):
                    response = protocol.build_error_response(
                        request,
                        error_code=error_code,
                        error_outcome=attention,
                        observed_ledger_head_sha256=None,
                    )
                    self.assertEqual(response["status"], "error")
                    self.assert_code(
                        "lifecycle_supervisor_remote_error_"
                        "outcome_invalid",
                        protocol.build_error_response,
                        request,
                        error_code=error_code,
                        error_outcome=final,
                        observed_ledger_head_sha256=request["payload"][
                            "expected_ledger_head_sha256"
                        ],
                    )
            for error_code in recovery_codes:
                with self.subTest(
                    operation=operation,
                    error_code=error_code,
                ):
                    response = protocol.build_error_response(
                        request,
                        error_code=error_code,
                        error_outcome=recover,
                        observed_ledger_head_sha256=None,
                    )
                    self.assertEqual(response["status"], "error")
                    self.assert_code(
                        "lifecycle_supervisor_remote_error_"
                        "outcome_invalid",
                        protocol.build_error_response,
                        request,
                        error_code=error_code,
                        error_outcome=final,
                        observed_ledger_head_sha256=request["payload"][
                            "expected_ledger_head_sha256"
                        ],
                    )

    def test_uncertain_error_outcomes_carry_nullable_observation(
        self,
    ) -> None:
        fixture = Fixture()
        request = self.request(fixture, "start_scope")
        cases = (
            (
                "provider_failure",
                protocol.ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED,
            ),
            (
                "journal_binding_mismatch",
                protocol.ERROR_OUTCOME_OPERATOR_ATTENTION_REQUIRED,
            ),
        )
        for error_code, error_outcome in cases:
            for observed_head in (None, digest("last-durable-head")):
                with self.subTest(
                    error_code=error_code,
                    observed_head=observed_head,
                ):
                    response = protocol.build_error_response(
                        request,
                        error_code=error_code,
                        error_outcome=error_outcome,
                        observed_ledger_head_sha256=observed_head,
                    )
                    self.assertEqual(
                        protocol.validate_response_for_request(
                            fixture.client_hello,
                            fixture.server_hello,
                            request,
                            response,
                        ),
                        response,
                    )
        response = protocol.build_error_response(
            request,
            error_code="provider_failure",
            error_outcome=(
                protocol.ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED
            ),
            observed_ledger_head_sha256=None,
        )
        response["observed_ledger_head_sha256"] = "not-a-digest"
        self.assert_code(
            "lifecycle_supervisor_observed_ledger_head_sha256_invalid",
            protocol.normalize_response,
            response,
        )

    def test_response_v3_preserves_v2_error_outcome_semantics(
        self,
    ) -> None:
        fixture = Fixture()
        request = self.request(fixture, "get_activation")
        response = protocol.build_success_response(
            request, result=fixture.result("get_activation")
        )
        self.assertTrue(protocol.RESPONSE_SCHEMA.endswith(".v3"))
        for field in (
            "error_code",
            "error_outcome",
            "observed_ledger_head_sha256",
        ):
            self.assertIsNone(response[field])
            changed = copy.deepcopy(response)
            changed[field] = (
                "activation_mismatch"
                if field == "error_code"
                else (
                    protocol.ERROR_OUTCOME_FINAL_NO_EFFECT
                    if field == "error_outcome"
                    else digest("forged-observed-head")
                )
            )
            self.assert_code(
                "lifecycle_supervisor_success_error_fields_invalid",
                protocol.normalize_response,
                changed,
            )

        legacy = copy.deepcopy(response)
        legacy.pop("error_outcome")
        legacy.pop("observed_ledger_head_sha256")
        legacy["retryable"] = False
        self.assert_code(
            "lifecycle_supervisor_response_fields_invalid",
            protocol.normalize_response,
            legacy,
        )
        for version in ("v1", "v2"):
            with self.subTest(old_schema=version):
                old_schema = copy.deepcopy(response)
                old_schema["schema_version"] = (
                    "john-lomein.persona-qualification-"
                    f"lifecycle-supervisor-response.{version}"
                )
                self.assert_code(
                    "lifecycle_supervisor_response_schema_invalid",
                    protocol.normalize_response,
                    old_schema,
                )

        final = protocol.ERROR_OUTCOME_FINAL_NO_EFFECT
        retry = protocol.ERROR_OUTCOME_RETRYABLE_NO_EFFECT
        recover = protocol.ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED
        attention = (
            protocol.ERROR_OUTCOME_OPERATOR_ATTENTION_REQUIRED
        )
        self.assertTrue(protocol.error_outcome_is_no_effect(final))
        self.assertTrue(protocol.error_outcome_is_no_effect(retry))
        self.assertFalse(protocol.error_outcome_retryable(final))
        self.assertTrue(protocol.error_outcome_retryable(retry))
        self.assertTrue(
            protocol.error_outcome_requires_recovery(recover)
        )
        self.assertTrue(
            protocol.error_outcome_requires_operator_attention(
                attention
            )
        )
        for helper in (
            protocol.error_outcome_is_no_effect,
            protocol.error_outcome_retryable,
            protocol.error_outcome_requires_recovery,
            protocol.error_outcome_requires_operator_attention,
        ):
            self.assert_code(
                "lifecycle_supervisor_remote_error_outcome_invalid",
                helper,
                "invented_outcome",
            )

    def test_receipt_digests_are_recomputed(self) -> None:
        fixture = Fixture()
        result = fixture.result("start_scope")
        result["scope_started_receipt_sha256"] = digest("forged")
        self.assert_code(
            "lifecycle_supervisor_scope_started_digest_mismatch",
            protocol.normalize_operation_result,
            "start_scope",
            result,
        )

        result = fixture.result("request_clearance")
        result["clearance_bundle"]["scope_empty_receipt"][
            "adoption_eligible"
        ] = False
        with self.assertRaises(
            protocol.LifecycleSupervisorProtocolError
        ):
            protocol.normalize_operation_result(
                "request_clearance", result
            )

    def test_clearance_response_binds_exact_outer_intent(self) -> None:
        fixture = Fixture()
        request = self.request(fixture, "request_clearance")
        result = fixture.result("request_clearance")
        result["clearance_bundle"]["clearance_intent_receipt"][
            "outer_clearance_intent_record_sha256"
        ] = digest("different-outer-clearance")
        intent = result["clearance_bundle"][
            "clearance_intent_receipt"
        ]
        result["clearance_bundle"][
            "clearance_intent_receipt_sha256"
        ] = lifecycle.clearance_intent_receipt_sha256(intent)
        result["clearance_bundle"]["scope_empty_receipt"][
            "outer_clearance_intent_record_sha256"
        ] = intent["outer_clearance_intent_record_sha256"]
        result["clearance_bundle"]["scope_empty_receipt"][
            "clearance_intent_receipt_sha256"
        ] = result["clearance_bundle"][
            "clearance_intent_receipt_sha256"
        ]
        empty = result["clearance_bundle"]["scope_empty_receipt"]
        result["clearance_bundle"]["scope_empty_receipt_sha256"] = (
            lifecycle.scope_empty_receipt_sha256(empty)
        )
        result["clearance_bundle_sha256"] = (
            lifecycle.clearance_bundle_sha256(
                result["clearance_bundle"]
            )
        )
        response = protocol.build_success_response(
            request, result=result
        )
        self.assert_code(
            "lifecycle_supervisor_clearance_binding_mismatch",
            protocol.validate_response_for_request,
            fixture.client_hello,
            fixture.server_hello,
            request,
            response,
        )

    def test_changed_epoch_cannot_be_clean_or_adoption_eligible(self) -> None:
        fixture = Fixture()
        result = fixture.result("recover_scope")
        result["clearance_bundle"]["scope_empty_receipt"][
            "clearance_supervisor_epoch_id"
        ] = digest("changed-clearance-epoch")
        with self.assertRaises(
            protocol.LifecycleSupervisorProtocolError
        ):
            protocol.normalize_operation_result(
                "recover_scope", result
            )

        forced = Fixture(
            disposition="forced_termination",
            changed_epoch=True,
        )
        result = forced.result("recover_scope")
        self.assertFalse(
            protocol.normalize_operation_result(
                "recover_scope", result
            )["clearance_bundle"]["scope_empty_receipt"][
                "adoption_eligible"
            ]
        )

    def test_server_request_guard_rejects_replay_and_gaps(self) -> None:
        fixture = Fixture()
        guard = protocol.ServerRequestGuard(
            fixture.client_hello, fixture.server_hello
        )
        first = self.request(fixture, "get_activation", sequence=1)
        guard.accept(first)
        self.assert_code(
            "lifecycle_supervisor_request_sequence_replayed",
            guard.accept,
            first,
        )
        third = self.request(fixture, "get_activation", sequence=3)
        self.assert_code(
            "lifecycle_supervisor_request_sequence_replayed",
            guard.accept,
            third,
        )

    def test_client_exchange_guard_allows_one_in_flight(self) -> None:
        fixture = Fixture()
        guard = protocol.ClientExchangeGuard(
            fixture.client_hello, fixture.server_hello
        )
        request = guard.build_request(
            request_id="jlqreq-" + ("a" * 32),
            operation="get_activation",
            payload=fixture.payload("get_activation"),
        )
        self.assert_code(
            "lifecycle_supervisor_request_already_in_flight",
            guard.build_request,
            request_id="jlqreq-" + ("b" * 32),
            operation="get_activation",
            payload=fixture.payload("get_activation"),
        )
        response = protocol.build_success_response(
            request, result=fixture.result("get_activation")
        )
        guard.accept_response(response)
        self.assert_code(
            "lifecycle_supervisor_response_without_request",
            guard.accept_response,
            response,
        )

    def test_null_activation_handshake_is_discovery_only(self) -> None:
        fixture = Fixture()
        hello = protocol.build_server_hello(
            fixture.client_hello,
            server_nonce=fixture.server_nonce,
            protocol_session_id=fixture.protocol_session,
            supervisor_incarnation_id=fixture.supervisor_incarnation,
            supervisor_epoch_id=fixture.clearance_epoch,
            host_boot_id_sha256=fixture.boot,
            supervisor_policy_sha256=fixture.policy,
            supervisor_bundle_sha256=fixture.bundle_digest,
            helper_activation_policy_sha256=fixture.helper_policy,
            lifecycle_canary_sha256=fixture.canary,
            activation_receipt_sha256=None,
        )
        payload = fixture.payload("get_activation")
        payload["expected_activation_receipt_sha256"] = None
        request = protocol.build_request(
            hello,
            request_id="jlqreq-" + ("c" * 32),
            sequence=1,
            operation="get_activation",
            payload=payload,
        )
        guard = protocol.ServerRequestGuard(
            fixture.client_hello, hello
        )
        guard.accept(request)
        self.assert_code(
            "lifecycle_supervisor_session_closed",
            guard.accept,
            request,
        )

        operational = protocol.build_request(
            hello,
            request_id="jlqreq-" + ("d" * 32),
            sequence=1,
            operation="start_scope",
            payload=fixture.payload("start_scope"),
        )
        self.assert_code(
            "lifecycle_supervisor_activation_discovery_required",
            protocol.validate_request_for_handshake,
            fixture.client_hello,
            hello,
            operational,
        )

    def test_recovery_result_cannot_claim_future_outer_record(self) -> None:
        fixture = Fixture()
        request = self.request(fixture, "recover_scope")
        result = fixture.result("recover_scope")
        result["effect_origin_record_revision"] = 11
        response = protocol.build_success_response(
            request, result=result
        )
        self.assert_code(
            "lifecycle_supervisor_recovery_future_outer_record",
            protocol.validate_response_for_request,
            fixture.client_hello,
            fixture.server_hello,
            request,
            response,
        )

    def test_attention_and_scope_empty_sessions_are_recoverable(self) -> None:
        fixture = Fixture()
        for state in (
            "operator_attention",
            "operator_resolved",
            "lifecycle_scope_empty",
        ):
            with self.subTest(state=state):
                payload = fixture.payload("recover_scope")
                payload["outer_journal_record_state"] = state
                payload["outer_journal_record_revision"] = 11
                payload["outer_journal_record_sha256"] = digest(
                    f"{state}-outer-record"
                )
                normalized = protocol.normalize_operation_payload(
                    "recover_scope", payload
                )
                self.assertEqual(
                    normalized["outer_journal_record_state"], state
                )
                request = protocol.build_request(
                    fixture.server_hello,
                    request_id="jlqreq-" + ("f" * 32),
                    sequence=1,
                    operation="recover_scope",
                    payload=payload,
                )
                response = protocol.build_success_response(
                    request, result=fixture.result("recover_scope")
                )
                self.assertEqual(
                    protocol.validate_response_for_request(
                        fixture.client_hello,
                        fixture.server_hello,
                        request,
                        response,
                    ),
                    response,
                )


if __name__ == "__main__":
    unittest.main()
