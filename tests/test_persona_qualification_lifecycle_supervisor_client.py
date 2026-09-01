from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import pickle
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (
    john_lomein_persona_qualification_capture_staging_receipts
    as staging_receipts,
)
from qualification_attestor import (
    john_lomein_persona_qualification_lifecycle_receipts as lifecycle,
)
from qualification_attestor import (
    john_lomein_persona_qualification_lifecycle_supervisor_client
    as client_module,
)
from qualification_attestor import (
    john_lomein_persona_qualification_lifecycle_supervisor_protocol
    as protocol,
)
from qualification_attestor import (
    john_lomein_persona_qualification_transaction_journal as journal,
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class DeterministicRandom:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, count: int) -> bytes:
        self.calls += 1
        seed = hashlib.sha256(
            f"random-{self.calls}".encode("ascii")
        ).digest()
        return seed[:count]


class ScriptedSupervisorSocket:
    def __init__(
        self,
        *,
        config: dict[str, Any],
        activation: dict[str, Any],
        response_factory,
        peer_uid: int = 0,
        activation_in_hello: bool = True,
        supervisor_epoch_id: str | None = None,
        fail_request_send: bool = False,
        mutate_server_hello=None,
        mutate_response=None,
        after_hello_drained=None,
        after_response_drained=None,
    ) -> None:
        self.config = config
        self.activation = activation
        self.response_factory = response_factory
        self.peer_uid = peer_uid
        self.activation_in_hello = activation_in_hello
        self.supervisor_epoch_id = (
            digest("supervisor-epoch")
            if supervisor_epoch_id is None
            else supervisor_epoch_id
        )
        self.fail_request_send = fail_request_send
        self.mutate_server_hello = mutate_server_hello
        self.mutate_response = mutate_response
        self.after_hello_drained = after_hello_drained
        self.after_response_drained = after_response_drained
        self.hello_drained = False
        self.response_drained = False
        self.sent: list[dict[str, Any]] = []
        self.connected: list[str] = []
        self.response = bytearray()
        self.closed = False
        self.server_hello: dict[str, Any] | None = None

    def settimeout(self, _timeout: float) -> None:
        return None

    def connect(self, selected: str) -> None:
        self.connected.append(selected)

    def getpeereid(self) -> tuple[int, int]:
        return self.peer_uid, 0

    def sendall(self, raw: bytes) -> None:
        message = protocol.decode_frame(raw)
        self.sent.append(message)
        if len(self.sent) == 1:
            hello = protocol.normalize_client_hello(message)
            self.server_hello = protocol.build_server_hello(
                hello,
                server_nonce=digest("server-nonce"),
                protocol_session_id=digest("protocol-session"),
                supervisor_incarnation_id=digest(
                    "supervisor-incarnation"
                ),
                supervisor_epoch_id=self.supervisor_epoch_id,
                host_boot_id_sha256=self.activation[
                    "host_boot_id_sha256"
                ],
                supervisor_policy_sha256=self.config[
                    "expected_supervisor_policy_sha256"
                ],
                supervisor_bundle_sha256=self.config[
                    "expected_supervisor_bundle_sha256"
                ],
                helper_activation_policy_sha256=self.config[
                    "expected_helper_activation_policy_sha256"
                ],
                lifecycle_canary_sha256=self.config[
                    "expected_lifecycle_canary_sha256"
                ],
                activation_receipt_sha256=(
                    lifecycle.activation_receipt_sha256(
                        self.activation
                    )
                    if self.activation_in_hello
                    else None
                ),
            )
            if self.mutate_server_hello is not None:
                self.server_hello = self.mutate_server_hello(
                    copy.deepcopy(self.server_hello)
                )
            self.response.extend(
                protocol.encode_frame(self.server_hello)
            )
            return
        if len(self.sent) != 2 or self.server_hello is None:
            raise AssertionError("unexpected client frame")
        if self.fail_request_send:
            raise OSError("simulated partial request write")
        request = protocol.validate_request_for_handshake(
            self.sent[0],
            self.server_hello,
            message,
        )
        response = self.response_factory(request, self.server_hello)
        if self.mutate_response is not None:
            response = self.mutate_response(copy.deepcopy(response))
        self.response.extend(protocol.encode_frame(response))

    def recv(self, count: int) -> bytes:
        if not self.response:
            return b""
        selected = bytes(self.response[:count])
        del self.response[:count]
        if (
            not self.response
            and len(self.sent) == 1
            and not self.hello_drained
        ):
            self.hello_drained = True
            if self.after_hello_drained is not None:
                self.after_hello_drained()
        elif (
            not self.response
            and len(self.sent) == 2
            and not self.response_drained
        ):
            self.response_drained = True
            if self.after_response_drained is not None:
                self.after_response_drained()
        return selected

    def close(self) -> None:
        self.closed = True


class LifecycleSupervisorClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.stores: list[journal.TransactionJournalStore] = []
        self.parent_fds: list[int] = []
        self.addCleanup(self.close_resources)
        self.activation = self.activation_receipt()
        self.config = self.client_config()
        self.random = DeterministicRandom()

    def close_resources(self) -> None:
        for descriptor in reversed(self.parent_fds):
            try:
                os.close(descriptor)
            except OSError:
                pass
        for store in reversed(self.stores):
            if store.active:
                store.close()

    def activation_receipt(self) -> dict[str, Any]:
        return {
            "schema_version": lifecycle.ACTIVATION_RECEIPT_SCHEMA,
            "status": lifecycle.ACTIVATION_STATUS,
            "system": "Linux",
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": "linux_cgroup_v2",
            "supervisor_policy_sha256": digest("supervisor-policy"),
            "supervisor_bundle_sha256": digest("supervisor-bundle"),
            "helper_activation_policy_sha256": digest(
                "helper-policy"
            ),
            "lifecycle_canary_sha256": digest("lifecycle-canary"),
            "host_boot_measurement": "linux_boot_id",
            "host_boot_id_sha256": digest("host-boot"),
            "assertions": {
                assertion: True
                for assertion in lifecycle.ACTIVATION_ASSERTIONS
            },
            "production_activation": False,
        }

    def client_config(self) -> dict[str, Any]:
        return {
            "schema_version": client_module.CLIENT_CONFIG_SCHEMA,
            "instance_slug": "john-test",
            "supervisor_uid": 0,
            "requester_uid": 0,
            "requester_gid": 0,
            "socket_path": "/run/john-lomein/lifecycle.sock",
            "connect_timeout_seconds": 5,
            "request_timeout_seconds": 30,
            "expected_supervisor_policy_sha256": self.activation[
                "supervisor_policy_sha256"
            ],
            "expected_supervisor_bundle_sha256": self.activation[
                "supervisor_bundle_sha256"
            ],
            "expected_helper_activation_policy_sha256": (
                self.activation[
                    "helper_activation_policy_sha256"
                ]
            ),
            "expected_lifecycle_canary_sha256": self.activation[
                "lifecycle_canary_sha256"
            ],
        }

    def client_with_socket(
        self,
        scripted: ScriptedSupervisorSocket,
    ) -> client_module.LifecycleSupervisorClient:
        return client_module._new_lifecycle_supervisor_client_for_test(
            self.config,
            socket_factory=lambda *_args: scripted,
            random_bytes=self.random,
        )

    def success_socket(
        self,
        response_factory,
        activation: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ScriptedSupervisorSocket:
        return ScriptedSupervisorSocket(
            config=self.config,
            activation=(
                self.activation if activation is None else activation
            ),
            response_factory=response_factory,
            **kwargs,
        )

    def make_layout(
        self,
        marker: int,
    ) -> tuple[Path, Path, Path]:
        anchor = self.root / f"layout-{marker}"
        store_path = anchor / "state" / "transactions"
        store_path.mkdir(parents=True, mode=0o700)
        anchor.chmod(0o700)
        (anchor / "state").chmod(0o700)
        store_path.chmod(0o700)
        completed = store_path / ".completed"
        completed.mkdir(mode=0o700)
        completed.chmod(0o700)
        lock = store_path / ".lock"
        lock.touch(mode=0o600)
        lock.chmod(0o600)
        final_parent = anchor / "final"
        final_parent.mkdir(mode=0o700)
        return anchor, store_path, final_parent

    def exposure_receipt(
        self,
        *,
        session_id: str,
        intent_sha256: str,
        filesystem_device: int,
    ) -> dict[str, Any]:
        return {
            "schema_version": (
                staging_receipts.STAGING_EXPOSURE_RECEIPT_SCHEMA
            ),
            "status": staging_receipts.STAGING_EXPOSURE_STATUS,
            "capture_session_id": session_id,
            "staging_leaf_name": f"session-{session_id}",
            "staging_transaction_intent_sha256": intent_sha256,
            "staging_leaf_identity_sha256": digest(
                f"leaf-{session_id}"
            ),
            "capture_uid": 4201,
            "export_gid": 4202,
            "staging_leaf_mode": 0o700,
            "filesystem_device": filesystem_device,
            "shared_root_identity_sha256": digest("shared-root"),
            "recovery_namespace_identity_sha256": digest("recovery"),
            "quarantine_namespace_identity_sha256": digest(
                "quarantine"
            ),
            "transactions_namespace_identity_sha256": digest(
                "transactions"
            ),
            "staging_journal_schema": (
                staging_receipts.CAPTURE_STAGING_JOURNAL_SCHEMA
            ),
            "staging_journal_sequence": 3,
            "staging_journal_head_sha256": digest("staging-head"),
        }

    def commit_lifecycle_successor(
        self,
        session: journal.TransactionJournalSession,
        *,
        operation: str,
        next_state: str,
        details: dict[str, Any],
        recorded_at_unix: int,
        marker: str,
        event_sequence: int | None = None,
        event: str | None = None,
        event_record_sha256: str | None = None,
        event_evidence_sha256: str | None = None,
    ) -> journal.TransactionJournalRecord:
        snapshot = session.live_snapshot()
        lease = session._begin_lifecycle_operation_for_client(
            operation=operation,
            snapshot=snapshot,
        )
        request_sha256 = digest(f"{marker}-request")
        lease.mark_dispatched(request_sha256)
        binding = {
            "schema_version": (
                journal.LIFECYCLE_OPERATION_BINDING_SCHEMA
            ),
            "operation": operation,
            "base_record_revision": snapshot.revision,
            "base_record_sha256": snapshot.head_record_sha256,
            "request_sha256": request_sha256,
            "response_sha256": digest(f"{marker}-response"),
            "outcome": "success",
            "error_code": None,
            "result_sha256": digest(f"{marker}-result"),
            "supervisor_ledger_head_sha256": digest(
                f"{marker}-ledger-head"
            ),
            "supervisor_event_sequence": event_sequence,
            "supervisor_event": event,
            "supervisor_event_record_sha256": event_record_sha256,
            "supervisor_event_evidence_sha256": (
                event_evidence_sha256
            ),
        }
        permit = lease.mint_successor_permit(
            next_state=next_state,
            details=details,
            lifecycle_operation_binding=binding,
            recorded_at_unix=recorded_at_unix,
        )
        return permit.commit()

    def make_journal(
        self,
        state: str,
        *,
        marker: int = 1,
    ) -> dict[str, Any]:
        anchor, store_path, final_parent = self.make_layout(marker)
        store = journal._open_transaction_store_for_test(
            store_path, anchor
        )
        self.stores.append(store)
        session = store._reserve_session_for_test(
            instance_slug="john-test",
            control_sha256=digest("control"),
            handoff_policy_sha256=digest("handoff-policy"),
            recorded_at_unix=1,
            session_id=f"{marker:064x}",
        )
        parent_fd = os.open(
            final_parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        os.set_inheritable(parent_fd, False)
        self.parent_fds.append(parent_fd)
        recorder = session.begin_capture_recording(
            capture_uid=4201,
            export_gid=4202,
            retained_final_parent_fd=parent_fd,
            handoff_policy_sha256=digest("handoff-policy"),
            recorded_at_unix=2,
        )
        exposure = self.exposure_receipt(
            session_id=session.session_id,
            intent_sha256=(
                recorder.staging_transaction_intent_sha256
            ),
            filesystem_device=recorder.required_device,
        )
        exposure_sha256 = (
            staging_receipts.staging_exposure_receipt_sha256(
                exposure
            )
        )
        recorder.record_staging_exposed(
            exposure,
            receipt_sha256=exposure_sha256,
            recorded_at_unix=3,
        )
        activation_sha256 = lifecycle.activation_receipt_sha256(
            self.activation
        )
        launch = recorder.record_child_launch_intent(
            self.activation,
            activation_receipt_sha256=activation_sha256,
            recorded_at_unix=4,
        )
        context: dict[str, Any] = {
            "store": store,
            "session": session,
            "recorder": recorder,
            "exposure": exposure,
            "exposure_sha256": exposure_sha256,
            "launch": launch,
            "activation_sha256": activation_sha256,
            "store_path": store_path,
        }
        if state == "child_launch_intent":
            return context
        staging_intent = next(
            record
            for record in session.records
            if record.state == "staging_create_intent"
        )
        scope_id = f"jlq-root_supervisor-{session.session_id}"
        incarnation = protocol.derive_scope_incarnation_id(
            instance_slug="john-test",
            capture_session_id=session.session_id,
            child_launch_intent_record_sha256=launch.record_sha256,
            lifecycle_activation_receipt_sha256=activation_sha256,
        )
        started = {
            "schema_version": lifecycle.SCOPE_STARTED_RECEIPT_SCHEMA,
            "status": lifecycle.SCOPE_STARTED_STATUS,
            "capture_session_id": session.session_id,
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": "linux_cgroup_v2",
            "lifecycle_scope_id": scope_id,
            "scope_incarnation_id": incarnation,
            "supervisor_epoch_id": digest("supervisor-epoch"),
            "host_boot_id_sha256": self.activation[
                "host_boot_id_sha256"
            ],
            "staging_transaction_intent_sha256": (
                staging_intent.record_sha256
            ),
            "staging_exposure_receipt_sha256": exposure_sha256,
            "child_launch_intent_record_sha256": (
                launch.record_sha256
            ),
            "handoff_policy_sha256": digest("handoff-policy"),
            "helper_activation_policy_sha256": self.activation[
                "helper_activation_policy_sha256"
            ],
            "capture_uid": 4201,
            "export_gid": 4202,
            "lifecycle_activation_receipt_sha256": (
                activation_sha256
            ),
        }
        started_sha256 = lifecycle.scope_started_receipt_sha256(
            started
        )
        running = self.commit_lifecycle_successor(
            session,
            operation="start_scope",
            next_state="child_running",
            details={
                "lifecycle_scope_started_receipt": started,
                "lifecycle_scope_started_receipt_sha256": (
                    started_sha256
                ),
            },
            recorded_at_unix=5,
            marker=f"fixture-start-{marker}",
        )
        context.update(
            {
                "scope_id": scope_id,
                "incarnation": incarnation,
                "started": started,
                "started_sha256": started_sha256,
                "running": running,
            }
        )
        if state == "child_running":
            return context
        ready_details = {
            "provisional_name": f"opaque-capture-{marker:032x}",
            "capture_object_identity_sha256": digest(
                f"capture-object-{marker}"
            ),
            "capture_selection_sha256": digest(
                f"capture-selection-{marker}"
            ),
            "capture_plan_sha256": digest(f"capture-plan-{marker}"),
            "capture_manifest_sha256": digest(
                f"capture-manifest-{marker}"
            ),
            "capture_boundary_policy_sha256": digest(
                "capture-boundary"
            ),
            "helper_activation_policy_sha256": self.activation[
                "helper_activation_policy_sha256"
            ],
            "request_sha256": digest(f"capture-request-{marker}"),
        }
        ready = self.commit_lifecycle_successor(
            session,
            operation="await_capture_event",
            next_state="capture_ready",
            details=ready_details,
            recorded_at_unix=6,
            marker=f"fixture-ready-{marker}",
            event_sequence=1,
            event="capture_ready",
            event_record_sha256=digest(
                f"fixture-ready-event-{marker}"
            ),
            event_evidence_sha256=(
                protocol.capture_event_evidence_sha256(
                    ready_details
                )
            ),
        )
        context["ready"] = ready
        if state == "capture_ready":
            return context
        clearance = recorder.record_lifecycle_clearance_intent(
            effect_origin_state="capture_ready",
            effect_origin_record_sha256=ready.record_sha256,
            scope_started_receipt_sha256=started_sha256,
            clearance_mode="wait_clean_then_terminate_on_deadline",
            recorded_at_unix=7,
        )
        context["clearance"] = clearance
        if state == "lifecycle_clearance_intent":
            return context
        raise AssertionError(f"unsupported fixture state: {state}")

    def make_lost_start_clearance(
        self,
        *,
        marker: int,
    ) -> dict[str, Any]:
        context = self.make_journal(
            "child_launch_intent", marker=marker
        )
        clearance = context[
            "recorder"
        ].record_lifecycle_clearance_intent(
            effect_origin_state="child_launch_intent",
            effect_origin_record_sha256=context[
                "launch"
            ].record_sha256,
            scope_started_receipt_sha256=None,
            clearance_mode="terminate_and_clear",
            recorded_at_unix=5,
        )
        session = context["session"]
        staging_intent = next(
            record
            for record in session.records
            if record.state == "staging_create_intent"
        )
        incarnation = protocol.derive_scope_incarnation_id(
            instance_slug="john-test",
            capture_session_id=session.session_id,
            child_launch_intent_record_sha256=context[
                "launch"
            ].record_sha256,
            lifecycle_activation_receipt_sha256=context[
                "activation_sha256"
            ],
        )
        started = {
            "schema_version": lifecycle.SCOPE_STARTED_RECEIPT_SCHEMA,
            "status": lifecycle.SCOPE_STARTED_STATUS,
            "capture_session_id": session.session_id,
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": "linux_cgroup_v2",
            "lifecycle_scope_id": (
                f"jlq-root_supervisor-{session.session_id}"
            ),
            "scope_incarnation_id": incarnation,
            "supervisor_epoch_id": digest(
                "lost-start-supervisor-epoch"
            ),
            "host_boot_id_sha256": self.activation[
                "host_boot_id_sha256"
            ],
            "staging_transaction_intent_sha256": (
                staging_intent.record_sha256
            ),
            "staging_exposure_receipt_sha256": context[
                "exposure_sha256"
            ],
            "child_launch_intent_record_sha256": context[
                "launch"
            ].record_sha256,
            "handoff_policy_sha256": digest("handoff-policy"),
            "helper_activation_policy_sha256": self.activation[
                "helper_activation_policy_sha256"
            ],
            "capture_uid": 4201,
            "export_gid": 4202,
            "lifecycle_activation_receipt_sha256": context[
                "activation_sha256"
            ],
        }
        context.update(
            {
                "clearance": clearance,
                "scope_id": started["lifecycle_scope_id"],
                "incarnation": incarnation,
                "started": started,
                "started_sha256": (
                    lifecycle.scope_started_receipt_sha256(started)
                ),
            }
        )
        return context

    def started_from_request(
        self,
        request: dict[str, Any],
        server: dict[str, Any],
    ) -> dict[str, Any]:
        payload = request["payload"]
        return {
            "schema_version": lifecycle.SCOPE_STARTED_RECEIPT_SCHEMA,
            "status": lifecycle.SCOPE_STARTED_STATUS,
            "capture_session_id": payload["capture_session_id"],
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": payload["lifecycle_provider"],
            "lifecycle_scope_id": payload["lifecycle_scope_id"],
            "scope_incarnation_id": payload["scope_incarnation_id"],
            "supervisor_epoch_id": server["supervisor_epoch_id"],
            "host_boot_id_sha256": server["host_boot_id_sha256"],
            "staging_transaction_intent_sha256": payload[
                "staging_transaction_intent_sha256"
            ],
            "staging_exposure_receipt_sha256": payload[
                "staging_exposure_receipt_sha256"
            ],
            "child_launch_intent_record_sha256": payload[
                "child_launch_intent_record_sha256"
            ],
            "handoff_policy_sha256": payload[
                "handoff_policy_sha256"
            ],
            "helper_activation_policy_sha256": payload[
                "helper_activation_policy_sha256"
            ],
            "capture_uid": payload["capture_uid"],
            "export_gid": payload["export_gid"],
            "lifecycle_activation_receipt_sha256": payload[
                "lifecycle_activation_receipt_sha256"
            ],
        }

    def clearance_bundle(
        self,
        context: dict[str, Any],
        request: dict[str, Any],
        server: dict[str, Any],
    ) -> dict[str, Any]:
        payload = request["payload"]
        host_reboot = (
            server["host_boot_id_sha256"]
            != context["started"]["host_boot_id_sha256"]
        )
        effect_origin_state = payload.get(
            "effect_origin_state",
            payload.get("expected_effect_origin_state"),
        )
        effect_origin_sha256 = payload.get(
            "effect_origin_record_sha256",
            payload.get("expected_effect_origin_record_sha256"),
        )
        intent_started_sha256 = payload.get(
            "scope_started_receipt_sha256",
            payload.get("expected_scope_started_receipt_sha256"),
        )
        clearance_mode = payload.get(
            "clearance_mode",
            payload.get("expected_clearance_mode"),
        )
        clearance_record_sha256 = payload.get(
            "lifecycle_clearance_intent_record_sha256",
            payload.get(
                "expected_clearance_intent_record_sha256"
            ),
        )
        intent = {
            "schema_version": (
                lifecycle.CLEARANCE_INTENT_RECEIPT_SCHEMA
            ),
            "status": lifecycle.CLEARANCE_INTENT_STATUS,
            "capture_session_id": payload["capture_session_id"],
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": "linux_cgroup_v2",
            "lifecycle_scope_id": payload["lifecycle_scope_id"],
            "scope_incarnation_id": payload["scope_incarnation_id"],
            "lifecycle_activation_receipt_sha256": payload[
                "lifecycle_activation_receipt_sha256"
            ],
            "child_launch_intent_record_sha256": payload[
                "child_launch_intent_record_sha256"
            ],
            "effect_origin_state": effect_origin_state,
            "effect_origin_record_sha256": effect_origin_sha256,
            "scope_started_receipt_sha256": intent_started_sha256,
            "clearance_mode": clearance_mode,
            "outer_clearance_intent_record_sha256": (
                clearance_record_sha256
            ),
        }
        intent_sha256 = lifecycle.clearance_intent_receipt_sha256(
            intent
        )
        empty = {
            "schema_version": lifecycle.SCOPE_EMPTY_RECEIPT_SCHEMA,
            "status": lifecycle.SCOPE_EMPTY_STATUS,
            "capture_session_id": payload["capture_session_id"],
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": "linux_cgroup_v2",
            "lifecycle_scope_id": payload["lifecycle_scope_id"],
            "scope_incarnation_id": payload["scope_incarnation_id"],
            "lifecycle_activation_receipt_sha256": payload[
                "lifecycle_activation_receipt_sha256"
            ],
            "child_launch_intent_record_sha256": payload[
                "child_launch_intent_record_sha256"
            ],
            "effect_origin_state": effect_origin_state,
            "effect_origin_record_sha256": effect_origin_sha256,
            "scope_started_receipt_sha256": context[
                "started_sha256"
            ],
            "clearance_intent_receipt_sha256": intent_sha256,
            "outer_clearance_intent_record_sha256": (
                clearance_record_sha256
            ),
            "clearance_mode": clearance_mode,
            "start_supervisor_epoch_id": context["started"][
                "supervisor_epoch_id"
            ],
            "clearance_supervisor_epoch_id": server[
                "supervisor_epoch_id"
            ],
            "start_host_boot_id_sha256": context["started"][
                "host_boot_id_sha256"
            ],
            "clearance_host_boot_id_sha256": server[
                "host_boot_id_sha256"
            ],
            "clearance_basis": (
                "host_boot_epoch_changed"
                if host_reboot
                else "linux_cgroup_kill_populated_zero"
            ),
            "completion_disposition": (
                "host_reboot"
                if host_reboot
                else (
                    "forced_termination"
                    if effect_origin_state == "child_launch_intent"
                    else "clean_exit"
                )
            ),
            "stderr_bytes": None if host_reboot else 0,
            "stderr_sha256": (
                None if host_reboot else lifecycle.EMPTY_SHA256
            ),
            "adoption_eligible": (
                not host_reboot
                and effect_origin_state == "capture_ready"
            ),
        }
        return {
            "schema_version": lifecycle.CLEARANCE_BUNDLE_SCHEMA,
            "status": lifecycle.CLEARANCE_BUNDLE_STATUS,
            "activation_receipt": copy.deepcopy(self.activation),
            "activation_receipt_sha256": context[
                "activation_sha256"
            ],
            "scope_started_receipt": copy.deepcopy(context["started"]),
            "scope_started_receipt_sha256": context[
                "started_sha256"
            ],
            "clearance_intent_receipt": intent,
            "clearance_intent_receipt_sha256": intent_sha256,
            "scope_empty_receipt": empty,
            "scope_empty_receipt_sha256": (
                lifecycle.scope_empty_receipt_sha256(empty)
            ),
        }

    def test_config_is_exact_root_pinned_and_production_disabled(
        self,
    ) -> None:
        self.assertEqual(
            client_module.normalize_client_config(self.config),
            self.config,
        )
        mutations = (
            ("supervisor_uid", 1),
            ("requester_uid", 501),
            ("requester_gid", 20),
            ("socket_path", "relative.sock"),
            ("connect_timeout_seconds", 31),
            ("expected_supervisor_bundle_sha256", "0" * 64),
        )
        for field, replacement in mutations:
            with self.subTest(field=field):
                candidate = dict(self.config)
                candidate[field] = replacement
                with self.assertRaises(
                    client_module.LifecycleSupervisorClientError
                ):
                    client_module.normalize_client_config(candidate)
        extra = {**self.config, "optional": True}
        with self.assertRaises(
            client_module.LifecycleSupervisorClientError
        ):
            client_module.normalize_client_config(extra)
        self.assertFalse(client_module.PRODUCTION_ACTIVATION)
        self.assertFalse(
            client_module.TRANSACTION_JOURNAL_OPERATION_LEASE_MISSING
        )
        self.assertFalse(
            hasattr(
                client_module,
                "TRANSACTION_JOURNAL_LIVE_SNAPSHOT_API_MISSING",
            )
        )
        self.assertEqual(self.config["requester_uid"], 0)
        self.assertEqual(self.config["requester_gid"], 0)
        self.assertEqual(client_module.CONFIG_FILE_MODE, 0o600)
        with self.assertRaisesRegex(
            client_module.LifecycleSupervisorClientError,
            "production_disabled",
        ):
            client_module.LifecycleSupervisorClient(object())

    def test_client_uses_only_public_live_journal_snapshot_api(
        self,
    ) -> None:
        source = inspect.getsource(client_module)
        for forbidden in (
            "_require_active",
            "_store._scan_session",
            "_directory_name",
            "TRANSACTION_JOURNAL_LIVE_SNAPSHOT_API_MISSING",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        self.assertIn(".live_snapshot()", source)
        self.assertIn(".assert_live_snapshot_current(", source)

    def test_config_loader_rejects_symlink_hardlink_mode_and_identity(
        self,
    ) -> None:
        public = self.root / "public"
        public.mkdir(mode=0o700)
        requester_uid = 0
        requester_gid = 0
        config_path = public / "client.json"
        config_path.write_text(
            json.dumps(self.config, sort_keys=True),
            encoding="ascii",
        )
        config_path.chmod(0o600)
        loaded = client_module._load_client_config_for_test(
            config_path,
            expected_owner_uid=os.getuid(),
            expected_owner_gid=os.getgid(),
            trusted_root=public,
            requester_uid=requester_uid,
            requester_groups={requester_gid},
        )
        self.assertEqual(loaded.value, self.config)
        with self.assertRaises(TypeError):
            pickle.dumps(loaded)

        symlink = public / "link.json"
        symlink.symlink_to(config_path.name)
        with self.assertRaises(
            client_module.LifecycleSupervisorClientError
        ):
            client_module._load_client_config_for_test(
                symlink,
                expected_owner_uid=os.getuid(),
                expected_owner_gid=os.getgid(),
                trusted_root=public,
                requester_uid=requester_uid,
                requester_groups={requester_gid},
            )
        hardlink = public / "hard.json"
        os.link(config_path, hardlink)
        with self.assertRaisesRegex(
            client_module.LifecycleSupervisorClientError, "unsafe"
        ):
            client_module._load_client_config_for_test(
                config_path,
                expected_owner_uid=os.getuid(),
                expected_owner_gid=os.getgid(),
                trusted_root=public,
                requester_uid=requester_uid,
                requester_groups={requester_gid},
            )
        hardlink.unlink()
        config_path.chmod(0o666)
        with self.assertRaisesRegex(
            client_module.LifecycleSupervisorClientError, "unsafe"
        ):
            client_module._load_client_config_for_test(
                config_path,
                expected_owner_uid=os.getuid(),
                expected_owner_gid=os.getgid(),
                trusted_root=public,
                requester_uid=requester_uid,
                requester_groups={requester_gid},
            )
        config_path.chmod(0o600)
        public.chmod(0o777)
        with self.assertRaisesRegex(
            client_module.LifecycleSupervisorClientError,
            "parent_unsafe",
        ):
            client_module._load_client_config_for_test(
                config_path,
                expected_owner_uid=os.getuid(),
                expected_owner_gid=os.getgid(),
                trusted_root=public,
                requester_uid=requester_uid,
                requester_groups={requester_gid},
            )

    def test_socket_leaf_parent_and_kernel_peer_are_checked(
        self,
    ) -> None:
        if os.getgid() == 0:
            runtime = self.root / "runtime"
            runtime.mkdir(mode=0o700)
            socket_path = runtime / "lifecycle.sock"
            listener = socket.socket(
                socket.AF_UNIX, socket.SOCK_STREAM
            )
            self.addCleanup(listener.close)
            listener.bind(str(socket_path))
            socket_path.chmod(0o600)
            selected = {
                **self.config,
                "socket_path": str(socket_path),
            }
            identity = client_module._validate_socket_leaf_for_test(
                selected,
                expected_owner_uid=os.getuid(),
                trusted_root=runtime,
            )
            self.assertGreater(identity.inode, 0)
            socket_path.chmod(0o660)
            with self.assertRaisesRegex(
                client_module.LifecycleSupervisorClientError,
                "unsafe",
            ):
                client_module._validate_socket_leaf_for_test(
                    selected,
                    expected_owner_uid=os.getuid(),
                    trusted_root=runtime,
                )

        scripted = self.success_socket(
            lambda request, _server: protocol.build_error_response(
                request,
                error_code="provider_unavailable",
                error_outcome=(
                    protocol.ERROR_OUTCOME_RETRYABLE_NO_EFFECT
                ),
                observed_ledger_head_sha256=None,
            ),
            peer_uid=1,
        )
        client = self.client_with_socket(scripted)
        with self.assertRaisesRegex(
            client_module.LifecycleSupervisorTransportError,
            "peer_uid_mismatch",
        ):
            client.get_activation()
        self.assertEqual(scripted.sent, [])
        self.assertTrue(scripted.closed)

    def test_get_activation_uses_discovery_only_handshake(self) -> None:
        def response(request, _server):
            return protocol.build_success_response(
                request,
                result={
                    "activation_receipt": self.activation,
                    "activation_receipt_sha256": (
                        lifecycle.activation_receipt_sha256(
                            self.activation
                        )
                    ),
                },
            )

        scripted = self.success_socket(
            response, activation_in_hello=False
        )
        client = self.client_with_socket(scripted)
        result = client.get_activation()
        self.assertEqual(result["activation_receipt"], self.activation)
        self.assertEqual(len(scripted.sent), 2)
        hello, request = scripted.sent
        self.assertNotEqual(
            hello["request_id"], request["request_id"]
        )
        self.assertNotEqual(
            hello["client_nonce"],
            hello["client_incarnation_id"],
        )
        self.assertIsNone(
            request["payload"][
                "expected_activation_receipt_sha256"
            ]
        )

    def test_handshake_measurements_fail_before_operation_dispatch(
        self,
    ) -> None:
        scripted = self.success_socket(
            lambda request, _server: protocol.build_error_response(
                request,
                error_code="activation_mismatch",
                error_outcome=(
                    protocol.ERROR_OUTCOME_FINAL_NO_EFFECT
                ),
                observed_ledger_head_sha256=None,
            ),
            mutate_server_hello=lambda value: {
                **value,
                "supervisor_policy_sha256": digest(
                    "wrong-supervisor-policy"
                ),
            },
        )
        client = self.client_with_socket(scripted)
        with self.assertRaisesRegex(
            client_module.LifecycleSupervisorTransportError,
            "handshake_invalid",
        ):
            client.get_activation()
        self.assertEqual(len(scripted.sent), 1)

    def test_reboot_activation_mismatch_requires_scope_recovery(
        self,
    ) -> None:
        reboot_activation = copy.deepcopy(self.activation)
        reboot_activation["host_boot_id_sha256"] = digest(
            "later-host-boot"
        )
        cases = (
            (
                "start_scope",
                self.make_journal(
                    "child_launch_intent", marker=22
                ),
            ),
            (
                "await_capture_event",
                self.make_journal("child_running", marker=23),
            ),
        )
        for operation, context in cases:
            with self.subTest(operation=operation):
                def unexpected_dispatch(_request, _server):
                    raise AssertionError(
                        "scope operation must not be dispatched"
                    )

                scripted = self.success_socket(
                    unexpected_dispatch,
                    activation=reboot_activation,
                )
                factory_calls = 0

                def factory(*_args):
                    nonlocal factory_calls
                    factory_calls += 1
                    return scripted

                constructor = (
                    client_module._new_lifecycle_supervisor_client_for_test
                )
                client = constructor(
                    self.config,
                    socket_factory=factory,
                    random_bytes=self.random,
                )
                with self.assertRaises(
                    client_module
                    .LifecycleSupervisorRecoveryRequiredError
                ) as raised:
                    if operation == "start_scope":
                        client.start_scope(
                            context["session"],
                            recorded_at_unix=5,
                        )
                    else:
                        client.await_capture_event(
                            context["session"],
                            timeout_seconds=20,
                            recorded_at_unix=6,
                        )
                failure = raised.exception
                expected_incarnation = (
                    context["started"]["scope_incarnation_id"]
                    if "started" in context
                    else protocol.derive_scope_incarnation_id(
                        instance_slug="john-test",
                        capture_session_id=(
                            context["session"].session_id
                        ),
                        child_launch_intent_record_sha256=(
                            context["launch"].record_sha256
                        ),
                        lifecycle_activation_receipt_sha256=(
                            context["activation_sha256"]
                        ),
                    )
                )
                self.assertEqual(
                    failure.remote_code, "activation_mismatch"
                )
                self.assertEqual(
                    failure.error_outcome,
                    protocol.ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED,
                )
                self.assertEqual(failure.operation, operation)
                self.assertNotEqual(
                    failure.request_id,
                    scripted.sent[0]["request_id"],
                )
                self.assertEqual(
                    failure.capture_session_id,
                    context["session"].session_id,
                )
                self.assertEqual(
                    failure.scope_incarnation_id,
                    expected_incarnation,
                )
                self.assertIsNone(
                    failure.observed_ledger_head_sha256
                )
                self.assertFalse(failure.request_dispatched)
                self.assertFalse(failure.outcome_ambiguous)
                self.assertNotIsInstance(
                    failure,
                    client_module.LifecycleSupervisorAmbiguousError,
                )
                self.assertFalse(failure.retryable)
                self.assertEqual(factory_calls, 1)
                self.assertEqual(len(scripted.sent), 1)
                self.assertTrue(scripted.closed)

    def test_randomness_must_be_nonzero_exact_and_collision_free(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            client_module.LifecycleSupervisorClientError,
            "randomness_collision",
        ):
            client_module._new_lifecycle_supervisor_client_for_test(
                self.config,
                socket_factory=lambda *_args: None,
                random_bytes=lambda count: b"\x00" * count,
            )
        with self.assertRaisesRegex(
            client_module.LifecycleSupervisorClientError,
            "randomness_invalid",
        ):
            client_module._new_lifecycle_supervisor_client_for_test(
                self.config,
                socket_factory=lambda *_args: None,
                random_bytes=lambda count: b"x" * (count - 1),
            )
        scripted = self.success_socket(
            lambda request, _server: protocol.build_error_response(
                request,
                error_code="provider_unavailable",
                error_outcome=(
                    protocol.ERROR_OUTCOME_RETRYABLE_NO_EFFECT
                ),
                observed_ledger_head_sha256=None,
            )
        )
        with self.assertRaisesRegex(
            client_module.LifecycleSupervisorTransportError,
            "response_timeout",
        ):
            client_module._read_exact(
                scripted,
                1,
                ambiguous=False,
                deadline=time.monotonic() - 1,
            )

    def test_start_scope_derives_every_authority_binding_from_live_journal(
        self,
    ) -> None:
        context = self.make_journal("child_launch_intent")

        def response(request, server):
            started = self.started_from_request(request, server)
            return protocol.build_success_response(
                request,
                result={
                    "scope_started_receipt": started,
                    "scope_started_receipt_sha256": (
                        lifecycle.scope_started_receipt_sha256(started)
                    ),
                    "ledger_head_sha256": digest("ledger-started"),
                },
            )

        scripted = self.success_socket(response)
        client = self.client_with_socket(scripted)
        result = client.start_scope(
            context["session"], recorded_at_unix=5
        )
        payload = scripted.sent[1]["payload"]
        self.assertEqual(
            payload["capture_session_id"],
            context["session"].session_id,
        )
        self.assertEqual(
            payload["child_launch_intent_record_sha256"],
            context["launch"].record_sha256,
        )
        staging_intent = next(
            record
            for record in context["session"].records
            if record.state == "staging_create_intent"
        )
        self.assertEqual(
            payload["staging_transaction_intent_sha256"],
            staging_intent.record_sha256,
        )
        self.assertEqual(
            result["scope_started_receipt"][
                "scope_incarnation_id"
            ],
            payload["scope_incarnation_id"],
        )
        self.assertNotEqual(
            payload["scope_incarnation_id"],
            client.client_incarnation_id,
        )
        self.assertEqual(
            payload["scope_incarnation_id"],
            protocol.derive_scope_incarnation_id(
                instance_slug="john-test",
                capture_session_id=context["session"].session_id,
                child_launch_intent_record_sha256=(
                    context["launch"].record_sha256
                ),
                lifecycle_activation_receipt_sha256=context[
                    "activation_sha256"
                ],
            ),
        )
        self.assertFalse(
            {
                "pid",
                "path",
                "signal",
                "command",
                "argv",
                "environment",
            }
            & set(payload)
        )

    def test_start_scope_rejects_provider_substitution_as_ambiguous(
        self,
    ) -> None:
        context = self.make_journal(
            "child_launch_intent", marker=15
        )

        def response(request, server):
            started = self.started_from_request(request, server)
            started["lifecycle_provider"] = (
                "systemd_transient_scope"
            )
            return protocol.build_success_response(
                request,
                result={
                    "scope_started_receipt": started,
                    "scope_started_receipt_sha256": (
                        lifecycle.scope_started_receipt_sha256(started)
                    ),
                    "ledger_head_sha256": digest(
                        "provider-substitution-ledger"
                    ),
                },
            )

        scripted = self.success_socket(response)
        client = self.client_with_socket(scripted)
        with self.assertRaises(
            client_module.LifecycleSupervisorAmbiguousError
        ) as raised:
            client.start_scope(
                context["session"], recorded_at_unix=5
            )
        self.assertEqual(
            raised.exception.operation, "start_scope"
        )
        self.assertTrue(raised.exception.outcome_ambiguous)
        self.assertTrue(context["session"].recovery_required)

    def test_scope_operations_require_exact_open_descriptor_session(
        self,
    ) -> None:
        scripted = self.success_socket(
            lambda request, _server: protocol.build_error_response(
                request,
                error_code="scope_not_found",
                error_outcome=(
                    protocol.ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED
                ),
                observed_ledger_head_sha256=None,
            )
        )
        client = self.client_with_socket(scripted)
        with self.assertRaisesRegex(
            client_module.LifecycleSupervisorClientError,
            "live_journal_session_required",
        ):
            client.start_scope(
                {
                    "instance_slug": "john-test",
                    "state": "child_launch_intent",
                    "record_sha256": digest("forged"),
                },
                recorded_at_unix=5,
            )
        context = self.make_journal(
            "child_launch_intent", marker=2
        )
        context["session"].close()
        with self.assertRaisesRegex(
            client_module.LifecycleSupervisorClientError,
            "journal_session_closed",
        ):
            client.start_scope(
                context["session"], recorded_at_unix=5
            )
        self.assertEqual(scripted.sent, [])

    def test_journal_is_rescanned_after_handshake_before_any_request(
        self,
    ) -> None:
        context = self.make_journal(
            "child_launch_intent", marker=10
        )
        session_directory = (
            context["store_path"]
            / f"session-{context['session'].session_id}"
        )

        def change_journal() -> None:
            (session_directory / "intruder").write_bytes(b"x")

        scripted = self.success_socket(
            lambda request, _server: protocol.build_error_response(
                request,
                error_code="scope_state_conflict",
                error_outcome=(
                    protocol.ERROR_OUTCOME_OPERATOR_ATTENTION_REQUIRED
                ),
                observed_ledger_head_sha256=None,
            ),
            after_hello_drained=change_journal,
        )
        client = self.client_with_socket(scripted)
        with self.assertRaisesRegex(
            client_module.LifecycleSupervisorClientError,
            "journal_rescan_failed",
        ) as raised:
            client.start_scope(
                context["session"], recorded_at_unix=5
            )
        self.assertFalse(raised.exception.outcome_ambiguous)
        self.assertEqual(len(scripted.sent), 1)

    def test_await_and_recover_bind_the_exact_current_outer_head(
        self,
    ) -> None:
        running = self.make_journal("child_running", marker=3)
        ready_details = {
            "provisional_name": f"opaque-capture-{3:032x}",
            "capture_object_identity_sha256": digest(
                "await-capture-object"
            ),
            "capture_selection_sha256": digest(
                "await-capture-selection"
            ),
            "capture_plan_sha256": digest("await-capture-plan"),
            "capture_manifest_sha256": digest(
                "await-capture-manifest"
            ),
            "capture_boundary_policy_sha256": digest(
                "capture-boundary"
            ),
            "helper_activation_policy_sha256": self.activation[
                "helper_activation_policy_sha256"
            ],
            "request_sha256": digest("await-capture-request"),
        }

        def await_response(request, _server):
            payload = request["payload"]
            return protocol.build_success_response(
                request,
                result={
                    "capture_session_id": payload[
                        "capture_session_id"
                    ],
                    "lifecycle_scope_id": payload[
                        "lifecycle_scope_id"
                    ],
                    "scope_incarnation_id": payload[
                        "scope_incarnation_id"
                    ],
                    "scope_started_receipt_sha256": payload[
                        "scope_started_receipt_sha256"
                    ],
                    "event_sequence": (
                        payload["after_event_sequence"] + 1
                    ),
                    "event": "capture_ready",
                    "event_record_sha256": digest("capture-event"),
                    "event_evidence_sha256": (
                        protocol.capture_event_evidence_sha256(
                            ready_details
                        )
                    ),
                    "ledger_head_sha256": digest("ledger-event"),
                },
            )

        scripted = self.success_socket(await_response)
        client = self.client_with_socket(scripted)
        pending = client.await_capture_event(
            running["session"],
            timeout_seconds=20,
            recorded_at_unix=6,
        )
        self.assertIsInstance(
            pending,
            client_module.LifecycleSupervisorPendingCaptureEvent,
        )
        with self.assertRaises(TypeError):
            pickle.dumps(pending)
        committed = pending.commit_capture_ready(
            ready_details,
            recorded_at_unix=6,
        )
        self.assertEqual(committed.state, "capture_ready")
        self.assertEqual(running["session"].state, "capture_ready")
        payload = scripted.sent[1]["payload"]
        self.assertEqual(
            (
                payload["outer_journal_record_state"],
                payload["outer_journal_record_revision"],
                payload["outer_journal_record_sha256"],
            ),
            (
                running["running"].state,
                running["running"].revision,
                running["running"].record_sha256,
            ),
        )

        early = self.make_journal(
            "child_launch_intent", marker=4
        )
        scripted_recovery = self.success_socket(
            lambda request, _server: protocol.build_success_response(
                request,
                result={
                    "recovery_state": "start_intent",
                    "capture_session_id": request["payload"][
                        "capture_session_id"
                    ],
                    "lifecycle_scope_id": request["payload"][
                        "lifecycle_scope_id"
                    ],
                    "scope_incarnation_id": request["payload"][
                        "scope_incarnation_id"
                    ],
                    "ledger_head_sha256": digest("ledger-recovered"),
                    "scope_started_receipt": None,
                    "scope_started_receipt_sha256": None,
                    "event_sequence": None,
                    "event": None,
                    "event_record_sha256": None,
                    "event_evidence_sha256": None,
                    "effect_origin_state": "child_launch_intent",
                    "effect_origin_record_revision": request["payload"][
                        "child_launch_intent_record_revision"
                    ],
                    "effect_origin_record_sha256": request["payload"][
                        "child_launch_intent_record_sha256"
                    ],
                    "clearance_bundle": None,
                    "clearance_bundle_sha256": None,
                },
            )
        )
        recovery_client = self.client_with_socket(
            scripted_recovery
        )
        result = recovery_client.recover_scope(
            early["session"],
            recovery_reason="client_restart",
            recorded_at_unix=5,
        )
        self.assertEqual(result.recovery_state, "start_intent")
        self.assertIsNone(result.clearance_result)
        self.assertEqual(
            result.result["scope_incarnation_id"],
            protocol.derive_scope_incarnation_id(
                instance_slug="john-test",
                capture_session_id=early["session"].session_id,
                child_launch_intent_record_sha256=early[
                    "launch"
                ].record_sha256,
                lifecycle_activation_receipt_sha256=early[
                    "activation_sha256"
                ],
            ),
        )

    def test_lost_start_response_is_recoverable_by_new_client_process(
        self,
    ) -> None:
        context = self.make_journal(
            "child_launch_intent", marker=11
        )
        lost_response = self.success_socket(
            lambda request, _server: protocol.build_error_response(
                request,
                error_code="provider_failure",
                error_outcome=(
                    protocol.ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED
                ),
                observed_ledger_head_sha256=None,
            ),
            fail_request_send=True,
        )
        first_client = self.client_with_socket(lost_response)
        with self.assertRaises(
            client_module.LifecycleSupervisorAmbiguousError
        ):
            first_client.start_scope(
                context["session"], recorded_at_unix=5
            )
        start_request = lost_response.sent[1]
        start_incarnation = start_request["payload"][
            "scope_incarnation_id"
        ]

        recovered = self.success_socket(
            lambda request, _server: protocol.build_success_response(
                request,
                result={
                    "recovery_state": "start_intent",
                    "capture_session_id": request["payload"][
                        "capture_session_id"
                    ],
                    "lifecycle_scope_id": request["payload"][
                        "lifecycle_scope_id"
                    ],
                    "scope_incarnation_id": request["payload"][
                        "scope_incarnation_id"
                    ],
                    "ledger_head_sha256": digest(
                        "ledger-after-client-restart"
                    ),
                    "scope_started_receipt": None,
                    "scope_started_receipt_sha256": None,
                    "event_sequence": None,
                    "event": None,
                    "event_record_sha256": None,
                    "event_evidence_sha256": None,
                    "effect_origin_state": "child_launch_intent",
                    "effect_origin_record_revision": request["payload"][
                        "child_launch_intent_record_revision"
                    ],
                    "effect_origin_record_sha256": request["payload"][
                        "child_launch_intent_record_sha256"
                    ],
                    "clearance_bundle": None,
                    "clearance_bundle_sha256": None,
                },
            )
        )
        restarted_client = self.client_with_socket(recovered)
        self.assertNotEqual(
            first_client.client_incarnation_id,
            restarted_client.client_incarnation_id,
        )
        restarted_client.recover_scope(
            context["session"],
            recovery_reason="request_outcome_unknown",
            recorded_at_unix=5,
        )
        self.assertEqual(
            recovered.sent[1]["payload"]["scope_incarnation_id"],
            start_incarnation,
        )

    def test_fixed_capture_events_commit_exact_clearance_policy(
        self,
    ) -> None:
        for (
            initial_state,
            event,
            marker,
            expected_mode,
            sequence,
        ) in (
            (
                "child_running",
                "child_exited",
                26,
                "terminate_and_clear",
                1,
            ),
            (
                "capture_ready",
                "capture_deadline_exceeded",
                27,
                "wait_clean_then_terminate_on_deadline",
                2,
            ),
        ):
            with self.subTest(initial_state=initial_state, event=event):
                context = self.make_journal(
                    initial_state, marker=marker
                )

                def response(request, _server):
                    payload = request["payload"]
                    return protocol.build_success_response(
                        request,
                        result={
                            "capture_session_id": payload[
                                "capture_session_id"
                            ],
                            "lifecycle_scope_id": payload[
                                "lifecycle_scope_id"
                            ],
                            "scope_incarnation_id": payload[
                                "scope_incarnation_id"
                            ],
                            "scope_started_receipt_sha256": payload[
                                "scope_started_receipt_sha256"
                            ],
                            "event_sequence": sequence,
                            "event": event,
                            "event_record_sha256": digest(
                                f"fixed-event-{marker}"
                            ),
                            "event_evidence_sha256": None,
                            "ledger_head_sha256": digest(
                                f"fixed-event-head-{marker}"
                            ),
                        },
                    )

                record = self.client_with_socket(
                    self.success_socket(response)
                ).await_capture_event(
                    context["session"],
                    timeout_seconds=20,
                    recorded_at_unix=8,
                )
                self.assertIsInstance(
                    record, journal.TransactionJournalRecord
                )
                self.assertEqual(
                    context["session"].state,
                    "lifecycle_clearance_intent",
                )
                self.assertEqual(
                    record.details["clearance_mode"],
                    expected_mode,
                )
                self.assertEqual(
                    record.details[
                        "lifecycle_operation_binding"
                    ]["supervisor_event"],
                    event,
                )

    def test_rotated_boot_can_recover_then_clear_old_scope(
        self,
    ) -> None:
        context = self.make_journal(
            "lifecycle_clearance_intent", marker=12
        )
        current_activation = copy.deepcopy(self.activation)
        current_activation["host_boot_id_sha256"] = digest(
            "host-boot-after-reboot"
        )
        current_epoch = digest("supervisor-epoch-after-reboot")

        def recovery_response(request, _server):
            return protocol.build_success_response(
                request,
                result={
                    "recovery_state": "provider_observation",
                    "capture_session_id": request["payload"][
                        "capture_session_id"
                    ],
                    "lifecycle_scope_id": request["payload"][
                        "lifecycle_scope_id"
                    ],
                    "scope_incarnation_id": request["payload"][
                        "scope_incarnation_id"
                    ],
                    "ledger_head_sha256": digest(
                        "reboot-recovery-ledger"
                    ),
                    "scope_started_receipt": context["started"],
                    "scope_started_receipt_sha256": context[
                        "started_sha256"
                    ],
                    "event_sequence": None,
                    "event": None,
                    "event_record_sha256": None,
                    "event_evidence_sha256": None,
                    "effect_origin_state": request["payload"][
                        "expected_effect_origin_state"
                    ],
                    "effect_origin_record_revision": request["payload"][
                        "expected_effect_origin_record_revision"
                    ],
                    "effect_origin_record_sha256": request["payload"][
                        "expected_effect_origin_record_sha256"
                    ],
                    "clearance_bundle": None,
                    "clearance_bundle_sha256": None,
                },
            )

        recovery_socket = self.success_socket(
            recovery_response,
            activation=current_activation,
            supervisor_epoch_id=current_epoch,
        )
        recovery_client = self.client_with_socket(recovery_socket)
        recovery = recovery_client.recover_scope(
            context["session"],
            recovery_reason="host_reboot",
            recorded_at_unix=8,
        )
        self.assertEqual(
            recovery.recovery_state, "provider_observation"
        )
        recover_payload = recovery_socket.sent[1]["payload"]
        self.assertEqual(
            recover_payload[
                "lifecycle_activation_receipt_sha256"
            ],
            context["activation_sha256"],
        )
        self.assertNotEqual(
            context["activation_sha256"],
            lifecycle.activation_receipt_sha256(
                current_activation
            ),
        )

        def clearance_response(request, server):
            bundle = self.clearance_bundle(
                context, request, server
            )
            return protocol.build_success_response(
                request,
                result={
                    "clearance_bundle": bundle,
                    "clearance_bundle_sha256": (
                        lifecycle.clearance_bundle_sha256(bundle)
                    ),
                    "ledger_head_sha256": digest(
                        "reboot-clearance-ledger"
                    ),
                },
            )

        clearance_socket = self.success_socket(
            clearance_response,
            activation=current_activation,
            supervisor_epoch_id=current_epoch,
        )
        clearance_client = self.client_with_socket(
            clearance_socket
        )
        cleared = clearance_client.request_clearance(
            context["session"],
            timeout_seconds=20,
            recorded_at_unix=9,
        )
        empty = cleared.clearance_bundle[
            "scope_empty_receipt"
        ]
        self.assertEqual(
            empty["completion_disposition"], "host_reboot"
        )
        self.assertFalse(
            cleared.scope_clearance_proof.adoption_eligible
        )
        with self.assertRaises(lifecycle.LifecycleReceiptError):
            cleared.scope_clearance_proof.consume(
                capture_session_id=context["session"].session_id,
                purpose="capture_adoption",
            )
        self.assertEqual(
            cleared.scope_clearance_proof.consume(
                capture_session_id=context["session"].session_id,
                purpose="staging_cleanup",
            )[0],
            context["session"].session_id,
        )

    def test_recover_replays_historical_settlement_and_remints_proof(
        self,
    ) -> None:
        context = self.make_journal(
            "lifecycle_clearance_intent", marker=13
        )
        current_activation = copy.deepcopy(self.activation)
        current_activation["host_boot_id_sha256"] = digest(
            "third-host-boot"
        )
        current_epoch = digest("third-supervisor-epoch")

        def response(request, server):
            historical_server = {
                **server,
                "host_boot_id_sha256": digest(
                    "settlement-host-boot"
                ),
                "supervisor_epoch_id": digest(
                    "settlement-supervisor-epoch"
                ),
            }
            bundle = self.clearance_bundle(
                context, request, historical_server
            )
            return protocol.build_success_response(
                request,
                result={
                    "recovery_state": "settled_bundle",
                    "capture_session_id": request["payload"][
                        "capture_session_id"
                    ],
                    "lifecycle_scope_id": request["payload"][
                        "lifecycle_scope_id"
                    ],
                    "scope_incarnation_id": request["payload"][
                        "scope_incarnation_id"
                    ],
                    "ledger_head_sha256": digest(
                        "historical-settlement-ledger"
                    ),
                    "scope_started_receipt": context["started"],
                    "scope_started_receipt_sha256": context[
                        "started_sha256"
                    ],
                    "event_sequence": None,
                    "event": None,
                    "event_record_sha256": None,
                    "event_evidence_sha256": None,
                    "effect_origin_state": request["payload"][
                        "expected_effect_origin_state"
                    ],
                    "effect_origin_record_revision": request["payload"][
                        "expected_effect_origin_record_revision"
                    ],
                    "effect_origin_record_sha256": request["payload"][
                        "expected_effect_origin_record_sha256"
                    ],
                    "clearance_bundle": bundle,
                    "clearance_bundle_sha256": (
                        lifecycle.clearance_bundle_sha256(bundle)
                    ),
                },
            )

        scripted = self.success_socket(
            response,
            activation=current_activation,
            supervisor_epoch_id=current_epoch,
        )
        client = self.client_with_socket(scripted)
        recovered = client.recover_scope(
            context["session"],
            recovery_reason="supervisor_restart",
            recorded_at_unix=8,
        )
        self.assertEqual(
            recovered.recovery_state, "settled_bundle"
        )
        self.assertIsInstance(
            recovered.clearance_result,
            client_module.LifecycleSupervisorClearanceResult,
        )
        assert recovered.clearance_result is not None
        empty = recovered.clearance_result.clearance_bundle[
            "scope_empty_receipt"
        ]
        self.assertEqual(
            empty["clearance_host_boot_id_sha256"],
            digest("settlement-host-boot"),
        )
        self.assertNotEqual(
            empty["clearance_host_boot_id_sha256"],
            current_activation["host_boot_id_sha256"],
        )
        proof = recovered.clearance_result.scope_clearance_proof
        self.assertTrue(proof.active)
        proof.consume(
            capture_session_id=context["session"].session_id,
            purpose="staging_cleanup",
        )
        self.assertFalse(proof.active)
        with self.assertRaises(TypeError):
            pickle.dumps(recovered)

    def test_recover_settled_bundle_accepts_authorized_late_start(
        self,
    ) -> None:
        context = self.make_lost_start_clearance(marker=16)

        def response(request, server):
            bundle = self.clearance_bundle(
                context, request, server
            )
            return protocol.build_success_response(
                request,
                result={
                    "recovery_state": "settled_bundle",
                    "capture_session_id": request["payload"][
                        "capture_session_id"
                    ],
                    "lifecycle_scope_id": request["payload"][
                        "lifecycle_scope_id"
                    ],
                    "scope_incarnation_id": request["payload"][
                        "scope_incarnation_id"
                    ],
                    "ledger_head_sha256": digest(
                        "late-start-settlement-ledger"
                    ),
                    "scope_started_receipt": context["started"],
                    "scope_started_receipt_sha256": context[
                        "started_sha256"
                    ],
                    "event_sequence": None,
                    "event": None,
                    "event_record_sha256": None,
                    "event_evidence_sha256": None,
                    "effect_origin_state": request["payload"][
                        "expected_effect_origin_state"
                    ],
                    "effect_origin_record_revision": request["payload"][
                        "expected_effect_origin_record_revision"
                    ],
                    "effect_origin_record_sha256": request["payload"][
                        "expected_effect_origin_record_sha256"
                    ],
                    "clearance_bundle": bundle,
                    "clearance_bundle_sha256": (
                        lifecycle.clearance_bundle_sha256(bundle)
                    ),
                },
            )

        scripted = self.success_socket(response)
        client = self.client_with_socket(scripted)
        recovered = client.recover_scope(
            context["session"],
            recovery_reason="request_outcome_unknown",
            recorded_at_unix=6,
        )
        self.assertEqual(
            recovered.recovery_state, "settled_bundle"
        )
        assert recovered.clearance_result is not None
        bundle = recovered.clearance_result.clearance_bundle
        self.assertIsNone(
            bundle["clearance_intent_receipt"][
                "scope_started_receipt_sha256"
            ]
        )
        self.assertEqual(
            bundle["scope_started_receipt_sha256"],
            context["started_sha256"],
        )
        self.assertEqual(
            bundle["scope_empty_receipt"][
                "completion_disposition"
            ],
            "forced_termination",
        )
        proof = recovered.clearance_result.scope_clearance_proof
        self.assertFalse(proof.adoption_eligible)
        proof.consume(
            capture_session_id=context["session"].session_id,
            purpose="staging_cleanup",
        )

    def test_request_clearance_returns_only_authenticated_one_shot_proof(
        self,
    ) -> None:
        context = self.make_journal(
            "lifecycle_clearance_intent", marker=5
        )

        def response(request, server):
            bundle = self.clearance_bundle(
                context, request, server
            )
            return protocol.build_success_response(
                request,
                result={
                    "clearance_bundle": bundle,
                    "clearance_bundle_sha256": (
                        lifecycle.clearance_bundle_sha256(bundle)
                    ),
                    "ledger_head_sha256": digest("ledger-empty"),
                },
            )

        scripted = self.success_socket(response)
        client = self.client_with_socket(scripted)
        original_mint = lifecycle._mint_scope_clearance_proof

        def mint_after_durable_outer(bundle):
            self.assertEqual(
                context["session"].state, "lifecycle_scope_empty"
            )
            self.assertEqual(
                context["session"].records[-1],
                context["session"].latest_record,
            )
            return original_mint(bundle)

        with mock.patch.object(
            lifecycle,
            "_mint_scope_clearance_proof",
            side_effect=mint_after_durable_outer,
        ) as mint:
            result = client.request_clearance(
                context["session"],
                timeout_seconds=20,
                recorded_at_unix=8,
            )
            mint.assert_called_once()
        self.assertEqual(
            result.outer_record_sha256,
            context["session"].latest_record.record_sha256,
        )
        self.assertIsInstance(
            result.scope_clearance_proof,
            lifecycle.ScopeClearanceProof,
        )
        self.assertEqual(
            result.clearance_bundle_sha256,
            lifecycle.clearance_bundle_sha256(
                result.clearance_bundle
            ),
        )
        proof = result.scope_clearance_proof
        self.assertTrue(proof.active)
        self.assertEqual(
            proof.consume(
                capture_session_id=context["session"].session_id,
                purpose="capture_adoption",
            ),
            (
                context["session"].session_id,
                result.clearance_bundle[
                    "scope_empty_receipt_sha256"
                ],
            ),
        )
        self.assertFalse(proof.active)
        with self.assertRaises(lifecycle.LifecycleReceiptError):
            proof.consume(
                capture_session_id=context["session"].session_id,
                purpose="staging_cleanup",
            )
        with self.assertRaises(lifecycle.LifecycleReceiptError):
            lifecycle.mint_scope_clearance_proof(
                result.clearance_bundle
            )
        with self.assertRaises(TypeError):
            pickle.dumps(result)
        with self.assertRaises(TypeError):
            client_module.LifecycleSupervisorClearanceResult(
                _token=object(),
                bundle=result.clearance_bundle,
                bundle_sha256=result.clearance_bundle_sha256,
                ledger_head_sha256=result.ledger_head_sha256,
                outer_record_sha256=result.outer_record_sha256,
                proof=proof,
            )

    def test_remote_retryability_is_definitive_and_not_ambiguous(
        self,
    ) -> None:
        for code, error_outcome, expected_retryable in (
            (
                "provider_unavailable",
                protocol.ERROR_OUTCOME_RETRYABLE_NO_EFFECT,
                True,
            ),
            (
                "activation_mismatch",
                protocol.ERROR_OUTCOME_FINAL_NO_EFFECT,
                False,
            ),
        ):
            with self.subTest(
                code=code, error_outcome=error_outcome
            ):
                scripted = self.success_socket(
                    lambda request,
                    _server,
                    selected=code,
                    outcome=error_outcome: (
                        protocol.build_error_response(
                            request,
                            error_code=selected,
                            error_outcome=outcome,
                            observed_ledger_head_sha256=None,
                        )
                    ),
                    activation_in_hello=False,
                )
                client = self.client_with_socket(scripted)
                with self.assertRaises(
                    client_module.LifecycleSupervisorRemoteError
                ) as raised:
                    client.get_activation()
                self.assertEqual(
                    raised.exception.remote_code, code
                )
                self.assertEqual(
                    raised.exception.retryable,
                    expected_retryable,
                )
                self.assertEqual(
                    raised.exception.error_outcome,
                    error_outcome,
                )
                self.assertIsNone(
                    raised.exception.observed_ledger_head_sha256
                )
                self.assertFalse(
                    raised.exception.outcome_ambiguous
                )
                self.assertEqual(len(scripted.sent), 2)
                self.assertTrue(scripted.closed)

        with self.assertRaisesRegex(
            client_module.LifecycleSupervisorClientError,
            "effect_uncertain",
        ):
            client_module.LifecycleSupervisorRemoteError(
                "provider_failure",
                error_outcome=(
                    protocol.ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED
                ),
                observed_ledger_head_sha256=None,
            )

    def test_scoped_no_effect_error_carries_observed_head(
        self,
    ) -> None:
        context = self.make_journal("child_running", marker=21)
        expected_head = context["running"].details[
            "lifecycle_operation_binding"
        ]["supervisor_ledger_head_sha256"]
        scripted = self.success_socket(
            lambda request, _server: protocol.build_error_response(
                request,
                error_code="provider_unavailable",
                error_outcome=(
                    protocol.ERROR_OUTCOME_RETRYABLE_NO_EFFECT
                ),
                observed_ledger_head_sha256=request["payload"][
                    "expected_ledger_head_sha256"
                ],
            )
        )
        client = self.client_with_socket(scripted)
        with self.assertRaises(
            client_module.LifecycleSupervisorRemoteError
        ) as raised:
            client.await_capture_event(
                context["session"],
                timeout_seconds=20,
                recorded_at_unix=6,
            )
        self.assertEqual(
            raised.exception.error_outcome,
            protocol.ERROR_OUTCOME_RETRYABLE_NO_EFFECT,
        )
        self.assertEqual(
            raised.exception.observed_ledger_head_sha256,
            expected_head,
        )
        self.assertTrue(raised.exception.retryable)
        self.assertFalse(raised.exception.outcome_ambiguous)
        self.assertEqual(len(scripted.sent), 2)
        self.assertFalse(context["session"].recovery_required)
        snapshot = context["session"].live_snapshot()
        replacement = context[
            "session"
        ]._begin_lifecycle_operation_for_client(
            operation="await_capture_event",
            snapshot=snapshot,
        )
        replacement.cancel_before_dispatch()

    def test_remote_action_outcomes_are_typed_and_never_retried(
        self,
    ) -> None:
        cases = (
            (
                "provider_failure",
                protocol.ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED,
                client_module.LifecycleSupervisorRecoveryRequiredError,
                18,
                True,
            ),
            (
                "journal_binding_mismatch",
                protocol.ERROR_OUTCOME_OPERATOR_ATTENTION_REQUIRED,
                client_module.LifecycleSupervisorOperatorAttentionError,
                19,
                False,
            ),
        )
        for (
            remote_code,
            error_outcome,
            expected_type,
            marker,
            expected_ambiguous,
        ) in cases:
            with self.subTest(
                remote_code=remote_code,
                error_outcome=error_outcome,
            ):
                context = self.make_journal(
                    "child_launch_intent", marker=marker
                )
                observed_head = digest(
                    f"uncertain-observed-{marker}"
                )
                scripted = self.success_socket(
                    lambda request,
                    _server,
                    selected_code=remote_code,
                    selected_outcome=error_outcome,
                    selected_head=observed_head: (
                        protocol.build_error_response(
                            request,
                            error_code=selected_code,
                            error_outcome=selected_outcome,
                            observed_ledger_head_sha256=(
                                selected_head
                            ),
                        )
                    )
                )
                factory_calls = 0

                def factory(*_args):
                    nonlocal factory_calls
                    factory_calls += 1
                    return scripted

                constructor = (
                    client_module._new_lifecycle_supervisor_client_for_test
                )
                client = constructor(
                    self.config,
                    socket_factory=factory,
                    random_bytes=self.random,
                )
                with self.assertRaises(expected_type) as raised:
                    client.start_scope(
                        context["session"],
                        recorded_at_unix=5,
                    )
                failure = raised.exception
                request = scripted.sent[1]
                self.assertNotIsInstance(
                    failure,
                    client_module.LifecycleSupervisorAmbiguousError,
                )
                self.assertEqual(failure.remote_code, remote_code)
                self.assertEqual(
                    failure.error_outcome, error_outcome
                )
                self.assertEqual(
                    failure.observed_ledger_head_sha256,
                    observed_head,
                )
                self.assertEqual(failure.operation, "start_scope")
                self.assertEqual(
                    failure.request_id, request["request_id"]
                )
                self.assertEqual(
                    failure.capture_session_id,
                    context["session"].session_id,
                )
                self.assertEqual(
                    failure.scope_incarnation_id,
                    request["payload"]["scope_incarnation_id"],
                )
                self.assertEqual(
                    failure.outcome_ambiguous,
                    expected_ambiguous,
                )
                if isinstance(
                    failure,
                    client_module.LifecycleSupervisorRecoveryRequiredError,
                ):
                    self.assertTrue(failure.request_dispatched)
                self.assertFalse(failure.retryable)
                self.assertEqual(factory_calls, 1)
                self.assertEqual(
                    context["session"].state, "operator_attention"
                )
                self.assertEqual(
                    context["session"].latest_record.details[
                        "lifecycle_operation_binding"
                    ]["outcome"],
                    (
                        "recovery"
                        if expected_ambiguous
                        else "attention"
                    ),
                )
                self.assertEqual(len(scripted.sent), 2)

    def test_invalid_correlated_errors_remain_ambiguous_responses(
        self,
    ) -> None:
        malformed = self.success_socket(
            lambda request, _server: protocol.build_error_response(
                request,
                error_code="activation_mismatch",
                error_outcome=(
                    protocol.ERROR_OUTCOME_FINAL_NO_EFFECT
                ),
                observed_ledger_head_sha256=None,
            ),
            activation_in_hello=False,
            mutate_response=lambda value: {
                key: selected
                for key, selected in value.items()
                if key != "error_outcome"
            },
        )
        malformed_client = self.client_with_socket(malformed)
        with self.assertRaises(
            client_module.LifecycleSupervisorAmbiguousError
        ) as malformed_raised:
            malformed_client.get_activation()
        self.assertEqual(
            malformed_raised.exception.code,
            "lifecycle_client_ambiguous_response_invalid",
        )
        self.assertFalse(malformed_raised.exception.retryable)

        context = self.make_journal("child_running", marker=20)
        expected_head = digest("expected-error-ledger-head")
        mismatched = self.success_socket(
            lambda request, _server: protocol.build_error_response(
                request,
                error_code="activation_unavailable",
                error_outcome=(
                    protocol.ERROR_OUTCOME_RETRYABLE_NO_EFFECT
                ),
                observed_ledger_head_sha256=request["payload"][
                    "expected_ledger_head_sha256"
                ],
            ),
            mutate_response=lambda value: {
                **value,
                "observed_ledger_head_sha256": digest(
                    "forged-error-ledger-head"
                ),
            },
        )
        mismatch_client = self.client_with_socket(mismatched)
        with self.assertRaises(
            client_module.LifecycleSupervisorAmbiguousError
        ) as mismatch_raised:
            mismatch_client.await_capture_event(
                context["session"],
                timeout_seconds=20,
                recorded_at_unix=6,
            )
        self.assertEqual(
            mismatch_raised.exception.code,
            "lifecycle_client_ambiguous_response_invalid",
        )
        self.assertEqual(
            mismatch_raised.exception.operation,
            "await_capture_event",
        )
        self.assertFalse(mismatch_raised.exception.retryable)
        self.assertNotIsInstance(
            mismatch_raised.exception,
            client_module.LifecycleSupervisorRemoteError,
        )
        self.assertTrue(context["session"].recovery_required)

    def test_partial_send_and_uncorrelated_response_are_ambiguous_once(
        self,
    ) -> None:
        context = self.make_journal(
            "child_launch_intent", marker=6
        )
        factories = 0
        scripted = self.success_socket(
            lambda request, _server: protocol.build_error_response(
                request,
                error_code="provider_unavailable",
                error_outcome=(
                    protocol.ERROR_OUTCOME_RETRYABLE_NO_EFFECT
                ),
                observed_ledger_head_sha256=None,
            ),
            fail_request_send=True,
        )

        def factory(*_args):
            nonlocal factories
            factories += 1
            return scripted

        client = client_module._new_lifecycle_supervisor_client_for_test(
            self.config,
            socket_factory=factory,
            random_bytes=self.random,
        )
        with self.assertRaises(
            client_module.LifecycleSupervisorAmbiguousError
        ) as raised:
            client.start_scope(
                context["session"], recorded_at_unix=5
            )
        self.assertTrue(raised.exception.outcome_ambiguous)
        self.assertFalse(raised.exception.retryable)
        self.assertEqual(
            raised.exception.capture_session_id,
            context["session"].session_id,
        )
        self.assertIsNotNone(
            raised.exception.scope_incarnation_id
        )
        self.assertEqual(factories, 1)
        self.assertEqual(len(scripted.sent), 2)
        self.assertTrue(context["session"].recovery_required)

        context_two = self.make_journal(
            "child_launch_intent", marker=7
        )

        def response(request, server):
            started = self.started_from_request(request, server)
            return protocol.build_success_response(
                request,
                result={
                    "scope_started_receipt": started,
                    "scope_started_receipt_sha256": (
                        lifecycle.scope_started_receipt_sha256(started)
                    ),
                    "ledger_head_sha256": digest("ledger-started"),
                },
            )

        def mutate(value):
            value["request_id"] = "jlqreq-" + ("f" * 32)
            return value

        uncorrelated = self.success_socket(
            response, mutate_response=mutate
        )
        second = self.client_with_socket(uncorrelated)
        with self.assertRaises(
            client_module.LifecycleSupervisorAmbiguousError
        ):
            second.start_scope(
                context_two["session"], recorded_at_unix=5
            )
        self.assertEqual(len(uncorrelated.sent), 2)

    def test_tampered_clearance_never_reaches_private_proof_mint(
        self,
    ) -> None:
        context = self.make_journal(
            "lifecycle_clearance_intent", marker=8
        )

        def response(request, server):
            bundle = self.clearance_bundle(
                context, request, server
            )
            return protocol.build_success_response(
                request,
                result={
                    "clearance_bundle": bundle,
                    "clearance_bundle_sha256": (
                        lifecycle.clearance_bundle_sha256(bundle)
                    ),
                    "ledger_head_sha256": digest("ledger-empty"),
                },
            )

        def mutate(value):
            value["result"]["clearance_bundle"][
                "scope_empty_receipt"
            ]["adoption_eligible"] = False
            return value

        scripted = self.success_socket(
            response, mutate_response=mutate
        )
        client = self.client_with_socket(scripted)
        with mock.patch.object(
            lifecycle,
            "_mint_scope_clearance_proof",
            side_effect=AssertionError("must not mint"),
        ) as mint:
            with self.assertRaises(
                client_module.LifecycleSupervisorAmbiguousError
            ):
                client.request_clearance(
                    context["session"],
                    timeout_seconds=20,
                    recorded_at_unix=8,
                )
            mint.assert_not_called()

    def test_post_response_journal_change_never_mints_proof(
        self,
    ) -> None:
        context = self.make_journal(
            "lifecycle_clearance_intent", marker=9
        )
        session_directory = (
            context["store_path"]
            / f"session-{context['session'].session_id}"
        )

        def valid_response(request, server):
            bundle = self.clearance_bundle(
                context, request, server
            )
            return protocol.build_success_response(
                request,
                result={
                    "clearance_bundle": bundle,
                    "clearance_bundle_sha256": (
                        lifecycle.clearance_bundle_sha256(bundle)
                    ),
                    "ledger_head_sha256": digest(
                        "ledger-empty-two"
                    ),
                },
            )

        scripted = self.success_socket(
            valid_response,
            after_response_drained=lambda: (
                session_directory / "intruder"
            ).write_bytes(b"x"),
        )
        client = self.client_with_socket(scripted)
        with mock.patch.object(
            lifecycle,
            "_mint_scope_clearance_proof",
            side_effect=AssertionError("must not mint"),
        ) as mint:
            with self.assertRaises(
                client_module.LifecycleSupervisorAmbiguousError
            ):
                client.request_clearance(
                    context["session"],
                    timeout_seconds=20,
                    recorded_at_unix=8,
                )
            mint.assert_not_called()

    def test_recovery_cannot_rewrite_already_accepted_scope_empty(
        self,
    ) -> None:
        context = self.make_journal(
            "lifecycle_clearance_intent", marker=17
        )

        def initial_response(request, server):
            bundle = self.clearance_bundle(
                context, request, server
            )
            return protocol.build_success_response(
                request,
                result={
                    "clearance_bundle": bundle,
                    "clearance_bundle_sha256": (
                        lifecycle.clearance_bundle_sha256(bundle)
                    ),
                    "ledger_head_sha256": digest(
                        "accepted-scope-empty-ledger"
                    ),
                },
            )

        initial_socket = self.success_socket(initial_response)
        initial_client = self.client_with_socket(initial_socket)
        accepted = initial_client.request_clearance(
            context["session"],
            timeout_seconds=20,
            recorded_at_unix=8,
        )
        alternate = copy.deepcopy(accepted.clearance_bundle)
        alternate_empty = alternate["scope_empty_receipt"]
        alternate_empty["completion_disposition"] = "abnormal_exit"
        alternate_empty["adoption_eligible"] = False
        alternate["scope_empty_receipt_sha256"] = (
            lifecycle.scope_empty_receipt_sha256(alternate_empty)
        )

        def replay_response(request, _server):
            return protocol.build_success_response(
                request,
                result={
                    "recovery_state": "settled_bundle",
                    "capture_session_id": request["payload"][
                        "capture_session_id"
                    ],
                    "lifecycle_scope_id": request["payload"][
                        "lifecycle_scope_id"
                    ],
                    "scope_incarnation_id": request["payload"][
                        "scope_incarnation_id"
                    ],
                    "ledger_head_sha256": digest(
                        "rewritten-scope-empty-ledger"
                    ),
                    "scope_started_receipt": context["started"],
                    "scope_started_receipt_sha256": context[
                        "started_sha256"
                    ],
                    "event_sequence": None,
                    "event": None,
                    "event_record_sha256": None,
                    "event_evidence_sha256": None,
                    "effect_origin_state": request["payload"][
                        "expected_effect_origin_state"
                    ],
                    "effect_origin_record_revision": request["payload"][
                        "expected_effect_origin_record_revision"
                    ],
                    "effect_origin_record_sha256": request["payload"][
                        "expected_effect_origin_record_sha256"
                    ],
                    "clearance_bundle": alternate,
                    "clearance_bundle_sha256": (
                        lifecycle.clearance_bundle_sha256(alternate)
                    ),
                },
            )

        replay_socket = self.success_socket(replay_response)
        replay_client = self.client_with_socket(replay_socket)
        with mock.patch.object(
            lifecycle,
            "_mint_scope_clearance_proof",
            side_effect=AssertionError("must not remint"),
        ) as mint:
            with self.assertRaises(
                client_module.LifecycleSupervisorAmbiguousError
            ) as raised:
                replay_client.recover_scope(
                    context["session"],
                    recovery_reason="client_restart",
                    recorded_at_unix=9,
                )
            self.assertIn(
                "clearance_bundle_changed",
                raised.exception.code,
            )
            mint.assert_not_called()

    def test_operation_lease_blocks_two_clients_and_append_bypasses(
        self,
    ) -> None:
        context = self.make_journal(
            "child_launch_intent", marker=24
        )
        blocked: list[str] = []
        second_socket = self.success_socket(
            lambda request, _server: protocol.build_error_response(
                request,
                error_code="scope_not_found",
                error_outcome=protocol.ERROR_OUTCOME_FINAL_NO_EFFECT,
                observed_ledger_head_sha256=None,
            )
        )
        second_client = self.client_with_socket(second_socket)

        def while_reserved() -> None:
            try:
                context["session"].append_event(
                    expected_state="child_launch_intent",
                    next_state="operator_attention",
                    details={
                        "from_state": "child_launch_intent",
                        "reason_code": "forged_race",
                        "incident_sha256": digest("forged-race"),
                        "lifecycle_operation_binding": {},
                    },
                    recorded_at_unix=5,
                )
            except journal.TransactionJournalError as exc:
                blocked.append(exc.code)
            try:
                context[
                    "recorder"
                ].record_lifecycle_clearance_intent(
                    effect_origin_state="child_launch_intent",
                    effect_origin_record_sha256=context[
                        "launch"
                    ].record_sha256,
                    scope_started_receipt_sha256=None,
                    clearance_mode="terminate_and_clear",
                    recorded_at_unix=5,
                )
            except journal.TransactionJournalError as exc:
                blocked.append(exc.code)
            try:
                second_client.start_scope(
                    context["session"], recorded_at_unix=5
                )
            except client_module.LifecycleSupervisorClientError as exc:
                blocked.append(exc.code)

        def response(request, server):
            started = self.started_from_request(request, server)
            return protocol.build_success_response(
                request,
                result={
                    "scope_started_receipt": started,
                    "scope_started_receipt_sha256": (
                        lifecycle.scope_started_receipt_sha256(started)
                    ),
                    "ledger_head_sha256": digest(
                        "two-client-ledger"
                    ),
                },
            )

        scripted = self.success_socket(
            response,
            after_hello_drained=while_reserved,
        )
        first_client = self.client_with_socket(scripted)
        first_client.start_scope(
            context["session"], recorded_at_unix=5
        )
        self.assertEqual(context["session"].state, "child_running")
        self.assertEqual(len(blocked), 3)
        self.assertTrue(
            all("operation" in code for code in blocked),
            blocked,
        )
        self.assertEqual(second_socket.sent, [])

    def test_reopened_incomplete_session_is_recovery_first(
        self,
    ) -> None:
        context = self.make_journal(
            "child_launch_intent", marker=25
        )
        context["store"].close()
        reopened = journal._open_transaction_store_for_test(
            context["store_path"],
            context["store_path"].parents[1],
        )
        self.stores.append(reopened)
        loaded = reopened.load_incomplete_sessions()
        self.assertEqual(len(loaded), 1)
        session = loaded[0]
        self.assertTrue(session.recovery_required)

        unused_socket = self.success_socket(
            lambda request, _server: protocol.build_error_response(
                request,
                error_code="scope_not_found",
                error_outcome=protocol.ERROR_OUTCOME_FINAL_NO_EFFECT,
                observed_ledger_head_sha256=None,
            )
        )
        with self.assertRaisesRegex(
            client_module.LifecycleSupervisorClientError,
            "lifecycle_recovery_required",
        ):
            self.client_with_socket(unused_socket).start_scope(
                session, recorded_at_unix=5
            )
        self.assertEqual(unused_socket.sent, [])

        recovery_socket = self.success_socket(
            lambda request, _server: protocol.build_success_response(
                request,
                result={
                    "recovery_state": "start_intent",
                    "capture_session_id": request["payload"][
                        "capture_session_id"
                    ],
                    "lifecycle_scope_id": request["payload"][
                        "lifecycle_scope_id"
                    ],
                    "scope_incarnation_id": request["payload"][
                        "scope_incarnation_id"
                    ],
                    "ledger_head_sha256": digest(
                        "reopened-recovery-ledger"
                    ),
                    "scope_started_receipt": None,
                    "scope_started_receipt_sha256": None,
                    "effect_origin_state": "child_launch_intent",
                    "effect_origin_record_revision": request[
                        "payload"
                    ]["child_launch_intent_record_revision"],
                    "effect_origin_record_sha256": request["payload"][
                        "child_launch_intent_record_sha256"
                    ],
                    "event_sequence": None,
                    "event": None,
                    "event_record_sha256": None,
                    "event_evidence_sha256": None,
                    "clearance_bundle": None,
                    "clearance_bundle_sha256": None,
                },
            )
        )
        recovered = self.client_with_socket(
            recovery_socket
        ).recover_scope(
            session,
            recovery_reason="client_restart",
            recorded_at_unix=5,
        )
        self.assertEqual(recovered.recovery_state, "start_intent")
        self.assertEqual(session.state, "lifecycle_clearance_intent")
        self.assertEqual(
            recovered.outer_record_sha256,
            session.latest_record.record_sha256,
        )

    def test_public_operation_api_has_no_process_control_escape_hatch(
        self,
    ) -> None:
        forbidden = {
            "pid",
            "pgid",
            "path",
            "signal",
            "command",
            "argv",
            "environment",
            "payload",
            "socket_factory",
            "random_bytes",
        }
        for name in (
            "get_activation",
            "start_scope",
            "await_capture_event",
            "request_clearance",
            "recover_scope",
        ):
            with self.subTest(name=name):
                parameters = set(
                    inspect.signature(
                        getattr(
                            client_module.LifecycleSupervisorClient,
                            name,
                        )
                    ).parameters
                )
                self.assertFalse(parameters & forbidden)
        self.assertNotIn(
            "_new_lifecycle_supervisor_client_for_test",
            client_module.__all__,
        )
        self.assertNotIn(
            "_mint_authenticated_clearance_proof",
            client_module.__all__,
        )


if __name__ == "__main__":
    unittest.main()
