#!/usr/bin/env python3
"""Dedicated sandbox-child entrypoint for qualification evidence capture.

This role receives one normalized initialization record, creates and retains
one opaque capture lease, and serves the digest-bound capture protocol.  It
does not import the privileged coordinator, sandbox policy construction,
activation receipts, root adoption, signing, or projection code.

Production remains disabled by the coordinator.  This entrypoint exists so a
privileged canary and a future reviewed installation can measure and confine
the child independently from the client that supervises it.
"""

from __future__ import annotations

import os
import sys
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# ``-I`` removes the script directory.  The child is measured inside the
# immutable role bundle, so add only that bundle root before sibling imports.
BUNDLE_ROOT = Path(__file__).resolve().parents[1]
if str(BUNDLE_ROOT) not in sys.path:
    sys.path.insert(0, str(BUNDLE_ROOT))

from qualification_attestor import (
    john_lomein_persona_qualification_capture_plan as capture_plan,
)
from qualification_attestor import (
    john_lomein_persona_qualification_capture_protocol as protocol,
)
from qualification_attestor import (
    john_lomein_persona_qualification_opaque_capture as opaque_capture,
)


SANDBOX_CHILD_ROLE = "qualification_capture_sandbox_child"
PRODUCTION_ACTIVATION = False
CHILD_ARGUMENT = "--capture-sandbox-child"


@dataclass(frozen=True)
class HandoffInitialization:
    """Exact semantic content of one capture/adoption v2 request."""

    session_id: str
    plan: dict[str, Any]
    plan_sha256: str
    capture_selection_sha256: str
    capture_boundary_policy_sha256: str
    helper_activation_policy_sha256: str
    destination_parent: Path
    evidence_uid: int
    capture_uid: int
    export_gid: int
    verifier_uid: int
    verifier_gid: int
    timeout_seconds: int
    request_sha256: str


def _error(code: str) -> protocol.CaptureProtocolError:
    return protocol.error(code)


def _absolute_path(value: Any, *, field: str) -> Path:
    if not isinstance(value, str):
        raise _error(f"{field}_invalid")
    path = Path(value)
    if (
        not value
        or len(os.fsencode(value)) > 4096
        or "\x00" in value
        or "\n" in value
        or "\r" in value
        or unicodedata.normalize("NFC", value) != value
        or not path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
        or os.path.normpath(value) != value
    ):
        raise _error(f"{field}_invalid")
    return path


def normalize_initialization(
    value: Any,
) -> tuple[str, dict[str, Any], str, Path, int, int, int]:
    """Validate the child-only semantic content of an initialization frame."""

    if not isinstance(value, Mapping) or set(value) != protocol.INIT_FIELDS:
        raise _error("capture_helper_initialization_fields_invalid")
    if (
        value.get("schema_version") != protocol.PROTOCOL_SCHEMA
        or value.get("command") != "initialize"
        or value.get("sequence") != 0
    ):
        raise _error("capture_helper_initialization_invalid")
    session = protocol.session_id(value.get("session_id"))
    try:
        plan = capture_plan.normalize_capture_plan(
            value.get("capture_plan")
        )
    except capture_plan.CapturePlanError as exc:
        raise _error(exc.code) from exc
    plan_sha256 = protocol.digest(
        value.get("capture_plan_sha256"),
        field="capture_helper_initialization_plan_sha256",
    )
    if capture_plan.capture_plan_sha256(plan) != plan_sha256:
        raise _error("capture_helper_initialization_plan_digest_mismatch")
    parent = _absolute_path(
        value.get("destination_parent"),
        field="capture_helper_initialization_destination_parent",
    )
    helper_uid = protocol.integer(
        value.get("helper_uid"),
        field="capture_helper_initialization_uid",
        minimum=1,
        maximum=2**31 - 1,
    )
    helper_gid = protocol.integer(
        value.get("helper_gid"),
        field="capture_helper_initialization_gid",
        minimum=1,
        maximum=2**31 - 1,
    )
    if (
        helper_uid != plan["evidence_uid"]
        or helper_gid != plan["verifier_gid"]
    ):
        raise _error("capture_helper_initialization_identity_mismatch")
    timeout_seconds = protocol.integer(
        value.get("timeout_seconds"),
        field="capture_helper_initialization_timeout_seconds",
        minimum=1,
        maximum=protocol.MAX_TIMEOUT_SECONDS,
    )
    return (
        session,
        plan,
        plan_sha256,
        parent,
        helper_uid,
        helper_gid,
        timeout_seconds,
    )


def normalize_handoff_initialization(
    value: Any,
) -> HandoffInitialization:
    """Validate every identity and digest in a v2 short-lived request."""

    if (
        not isinstance(value, Mapping)
        or set(value) != protocol.HANDOFF_INIT_FIELDS
        or value.get("schema_version")
        != protocol.HANDOFF_PROTOCOL_SCHEMA
        or value.get("command") != "initialize_handoff"
        or value.get("sequence") != 0
    ):
        raise _error("capture_handoff_initialization_invalid")
    request_sha256 = protocol.verify_handoff_request_digest(value)
    session = protocol.session_id(value.get("session_id"))
    try:
        plan = capture_plan.normalize_capture_plan(
            value.get("capture_plan")
        )
    except capture_plan.CapturePlanError as exc:
        raise _error(exc.code) from exc
    plan_sha256 = protocol.digest(
        value.get("capture_plan_sha256"),
        field="capture_handoff_plan_sha256",
    )
    if capture_plan.capture_plan_sha256(plan) != plan_sha256:
        raise _error("capture_handoff_plan_digest_mismatch")
    evidence_uid = protocol.integer(
        value.get("evidence_uid"),
        field="capture_handoff_evidence_uid",
        minimum=1,
        maximum=2**31 - 1,
    )
    capture_uid = protocol.integer(
        value.get("capture_uid"),
        field="capture_handoff_capture_uid",
        minimum=1,
        maximum=2**31 - 1,
    )
    export_gid = protocol.integer(
        value.get("export_gid"),
        field="capture_handoff_export_gid",
        minimum=1,
        maximum=2**31 - 1,
    )
    verifier_uid = protocol.integer(
        value.get("verifier_uid"),
        field="capture_handoff_verifier_uid",
        minimum=1,
        maximum=2**31 - 1,
    )
    verifier_gid = protocol.integer(
        value.get("verifier_gid"),
        field="capture_handoff_verifier_gid",
        minimum=1,
        maximum=2**31 - 1,
    )
    if (
        evidence_uid != plan["evidence_uid"]
        or verifier_gid != plan["verifier_gid"]
        or len({evidence_uid, capture_uid, verifier_uid}) != 3
        or export_gid == verifier_gid
    ):
        raise _error("capture_handoff_identity_mismatch")
    return HandoffInitialization(
        session_id=session,
        plan=plan,
        plan_sha256=plan_sha256,
        capture_selection_sha256=protocol.digest(
            value.get("capture_selection_sha256"),
            field="capture_handoff_selection_sha256",
        ),
        capture_boundary_policy_sha256=protocol.digest(
            value.get("capture_boundary_policy_sha256"),
            field="capture_handoff_boundary_policy_sha256",
        ),
        helper_activation_policy_sha256=protocol.digest(
            value.get("helper_activation_policy_sha256"),
            field="capture_handoff_helper_policy_sha256",
        ),
        destination_parent=_absolute_path(
            value.get("destination_parent"),
            field="capture_handoff_destination_parent",
        ),
        evidence_uid=evidence_uid,
        capture_uid=capture_uid,
        export_gid=export_gid,
        verifier_uid=verifier_uid,
        verifier_gid=verifier_gid,
        timeout_seconds=protocol.integer(
            value.get("timeout_seconds"),
            field="capture_handoff_timeout_seconds",
            minimum=1,
            maximum=protocol.MAX_TIMEOUT_SECONDS,
        ),
        request_sha256=request_sha256,
    )


def safe_child_error_code(exc: BaseException) -> str:
    if isinstance(exc, protocol.CaptureProtocolError):
        return exc.code
    if isinstance(exc, opaque_capture.OpaqueCaptureError):
        # Opaque-capture codes contain no source bytes or exception text.
        return exc.code
    if isinstance(exc, capture_plan.CapturePlanError):
        return exc.code
    return "capture_helper_child_failed"


def _verify_sealed(
    lease: opaque_capture.OpaqueCaptureLease,
    *,
    plan: Mapping[str, Any],
    helper_uid: int,
    helper_gid: int,
) -> None:
    opaque_capture.verify_sealed_opaque_capture(
        lease.snapshot_root,
        plan=plan,
        expected_plan_sha256=lease.capture_plan_sha256,
        expected_capture_uid=helper_uid,
        expected_verifier_gid=helper_gid,
        expected_manifest_sha256=lease.capture_manifest_sha256,
    )


def _revalidate_live(
    lease: opaque_capture.OpaqueCaptureLease,
    *,
    plan: Mapping[str, Any],
    helper_uid: int,
    helper_gid: int,
) -> None:
    opaque_capture.revalidate_live_opaque_sources(
        lease.snapshot_root,
        plan=plan,
        expected_plan_sha256=lease.capture_plan_sha256,
        expected_capture_uid=helper_uid,
        expected_verifier_gid=helper_gid,
        expected_manifest_sha256=lease.capture_manifest_sha256,
    )


def serve_protocol_with_lease(
    *,
    control_fd: int,
    event_fd: int,
    session_id: str,
    plan: Mapping[str, Any],
    helper_uid: int,
    helper_gid: int,
    lease: Any,
    deadline: float,
    verify_sealed: Callable[[], None],
    revalidate_live: Callable[[], None],
    monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Serve one leased session; injected checks are narrow test seams."""

    # These values belong to the retained lease checks supplied by child_main.
    # Keeping them explicit prevents a future adoption refactor from silently
    # dropping the plan/identity binding at this role boundary.
    del plan, helper_uid, helper_gid
    machine = protocol.ProtocolMachine(session_id)
    try:
        protocol.write_frame(
            event_fd,
            {
                "schema_version": protocol.PROTOCOL_SCHEMA,
                "session_id": session_id,
                "sequence": 0,
                "event": "capture_ready",
                "capture_root": str(lease.snapshot_root),
                "capture_plan_sha256": lease.capture_plan_sha256,
                "capture_manifest_sha256": (
                    lease.capture_manifest_sha256
                ),
            },
            maximum_bytes=protocol.MAX_EVENT_FRAME_BYTES,
            deadline=deadline,
            monotonic=monotonic,
        )
        while True:
            command_value = protocol.read_frame(
                control_fd,
                maximum_bytes=protocol.MAX_CONTROL_FRAME_BYTES,
                deadline=deadline,
                monotonic=monotonic,
            )
            command, artifact, _reason = machine.accept(command_value)
            if command == "abort":
                lease.cleanup()
                protocol.write_frame(
                    event_fd,
                    protocol.event_record(
                        session=session_id,
                        sequence=machine.sequence,
                        name="aborted",
                        artifact_sha256=None,
                    ),
                    maximum_bytes=protocol.MAX_EVENT_FRAME_BYTES,
                    deadline=deadline,
                    monotonic=monotonic,
                )
                return 0
            try:
                if command == "begin_verification":
                    verify_sealed()
                elif command == "complete_verification":
                    # This is the private-key-loader gate: the snapshot and
                    # every live source are revalidated before the ACK.
                    verify_sealed()
                    revalidate_live()
                elif command == "complete_signing":
                    # After the verified ACK, the signed claim is about the
                    # retained sealed object rather than mutable live inputs.
                    verify_sealed()
                elif command == "complete_publication":
                    verify_sealed()
                    lease.cleanup()
            except BaseException as exc:
                protocol.write_frame(
                    event_fd,
                    protocol.error_record(
                        session=session_id,
                        sequence=machine.sequence,
                        error_code=safe_child_error_code(exc),
                    ),
                    maximum_bytes=protocol.MAX_EVENT_FRAME_BYTES,
                    deadline=deadline,
                    monotonic=monotonic,
                )
                raise
            transition = protocol.COMMAND_TRANSITIONS[command]
            protocol.write_frame(
                event_fd,
                protocol.event_record(
                    session=session_id,
                    sequence=machine.sequence,
                    name=transition[2],
                    artifact_sha256=artifact,
                ),
                maximum_bytes=protocol.MAX_EVENT_FRAME_BYTES,
                deadline=deadline,
                monotonic=monotonic,
            )
            if command == "complete_publication":
                return 0
    finally:
        if getattr(lease, "active", False):
            lease.cleanup()


def _verify_provisional(
    lease: opaque_capture.OpaqueCaptureLease,
    initialization: HandoffInitialization,
) -> None:
    opaque_capture.verify_sealed_opaque_capture(
        lease.snapshot_root,
        plan=initialization.plan,
        expected_plan_sha256=initialization.plan_sha256,
        expected_capture_uid=initialization.capture_uid,
        expected_verifier_gid=initialization.verifier_gid,
        expected_manifest_sha256=lease.capture_manifest_sha256,
        expected_snapshot_gid=initialization.export_gid,
        expected_directory_mode=(
            opaque_capture.PROVISIONAL_DIRECTORY_MODE
        ),
        expected_file_mode=opaque_capture.PROVISIONAL_FILE_MODE,
        expected_source_directory_mode=(
            opaque_capture.EXPORT_SOURCE_DIRECTORY_MODE
        ),
        expected_source_file_mode=(
            opaque_capture.EXPORT_SOURCE_FILE_MODE
        ),
    )


def _revalidate_provisional_sources(
    lease: opaque_capture.OpaqueCaptureLease,
    initialization: HandoffInitialization,
) -> None:
    opaque_capture.revalidate_live_opaque_sources(
        lease.snapshot_root,
        plan=initialization.plan,
        expected_plan_sha256=initialization.plan_sha256,
        expected_capture_uid=initialization.capture_uid,
        expected_verifier_gid=initialization.verifier_gid,
        expected_manifest_sha256=lease.capture_manifest_sha256,
        expected_snapshot_gid=initialization.export_gid,
        expected_directory_mode=(
            opaque_capture.PROVISIONAL_DIRECTORY_MODE
        ),
        expected_file_mode=opaque_capture.PROVISIONAL_FILE_MODE,
        source_gid=initialization.export_gid,
        source_directory_mode=(
            opaque_capture.EXPORT_SOURCE_DIRECTORY_MODE
        ),
        source_file_mode=opaque_capture.EXPORT_SOURCE_FILE_MODE,
    )


def serve_handoff_with_lease(
    *,
    event_fd: int,
    initialization: HandoffInitialization,
    lease: Any,
    deadline: float,
    verify_provisional: Callable[[], None],
    revalidate_sources: Callable[[], None],
    monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Emit one v2 staged result, relinquish it, and return immediately."""

    try:
        verify_provisional()
        revalidate_sources()
        object_identity_sha256 = (
            lease._object_identity_sha256_for_adoption()
        )
        provisional_name = lease.snapshot_root.name
        if not opaque_capture.CAPTURE_NAME_RE.fullmatch(
            provisional_name
        ) or provisional_name.endswith(".building"):
            raise _error("capture_handoff_provisional_name_invalid")
        protocol.write_frame(
            event_fd,
            {
                "schema_version": protocol.HANDOFF_PROTOCOL_SCHEMA,
                "session_id": initialization.session_id,
                "sequence": 0,
                "event": "capture_staged",
                "provisional_name": provisional_name,
                "capture_plan_sha256": initialization.plan_sha256,
                "capture_selection_sha256": (
                    initialization.capture_selection_sha256
                ),
                "capture_manifest_sha256": (
                    lease.capture_manifest_sha256
                ),
                "capture_boundary_policy_sha256": (
                    initialization.capture_boundary_policy_sha256
                ),
                "helper_activation_policy_sha256": (
                    initialization.helper_activation_policy_sha256
                ),
                "request_sha256": initialization.request_sha256,
                "object_identity_sha256": object_identity_sha256,
            },
            maximum_bytes=protocol.MAX_EVENT_FRAME_BYTES,
            deadline=deadline,
            monotonic=monotonic,
        )
        # The parent may have received the frame, but it is forbidden to
        # adopt until the reaper proves this process group has disappeared.
        lease._relinquish_for_adoption()
        return 0
    finally:
        if getattr(lease, "active", False):
            lease.cleanup()


def handoff_child_main(
    initialization_value: Mapping[str, Any],
) -> int:
    """Run the short-lived v2 child after the shared frame was read."""

    lease: opaque_capture.OpaqueCaptureLease | None = None
    initialization = normalize_handoff_initialization(
        initialization_value
    )
    if (
        os.getuid() != initialization.capture_uid
        or os.geteuid() != initialization.capture_uid
        or os.getgid() != initialization.export_gid
        or os.getegid() != initialization.export_gid
        or os.getgroups()
    ):
        raise _error("capture_handoff_child_identity_invalid")
    lease = opaque_capture._capture_provisional_snapshot_for_adoption(
        plan=initialization.plan,
        plan_sha256=initialization.plan_sha256,
        destination_parent=initialization.destination_parent,
        evidence_uid=initialization.evidence_uid,
        capture_uid=initialization.capture_uid,
        export_gid=initialization.export_gid,
    )
    deadline = time.monotonic() + initialization.timeout_seconds
    return serve_handoff_with_lease(
        event_fd=1,
        initialization=initialization,
        lease=lease,
        deadline=deadline,
        verify_provisional=lambda: _verify_provisional(
            lease,
            initialization,
        ),
        revalidate_sources=lambda: _revalidate_provisional_sources(
            lease,
            initialization,
        ),
    )


def child_main() -> int:
    lease: opaque_capture.OpaqueCaptureLease | None = None
    session = "0" * 64
    handoff_request_sha256 = "0" * 64
    handoff_protocol = False
    try:
        initialization = protocol.read_frame(
            0,
            maximum_bytes=protocol.MAX_INITIALIZATION_FRAME_BYTES,
            deadline=time.monotonic() + protocol.MAX_TIMEOUT_SECONDS,
        )
        if (
            initialization.get("schema_version")
            == protocol.HANDOFF_PROTOCOL_SCHEMA
        ):
            handoff_protocol = True
            candidate_session = initialization.get("session_id")
            if (
                isinstance(candidate_session, str)
                and protocol.SESSION_ID_RE.fullmatch(candidate_session)
            ):
                session = candidate_session
            candidate_digest = initialization.get("request_sha256")
            if (
                isinstance(candidate_digest, str)
                and protocol.SHA256_RE.fullmatch(candidate_digest)
            ):
                handoff_request_sha256 = candidate_digest
            return handoff_child_main(initialization)
        (
            session,
            plan,
            plan_sha256,
            parent,
            helper_uid,
            helper_gid,
            timeout_seconds,
        ) = normalize_initialization(initialization)
        if (
            os.getuid() != helper_uid
            or os.geteuid() != helper_uid
            or os.getgid() != helper_gid
            or os.getegid() != helper_gid
            or os.getgroups()
        ):
            raise _error("capture_helper_child_identity_invalid")
        lease = opaque_capture._capture_opaque_snapshot_from_plan(
            plan=plan,
            plan_sha256=plan_sha256,
            destination_parent=parent,
            capture_uid=helper_uid,
        )
        deadline = time.monotonic() + timeout_seconds
        return serve_protocol_with_lease(
            control_fd=0,
            event_fd=1,
            session_id=session,
            plan=plan,
            helper_uid=helper_uid,
            helper_gid=helper_gid,
            lease=lease,
            deadline=deadline,
            verify_sealed=lambda: _verify_sealed(
                lease,
                plan=plan,
                helper_uid=helper_uid,
                helper_gid=helper_gid,
            ),
            revalidate_live=lambda: _revalidate_live(
                lease,
                plan=plan,
                helper_uid=helper_uid,
                helper_gid=helper_gid,
            ),
        )
    except BaseException as exc:
        try:
            if handoff_protocol:
                response = protocol.handoff_error_record(
                    session=session,
                    request_sha256=handoff_request_sha256,
                    error_code=safe_child_error_code(exc),
                )
            else:
                response = protocol.error_record(
                    session=session,
                    sequence=0,
                    error_code=safe_child_error_code(exc),
                )
            protocol.write_frame(
                1,
                response,
                maximum_bytes=protocol.MAX_EVENT_FRAME_BYTES,
            )
        except BaseException:
            pass
        return 125
    finally:
        if lease is not None and lease.active:
            try:
                lease.cleanup()
            except BaseException:
                pass


def _main(argv: Sequence[str]) -> int:
    if list(argv) != [CHILD_ARGUMENT]:
        return 2
    return child_main()


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
