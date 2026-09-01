from __future__ import annotations

import copy
import os
import pickle
import stat
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_adoption as adoption,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_child as child,
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
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_opaque_capture as opaque_capture,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_source_revalidation_binding
    as source_revalidation_binding,
)


class _FakeAdoptedLease:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.active = True
        self.capture_root = Path(
            "/var/lib/john-lomein/captures/"
            "opaque-capture-0123456789abcdef0123456789abcdef"
        )
        self.receipt = {
            "schema_version": adoption.ADOPTION_RECEIPT_SCHEMA,
            "status": adoption.ADOPTION_STATUS,
        }
        self.receipt_sha256 = "9" * 64

    def cleanup(self) -> None:
        if self.active:
            self.events.append("cleanup")
            self.active = False


class _RetryCleanupLease(_FakeAdoptedLease):
    def __init__(
        self,
        events: list[str],
        *,
        cleanup_failures: int,
    ) -> None:
        super().__init__(events)
        self.cleanup_failures = cleanup_failures

    def cleanup(self) -> None:
        if not self.active:
            return
        self.events.append("cleanup")
        if self.cleanup_failures:
            self.cleanup_failures -= 1
            raise RuntimeError("injected cleanup failure")
        self.active = False


class _FakeRecoveryLease(_FakeAdoptedLease):
    def __init__(
        self,
        events: list[str],
        *,
        ready: helper.CaptureStagedReadyV2,
        session_id: str,
        cleanup_failures: int = 0,
    ) -> None:
        super().__init__(events)
        self.ready = ready
        self.session_id = session_id
        self.cleanup_failures = cleanup_failures
        self.detached = False
        self.receipt["final_name"] = ready.provisional_name
        self._recovery_handoff_receipt = None

    def cleanup(self) -> None:
        if not self.active:
            return
        self.events.append("cleanup")
        if self.cleanup_failures:
            self.cleanup_failures -= 1
            raise RuntimeError("injected cleanup failure")
        self.active = False

    def defer_to_recovery(
        self,
        *,
        expected_object_sha256: str,
        expected_adoption_receipt_sha256: str,
        requested_evidence_sha256: str,
    ) -> dict[str, object]:
        if self._recovery_handoff_receipt is not None:
            return dict(self._recovery_handoff_receipt)
        if expected_object_sha256 != self.ready.object_identity_sha256:
            raise AssertionError("unexpected object binding")
        if expected_adoption_receipt_sha256 != self.receipt_sha256:
            raise AssertionError("unexpected adoption binding")
        self.events.append("defer")
        receipt = {
            "schema_version": adoption.RECOVERY_HANDOFF_RECEIPT_SCHEMA,
            "status": adoption.RECOVERY_HANDOFF_STATUS,
            "capture_session_id": self.session_id,
            "capture_adoption_receipt_sha256": self.receipt_sha256,
            "capture_object_identity_sha256": (
                self.ready.object_identity_sha256
            ),
            "capture_plan_sha256": self.ready.capture_plan_sha256,
            "capture_manifest_sha256": (
                self.ready.capture_manifest_sha256
            ),
            "capture_request_sha256": self.ready.request_sha256,
            "requested_evidence_sha256": requested_evidence_sha256,
            "final_name": self.ready.provisional_name,
            "deferred_object_stat_sha256": "a" * 64,
            "recovery_parent_identity_sha256": "b" * 64,
            "deferred_by_uid": 0,
            "deferred_at_unix": 1_900_000_000,
        }
        self._recovery_handoff_receipt = (
            adoption.normalize_recovery_handoff_receipt(receipt)
        )
        self.detached = True
        self.active = False
        return dict(self._recovery_handoff_receipt)

    @property
    def recovery_handoff_receipt(self) -> dict[str, object]:
        if self._recovery_handoff_receipt is None:
            raise AssertionError("not detached")
        return dict(self._recovery_handoff_receipt)


class _StrictRevalidationLease:
    def __init__(
        self,
        *,
        ready: helper.CaptureStagedReadyV2,
        events: list[str],
        cleanup_error: bool = False,
    ) -> None:
        self.events = events
        self.active = True
        self.capture_root = Path(
            "/var/lib/john-lomein/captures/"
            "opaque-capture-0123456789abcdef0123456789abcdef"
        )
        self.receipt = {
            "schema_version": adoption.ADOPTION_RECEIPT_SCHEMA,
            "status": adoption.ADOPTION_STATUS,
        }
        self.receipt_sha256 = "9" * 64
        binding = {
            "snapshot_root": self.capture_root,
            "capture_adoption_receipt_sha256": self.receipt_sha256,
            "capture_object_identity_sha256": (
                ready.object_identity_sha256
            ),
            "capture_plan_sha256": ready.capture_plan_sha256,
            "capture_manifest_sha256": (
                ready.capture_manifest_sha256
            ),
        }
        self.bindings: list[dict[str, object] | BaseException] = [
            binding,
            dict(binding),
        ]
        self.binding_calls = 0
        self.cleanup_error = cleanup_error

    def _assert_post_verifier_revalidation_binding(
        self,
    ) -> dict[str, object]:
        self.events.append(
            "pre_binding"
            if self.binding_calls == 0
            else "post_binding"
        )
        outcome = self.bindings[min(self.binding_calls, 1)]
        self.binding_calls += 1
        if isinstance(outcome, BaseException):
            raise outcome
        return dict(outcome)

    def cleanup(self) -> None:
        self.events.append("cleanup")
        if self.cleanup_error:
            raise RuntimeError("injected cleanup failure")
        self.active = False


class _FakeStagingLease:
    def __init__(
        self,
        *,
        staging_root: Path,
        session_id: str,
        events: list[str],
    ) -> None:
        self.active = True
        self._session_id = session_id
        self._events = events
        self._spawned = False
        self._dead = False
        self.leaf_path = (
            staging_root
            / helper.capture_staging.RECOVERY_NAMESPACE
            / f"session-{session_id}"
        )

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def spawned(self) -> bool:
        return self.active and self._spawned

    @property
    def process_scope_dead(self) -> bool:
        return self.active and self._dead

    def duplicate_leaf_descriptor(self) -> int:
        self._events.append("staging_duplicate")
        return os.open("/dev/null", os.O_RDONLY)

    def record_spawn_intent(self) -> None:
        self._events.append("spawn_intent")

    def record_spawn_failed(self) -> None:
        self._events.append("spawn_failed")

    def record_spawned(self) -> None:
        self._events.append("spawned")
        self._spawned = True

    def record_ready_bound(self) -> None:
        self._events.append("ready_bound")

    def mark_process_scope_dead(self) -> None:
        self._events.append("process_scope_dead")
        self._dead = True

    def finish_success(self) -> str:
        self._events.append("staging_success")
        self.active = False
        return "removed"

    def finish_failure(self) -> str:
        self._events.append("staging_failure")
        self.active = False
        return "removed"

    def abandon(self) -> None:
        self._events.append("staging_abandon")
        self.active = False


class _FakeProvisionalLease:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.active = True
        self.snapshot_root = Path(
            "/var/lib/john-lomein/staging/session/"
            "opaque-capture-0123456789abcdef0123456789abcdef"
        )
        self.capture_manifest_sha256 = "8" * 64

    def _object_identity_sha256_for_adoption(self) -> str:
        self.events.append("object_identity")
        return "7" * 64

    def _relinquish_for_adoption(self) -> None:
        self.events.append("relinquish")
        self.active = False

    def cleanup(self) -> None:
        self.events.append("cleanup")
        self.active = False


class PersonaQualificationCaptureHandoffV2Tests(unittest.TestCase):
    maxDiff = None

    session_id = "1" * 64

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(helper.CaptureHelperError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def plan(self) -> dict[str, object]:
        return capture_plan.normalize_capture_plan(
            {
                "schema_version": capture_plan.CAPTURE_PLAN_SCHEMA,
                "instance_slug": "john-example",
                "evidence_uid": 801,
                "verifier_gid": 804,
                "sources": [
                    {
                        "source_id": "instance",
                        "source_class": "instance_manifest",
                        "kind": "file",
                        "source_path": (
                            "/srv/john-lomein/export/instance.yaml"
                        ),
                        "destination_path": "instance/instance.yaml",
                    },
                    {
                        "source_id": "current-run",
                        "source_class": "qualification_private",
                        "kind": "tree",
                        "source_path": (
                            "/srv/john-lomein/export/current-run"
                        ),
                        "destination_path": "private",
                    },
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

    def policy(self) -> helper.CaptureHandoffPolicyV2:
        plan = self.plan()
        return helper.CaptureHandoffPolicyV2(
            system="Linux",
            kernel_release="fixture-kernel",
            backend_path=Path("/usr/bin/bwrap"),
            backend_sha256="2" * 64,
            bundle_root=Path("/opt/john-lomein/capture-v2"),
            bundle_sha256="3" * 64,
            python_path=Path(
                "/opt/john-lomein/capture-v2/bin/python3"
            ),
            entrypoint_path=Path(
                "/opt/john-lomein/capture-v2/capture_child.py"
            ),
            installed_plan_path=Path(
                "/etc/john-lomein/capture-plan.json"
            ),
            capture_plan_bytes=protocol.canonical_json(plan),
            capture_plan_sha256=capture_plan.capture_plan_sha256(plan),
            capture_selection_sha256="4" * 64,
            capture_boundary_policy_sha256="5" * 64,
            source_mounts=tuple(
                helper.CaptureSourceMount(
                    Path(source["source_path"]),
                    source["kind"],
                )
                for source in plan["sources"]
            ),
            staging_parent=Path(
                "/var/lib/john-lomein/staging/session"
            ),
            final_parent=Path("/var/lib/john-lomein/captures"),
            activation_receipt_path=Path(
                "/etc/john-lomein/capture-handoff-activation.json"
            ),
            evidence_uid=801,
            capture_uid=802,
            export_gid=803,
            verifier_uid=805,
            verifier_gid=804,
            timeout_seconds=120,
            denied_secret_paths=(
                helper.DeniedSecretPath(
                    "attestation_state",
                    Path("/var/lib/john-lomein/attestor/state"),
                ),
                helper.DeniedSecretPath(
                    "model_secret",
                    Path("/etc/john-lomein/model-secrets.env"),
                ),
                helper.DeniedSecretPath(
                    "private_key",
                    Path("/var/lib/john-lomein/attestor/key.pem"),
                ),
                helper.DeniedSecretPath(
                    "public_projection",
                    Path("/var/lib/john-lomein/public/trust.json"),
                ),
            ),
            loader_mounts=(
                helper.ImmutableReadMount(
                    Path("/usr/lib"),
                    Path("/usr/lib"),
                    "directory",
                ),
            ),
        )

    def initialization(
        self,
        policy: helper.CaptureHandoffPolicyV2 | None = None,
    ) -> dict[str, object]:
        return helper._handoff_initialization_record(
            policy or self.policy(),
            session_id=self.session_id,
        )

    def ready(
        self,
        policy: helper.CaptureHandoffPolicyV2 | None = None,
    ) -> dict[str, object]:
        selected = policy or self.policy()
        initialization = self.initialization(selected)
        return {
            "schema_version": protocol.HANDOFF_PROTOCOL_SCHEMA,
            "session_id": self.session_id,
            "sequence": 0,
            "event": "capture_staged",
            "provisional_name": (
                "opaque-capture-"
                "0123456789abcdef0123456789abcdef"
            ),
            "capture_plan_sha256": selected.capture_plan_sha256,
            "capture_selection_sha256": (
                selected.capture_selection_sha256
            ),
            "capture_manifest_sha256": "8" * 64,
            "capture_boundary_policy_sha256": (
                selected.capture_boundary_policy_sha256
            ),
            "helper_activation_policy_sha256": (
                selected.activation_policy_sha256()
            ),
            "request_sha256": initialization["request_sha256"],
            "object_identity_sha256": "7" * 64,
        }

    def launcher_ready(
        self,
        policy: helper.CaptureHandoffPolicyV2,
        staging_lease: _FakeStagingLease,
    ) -> dict[str, object]:
        initialization = helper._handoff_initialization_record(
            policy,
            session_id=staging_lease.session_id,
            destination_parent=staging_lease.leaf_path,
        )
        ready = self.ready(policy)
        ready["request_sha256"] = initialization["request_sha256"]
        return ready

    def strict_revalidation_session(
        self,
        *,
        events: list[str] | None = None,
        cleanup_error: bool = False,
    ) -> tuple[
        helper.CaptureHandoffPolicyV2,
        helper.CaptureStagedReadyV2,
        _StrictRevalidationLease,
        object,
        helper.AdoptedCaptureSessionV2,
    ]:
        policy = self.policy()
        initialization = self.initialization(policy)
        ready = helper._normalize_handoff_ready(
            self.ready(policy),
            policy=policy,
            session_id=self.session_id,
            request_sha256=initialization["request_sha256"],
        )
        lease = _StrictRevalidationLease(
            ready=ready,
            events=events if events is not None else [],
            cleanup_error=cleanup_error,
        )
        adoption_module = mock.Mock()
        adoption_module.AdoptedCaptureLease = _StrictRevalidationLease
        adoption_module.ADOPTED_DIRECTORY_MODE = 0o550
        adoption_module.ADOPTED_FILE_MODE = 0o440
        with mock.patch.object(
            helper,
            "_capture_adoption_module",
            return_value=adoption_module,
        ):
            session = helper.AdoptedCaptureSessionV2(
                _token=helper._HANDOFF_SESSION_TOKEN,
                lease=lease,
                policy=policy,
                ready=ready,
                session_id=self.session_id,
            )
        return policy, ready, lease, adoption_module, session

    def unprivileged_session(
        self,
        lease: _FakeAdoptedLease,
    ) -> helper.AdoptedCaptureSessionV2:
        policy = self.policy()
        initialization = self.initialization(policy)
        ready = helper._normalize_handoff_ready(
            self.ready(policy),
            policy=policy,
            session_id=self.session_id,
            request_sha256=initialization["request_sha256"],
        )
        return helper.AdoptedCaptureSessionV2(
            _token=helper._HANDOFF_SESSION_TOKEN,
            lease=lease,
            policy=policy,
            ready=ready,
            session_id=self.session_id,
            strict_lease_type=False,
        )

    def test_v2_request_binds_every_field_and_keeps_v1_explicit(self) -> None:
        policy = self.policy()
        initialization = self.initialization(policy)
        self.assertEqual(
            initialization["schema_version"],
            protocol.HANDOFF_PROTOCOL_SCHEMA,
        )
        self.assertEqual(
            protocol.PROTOCOL_SCHEMA,
            protocol.LEGACY_PROTOCOL_SCHEMA,
        )
        normalized = child.normalize_handoff_initialization(
            initialization
        )
        self.assertEqual(normalized.evidence_uid, 801)
        self.assertEqual(normalized.capture_uid, 802)
        self.assertEqual(normalized.export_gid, 803)
        self.assertEqual(normalized.verifier_uid, 805)
        self.assertEqual(normalized.verifier_gid, 804)

        for field, replacement in (
            ("capture_uid", 806),
            ("export_gid", 807),
            ("verifier_uid", 808),
            ("capture_selection_sha256", "a" * 64),
            ("capture_boundary_policy_sha256", "b" * 64),
            ("helper_activation_policy_sha256", "c" * 64),
            ("destination_parent", "/var/lib/other"),
        ):
            tampered = copy.deepcopy(initialization)
            tampered[field] = replacement
            self.assert_code(
                "capture_handoff_request_digest_mismatch",
                child.normalize_handoff_initialization,
                tampered,
            )

        rebound = dict(initialization)
        rebound["capture_uid"] = 801
        rebound.pop("request_sha256")
        rebound = protocol.bind_handoff_request(rebound)
        self.assert_code(
            "capture_handoff_identity_mismatch",
            child.normalize_handoff_initialization,
            rebound,
        )
        missing = dict(initialization)
        missing.pop("export_gid")
        self.assert_code(
            "capture_handoff_initialization_invalid",
            child.normalize_handoff_initialization,
            missing,
        )

    def test_policy_has_no_helper_identity_alias_and_is_strict(self) -> None:
        policy = self.policy()
        helper._validate_handoff_policy_shape(policy)
        self.assertFalse(hasattr(policy, "helper_uid"))
        self.assertFalse(hasattr(policy, "helper_gid"))
        self.assertEqual(helper._child_identity(policy), (802, 803))
        record = policy.activation_record()
        self.assertEqual(
            record["identities"],
            {
                "evidence_uid": 801,
                "capture_uid": 802,
                "export_gid": 803,
                "verifier_uid": 805,
                "verifier_gid": 804,
            },
        )
        self.assertEqual(
            record["source_contract"]["directory_mode"],
            0o750,
        )
        self.assertEqual(
            record["provisional_contract"]["file_mode"],
            0o400,
        )
        self.assertEqual(
            record["lifetime_contract"],
            "root-leaf-lock-ready-fd-reap-adoption-cleanup",
        )
        staging_leaf = (
            policy.staging_parent
            / helper.capture_staging.RECOVERY_NAMESPACE
            / f"session-{self.session_id}"
        )
        self.assert_code(
            "capture_handoff_session_staging_required",
            helper.build_linux_command,
            policy,
        )
        command = helper.build_linux_command(
            policy,
            staging_leaf=staging_leaf,
        )
        self.assertEqual(command[command.index("--uid") + 1], "802")
        self.assertEqual(command[command.index("--gid") + 1], "803")
        self.assertNotIn(str(policy.final_parent), command)
        self.assertNotIn(str(policy.staging_parent), command)
        self.assertIn(str(staging_leaf), command)
        self.assertEqual(
            record["staging_root_contract"]["mode"],
            0o711,
        )

        self.assert_code(
            "capture_handoff_uid_separation_missing",
            helper._validate_handoff_policy_shape,
            replace(policy, capture_uid=policy.evidence_uid),
        )
        self.assert_code(
            "capture_handoff_group_separation_missing",
            helper._validate_handoff_policy_shape,
            replace(policy, export_gid=policy.verifier_gid),
        )
        self.assert_code(
            "capture_handoff_identity_plan_mismatch",
            helper._validate_handoff_policy_shape,
            replace(policy, verifier_gid=900),
        )

    def test_child_rejects_wrong_runtime_uid_gid_and_groups_pre_capture(
        self,
    ) -> None:
        initialization = self.initialization()
        cases = (
            (801, 802, 803, 803, []),
            (802, 802, 804, 804, []),
            (802, 802, 803, 803, [803]),
        )
        for real_uid, effective_uid, real_gid, effective_gid, groups in cases:
            with self.subTest(
                uid=(real_uid, effective_uid),
                gid=(real_gid, effective_gid),
                groups=groups,
            ), mock.patch.object(
                child.os,
                "getuid",
                return_value=real_uid,
            ), mock.patch.object(
                child.os,
                "geteuid",
                return_value=effective_uid,
            ), mock.patch.object(
                child.os,
                "getgid",
                return_value=real_gid,
            ), mock.patch.object(
                child.os,
                "getegid",
                return_value=effective_gid,
            ), mock.patch.object(
                child.os,
                "getgroups",
                return_value=groups,
            ), mock.patch.object(
                child.opaque_capture,
                "_capture_provisional_snapshot_for_adoption",
            ) as capture:
                self.assert_code(
                    "capture_handoff_child_identity_invalid",
                    child.handoff_child_main,
                    initialization,
                )
                capture.assert_not_called()

    def test_child_emits_then_relinquishes_and_never_serves_commands(
        self,
    ) -> None:
        initialization = child.normalize_handoff_initialization(
            self.initialization()
        )
        events: list[str] = []
        lease = _FakeProvisionalLease(events)
        read_fd, write_fd = os.pipe()
        try:
            result = child.serve_handoff_with_lease(
                event_fd=write_fd,
                initialization=initialization,
                lease=lease,
                deadline=time.monotonic() + 1,
                verify_provisional=lambda: events.append("verify"),
                revalidate_sources=lambda: events.append("revalidate"),
            )
            os.close(write_fd)
            write_fd = -1
            ready = protocol.read_frame(
                read_fd,
                maximum_bytes=protocol.MAX_EVENT_FRAME_BYTES,
                deadline=time.monotonic() + 1,
            )
        finally:
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)
        self.assertEqual(result, 0)
        self.assertEqual(
            events,
            ["verify", "revalidate", "object_identity", "relinquish"],
        )
        self.assertEqual(ready["event"], "capture_staged")
        self.assertEqual(
            set(ready),
            protocol.HANDOFF_READY_FIELDS,
        )
        self.assertFalse(lease.active)

    def test_opaque_engine_mechanically_seals_export_provisional_modes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            # macOS spells the temporary root through a /var symlink; the
            # descriptor-relative contract deliberately rejects symlinks.
            root = Path(temporary).resolve()
            export = root / "export"
            run = export / "current-run"
            staging = root / "staging"
            export.mkdir(mode=0o750)
            run.mkdir(mode=0o750)
            staging.mkdir(mode=0o700)
            export.chmod(0o750)
            run.chmod(0o750)
            staging.chmod(0o700)
            instance = export / "instance.yaml"
            status = run / "status.json"
            instance.write_bytes(b"instance\n")
            status.write_bytes(b'{"status":"qualified"}\n')
            instance.chmod(0o640)
            status.chmod(0o640)
            uid = os.geteuid()
            gid = os.getegid()
            verifier_gid = 1 if gid != 1 else 2
            plan = capture_plan.normalize_capture_plan(
                {
                    "schema_version": capture_plan.CAPTURE_PLAN_SCHEMA,
                    "instance_slug": "mechanical-export",
                    "evidence_uid": uid,
                    "verifier_gid": verifier_gid,
                    "sources": [
                        {
                            "source_id": "instance",
                            "source_class": "instance_manifest",
                            "kind": "file",
                            "source_path": str(instance),
                            "destination_path": (
                                "instance/instance.yaml"
                            ),
                        },
                        {
                            "source_id": "run",
                            "source_class": "qualification_private",
                            "kind": "tree",
                            "source_path": str(run),
                            "destination_path": "private",
                        },
                    ],
                    "limits": {
                        "max_files": 16,
                        "max_directories": 16,
                        "max_bytes": 1024 * 1024,
                        "max_file_bytes": 256 * 1024,
                        "max_depth": 16,
                    },
                    "lifecycle": {
                        "retention": "ephemeral",
                        "max_capture_slots": 2,
                        "max_orphan_age_seconds": 60,
                    },
                }
            )
            plan_sha256 = capture_plan.capture_plan_sha256(plan)
            lease = opaque_capture._capture_opaque_snapshot_from_plan(
                plan=plan,
                plan_sha256=plan_sha256,
                destination_parent=staging,
                capture_uid=uid,
                capture_gid=gid,
                destination_parent_mode=0o700,
                sealed_directory_mode=0o500,
                sealed_file_mode=0o400,
                source_gid=gid,
                source_directory_mode=0o750,
                source_file_mode=0o640,
            )
            try:
                self.assertEqual(
                    adoption.capture_object_identity_sha256(
                        lease._fileno_for_test()
                    ),
                    lease._object_identity_sha256_for_adoption(),
                )
                manifest = lease.manifest
                self.assertEqual(
                    {
                        entry["source_mode"]
                        for entry in manifest["source_directories"]
                    },
                    {0o750},
                )
                self.assertEqual(
                    {
                        entry["source_mode"]
                        for entry in manifest["files"]
                    },
                    {0o640},
                )
                for directory, directories, files in os.walk(
                    lease.snapshot_root
                ):
                    info = os.lstat(directory)
                    self.assertEqual(info.st_uid, uid)
                    self.assertEqual(info.st_gid, gid)
                    self.assertEqual(
                        stat.S_IMODE(info.st_mode),
                        0o500,
                    )
                    for name in directories:
                        child_path = Path(directory) / name
                        child_info = os.lstat(child_path)
                        self.assertEqual(child_info.st_uid, uid)
                        self.assertEqual(child_info.st_gid, gid)
                    for name in files:
                        child_path = Path(directory) / name
                        child_info = os.lstat(child_path)
                        self.assertEqual(child_info.st_uid, uid)
                        self.assertEqual(child_info.st_gid, gid)
                        self.assertEqual(
                            stat.S_IMODE(child_info.st_mode),
                            0o400,
                        )
            finally:
                lease.cleanup()
            self.assertEqual(list(staging.iterdir()), [])

    def test_root_orders_reap_before_adoption_and_lease_spans_use(
        self,
    ) -> None:
        policy = self.policy()
        initialization = self.initialization(policy)
        ready = self.ready(policy)
        events: list[str] = []
        proof = object()

        def reaper(**kwargs):
            self.assertEqual(kwargs["capture_uid"], 802)
            events.append("reap")
            return proof

        def adopter(adoption_policy, observed_proof, **kwargs):
            self.assertIs(observed_proof, proof)
            self.assertEqual(adoption_policy.capture_gid, 803)
            self.assertEqual(adoption_policy.verifier_uid, 805)
            self.assertEqual(adoption_policy.verifier_gid, 804)
            self.assertEqual(
                adoption_policy.expected_object_sha256,
                "7" * 64,
            )
            self.assertEqual(set(kwargs), {
                "staging_parent_fd",
                "final_parent_fd",
            })
            events.append("adopt")
            return _FakeAdoptedLease(events)

        session = helper._coordinate_handoff_for_test(
            policy=policy,
            ready_value=ready,
            session_id=self.session_id,
            request_sha256=initialization["request_sha256"],
            pid=1234,
            staging_parent_fd=-1,
            final_parent_fd=-1,
            reaper=reaper,
            adopter=adopter,
        )
        self.assertEqual(events, ["reap", "adopt"])
        self.assertTrue(session.active)
        self.assertEqual(
            session.begin_verification(),
            "verification_authorized",
        )
        self.assertTrue(session.active)
        self.assertEqual(
            session.complete_verification("a" * 64),
            "signing_authorized",
        )
        self.assertTrue(session.active)
        self.assertEqual(
            session.complete_signing("b" * 64),
            "publication_authorized",
        )
        self.assertEqual(
            session.complete_signing("b" * 64),
            "publication_authorized",
        )
        self.assert_code(
            "capture_handoff_signing_digest_mismatch",
            session.complete_signing,
            "d" * 64,
        )
        self.assertFalse(session.active)
        self.assertEqual(
            session.complete_publication("c" * 64),
            "cleaned",
        )
        self.assertEqual(
            session.complete_publication("c" * 64),
            "cleaned",
        )
        self.assert_code(
            "capture_handoff_publication_digest_mismatch",
            session.complete_publication,
            "e" * 64,
        )
        self.assertEqual(events, ["reap", "adopt", "cleanup"])
        self.assertFalse(session.active)

    def test_signing_commit_cleanup_retries_only_exact_digest(
        self,
    ) -> None:
        events: list[str] = []
        (
            _policy,
            _ready,
            lease,
            adoption_module,
            session,
        ) = self.strict_revalidation_session(
            events=events,
            cleanup_error=True,
        )
        session.begin_verification()
        with (
            mock.patch.object(
                helper,
                "_capture_adoption_module",
                return_value=adoption_module,
            ),
            mock.patch.object(helper.os, "getuid", return_value=0),
            mock.patch.object(helper.os, "geteuid", return_value=0),
            mock.patch.object(
                helper.opaque_capture,
                "revalidate_live_opaque_sources",
                return_value={},
            ),
            mock.patch.object(
                helper.time,
                "time",
                return_value=1_800_000_000,
            ),
        ):
            session.complete_verification("a" * 64)

        self.assert_code(
            "capture_handoff_attestation_commit_cleanup_failed",
            session.complete_signing,
            "b" * 64,
        )
        self.assertTrue(session.active)
        self.assertEqual(events[-1:], ["cleanup"])
        self.assert_code(
            "capture_handoff_attestation_commit_cleanup_pending",
            session.complete_publication,
            "c" * 64,
        )
        self.assert_code(
            "capture_handoff_signing_digest_mismatch",
            session.complete_signing,
            "d" * 64,
        )
        self.assertEqual(events[-1:], ["cleanup"])

        lease.cleanup_error = False
        self.assertEqual(
            session.complete_signing("b" * 64),
            "publication_authorized",
        )
        self.assertEqual(events[-2:], ["cleanup", "cleanup"])
        self.assertFalse(session.active)
        self.assertEqual(session.capture_session_id, self.session_id)
        self.assertEqual(
            session.adoption_receipt_sha256,
            "9" * 64,
        )
        self.assertEqual(
            session.adoption_receipt["status"],
            adoption.ADOPTION_STATUS,
        )
        self.assertEqual(
            session.abort("late_abort"),
            "attestation_committed_cleaned",
        )
        self.assertEqual(
            session.complete_publication("c" * 64),
            "cleaned",
        )

    def test_context_exit_retries_committed_cleanup_without_abort(
        self,
    ) -> None:
        events: list[str] = []
        lease = _RetryCleanupLease(events, cleanup_failures=1)
        session = self.unprivileged_session(lease)
        session.begin_verification()
        session.complete_verification("a" * 64)

        with self.assertRaises(helper.CaptureHelperError):
            with session:
                session.complete_signing("b" * 64)
        self.assertEqual(events, ["cleanup", "cleanup"])
        self.assertFalse(lease.active)
        self.assertFalse(session.active)
        self.assertEqual(
            session._state,
            "attestation_committed_cleaned",
        )
        session.close()
        self.assertEqual(events, ["cleanup", "cleanup"])

    def test_finalizer_retries_committed_cleanup_without_abort_label(
        self,
    ) -> None:
        events: list[str] = []
        lease = _RetryCleanupLease(events, cleanup_failures=1)
        session = self.unprivileged_session(lease)
        session.begin_verification()
        session.complete_verification("a" * 64)
        self.assert_code(
            "capture_handoff_attestation_commit_cleanup_failed",
            session.complete_signing,
            "b" * 64,
        )

        session.__del__()
        self.assertEqual(events, ["cleanup", "cleanup"])
        self.assertFalse(lease.active)
        self.assertEqual(
            session._state,
            "attestation_committed_cleaned",
        )

    def test_publication_ambiguity_detaches_and_context_gc_never_cleans(
        self,
    ) -> None:
        events: list[str] = []
        policy = self.policy()
        initialization = self.initialization(policy)
        ready = helper._normalize_handoff_ready(
            self.ready(policy),
            policy=policy,
            session_id=self.session_id,
            request_sha256=initialization["request_sha256"],
        )
        lease = _FakeRecoveryLease(
            events,
            ready=ready,
            session_id=self.session_id,
        )
        session = helper.AdoptedCaptureSessionV2(
            _token=helper._HANDOFF_SESSION_TOKEN,
            lease=lease,
            policy=policy,
            ready=ready,
            session_id=self.session_id,
            strict_lease_type=False,
        )
        session.begin_verification()
        session.complete_verification("a" * 64)

        with session:
            receipt = session.defer_publication_ambiguity("c" * 64)

        self.assertEqual(events, ["defer"])
        self.assertFalse(session.active)
        self.assertTrue(lease.detached)
        self.assertEqual(
            session._state,
            "publication_ambiguity_deferred",
        )
        self.assertEqual(
            session.recovery_handoff_receipt,
            adoption.normalize_recovery_handoff_receipt(receipt),
        )
        self.assertEqual(
            session.recovery_handoff_receipt_sha256,
            adoption.recovery_handoff_receipt_sha256(receipt),
        )
        self.assertEqual(
            session.capture_session_id,
            self.session_id,
        )
        self.assertEqual(
            session.capture_request_sha256,
            ready.request_sha256,
        )
        self.assertEqual(
            session.defer_publication_ambiguity("c" * 64),
            receipt,
        )
        self.assert_code(
            "capture_handoff_publication_ambiguity_digest_mismatch",
            session.defer_publication_ambiguity,
            "d" * 64,
        )
        self.assert_code(
            "capture_handoff_session_transition_invalid",
            session.complete_publication,
            "e" * 64,
        )
        self.assertEqual(
            session.abort("late_ambiguity_abort"),
            "publication_ambiguity_deferred",
        )
        session.close()
        session.__del__()
        self.assertEqual(events, ["defer"])

    def test_cleanup_pending_may_defer_only_the_exact_ambiguity_digest(
        self,
    ) -> None:
        events: list[str] = []
        policy = self.policy()
        initialization = self.initialization(policy)
        ready = helper._normalize_handoff_ready(
            self.ready(policy),
            policy=policy,
            session_id=self.session_id,
            request_sha256=initialization["request_sha256"],
        )
        lease = _FakeRecoveryLease(
            events,
            ready=ready,
            session_id=self.session_id,
            cleanup_failures=1,
        )
        session = helper.AdoptedCaptureSessionV2(
            _token=helper._HANDOFF_SESSION_TOKEN,
            lease=lease,
            policy=policy,
            ready=ready,
            session_id=self.session_id,
            strict_lease_type=False,
        )
        session.begin_verification()
        session.complete_verification("a" * 64)
        self.assert_code(
            "capture_handoff_attestation_commit_cleanup_failed",
            session.complete_signing,
            "b" * 64,
        )
        receipt = session.defer_publication_ambiguity("c" * 64)
        self.assertEqual(events, ["cleanup", "defer"])
        self.assertEqual(
            receipt["requested_evidence_sha256"],
            "c" * 64,
        )
        self.assertEqual(
            session.defer_publication_ambiguity("c" * 64),
            receipt,
        )
        self.assert_code(
            "capture_handoff_publication_ambiguity_digest_mismatch",
            session.defer_publication_ambiguity,
            "d" * 64,
        )
        session.close()
        session.__del__()
        self.assertEqual(events, ["cleanup", "defer"])

    def test_root_revalidates_live_sources_before_authorizing_signing(
        self,
    ) -> None:
        events: list[str] = []
        (
            policy,
            ready,
            lease,
            adoption_module,
            session,
        ) = self.strict_revalidation_session(events=events)
        self.assertEqual(
            session.begin_verification(),
            "verification_authorized",
        )

        def revalidate(snapshot_root, **_kwargs):
            self.assertEqual(snapshot_root, lease.capture_root)
            events.append("revalidate")
            return {"status": "checked"}

        def clock() -> float:
            events.append("clock")
            return 1_800_000_000

        with (
            mock.patch.object(
                helper,
                "_capture_adoption_module",
                return_value=adoption_module,
            ),
            mock.patch.object(
                helper.os,
                "getuid",
                return_value=0,
            ),
            mock.patch.object(
                helper.os,
                "geteuid",
                return_value=0,
            ),
            mock.patch.object(
                helper.opaque_capture,
                "revalidate_live_opaque_sources",
                side_effect=revalidate,
            ) as revalidator,
            mock.patch.object(
                helper.time,
                "time",
                side_effect=clock,
            ),
        ):
            receipt = session.complete_verification("a" * 64)

        self.assertEqual(
            events,
            ["pre_binding", "revalidate", "post_binding", "clock"],
        )
        self.assertEqual(
            receipt,
            source_revalidation_binding
            .normalize_source_revalidation_receipt(receipt),
        )
        self.assertEqual(
            receipt["schema_version"],
            source_revalidation_binding
            .SOURCE_REVALIDATION_RECEIPT_SCHEMA,
        )
        self.assertEqual(receipt["status"], "revalidated")
        self.assertEqual(receipt["revalidator_uid"], 0)
        self.assertEqual(receipt["revalidated_at_unix"], 1_800_000_000)
        self.assertEqual(
            receipt["capture_adoption_receipt_sha256"],
            lease.receipt_sha256,
        )
        self.assertEqual(
            receipt["capture_object_identity_sha256"],
            ready.object_identity_sha256,
        )
        self.assertEqual(receipt["verifier_output_sha256"], "a" * 64)
        self.assertRegex(
            source_revalidation_binding
            .source_revalidation_receipt_sha256(receipt),
            r"^[0-9a-f]{64}$",
        )
        revalidator.assert_called_once_with(
            lease.capture_root,
            plan=policy.capture_plan,
            expected_plan_sha256=ready.capture_plan_sha256,
            expected_capture_uid=0,
            expected_verifier_gid=policy.verifier_gid,
            expected_manifest_sha256=ready.capture_manifest_sha256,
            expected_manifest_capture_uid=policy.capture_uid,
            expected_snapshot_gid=policy.verifier_gid,
            expected_directory_mode=0o550,
            expected_file_mode=0o440,
            source_gid=policy.export_gid,
            source_directory_mode=0o750,
            source_file_mode=0o640,
        )
        self.assertEqual(
            session.complete_signing("b" * 64),
            "publication_authorized",
        )
        session.abort()

    def test_post_verifier_revalidation_requires_real_root_and_closes(
        self,
    ) -> None:
        events: list[str] = []
        (
            _policy,
            _ready,
            _lease,
            adoption_module,
            session,
        ) = self.strict_revalidation_session(events=events)
        session.begin_verification()
        with (
            mock.patch.object(
                helper,
                "_capture_adoption_module",
                return_value=adoption_module,
            ),
            mock.patch.object(
                helper.os,
                "getuid",
                return_value=501,
            ),
            mock.patch.object(
                helper.os,
                "geteuid",
                return_value=0,
            ),
            mock.patch.object(
                helper.opaque_capture,
                "revalidate_live_opaque_sources",
            ) as revalidator,
        ):
            self.assert_code(
                "capture_handoff_post_verifier_"
                "revalidation_requires_root",
                session.complete_verification,
                "a" * 64,
            )
        self.assertEqual(events, ["cleanup"])
        revalidator.assert_not_called()
        self.assertFalse(session.active)
        self.assert_code(
            "capture_handoff_session_closed",
            session.complete_signing,
            "b" * 64,
        )

    def test_live_source_tamper_is_terminal_and_returns_no_receipt(
        self,
    ) -> None:
        events: list[str] = []
        (
            _policy,
            _ready,
            _lease,
            adoption_module,
            session,
        ) = self.strict_revalidation_session(events=events)
        session.begin_verification()
        clock = mock.Mock(return_value=1_800_000_000)

        def reject(*_args, **_kwargs):
            events.append("revalidate")
            raise opaque_capture.OpaqueCaptureError(
                "opaque_capture_live_source_file_changed"
            )

        with (
            mock.patch.object(
                helper,
                "_capture_adoption_module",
                return_value=adoption_module,
            ),
            mock.patch.object(helper.os, "getuid", return_value=0),
            mock.patch.object(helper.os, "geteuid", return_value=0),
            mock.patch.object(
                helper.opaque_capture,
                "revalidate_live_opaque_sources",
                side_effect=reject,
            ),
            mock.patch.object(helper.time, "time", clock),
        ):
            self.assert_code(
                "opaque_capture_live_source_file_changed",
                session.complete_verification,
                "a" * 64,
            )
        self.assertEqual(
            events,
            ["pre_binding", "revalidate", "cleanup"],
        )
        clock.assert_not_called()
        self.assertFalse(session.active)

    def test_post_revalidation_rebind_is_terminal_before_timestamp(
        self,
    ) -> None:
        events: list[str] = []
        (
            _policy,
            _ready,
            lease,
            adoption_module,
            session,
        ) = self.strict_revalidation_session(events=events)
        changed = dict(lease.bindings[1])
        changed["capture_object_identity_sha256"] = "f" * 64
        lease.bindings[1] = changed
        session.begin_verification()
        clock = mock.Mock(return_value=1_800_000_000)

        def revalidate(*_args, **_kwargs):
            events.append("revalidate")
            return {}

        with (
            mock.patch.object(
                helper,
                "_capture_adoption_module",
                return_value=adoption_module,
            ),
            mock.patch.object(helper.os, "getuid", return_value=0),
            mock.patch.object(helper.os, "geteuid", return_value=0),
            mock.patch.object(
                helper.opaque_capture,
                "revalidate_live_opaque_sources",
                side_effect=revalidate,
            ),
            mock.patch.object(helper.time, "time", clock),
        ):
            self.assert_code(
                "capture_handoff_post_verifier_binding_changed",
                session.complete_verification,
                "a" * 64,
            )
        self.assertEqual(
            events,
            [
                "pre_binding",
                "revalidate",
                "post_binding",
                "cleanup",
            ],
        )
        clock.assert_not_called()
        self.assertFalse(session.active)

    def test_post_ready_reap_timeout_is_capped_by_adoption_contract(
        self,
    ) -> None:
        policy = replace(self.policy(), timeout_seconds=120)
        self.assertEqual(
            helper._handoff_reap_timeout(policy),
            adoption.MAX_REAP_SECONDS,
        )

    def test_launcher_retains_ready_object_before_reap_and_closes(
        self,
    ) -> None:
        policy = self.policy()
        events: list[str] = []
        staging_lease = _FakeStagingLease(
            staging_root=policy.staging_parent,
            session_id=self.session_id,
            events=events,
        )
        initialization = helper._handoff_initialization_record(
            policy,
            session_id=self.session_id,
            destination_parent=staging_lease.leaf_path,
        )
        ready = self.ready(policy)
        ready["request_sha256"] = initialization["request_sha256"]
        authority = mock.Mock()
        authority.close.side_effect = lambda: events.append("close")
        real_normalize = helper._normalize_handoff_ready

        def open_parent(*_args, **_kwargs) -> int:
            return os.open("/dev/null", os.O_RDONLY)

        def normalize(*args, **kwargs):
            events.append("normalize")
            return real_normalize(*args, **kwargs)

        def retain(**kwargs):
            self.assertEqual(kwargs["session_id"], self.session_id)
            self.assertEqual(kwargs["capture_uid"], 802)
            self.assertEqual(
                kwargs["provisional_name"],
                ready["provisional_name"],
            )
            self.assertEqual(
                kwargs["expected_object_sha256"],
                ready["object_identity_sha256"],
            )
            events.append("retain")
            return authority

        def reap(**_kwargs):
            events.append("reap")
            return object()

        def adopt(**kwargs):
            self.assertIs(
                kwargs["provisional_authority"],
                authority,
            )
            self.assertEqual(
                kwargs["session_staging_parent"],
                staging_lease.leaf_path,
            )
            events.append("adopt")
            return "adopted-session"

        def create_staging(*_args, **kwargs):
            self.assertEqual(kwargs["capture_uid"], 802)
            self.assertEqual(kwargs["export_gid"], 803)
            events.append("staging_create")
            return staging_lease

        with (
            mock.patch.object(
                helper,
                "_open_handoff_parent",
                side_effect=open_parent,
            ),
            mock.patch.object(
                helper.capture_staging,
                "create_session_staging",
                side_effect=create_staging,
            ),
            mock.patch.object(
                helper,
                "build_linux_command",
                return_value=("/bin/true",),
            ),
            mock.patch.object(
                helper,
                "build_linux_seccomp_filter",
                return_value=b"filter",
            ),
            mock.patch.object(
                helper,
                "_spawn_child",
                return_value=6161,
            ),
            mock.patch.object(helper, "_write_frame"),
            mock.patch.object(
                helper,
                "_read_frame",
                return_value=ready,
            ),
            mock.patch.object(
                helper,
                "_normalize_handoff_ready",
                side_effect=normalize,
            ),
            mock.patch.object(
                adoption,
                "retain_provisional_capture",
                side_effect=retain,
            ),
            mock.patch.object(
                adoption,
                "reap_capture_child",
                side_effect=reap,
            ),
            mock.patch.object(
                helper,
                "_adopt_ready_capture",
                side_effect=adopt,
            ),
            mock.patch.object(helper, "_kill_and_reap") as fallback,
        ):
            session = helper._launch_validated_handoff(
                policy,
                adopter=lambda *_args, **_kwargs: object(),
            )
        self.assertEqual(session, "adopted-session")
        self.assertEqual(
            events,
            [
                "staging_create",
                "staging_duplicate",
                "spawn_intent",
                "spawned",
                "normalize",
                "retain",
                "ready_bound",
                "reap",
                "process_scope_dead",
                "adopt",
                "staging_success",
                "close",
            ],
        )
        fallback.assert_not_called()

    def test_reaped_failure_never_enters_numeric_pid_cleanup(
        self,
    ) -> None:
        policy = self.policy()
        events: list[str] = []
        staging_lease = _FakeStagingLease(
            staging_root=policy.staging_parent,
            session_id=self.session_id,
            events=events,
        )
        initialization = helper._handoff_initialization_record(
            policy,
            session_id=self.session_id,
            destination_parent=staging_lease.leaf_path,
        )
        ready = self.ready(policy)
        ready["request_sha256"] = initialization["request_sha256"]
        reaped_error = adoption.CaptureAdoptionError(
            "capture_adoption_child_exit_failed",
            child_reaped=True,
        )
        authority = mock.Mock()

        def open_parent(*_args, **_kwargs) -> int:
            return os.open("/dev/null", os.O_RDONLY)

        with (
            mock.patch.object(
                helper,
                "_open_handoff_parent",
                side_effect=open_parent,
            ),
            mock.patch.object(
                helper.capture_staging,
                "create_session_staging",
                return_value=staging_lease,
            ),
            mock.patch.object(
                helper,
                "build_linux_command",
                return_value=("/bin/true",),
            ),
            mock.patch.object(
                helper,
                "build_linux_seccomp_filter",
                return_value=b"filter",
            ),
            mock.patch.object(
                helper,
                "_spawn_child",
                return_value=6262,
            ),
            mock.patch.object(helper, "_write_frame"),
            mock.patch.object(
                helper,
                "_read_frame",
                return_value=ready,
            ),
            mock.patch.object(
                adoption,
                "retain_provisional_capture",
                return_value=authority,
            ),
            mock.patch.object(
                adoption,
                "reap_capture_child",
                side_effect=reaped_error,
            ),
            mock.patch.object(helper, "_kill_and_reap") as fallback,
        ):
            with self.assertRaises(adoption.CaptureAdoptionError) as caught:
                helper._launch_validated_handoff(
                    policy,
                    adopter=lambda *_args, **_kwargs: object(),
                )
        self.assertIs(caught.exception, reaped_error)
        fallback.assert_not_called()
        authority.close.assert_called_once_with()
        self.assertEqual(
            events,
            [
                "staging_duplicate",
                "spawn_intent",
                "spawned",
                "ready_bound",
                "process_scope_dead",
                "staging_failure",
            ],
        )

    def test_spawn_failure_revokes_leaf_without_process_signalling(
        self,
    ) -> None:
        policy = self.policy()
        events: list[str] = []
        staging_lease = _FakeStagingLease(
            staging_root=policy.staging_parent,
            session_id=self.session_id,
            events=events,
        )

        def open_parent(*_args, **_kwargs) -> int:
            return os.open("/dev/null", os.O_RDONLY)

        with (
            mock.patch.object(
                helper,
                "_open_handoff_parent",
                side_effect=open_parent,
            ),
            mock.patch.object(
                helper.capture_staging,
                "create_session_staging",
                return_value=staging_lease,
            ),
            mock.patch.object(
                helper,
                "build_linux_command",
                return_value=("/bin/true",),
            ),
            mock.patch.object(
                helper,
                "build_linux_seccomp_filter",
                return_value=b"filter",
            ),
            mock.patch.object(
                helper,
                "_spawn_child",
                side_effect=helper.CaptureHelperError(
                    "capture_helper_fork_failed"
                ),
            ),
            mock.patch.object(helper, "_kill_and_reap") as fallback,
        ):
            self.assert_code(
                "capture_helper_fork_failed",
                helper._launch_validated_handoff,
                policy,
                adopter=lambda *_args, **_kwargs: object(),
            )
        fallback.assert_not_called()
        self.assertEqual(
            events,
            [
                "staging_duplicate",
                "spawn_intent",
                "spawn_failed",
                "staging_failure",
            ],
        )

    def test_ready_failure_contains_child_before_leaf_revocation(
        self,
    ) -> None:
        policy = self.policy()
        events: list[str] = []
        staging_lease = _FakeStagingLease(
            staging_root=policy.staging_parent,
            session_id=self.session_id,
            events=events,
        )

        def open_parent(*_args, **_kwargs) -> int:
            return os.open("/dev/null", os.O_RDONLY)

        def contain(pid: int) -> int:
            self.assertEqual(pid, 6363)
            events.append("contain")
            return -9

        with (
            mock.patch.object(
                helper,
                "_open_handoff_parent",
                side_effect=open_parent,
            ),
            mock.patch.object(
                helper.capture_staging,
                "create_session_staging",
                return_value=staging_lease,
            ),
            mock.patch.object(
                helper,
                "build_linux_command",
                return_value=("/bin/true",),
            ),
            mock.patch.object(
                helper,
                "build_linux_seccomp_filter",
                return_value=b"filter",
            ),
            mock.patch.object(
                helper,
                "_spawn_child",
                return_value=6363,
            ),
            mock.patch.object(helper, "_write_frame"),
            mock.patch.object(
                helper,
                "_read_frame",
                side_effect=helper.CaptureHelperError(
                    "capture_helper_deadline_exceeded"
                ),
            ),
            mock.patch.object(
                helper,
                "_kill_and_reap",
                side_effect=contain,
            ),
        ):
            self.assert_code(
                "capture_helper_deadline_exceeded",
                helper._launch_validated_handoff,
                policy,
                adopter=lambda *_args, **_kwargs: object(),
            )
        self.assertEqual(
            events,
            [
                "staging_duplicate",
                "spawn_intent",
                "spawned",
                "contain",
                "process_scope_dead",
                "staging_failure",
            ],
        )

    def test_adoption_failure_cleans_only_after_reaped_scope(
        self,
    ) -> None:
        policy = self.policy()
        events: list[str] = []
        staging_lease = _FakeStagingLease(
            staging_root=policy.staging_parent,
            session_id=self.session_id,
            events=events,
        )
        ready = self.launcher_ready(policy, staging_lease)
        authority = mock.Mock()

        def open_parent(*_args, **_kwargs) -> int:
            return os.open("/dev/null", os.O_RDONLY)

        with (
            mock.patch.object(
                helper,
                "_open_handoff_parent",
                side_effect=open_parent,
            ),
            mock.patch.object(
                helper.capture_staging,
                "create_session_staging",
                return_value=staging_lease,
            ),
            mock.patch.object(
                helper,
                "build_linux_command",
                return_value=("/bin/true",),
            ),
            mock.patch.object(
                helper,
                "build_linux_seccomp_filter",
                return_value=b"filter",
            ),
            mock.patch.object(
                helper,
                "_spawn_child",
                return_value=6464,
            ),
            mock.patch.object(helper, "_write_frame"),
            mock.patch.object(
                helper,
                "_read_frame",
                return_value=ready,
            ),
            mock.patch.object(
                adoption,
                "retain_provisional_capture",
                return_value=authority,
            ),
            mock.patch.object(
                adoption,
                "reap_capture_child",
                return_value=object(),
            ),
            mock.patch.object(
                helper,
                "_adopt_ready_capture",
                side_effect=helper.CaptureHelperError(
                    "capture_adoption_injected_failure"
                ),
            ),
            mock.patch.object(helper, "_kill_and_reap") as fallback,
        ):
            self.assert_code(
                "capture_adoption_injected_failure",
                helper._launch_validated_handoff,
                policy,
                adopter=lambda *_args, **_kwargs: object(),
            )
        fallback.assert_not_called()
        self.assertEqual(
            events,
            [
                "staging_duplicate",
                "spawn_intent",
                "spawned",
                "ready_bound",
                "process_scope_dead",
                "staging_failure",
            ],
        )
        authority.close.assert_called_once_with()

    def test_staging_cleanup_failure_aborts_adopted_capture(
        self,
    ) -> None:
        policy = self.policy()
        events: list[str] = []
        staging_lease = _FakeStagingLease(
            staging_root=policy.staging_parent,
            session_id=self.session_id,
            events=events,
        )
        ready = self.launcher_ready(policy, staging_lease)
        authority = mock.Mock()
        adopted_session = mock.Mock()
        adopted_session.active = True

        def open_parent(*_args, **_kwargs) -> int:
            return os.open("/dev/null", os.O_RDONLY)

        def fail_success() -> str:
            events.append("staging_success_failed")
            raise helper.capture_staging.CaptureStagingError(
                "capture_staging_success_remove_failed"
            )

        staging_lease.finish_success = fail_success
        with (
            mock.patch.object(
                helper,
                "_open_handoff_parent",
                side_effect=open_parent,
            ),
            mock.patch.object(
                helper.capture_staging,
                "create_session_staging",
                return_value=staging_lease,
            ),
            mock.patch.object(
                helper,
                "build_linux_command",
                return_value=("/bin/true",),
            ),
            mock.patch.object(
                helper,
                "build_linux_seccomp_filter",
                return_value=b"filter",
            ),
            mock.patch.object(
                helper,
                "_spawn_child",
                return_value=6565,
            ),
            mock.patch.object(helper, "_write_frame"),
            mock.patch.object(
                helper,
                "_read_frame",
                return_value=ready,
            ),
            mock.patch.object(
                adoption,
                "retain_provisional_capture",
                return_value=authority,
            ),
            mock.patch.object(
                adoption,
                "reap_capture_child",
                return_value=object(),
            ),
            mock.patch.object(
                helper,
                "_adopt_ready_capture",
                return_value=adopted_session,
            ),
        ):
            self.assert_code(
                "capture_staging_success_remove_failed",
                helper._launch_validated_handoff,
                policy,
                adopter=lambda *_args, **_kwargs: object(),
            )
        adopted_session.abort.assert_called_once_with(
            "capture_handoff_staging_cleanup_failed"
        )
        self.assertIn("staging_success_failed", events)
        self.assertEqual(events[-1], "staging_failure")

    def test_ready_tamper_never_reaps_or_adopts(self) -> None:
        policy = self.policy()
        initialization = self.initialization(policy)
        for field, replacement in (
            ("capture_selection_sha256", "a" * 64),
            ("capture_manifest_sha256", "not-a-digest"),
            ("capture_boundary_policy_sha256", "b" * 64),
            ("helper_activation_policy_sha256", "c" * 64),
            ("request_sha256", "d" * 64),
            ("object_identity_sha256", "bad"),
            ("provisional_name", "../capture"),
        ):
            ready = self.ready(policy)
            ready[field] = replacement
            events: list[str] = []
            with self.subTest(field=field), self.assertRaises(
                helper.CaptureHelperError
            ):
                helper._coordinate_handoff_for_test(
                    policy=policy,
                    ready_value=ready,
                    session_id=self.session_id,
                    request_sha256=initialization["request_sha256"],
                    pid=1234,
                    staging_parent_fd=-1,
                    final_parent_fd=-1,
                    reaper=lambda **_kwargs: events.append("reap"),
                    adopter=lambda *_args, **_kwargs: events.append(
                        "adopt"
                    ),
                )
            self.assertEqual(events, [])

    def test_forged_proof_and_lease_are_rejected(self) -> None:
        policy = self.policy()
        initialization = self.initialization(policy)
        ready = self.ready(policy)
        normalized_ready = helper._normalize_handoff_ready(
            ready,
            policy=policy,
            session_id=self.session_id,
            request_sha256=initialization["request_sha256"],
        )
        strict_adopter = mock.Mock()
        self.assert_code(
            "capture_handoff_provisional_authority_required",
            helper._adopt_ready_capture,
            policy=policy,
            ready=normalized_ready,
            session_id=self.session_id,
            proof=object(),
            staging_parent_fd=-1,
            final_parent_fd=-1,
            adopter=strict_adopter,
            strict_lease_type=True,
        )
        strict_adopter.assert_not_called()
        self.assert_code(
            "capture_adoption_child_proof_required",
            helper._coordinate_handoff_for_test,
            policy=policy,
            ready_value=ready,
            session_id=self.session_id,
            request_sha256=initialization["request_sha256"],
            pid=1234,
            staging_parent_fd=-1,
            final_parent_fd=-1,
            reaper=lambda **_kwargs: object(),
            adopter=adoption._adopt_staged_capture_for_test,
        )
        self.assert_code(
            "capture_handoff_adopted_lease_inactive",
            helper._coordinate_handoff_for_test,
            policy=policy,
            ready_value=ready,
            session_id=self.session_id,
            request_sha256=initialization["request_sha256"],
            pid=1234,
            staging_parent_fd=-1,
            final_parent_fd=-1,
            reaper=lambda **_kwargs: object(),
            adopter=lambda *_args, **_kwargs: object(),
        )
        with self.assertRaises(TypeError):
            helper.AdoptedCaptureSessionV2(
                _token=object(),
                lease=_FakeAdoptedLease([]),
                policy=policy,
                ready=normalized_ready,
                session_id=self.session_id,
                strict_lease_type=False,
            )

        events: list[str] = []
        session = helper._coordinate_handoff_for_test(
            policy=policy,
            ready_value=ready,
            session_id=self.session_id,
            request_sha256=initialization["request_sha256"],
            pid=1234,
            staging_parent_fd=-1,
            final_parent_fd=-1,
            reaper=lambda **_kwargs: object(),
            adopter=lambda *_args, **_kwargs: _FakeAdoptedLease(
                events
            ),
        )
        with self.assertRaises(TypeError):
            pickle.dumps(session)
        session.close()

    def test_public_paths_fail_closed_without_root_but_test_seam_does_not(
        self,
    ) -> None:
        policy = self.policy()
        self.assertIs(helper.PRODUCTION_ACTIVATION, False)
        self.assertIs(helper.CAPTURE_ADOPTION_IMPLEMENTED, False)
        self.assertIs(helper.CAPTURE_HANDOFF_V2_IMPLEMENTED, True)
        with mock.patch.object(
            helper.os, "getuid", return_value=501
        ), mock.patch.object(
            helper.os, "geteuid", return_value=501
        ), mock.patch.object(
            helper,
            "_validate_handoff_policy_runtime",
        ) as runtime:
            self.assert_code(
                "capture_handoff_canary_requires_root",
                helper.launch_privileged_capture_handoff_canary,
                policy,
            )
            runtime.assert_not_called()
        self.assert_code(
            "capture_handoff_production_disabled",
            helper.launch_protected_capture_handoff,
            policy,
        )

        initialization = self.initialization(policy)
        events: list[str] = []
        session = helper._coordinate_handoff_for_test(
            policy=policy,
            ready_value=self.ready(policy),
            session_id=self.session_id,
            request_sha256=initialization["request_sha256"],
            pid=1234,
            staging_parent_fd=-1,
            final_parent_fd=-1,
            reaper=lambda **_kwargs: events.append("reap") or object(),
            adopter=lambda *_args, **_kwargs: (
                events.append("adopt")
                or _FakeAdoptedLease(events)
            ),
        )
        self.assertEqual(events, ["reap", "adopt"])
        session.close()


if __name__ == "__main__":
    unittest.main()
