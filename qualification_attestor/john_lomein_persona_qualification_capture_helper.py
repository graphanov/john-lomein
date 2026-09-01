#!/usr/bin/env python3
"""Privileged coordinator for a dedicated sandboxed capture child.

This module is a dormant installation primitive.  It deliberately has no
signing, attestation-state, projection, model, YAML, or network dependency.
The privileged coordinator validates a fixed installed capture plan and then
starts the separate, measured
``john_lomein_persona_qualification_capture_child.py`` entrypoint behind a
deny-default operating-system sandbox.  This coordinator is never the child
entrypoint, and the child never imports this coordinator.

Only bounded canonical protocol records cross back to the coordinator.  Raw
captured bytes and the capture manifest never do.  If the coordinator closes
its control pipe, the child cleans the lease in ``finally``.  If either side is
killed before Python cleanup can run, the root-only parent admission lock in
the opaque-capture engine makes forced orphan recovery safe on the next launch.

Production launch remains hard-disabled.  An installer must provide dedicated
identities, an immutable bundle, and a privileged-canary activation receipt
before changing that constant in a reviewed release.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import os
import platform
import re
import resource
import secrets
import signal
import stat
import struct
import sys
import tempfile
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

# ``-I`` deliberately removes the script directory from ``sys.path``.  Every
# installed helper entrypoint is measured inside a role bundle, so re-add only
# that immutable bundle root before importing sibling qualification modules.
BUNDLE_ROOT = Path(__file__).resolve().parents[1]
if str(BUNDLE_ROOT) not in sys.path:
    sys.path.insert(0, str(BUNDLE_ROOT))

from qualification_attestor import (
    john_lomein_persona_qualification_capture_plan as capture_plan,
)
from qualification_attestor import (
    john_lomein_persona_qualification_capture_protocol as capture_protocol,
)
from qualification_attestor import (
    john_lomein_persona_qualification_capture_staging as capture_staging,
)
from qualification_attestor import (
    john_lomein_persona_qualification_opaque_capture as opaque_capture,
)
from qualification_attestor import (
    john_lomein_persona_qualification_source_revalidation_binding
    as source_revalidation_binding,
)


PRODUCTION_ACTIVATION = False
# The current opaque engine can safely create a snapshot owned by the
# permanently dropped helper identity, which is sufficient for boundary
# canaries.  Production's stronger root-owned 0550 publication contract needs
# a separately reviewed descriptor-relative adoption step.  Never "solve"
# that by copying evidence before the drop or by briefly regaining root.
CAPTURE_ADOPTION_IMPLEMENTED = False
CAPTURE_HANDOFF_V2_IMPLEMENTED = True

COORDINATOR_ROLE = "qualification_capture_privileged_coordinator"
SANDBOX_CHILD_ROLE = "qualification_capture_sandbox_child"
PROTOCOL_SCHEMA = capture_protocol.PROTOCOL_SCHEMA
HANDOFF_PROTOCOL_SCHEMA = capture_protocol.HANDOFF_PROTOCOL_SCHEMA
ACTIVATION_RECEIPT_SCHEMA = (
    "john-lomein.persona.capture-helper-sandbox-activation.v2"
)
ACTIVATION_STATUS = "privileged_canary_passed"
ACTIVATION_POLICY_SCHEMA = (
    "john-lomein.persona.capture-helper-sandbox-policy.v1"
)
FIXED_PYTHON_FLAGS = ("-I", "-S", "-B")
FIXED_ENVIRONMENT_KEYS = (
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "TMPDIR",
    "TZ",
)
CONTROLLED_PATH = "/nonexistent"
CHILD_ARGUMENT = "--capture-sandbox-child"

MAX_CONTROL_FRAME_BYTES = capture_protocol.MAX_CONTROL_FRAME_BYTES
MAX_EVENT_FRAME_BYTES = capture_protocol.MAX_EVENT_FRAME_BYTES
MAX_INITIALIZATION_FRAME_BYTES = (
    capture_protocol.MAX_INITIALIZATION_FRAME_BYTES
)
MAX_STDERR_BYTES = 128 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_TIMEOUT_SECONDS = capture_protocol.MAX_TIMEOUT_SECONDS
MAX_LOADER_MOUNTS = 32
MAX_SECRET_PATHS_PER_CLASS = 64
MAX_OPEN_FILES = 256
MAX_ADDRESS_SPACE_BYTES = 1_073_741_824
MAX_HELPER_PROCESSES = 8
SECCOMP_FD = 3

LINUX_BWRAP_PATHS = (Path("/usr/bin/bwrap"), Path("/bin/bwrap"))
DARWIN_SANDBOX_PATH = Path("/usr/bin/sandbox-exec")

SECRET_CATEGORIES = (
    "private_key",
    "attestation_state",
    "public_projection",
    "model_secret",
)
CANARY_ASSERTIONS = (
    "backend_fail_closed",
    "capture_parent_only_write",
    "child_death_recovered",
    "close_fds",
    "filesystem_allowlist",
    "fork_denied",
    "groups_empty",
    "key_unreadable",
    "linux_capabilities_empty_or_not_applicable",
    "linux_no_new_privs_or_not_applicable",
    "model_secrets_unreadable",
    "network_denied",
    "parent_death_cleanup_or_recovery",
    "process_group_reaped",
    "projection_unreadable",
    "saved_gid_regain_denied",
    "saved_uid_regain_denied",
    "source_read_only",
    "state_unreadable",
    "wrapper_containment_proven",
)

SESSION_ID_RE = capture_protocol.SESSION_ID_RE
SHA256_RE = capture_protocol.SHA256_RE
REASON_CODE_RE = capture_protocol.REASON_CODE_RE

INIT_FIELDS = capture_protocol.INIT_FIELDS
COMMAND_FIELDS = capture_protocol.COMMAND_FIELDS
READY_FIELDS = capture_protocol.READY_FIELDS
EVENT_FIELDS = capture_protocol.EVENT_FIELDS
ERROR_FIELDS = capture_protocol.ERROR_FIELDS
COMMAND_TRANSITIONS = capture_protocol.COMMAND_TRANSITIONS


# Classic-BPF/seccomp constants.  The filter is passed to bubblewrap as raw
# eight-byte sock_filter records and applies to the final Python helper.
_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_JSET = 0x40
_BPF_K = 0x00
_BPF_RET = 0x06
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_AUDIT_ARCH_X86_64 = 0xC000003E
_AUDIT_ARCH_AARCH64 = 0xC00000B7
_X32_SYSCALL_BIT = 0x40000000

_PR_CAPBSET_READ = 23
_PR_CAPBSET_DROP = 24
_PR_SET_PDEATHSIG = 1
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39
_PR_CAP_AMBIENT = 47
_PR_CAP_AMBIENT_IS_SET = 1
_PR_CAP_AMBIENT_CLEAR_ALL = 4
_LINUX_CAPABILITY_VERSION_3 = 0x20080522


CaptureHelperError = capture_protocol.CaptureHelperError


def _error(code: str) -> CaptureHelperError:
    return capture_protocol.error(code)


@dataclass(frozen=True)
class ImmutableReadMount:
    """One immutable platform-loader dependency."""

    source: Path
    destination: Path
    kind: Literal["file", "directory"]

    def as_record(self) -> dict[str, str]:
        return {
            "source": str(self.source),
            "destination": str(self.destination),
            "kind": self.kind,
        }


@dataclass(frozen=True)
class DeniedSecretPath:
    """One explicitly named authority path excluded from the sandbox."""

    category: Literal[
        "private_key",
        "attestation_state",
        "public_projection",
        "model_secret",
    ]
    path: Path

    def as_record(self) -> dict[str, str]:
        return {"category": self.category, "path": str(self.path)}


@dataclass(frozen=True)
class CaptureSourceMount:
    """One exact source binding derived from the installed capture plan."""

    path: Path
    kind: Literal["file", "tree"]

    def as_record(self) -> dict[str, str]:
        return {"path": str(self.path), "kind": self.kind}


@dataclass(frozen=True)
class CaptureHelperPolicy:
    """Complete immutable policy input for one sandbox-child run."""

    system: Literal["Linux", "Darwin"]
    kernel_release: str
    backend_path: Path
    backend_sha256: str
    bundle_root: Path
    bundle_sha256: str
    python_path: Path
    # This is the dedicated sandbox-child script, never this coordinator.
    entrypoint_path: Path
    installed_plan_path: Path
    capture_plan_bytes: bytes
    capture_plan_sha256: str
    source_mounts: tuple[CaptureSourceMount, ...]
    destination_parent: Path
    activation_receipt_path: Path
    helper_uid: int
    helper_gid: int
    timeout_seconds: int
    denied_secret_paths: tuple[DeniedSecretPath, ...]
    loader_mounts: tuple[ImmutableReadMount, ...] = ()
    maximum_control_frame_bytes: int = MAX_CONTROL_FRAME_BYTES
    maximum_event_frame_bytes: int = MAX_EVENT_FRAME_BYTES
    maximum_stderr_bytes: int = MAX_STDERR_BYTES

    @property
    def capture_plan(self) -> dict[str, Any]:
        parsed = _parse_canonical_json(
            self.capture_plan_bytes,
            maximum_bytes=capture_plan.MAX_PLAN_BYTES,
            field="capture_helper_embedded_plan",
        )
        return capture_plan.normalize_capture_plan(parsed)

    def fixed_environment(self) -> dict[str, str]:
        return {
            "HOME": CONTROLLED_PATH,
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": CONTROLLED_PATH,
            "TMPDIR": CONTROLLED_PATH,
            "TZ": "UTC",
        }

    def child_argv(self) -> tuple[str, ...]:
        return (
            str(self.python_path),
            *FIXED_PYTHON_FLAGS,
            str(self.entrypoint_path),
            CHILD_ARGUMENT,
        )

    def activation_record(self) -> dict[str, Any]:
        return {
            "schema_version": ACTIVATION_POLICY_SCHEMA,
            "system": self.system,
            "kernel_release": self.kernel_release,
            "backend_path": str(self.backend_path),
            "backend_sha256": self.backend_sha256,
            "bundle_root": str(self.bundle_root),
            "bundle_sha256": self.bundle_sha256,
            "python_path": str(self.python_path),
            "entrypoint_path": str(self.entrypoint_path),
            "entrypoint_role": SANDBOX_CHILD_ROLE,
            "installed_plan_path": str(self.installed_plan_path),
            "capture_plan_sha256": self.capture_plan_sha256,
            "source_mounts": [
                mount.as_record() for mount in self.source_mounts
            ],
            "destination_parent": str(self.destination_parent),
            "helper_uid": self.helper_uid,
            "helper_gid": self.helper_gid,
            "timeout_seconds": self.timeout_seconds,
            "denied_secret_paths": [
                item.as_record() for item in self.denied_secret_paths
            ],
            "loader_mounts": [
                mount.as_record() for mount in self.loader_mounts
            ],
            "maximum_control_frame_bytes": (
                self.maximum_control_frame_bytes
            ),
            "maximum_event_frame_bytes": self.maximum_event_frame_bytes,
            "maximum_stderr_bytes": self.maximum_stderr_bytes,
            "fixed_argv": list(self.child_argv()),
            "fixed_environment": self.fixed_environment(),
            "filesystem_policy": (
                "deny-default:bundle+plan+exact-sources-read:"
                "one-capture-parent-write:explicit-authority-deny"
            ),
            "linux_seccomp_version": 1,
            "protocol_schema": PROTOCOL_SCHEMA,
            "capture_ownership_contract": (
                "root_owned_descriptor_relative_adoption_required"
            ),
            "capture_adoption_implemented": CAPTURE_ADOPTION_IMPLEMENTED,
        }

    def activation_policy_sha256(self) -> str:
        return _sha256(_canonical_json(self.activation_record()))


@dataclass(frozen=True)
class CaptureHandoffPolicyV2:
    """Complete policy for a short-lived C:export capture child.

    The v1 ``helper_uid/helper_gid`` pair is intentionally absent.  Each
    authority has one explicit meaning here: evidence owns the exported
    inputs, capture runs the sandbox child, export is the child's sole group,
    and verifier is the only non-root reader after adoption.
    """

    system: Literal["Linux", "Darwin"]
    kernel_release: str
    backend_path: Path
    backend_sha256: str
    bundle_root: Path
    bundle_sha256: str
    python_path: Path
    entrypoint_path: Path
    installed_plan_path: Path
    capture_plan_bytes: bytes
    capture_plan_sha256: str
    capture_selection_sha256: str
    capture_boundary_policy_sha256: str
    source_mounts: tuple[CaptureSourceMount, ...]
    staging_parent: Path
    final_parent: Path
    activation_receipt_path: Path
    evidence_uid: int
    capture_uid: int
    export_gid: int
    verifier_uid: int
    verifier_gid: int
    timeout_seconds: int
    denied_secret_paths: tuple[DeniedSecretPath, ...]
    loader_mounts: tuple[ImmutableReadMount, ...] = ()
    maximum_control_frame_bytes: int = MAX_CONTROL_FRAME_BYTES
    maximum_event_frame_bytes: int = MAX_EVENT_FRAME_BYTES
    maximum_stderr_bytes: int = MAX_STDERR_BYTES

    @property
    def destination_parent(self) -> Path:
        """Sandbox-compatible name for the per-session staging parent."""

        return self.staging_parent

    @property
    def capture_plan(self) -> dict[str, Any]:
        parsed = _parse_canonical_json(
            self.capture_plan_bytes,
            maximum_bytes=capture_plan.MAX_PLAN_BYTES,
            field="capture_handoff_embedded_plan",
        )
        return capture_plan.normalize_capture_plan(parsed)

    def fixed_environment(self) -> dict[str, str]:
        return {
            "HOME": CONTROLLED_PATH,
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": CONTROLLED_PATH,
            "TMPDIR": CONTROLLED_PATH,
            "TZ": "UTC",
        }

    def child_argv(self) -> tuple[str, ...]:
        return (
            str(self.python_path),
            *FIXED_PYTHON_FLAGS,
            str(self.entrypoint_path),
            CHILD_ARGUMENT,
        )

    def activation_record(self) -> dict[str, Any]:
        return {
            "schema_version": (
                "john-lomein.persona.capture-handoff-policy.v2"
            ),
            "system": self.system,
            "kernel_release": self.kernel_release,
            "backend_path": str(self.backend_path),
            "backend_sha256": self.backend_sha256,
            "bundle_root": str(self.bundle_root),
            "bundle_sha256": self.bundle_sha256,
            "python_path": str(self.python_path),
            "entrypoint_path": str(self.entrypoint_path),
            "entrypoint_role": SANDBOX_CHILD_ROLE,
            "installed_plan_path": str(self.installed_plan_path),
            "capture_plan_sha256": self.capture_plan_sha256,
            "capture_selection_sha256": (
                self.capture_selection_sha256
            ),
            "capture_boundary_policy_sha256": (
                self.capture_boundary_policy_sha256
            ),
            "source_mounts": [
                mount.as_record() for mount in self.source_mounts
            ],
            "staging_parent": str(self.staging_parent),
            "staging_root_contract": {
                "owner_uid": 0,
                "group_gid": 0,
                "mode": capture_staging.SHARED_ROOT_MODE,
                "recovery_namespace": (
                    capture_staging.RECOVERY_NAMESPACE
                ),
                "recovery_namespace_mode": (
                    capture_staging.RECOVERY_NAMESPACE_MODE
                ),
                "session_name": "session-<64-lowercase-hex>",
                "session_owner": "capture_uid",
                "session_group": "export_gid",
                "session_mode": capture_staging.EXPOSED_LEAF_MODE,
                "transaction_lock": (
                    "root-exclusive-whole-live-staging-session"
                ),
                "crash_recovery": (
                    "exact-inode-whole-leaf-same-device-quarantine"
                ),
            },
            "final_parent": str(self.final_parent),
            "identities": {
                "evidence_uid": self.evidence_uid,
                "capture_uid": self.capture_uid,
                "export_gid": self.export_gid,
                "verifier_uid": self.verifier_uid,
                "verifier_gid": self.verifier_gid,
            },
            "source_contract": {
                "owner": "evidence_uid",
                "group": "export_gid",
                "directory_mode": 0o750,
                "file_mode": 0o640,
            },
            "provisional_contract": {
                "owner": "capture_uid",
                "group": "export_gid",
                "directory_mode": 0o500,
                "file_mode": 0o400,
            },
            "adopted_contract": {
                "owner_uid": 0,
                "group": "verifier_gid",
                "directory_mode": 0o550,
                "file_mode": 0o440,
            },
            "child_identity_contract": {
                "primary_gid": "export_gid",
                "supplementary_groups": [],
                "saved_ids_equal_effective": True,
                "root_regain_denied": True,
            },
            "timeout_seconds": self.timeout_seconds,
            "denied_secret_paths": [
                item.as_record() for item in self.denied_secret_paths
            ],
            "loader_mounts": [
                mount.as_record() for mount in self.loader_mounts
            ],
            "maximum_control_frame_bytes": (
                self.maximum_control_frame_bytes
            ),
            "maximum_event_frame_bytes": self.maximum_event_frame_bytes,
            "maximum_stderr_bytes": self.maximum_stderr_bytes,
            "fixed_argv": list(self.child_argv()),
            "fixed_environment": self.fixed_environment(),
            "protocol_schema": HANDOFF_PROTOCOL_SCHEMA,
            "lifetime_contract": (
                "root-leaf-lock-ready-fd-reap-adoption-cleanup"
            ),
            "production_activation": False,
        }

    def activation_policy_sha256(self) -> str:
        return _sha256(_canonical_json(self.activation_record()))


@dataclass(frozen=True)
class CaptureReady:
    """The only capture metadata returned to the privileged parent."""

    capture_root: Path
    capture_plan_sha256: str
    capture_manifest_sha256: str


@dataclass(frozen=True)
class CaptureStagedReadyV2:
    """Bound metadata for one provisional object; never an authority token."""

    provisional_name: str
    capture_plan_sha256: str
    capture_selection_sha256: str
    capture_manifest_sha256: str
    capture_boundary_policy_sha256: str
    helper_activation_policy_sha256: str
    request_sha256: str
    object_identity_sha256: str


_canonical_json = capture_protocol.canonical_json
_sha256 = capture_protocol.sha256
_reject_duplicate_keys = capture_protocol._reject_duplicate_keys
_parse_canonical_json = capture_protocol.parse_canonical_json
_write_all = capture_protocol._write_all
_encode_frame = capture_protocol.encode_frame
_write_frame = capture_protocol.write_frame
_read_exact = capture_protocol._read_exact
_read_frame = capture_protocol.read_frame
_integer = capture_protocol.integer
_digest = capture_protocol.digest
_session_id = capture_protocol.session_id


def _absolute_path(value: Path | str, *, field: str) -> Path:
    text = str(value)
    path = Path(text)
    if (
        not text
        or len(os.fsencode(text)) > 4096
        or "\x00" in text
        or "\n" in text
        or "\r" in text
        or unicodedata.normalize("NFC", text) != text
        or not path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
        or os.path.normpath(text) != text
    ):
        raise _error(f"{field}_invalid")
    return path


def _identity_path(path: Path) -> tuple[str, ...]:
    return tuple(
        unicodedata.normalize("NFC", part).casefold()
        for part in path.parts
    )


def _inside(path: Path, root: Path) -> bool:
    parts = _identity_path(path)
    root_parts = _identity_path(root)
    return parts[: len(root_parts)] == root_parts


def _overlap(left: Path, right: Path) -> bool:
    return _inside(left, right) or _inside(right, left)


def _normalize_secret_paths(
    *,
    private_key_paths: Sequence[Path],
    attestation_state_paths: Sequence[Path],
    public_projection_paths: Sequence[Path],
    model_secret_paths: Sequence[Path],
) -> tuple[DeniedSecretPath, ...]:
    categorized: tuple[tuple[str, Sequence[Path]], ...] = (
        ("private_key", private_key_paths),
        ("attestation_state", attestation_state_paths),
        ("public_projection", public_projection_paths),
        ("model_secret", model_secret_paths),
    )
    result: list[DeniedSecretPath] = []
    identities: set[tuple[str, ...]] = set()
    for category, values in categorized:
        if not values or len(values) > MAX_SECRET_PATHS_PER_CLASS:
            raise _error(f"capture_helper_{category}_paths_invalid")
        for value in values:
            path = _absolute_path(
                value,
                field=f"capture_helper_{category}_path",
            )
            identity = _identity_path(path)
            if identity in identities:
                raise _error("capture_helper_secret_path_duplicate")
            identities.add(identity)
            result.append(
                DeniedSecretPath(
                    category=category,  # type: ignore[arg-type]
                    path=path,
                )
            )
    return tuple(
        sorted(result, key=lambda item: (item.category, str(item.path)))
    )


def _normalize_loader_mounts(
    values: Sequence[ImmutableReadMount],
    *,
    system: str,
) -> tuple[ImmutableReadMount, ...]:
    if len(values) > MAX_LOADER_MOUNTS:
        raise _error("capture_helper_loader_mounts_too_many")
    if system == "Linux":
        roots = (
            Path("/lib"),
            Path("/lib64"),
            Path("/usr/lib"),
            Path("/usr/lib64"),
            Path("/etc/ld.so.cache"),
        )
    elif system == "Darwin":
        roots = (
            Path("/usr/lib"),
            Path("/System/Library"),
            Path("/private/var/db/dyld"),
        )
    else:
        raise _error("capture_helper_platform_unsupported")
    result: list[ImmutableReadMount] = []
    destinations: list[Path] = []
    for value in values:
        if type(value) is not ImmutableReadMount:
            raise _error("capture_helper_loader_mount_invalid")
        source = _absolute_path(
            value.source,
            field="capture_helper_loader_source",
        )
        destination = _absolute_path(
            value.destination,
            field="capture_helper_loader_destination",
        )
        if value.kind not in {"file", "directory"}:
            raise _error("capture_helper_loader_kind_invalid")
        if not any(_inside(source, root) for root in roots) or not any(
            _inside(destination, root) for root in roots
        ):
            raise _error("capture_helper_loader_outside_system_closure")
        if system == "Darwin" and source != destination:
            raise _error("capture_helper_seatbelt_loader_alias_unsupported")
        if destination in {
            Path("/"),
            Path("/usr"),
            Path("/etc"),
            Path("/System"),
            Path("/private"),
        }:
            raise _error("capture_helper_loader_too_broad")
        if any(_overlap(destination, old) for old in destinations):
            raise _error("capture_helper_loader_destinations_overlap")
        destinations.append(destination)
        result.append(
            ImmutableReadMount(source, destination, value.kind)
        )
    return tuple(result)


def _discover_backend(system: str) -> Path:
    if system == "Darwin":
        candidates = (DARWIN_SANDBOX_PATH,)
        missing = "capture_helper_seatbelt_unavailable"
    elif system == "Linux":
        candidates = LINUX_BWRAP_PATHS
        missing = "capture_helper_bubblewrap_unavailable"
    else:
        raise _error("capture_helper_platform_unsupported")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise _error(missing)


def _sha256_file(
    path: Path,
    *,
    maximum_bytes: int = 128 * 1024 * 1024,
) -> str:
    digest = hashlib.sha256()
    observed = 0
    try:
        with path.open("rb", buffering=0) as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                observed += len(chunk)
                if observed > maximum_bytes:
                    raise _error("capture_helper_file_too_large")
                digest.update(chunk)
    except CaptureHelperError:
        raise
    except OSError as exc:
        raise _error("capture_helper_file_unreadable") from exc
    return digest.hexdigest()


def _normalize_plan_bytes(plan: Mapping[str, Any]) -> bytes:
    normalized = capture_plan.normalize_capture_plan(plan)
    raw = _canonical_json(normalized)
    if len(raw) > capture_plan.MAX_PLAN_BYTES:
        raise _error("capture_helper_plan_too_large")
    return raw


def build_capture_helper_policy(
    *,
    installed_plan_path: Path,
    destination_parent: Path,
    bundle_root: Path,
    bundle_sha256: str,
    python_path: Path,
    entrypoint_path: Path,
    activation_receipt_path: Path,
    helper_uid: int,
    helper_gid: int,
    timeout_seconds: int,
    private_key_paths: Sequence[Path],
    attestation_state_paths: Sequence[Path],
    public_projection_paths: Sequence[Path],
    model_secret_paths: Sequence[Path],
    loader_mounts: Sequence[ImmutableReadMount] = (),
    system: str | None = None,
    backend_path: Path | None = None,
    backend_sha256: str | None = None,
    kernel_release: str | None = None,
    maximum_control_frame_bytes: int = MAX_CONTROL_FRAME_BYTES,
    maximum_event_frame_bytes: int = MAX_EVENT_FRAME_BYTES,
    maximum_stderr_bytes: int = MAX_STDERR_BYTES,
) -> CaptureHelperPolicy:
    """Build and structurally validate one immutable helper policy.

    The root-owned plan is read here, before any helper exists.  Only its
    canonical control description is later sent over stdin; evidence bytes are
    copied exclusively inside the confined child.
    """

    selected_system = system or platform.system()
    if selected_system not in {"Linux", "Darwin"}:
        raise _error("capture_helper_platform_unsupported")
    try:
        normalized_plan, plan_sha256 = (
            capture_plan.read_installed_capture_plan(
                _absolute_path(
                    installed_plan_path,
                    field="capture_helper_installed_plan_path",
                ),
                expected_owner_uid=0,
            )
        )
    except capture_plan.CapturePlanError as exc:
        raise _error(exc.code) from exc
    normalized_uid = _integer(
        helper_uid,
        field="capture_helper_uid",
        minimum=1,
        maximum=2**31 - 1,
    )
    normalized_gid = _integer(
        helper_gid,
        field="capture_helper_gid",
        minimum=1,
        maximum=2**31 - 1,
    )
    # The helper must not be a second all-powerful identity.  A future
    # installer provides a bounded, read-only export owned by evidence_uid.
    if (
        normalized_uid != normalized_plan["evidence_uid"]
        or normalized_gid != normalized_plan["verifier_gid"]
    ):
        raise _error("capture_helper_identity_plan_mismatch")
    selected_backend = (
        _discover_backend(selected_system)
        if backend_path is None
        else _absolute_path(
            backend_path,
            field="capture_helper_backend_path",
        )
    )
    selected_backend_digest = (
        _sha256_file(selected_backend)
        if backend_sha256 is None
        else _digest(
            backend_sha256,
            field="capture_helper_backend_sha256",
        )
    )
    sources = tuple(
        CaptureSourceMount(
            _absolute_path(
                source["source_path"],
                field="capture_helper_source_path",
            ),
            source["kind"],
        )
        for source in normalized_plan["sources"]
    )
    policy = CaptureHelperPolicy(
        system=selected_system,  # type: ignore[arg-type]
        kernel_release=kernel_release or platform.release(),
        backend_path=selected_backend,
        backend_sha256=selected_backend_digest,
        bundle_root=_absolute_path(
            bundle_root,
            field="capture_helper_bundle_root",
        ),
        bundle_sha256=_digest(
            bundle_sha256,
            field="capture_helper_bundle_sha256",
        ),
        python_path=_absolute_path(
            python_path,
            field="capture_helper_python_path",
        ),
        entrypoint_path=_absolute_path(
            entrypoint_path,
            field="capture_helper_entrypoint_path",
        ),
        installed_plan_path=_absolute_path(
            installed_plan_path,
            field="capture_helper_installed_plan_path",
        ),
        capture_plan_bytes=_normalize_plan_bytes(normalized_plan),
        capture_plan_sha256=plan_sha256,
        source_mounts=sources,
        destination_parent=_absolute_path(
            destination_parent,
            field="capture_helper_destination_parent",
        ),
        activation_receipt_path=_absolute_path(
            activation_receipt_path,
            field="capture_helper_activation_receipt_path",
        ),
        helper_uid=normalized_uid,
        helper_gid=normalized_gid,
        timeout_seconds=_integer(
            timeout_seconds,
            field="capture_helper_timeout_seconds",
            minimum=1,
            maximum=MAX_TIMEOUT_SECONDS,
        ),
        denied_secret_paths=_normalize_secret_paths(
            private_key_paths=private_key_paths,
            attestation_state_paths=attestation_state_paths,
            public_projection_paths=public_projection_paths,
            model_secret_paths=model_secret_paths,
        ),
        loader_mounts=_normalize_loader_mounts(
            loader_mounts,
            system=selected_system,
        ),
        maximum_control_frame_bytes=_integer(
            maximum_control_frame_bytes,
            field="capture_helper_maximum_control_frame_bytes",
            minimum=256,
            maximum=MAX_CONTROL_FRAME_BYTES,
        ),
        maximum_event_frame_bytes=_integer(
            maximum_event_frame_bytes,
            field="capture_helper_maximum_event_frame_bytes",
            minimum=256,
            maximum=MAX_EVENT_FRAME_BYTES,
        ),
        maximum_stderr_bytes=_integer(
            maximum_stderr_bytes,
            field="capture_helper_maximum_stderr_bytes",
            minimum=1024,
            maximum=MAX_STDERR_BYTES,
        ),
    )
    _validate_policy_shape(policy)
    return policy


def _validate_policy_shape(policy: CaptureHelperPolicy) -> None:
    if policy.system not in {"Linux", "Darwin"}:
        raise _error("capture_helper_platform_unsupported")
    for path, field in (
        (policy.backend_path, "capture_helper_backend_path"),
        (policy.bundle_root, "capture_helper_bundle_root"),
        (policy.python_path, "capture_helper_python_path"),
        (policy.entrypoint_path, "capture_helper_entrypoint_path"),
        (
            policy.installed_plan_path,
            "capture_helper_installed_plan_path",
        ),
        (
            policy.destination_parent,
            "capture_helper_destination_parent",
        ),
        (
            policy.activation_receipt_path,
            "capture_helper_activation_receipt_path",
        ),
    ):
        if _absolute_path(path, field=field) != path:
            raise _error(f"{field}_noncanonical")
    _digest(
        policy.backend_sha256,
        field="capture_helper_backend_sha256",
    )
    _digest(
        policy.bundle_sha256,
        field="capture_helper_bundle_sha256",
    )
    _digest(
        policy.capture_plan_sha256,
        field="capture_helper_plan_sha256",
    )
    _integer(
        policy.helper_uid,
        field="capture_helper_uid",
        minimum=1,
        maximum=2**31 - 1,
    )
    _integer(
        policy.helper_gid,
        field="capture_helper_gid",
        minimum=1,
        maximum=2**31 - 1,
    )
    _integer(
        policy.timeout_seconds,
        field="capture_helper_timeout_seconds",
        minimum=1,
        maximum=MAX_TIMEOUT_SECONDS,
    )
    _integer(
        policy.maximum_control_frame_bytes,
        field="capture_helper_maximum_control_frame_bytes",
        minimum=256,
        maximum=MAX_CONTROL_FRAME_BYTES,
    )
    _integer(
        policy.maximum_event_frame_bytes,
        field="capture_helper_maximum_event_frame_bytes",
        minimum=256,
        maximum=MAX_EVENT_FRAME_BYTES,
    )
    _integer(
        policy.maximum_stderr_bytes,
        field="capture_helper_maximum_stderr_bytes",
        minimum=1024,
        maximum=MAX_STDERR_BYTES,
    )
    if (
        not _inside(policy.python_path, policy.bundle_root)
        or not _inside(policy.entrypoint_path, policy.bundle_root)
    ):
        raise _error("capture_helper_executable_outside_bundle")
    if set(policy.fixed_environment()) != set(FIXED_ENVIRONMENT_KEYS):
        raise _error("capture_helper_environment_contract_invalid")
    if (
        capture_plan.capture_plan_sha256(policy.capture_plan)
        != policy.capture_plan_sha256
    ):
        raise _error("capture_helper_plan_digest_mismatch")
    normalized_plan = policy.capture_plan
    if (
        policy.helper_uid != normalized_plan["evidence_uid"]
        or policy.helper_gid != normalized_plan["verifier_gid"]
    ):
        raise _error("capture_helper_identity_plan_mismatch")
    expected_sources = tuple(
        CaptureSourceMount(
            Path(source["source_path"]),
            source["kind"],
        )
        for source in normalized_plan["sources"]
    )
    if policy.source_mounts != expected_sources:
        raise _error("capture_helper_source_mounts_plan_mismatch")
    normalized_loaders = _normalize_loader_mounts(
        policy.loader_mounts,
        system=policy.system,
    )
    if policy.loader_mounts != normalized_loaders:
        raise _error("capture_helper_loader_mounts_noncanonical")
    normalized_denied: list[DeniedSecretPath] = []
    for denied in policy.denied_secret_paths:
        if (
            type(denied) is not DeniedSecretPath
            or denied.category not in SECRET_CATEGORIES
        ):
            raise _error("capture_helper_secret_path_invalid")
        path = _absolute_path(
            denied.path,
            field="capture_helper_secret_path",
        )
        normalized_denied.append(
            DeniedSecretPath(denied.category, path)
        )
    if tuple(
        sorted(
            normalized_denied,
            key=lambda item: (item.category, str(item.path)),
        )
    ) != policy.denied_secret_paths:
        raise _error("capture_helper_secret_paths_noncanonical")
    allowed = [
        policy.bundle_root,
        policy.installed_plan_path,
        policy.destination_parent,
        *(mount.path for mount in policy.source_mounts),
        *(mount.source for mount in policy.loader_mounts),
        *(mount.destination for mount in policy.loader_mounts),
    ]
    fixed_control = (
        policy.activation_receipt_path,
        policy.bundle_root,
        policy.installed_plan_path,
        policy.destination_parent,
    )
    for index, left in enumerate(fixed_control):
        for right in fixed_control[index + 1 :]:
            if _overlap(left, right):
                raise _error("capture_helper_control_paths_overlap")
    for denied in policy.denied_secret_paths:
        if any(_overlap(denied.path, path) for path in allowed):
            raise _error("capture_helper_secret_path_allowlist_overlap")
    categories = {item.category for item in policy.denied_secret_paths}
    if categories != set(SECRET_CATEGORIES):
        raise _error("capture_helper_secret_categories_incomplete")
    for index, source in enumerate(policy.source_mounts):
        if any(
            _overlap(source.path, fixed)
            for fixed in (
                policy.bundle_root,
                policy.installed_plan_path,
                policy.destination_parent,
                policy.activation_receipt_path,
            )
        ):
            raise _error("capture_helper_source_destination_overlap")
        for other in policy.source_mounts[index + 1 :]:
            if _overlap(source.path, other.path):
                raise _error("capture_helper_sources_overlap")
        if any(
            _overlap(source.path, mount.destination)
            for mount in policy.loader_mounts
        ):
            raise _error("capture_helper_source_loader_overlap")
    if policy.system == "Linux":
        if policy.backend_path not in LINUX_BWRAP_PATHS:
            raise _error("capture_helper_backend_path_untrusted")
    elif policy.system == "Darwin":
        if policy.backend_path != DARWIN_SANDBOX_PATH:
            raise _error("capture_helper_backend_path_untrusted")
    else:
        raise _error("capture_helper_platform_unsupported")


def build_capture_handoff_policy_v2(
    *,
    installed_plan_path: Path,
    staging_parent: Path,
    final_parent: Path,
    bundle_root: Path,
    bundle_sha256: str,
    python_path: Path,
    entrypoint_path: Path,
    activation_receipt_path: Path,
    evidence_uid: int,
    capture_uid: int,
    export_gid: int,
    verifier_uid: int,
    verifier_gid: int,
    capture_selection_sha256: str,
    capture_boundary_policy_sha256: str,
    timeout_seconds: int,
    private_key_paths: Sequence[Path],
    attestation_state_paths: Sequence[Path],
    public_projection_paths: Sequence[Path],
    model_secret_paths: Sequence[Path],
    loader_mounts: Sequence[ImmutableReadMount] = (),
    system: str | None = None,
    backend_path: Path | None = None,
    backend_sha256: str | None = None,
    kernel_release: str | None = None,
) -> CaptureHandoffPolicyV2:
    """Build one strict v2 policy without translating identities through v1."""

    selected_system = system or platform.system()
    if selected_system not in {"Linux", "Darwin"}:
        raise _error("capture_handoff_platform_unsupported")
    try:
        normalized_plan, plan_sha256 = (
            capture_plan.read_installed_capture_plan(
                _absolute_path(
                    installed_plan_path,
                    field="capture_handoff_installed_plan_path",
                ),
                expected_owner_uid=0,
            )
        )
    except capture_plan.CapturePlanError as exc:
        raise _error(exc.code) from exc
    selected_backend = (
        _discover_backend(selected_system)
        if backend_path is None
        else _absolute_path(
            backend_path,
            field="capture_handoff_backend_path",
        )
    )
    policy = CaptureHandoffPolicyV2(
        system=selected_system,  # type: ignore[arg-type]
        kernel_release=kernel_release or platform.release(),
        backend_path=selected_backend,
        backend_sha256=(
            _sha256_file(selected_backend)
            if backend_sha256 is None
            else _digest(
                backend_sha256,
                field="capture_handoff_backend_sha256",
            )
        ),
        bundle_root=_absolute_path(
            bundle_root,
            field="capture_handoff_bundle_root",
        ),
        bundle_sha256=_digest(
            bundle_sha256,
            field="capture_handoff_bundle_sha256",
        ),
        python_path=_absolute_path(
            python_path,
            field="capture_handoff_python_path",
        ),
        entrypoint_path=_absolute_path(
            entrypoint_path,
            field="capture_handoff_entrypoint_path",
        ),
        installed_plan_path=_absolute_path(
            installed_plan_path,
            field="capture_handoff_installed_plan_path",
        ),
        capture_plan_bytes=_normalize_plan_bytes(normalized_plan),
        capture_plan_sha256=plan_sha256,
        capture_selection_sha256=_digest(
            capture_selection_sha256,
            field="capture_handoff_selection_sha256",
        ),
        capture_boundary_policy_sha256=_digest(
            capture_boundary_policy_sha256,
            field="capture_handoff_boundary_policy_sha256",
        ),
        source_mounts=tuple(
            CaptureSourceMount(
                _absolute_path(
                    source["source_path"],
                    field="capture_handoff_source_path",
                ),
                source["kind"],
            )
            for source in normalized_plan["sources"]
        ),
        staging_parent=_absolute_path(
            staging_parent,
            field="capture_handoff_staging_parent",
        ),
        final_parent=_absolute_path(
            final_parent,
            field="capture_handoff_final_parent",
        ),
        activation_receipt_path=_absolute_path(
            activation_receipt_path,
            field="capture_handoff_activation_receipt_path",
        ),
        evidence_uid=_integer(
            evidence_uid,
            field="capture_handoff_evidence_uid",
            minimum=1,
            maximum=2**31 - 1,
        ),
        capture_uid=_integer(
            capture_uid,
            field="capture_handoff_capture_uid",
            minimum=1,
            maximum=2**31 - 1,
        ),
        export_gid=_integer(
            export_gid,
            field="capture_handoff_export_gid",
            minimum=1,
            maximum=2**31 - 1,
        ),
        verifier_uid=_integer(
            verifier_uid,
            field="capture_handoff_verifier_uid",
            minimum=1,
            maximum=2**31 - 1,
        ),
        verifier_gid=_integer(
            verifier_gid,
            field="capture_handoff_verifier_gid",
            minimum=1,
            maximum=2**31 - 1,
        ),
        timeout_seconds=_integer(
            timeout_seconds,
            field="capture_handoff_timeout_seconds",
            minimum=1,
            maximum=MAX_TIMEOUT_SECONDS,
        ),
        denied_secret_paths=_normalize_secret_paths(
            private_key_paths=private_key_paths,
            attestation_state_paths=attestation_state_paths,
            public_projection_paths=public_projection_paths,
            model_secret_paths=model_secret_paths,
        ),
        loader_mounts=_normalize_loader_mounts(
            loader_mounts,
            system=selected_system,
        ),
    )
    _validate_handoff_policy_shape(policy)
    return policy


def _validate_handoff_policy_shape(
    policy: CaptureHandoffPolicyV2,
) -> None:
    if type(policy) is not CaptureHandoffPolicyV2:
        raise _error("capture_handoff_policy_invalid")
    if policy.system not in {"Linux", "Darwin"}:
        raise _error("capture_handoff_platform_unsupported")
    for path, field in (
        (policy.backend_path, "capture_handoff_backend_path"),
        (policy.bundle_root, "capture_handoff_bundle_root"),
        (policy.python_path, "capture_handoff_python_path"),
        (policy.entrypoint_path, "capture_handoff_entrypoint_path"),
        (
            policy.installed_plan_path,
            "capture_handoff_installed_plan_path",
        ),
        (policy.staging_parent, "capture_handoff_staging_parent"),
        (policy.final_parent, "capture_handoff_final_parent"),
        (
            policy.activation_receipt_path,
            "capture_handoff_activation_receipt_path",
        ),
    ):
        if _absolute_path(path, field=field) != path:
            raise _error(f"{field}_noncanonical")
    for value, field in (
        (policy.backend_sha256, "capture_handoff_backend_sha256"),
        (policy.bundle_sha256, "capture_handoff_bundle_sha256"),
        (policy.capture_plan_sha256, "capture_handoff_plan_sha256"),
        (
            policy.capture_selection_sha256,
            "capture_handoff_selection_sha256",
        ),
        (
            policy.capture_boundary_policy_sha256,
            "capture_handoff_boundary_policy_sha256",
        ),
    ):
        _digest(value, field=field)
    for value, field in (
        (policy.evidence_uid, "capture_handoff_evidence_uid"),
        (policy.capture_uid, "capture_handoff_capture_uid"),
        (policy.export_gid, "capture_handoff_export_gid"),
        (policy.verifier_uid, "capture_handoff_verifier_uid"),
        (policy.verifier_gid, "capture_handoff_verifier_gid"),
    ):
        _integer(
            value,
            field=field,
            minimum=1,
            maximum=2**31 - 1,
        )
    if (
        len(
            {
                policy.evidence_uid,
                policy.capture_uid,
                policy.verifier_uid,
            }
        )
        != 3
    ):
        raise _error("capture_handoff_uid_separation_missing")
    if policy.export_gid == policy.verifier_gid:
        raise _error("capture_handoff_group_separation_missing")
    _integer(
        policy.timeout_seconds,
        field="capture_handoff_timeout_seconds",
        minimum=1,
        maximum=MAX_TIMEOUT_SECONDS,
    )
    _integer(
        policy.maximum_control_frame_bytes,
        field="capture_handoff_maximum_control_frame_bytes",
        minimum=256,
        maximum=MAX_CONTROL_FRAME_BYTES,
    )
    _integer(
        policy.maximum_event_frame_bytes,
        field="capture_handoff_maximum_event_frame_bytes",
        minimum=256,
        maximum=MAX_EVENT_FRAME_BYTES,
    )
    _integer(
        policy.maximum_stderr_bytes,
        field="capture_handoff_maximum_stderr_bytes",
        minimum=1024,
        maximum=MAX_STDERR_BYTES,
    )
    normalized_plan = policy.capture_plan
    if (
        capture_plan.capture_plan_sha256(normalized_plan)
        != policy.capture_plan_sha256
    ):
        raise _error("capture_handoff_plan_digest_mismatch")
    if (
        normalized_plan["evidence_uid"] != policy.evidence_uid
        or normalized_plan["verifier_gid"] != policy.verifier_gid
    ):
        raise _error("capture_handoff_identity_plan_mismatch")
    if (
        not _inside(policy.python_path, policy.bundle_root)
        or not _inside(policy.entrypoint_path, policy.bundle_root)
    ):
        raise _error("capture_handoff_executable_outside_bundle")
    if set(policy.fixed_environment()) != set(FIXED_ENVIRONMENT_KEYS):
        raise _error("capture_handoff_environment_contract_invalid")
    expected_sources = tuple(
        CaptureSourceMount(
            Path(source["source_path"]),
            source["kind"],
        )
        for source in normalized_plan["sources"]
    )
    if policy.source_mounts != expected_sources:
        raise _error("capture_handoff_source_mounts_plan_mismatch")
    if policy.loader_mounts != _normalize_loader_mounts(
        policy.loader_mounts,
        system=policy.system,
    ):
        raise _error("capture_handoff_loader_mounts_noncanonical")
    if _overlap(policy.staging_parent, policy.final_parent):
        raise _error("capture_handoff_parents_overlap")
    fixed_control = (
        policy.activation_receipt_path,
        policy.bundle_root,
        policy.installed_plan_path,
        policy.staging_parent,
        policy.final_parent,
    )
    for index, left in enumerate(fixed_control):
        for right in fixed_control[index + 1 :]:
            if _overlap(left, right):
                raise _error("capture_handoff_control_paths_overlap")
    normalized_denied: list[DeniedSecretPath] = []
    for denied in policy.denied_secret_paths:
        if (
            type(denied) is not DeniedSecretPath
            or denied.category not in SECRET_CATEGORIES
        ):
            raise _error("capture_handoff_secret_path_invalid")
        normalized_denied.append(
            DeniedSecretPath(
                denied.category,
                _absolute_path(
                    denied.path,
                    field="capture_handoff_secret_path",
                ),
            )
        )
    if tuple(
        sorted(
            normalized_denied,
            key=lambda item: (item.category, str(item.path)),
        )
    ) != policy.denied_secret_paths:
        raise _error("capture_handoff_secret_paths_noncanonical")
    if {
        item.category for item in policy.denied_secret_paths
    } != set(SECRET_CATEGORIES):
        raise _error("capture_handoff_secret_categories_incomplete")
    allowed = [
        policy.bundle_root,
        policy.installed_plan_path,
        policy.staging_parent,
        *(mount.path for mount in policy.source_mounts),
        *(mount.source for mount in policy.loader_mounts),
        *(mount.destination for mount in policy.loader_mounts),
    ]
    for denied in policy.denied_secret_paths:
        if any(_overlap(denied.path, path) for path in allowed):
            raise _error("capture_handoff_secret_path_allowlist_overlap")
    for index, source in enumerate(policy.source_mounts):
        if any(
            _overlap(source.path, fixed)
            for fixed in fixed_control
        ):
            raise _error("capture_handoff_source_control_overlap")
        for other in policy.source_mounts[index + 1 :]:
            if _overlap(source.path, other.path):
                raise _error("capture_handoff_sources_overlap")
        if any(
            _overlap(source.path, mount.destination)
            for mount in policy.loader_mounts
        ):
            raise _error("capture_handoff_source_loader_overlap")
    if policy.system == "Linux":
        if policy.backend_path not in LINUX_BWRAP_PATHS:
            raise _error("capture_handoff_backend_path_untrusted")
    elif policy.backend_path != DARWIN_SANDBOX_PATH:
        raise _error("capture_handoff_backend_path_untrusted")


def _scheme_string(value: Path | str) -> str:
    text = str(value)
    if "\x00" in text or "\n" in text or "\r" in text:
        raise _error("capture_helper_policy_path_unsafe")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _darwin_literal_ancestors(paths: Sequence[Path]) -> tuple[Path, ...]:
    """Return exact traversal points without granting ancestor subtrees."""

    ancestors: set[Path] = set()
    for path in paths:
        current = path.parent
        while True:
            ancestors.add(current)
            if current.parent == current:
                break
            current = current.parent
    return tuple(
        sorted(
            ancestors,
            key=lambda item: (len(item.parts), str(item)),
        )
    )


def _child_identity(
    policy: CaptureHelperPolicy | CaptureHandoffPolicyV2,
) -> tuple[int, int]:
    if type(policy) is CaptureHandoffPolicyV2:
        return policy.capture_uid, policy.export_gid
    if type(policy) is CaptureHelperPolicy:
        return policy.helper_uid, policy.helper_gid
    raise _error("capture_helper_policy_invalid")


def _sandbox_destination_parent(
    policy: CaptureHelperPolicy | CaptureHandoffPolicyV2,
    *,
    staging_leaf: Path | None,
) -> Path:
    if type(policy) is CaptureHelperPolicy:
        if staging_leaf is not None:
            raise _error("capture_helper_staging_leaf_unexpected")
        return policy.destination_parent
    if type(policy) is not CaptureHandoffPolicyV2:
        raise _error("capture_helper_policy_invalid")
    if staging_leaf is None:
        raise _error("capture_handoff_session_staging_required")
    leaf = _absolute_path(
        staging_leaf,
        field="capture_handoff_session_staging_leaf",
    )
    if (
        leaf.parent
        != policy.staging_parent / capture_staging.RECOVERY_NAMESPACE
        or not capture_staging.SESSION_NAME_RE.fullmatch(leaf.name)
    ):
        raise _error("capture_handoff_session_staging_leaf_invalid")
    return leaf


def build_darwin_profile(
    policy: CaptureHelperPolicy | CaptureHandoffPolicyV2,
    *,
    staging_leaf: Path | None = None,
) -> str:
    """Return a deny-default Seatbelt profile with explicit authority denies."""

    if policy.system != "Darwin":
        raise _error("capture_helper_seatbelt_platform_mismatch")
    destination_parent = _sandbox_destination_parent(
        policy,
        staging_leaf=staging_leaf,
    )
    deny_filters = [
        f"(subpath {_scheme_string(item.path)})"
        for item in policy.denied_secret_paths
    ]
    read_filters = [
        f"(subpath {_scheme_string(policy.bundle_root)})",
        f"(literal {_scheme_string(policy.installed_plan_path)})",
        f"(subpath {_scheme_string(destination_parent)})",
    ]
    traversal_paths = [
        policy.bundle_root,
        policy.installed_plan_path,
        destination_parent,
        policy.python_path,
        policy.entrypoint_path,
    ]
    for source in policy.source_mounts:
        operation = "literal" if source.kind == "file" else "subpath"
        read_filters.append(
            f"({operation} {_scheme_string(source.path)})"
        )
        traversal_paths.append(source.path)
    for mount in policy.loader_mounts:
        operation = "literal" if mount.kind == "file" else "subpath"
        read_filters.append(
            f"({operation} {_scheme_string(mount.destination)})"
        )
        traversal_paths.append(mount.destination)
    read_filters.extend(
        f"(literal {_scheme_string(ancestor)})"
        for ancestor in _darwin_literal_ancestors(traversal_paths)
    )
    lines = [
        "(version 1)",
        "(deny default)",
        "(deny network*)",
        "(deny process-fork)",
        "(deny file-link)",
    ]
    if deny_filters:
        lines.extend(
            [
                "(deny file-read*",
                *(f"  {item}" for item in deny_filters),
                ")",
                "(deny file-write*",
                *(f"  {item}" for item in deny_filters),
                ")",
            ]
        )
    lines.extend(
        [
            "(allow process-exec "
            f"(literal {_scheme_string(policy.python_path)}))",
            "(allow process-info*)",
            "(allow sysctl-read)",
            "(allow file-read*",
            *(f"  {item}" for item in read_filters),
            ")",
            "(allow file-write*",
            f"  (subpath {_scheme_string(destination_parent)})",
            ")",
            "",
        ]
    )
    return "\n".join(lines)


def build_darwin_command(
    policy: CaptureHelperPolicy | CaptureHandoffPolicyV2,
    *,
    staging_leaf: Path | None = None,
) -> list[str]:
    if policy.system != "Darwin":
        raise _error("capture_helper_seatbelt_platform_mismatch")
    return [
        str(policy.backend_path),
        "-p",
        build_darwin_profile(policy, staging_leaf=staging_leaf),
        *policy.child_argv(),
    ]


def _linux_syscalls(
    machine: str,
) -> tuple[int, tuple[tuple[str, int], ...]]:
    x86_64 = (
        ("fork", 57),
        ("vfork", 58),
        ("clone", 56),
        ("clone3", 435),
        ("socket", 41),
        ("socketpair", 53),
        ("connect", 42),
        ("accept", 43),
        ("sendto", 44),
        ("recvfrom", 45),
        ("sendmsg", 46),
        ("recvmsg", 47),
        ("bind", 49),
        ("listen", 50),
        ("accept4", 288),
        ("unshare", 272),
        ("setns", 308),
        ("mount", 165),
        ("umount2", 166),
        ("pivot_root", 155),
        ("ptrace", 101),
        ("bpf", 321),
        ("keyctl", 250),
        ("add_key", 248),
        ("request_key", 249),
        ("open_by_handle_at", 304),
        ("pidfd_getfd", 438),
        ("process_vm_readv", 310),
        ("process_vm_writev", 311),
        ("io_uring_setup", 425),
        ("io_uring_enter", 426),
        ("io_uring_register", 427),
        ("setuid", 105),
        ("setgid", 106),
        ("setreuid", 113),
        ("setregid", 114),
        ("setresuid", 117),
        ("setresgid", 119),
        ("setgroups", 116),
        ("setfsuid", 122),
        ("setfsgid", 123),
        ("capset", 126),
        ("execveat", 322),
    )
    aarch64 = (
        ("clone", 220),
        ("clone3", 435),
        ("socket", 198),
        ("socketpair", 199),
        ("bind", 200),
        ("listen", 201),
        ("accept", 202),
        ("connect", 203),
        ("sendto", 206),
        ("recvfrom", 207),
        ("sendmsg", 211),
        ("recvmsg", 212),
        ("accept4", 242),
        ("unshare", 97),
        ("setns", 268),
        ("mount", 40),
        ("umount2", 39),
        ("pivot_root", 41),
        ("ptrace", 117),
        ("bpf", 280),
        ("keyctl", 219),
        ("add_key", 217),
        ("request_key", 218),
        ("open_by_handle_at", 265),
        ("pidfd_getfd", 438),
        ("process_vm_readv", 270),
        ("process_vm_writev", 271),
        ("io_uring_setup", 425),
        ("io_uring_enter", 426),
        ("io_uring_register", 427),
        ("setuid", 146),
        ("setgid", 144),
        ("setreuid", 145),
        ("setregid", 143),
        ("setresuid", 147),
        ("setresgid", 149),
        ("setgroups", 159),
        ("setfsuid", 151),
        ("setfsgid", 152),
        ("capset", 91),
        ("execveat", 281),
    )
    normalized = machine.lower()
    if normalized in {"x86_64", "amd64"}:
        return _AUDIT_ARCH_X86_64, x86_64
    if normalized in {"aarch64", "arm64"}:
        return _AUDIT_ARCH_AARCH64, aarch64
    raise _error("capture_helper_linux_architecture_unsupported")


def linux_seccomp_denied_syscalls(
    machine: str | None = None,
) -> tuple[str, ...]:
    _arch, values = _linux_syscalls(machine or platform.machine())
    return tuple(name for name, _number in values)


def build_linux_seccomp_filter(machine: str | None = None) -> bytes:
    audit_arch, denied = _linux_syscalls(machine or platform.machine())
    instructions: list[tuple[int, int, int, int]] = [
        (_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, 4),
        (_BPF_JMP | _BPF_JEQ | _BPF_K, 1, 0, audit_arch),
        (_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        (_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, 0),
    ]
    if audit_arch == _AUDIT_ARCH_X86_64:
        instructions.extend(
            (
                (
                    _BPF_JMP | _BPF_JSET | _BPF_K,
                    0,
                    1,
                    _X32_SYSCALL_BIT,
                ),
                (
                    _BPF_RET | _BPF_K,
                    0,
                    0,
                    _SECCOMP_RET_KILL_PROCESS,
                ),
            )
        )
    for _name, number in denied:
        instructions.extend(
            (
                (
                    _BPF_JMP | _BPF_JEQ | _BPF_K,
                    0,
                    1,
                    number,
                ),
                (
                    _BPF_RET | _BPF_K,
                    0,
                    0,
                    _SECCOMP_RET_ERRNO | errno.EPERM,
                ),
            )
        )
    instructions.append(
        (_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ALLOW)
    )
    return b"".join(
        struct.pack("=HBBI", code, yes, no, value)
        for code, yes, no, value in instructions
    )


def build_linux_command(
    policy: CaptureHelperPolicy | CaptureHandoffPolicyV2,
    *,
    seccomp_fd: int = SECCOMP_FD,
    staging_leaf: Path | None = None,
) -> list[str]:
    if policy.system != "Linux":
        raise _error("capture_helper_bubblewrap_platform_mismatch")
    child_uid, child_gid = _child_identity(policy)
    destination_parent = _sandbox_destination_parent(
        policy,
        staging_leaf=staging_leaf,
    )
    command = [
        str(policy.backend_path),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--cap-drop",
        "ALL",
        "--uid",
        str(child_uid),
        "--gid",
        str(child_gid),
        "--clearenv",
        "--tmpfs",
        "/",
        "--ro-bind",
        str(policy.bundle_root),
        str(policy.bundle_root),
        "--ro-bind",
        str(policy.installed_plan_path),
        str(policy.installed_plan_path),
    ]
    for source in policy.source_mounts:
        command.extend(
            ("--ro-bind", str(source.path), str(source.path))
        )
    for mount in policy.loader_mounts:
        command.extend(
            (
                "--ro-bind",
                str(mount.source),
                str(mount.destination),
            )
        )
    command.extend(
        (
            "--bind",
            str(destination_parent),
            str(destination_parent),
            "--remount-ro",
            "/",
            "--chdir",
            str(policy.bundle_root),
        )
    )
    for key, value in policy.fixed_environment().items():
        command.extend(("--setenv", key, value))
    command.extend(
        (
            "--seccomp",
            str(seccomp_fd),
            "--",
            *policy.child_argv(),
        )
    )
    return command


def _path_parent_chain(path: Path) -> list[Path]:
    values: list[Path] = []
    current = path
    while current != current.parent:
        values.append(current)
        current = current.parent
    values.append(current)
    return list(reversed(values))


def _reject_fd_metadata(descriptor: int, *, field: str) -> None:
    try:
        capture_plan._reject_fd_metadata(descriptor, field=field)
    except capture_plan.CapturePlanError as exc:
        raise _error(exc.code) from exc


def _validate_trusted_parent_chain(path: Path) -> None:
    for parent in _path_parent_chain(path):
        try:
            info = parent.lstat()
        except OSError as exc:
            raise _error("capture_helper_parent_unreadable") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
        ):
            raise _error("capture_helper_parent_unsafe")


def _validate_root_leaf(
    path: Path,
    *,
    field: str,
    executable: bool = False,
    exact_mode: int | None = None,
) -> None:
    _validate_trusted_parent_chain(path.parent)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    else:
        raise _error("capture_helper_nofollow_unsupported")
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o022
            or (executable and not info.st_mode & 0o500)
            or (
                exact_mode is not None
                and stat.S_IMODE(info.st_mode) != exact_mode
            )
        ):
            raise _error(f"{field}_unsafe")
        _reject_fd_metadata(descriptor, field=field)
    finally:
        os.close(descriptor)


def _validate_root_directory(path: Path, *, field: str) -> None:
    _validate_trusted_parent_chain(path.parent)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    else:
        raise _error("capture_helper_nofollow_unsupported")
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
        ):
            raise _error(f"{field}_unsafe")
        _reject_fd_metadata(descriptor, field=field)
    finally:
        os.close(descriptor)


def _validate_capture_parent_runtime(policy: CaptureHelperPolicy) -> None:
    _validate_trusted_parent_chain(policy.destination_parent.parent)
    try:
        info = policy.destination_parent.lstat()
    except OSError as exc:
        raise _error("capture_helper_destination_parent_unreadable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != policy.helper_uid
        or info.st_gid != policy.helper_gid
        or stat.S_IMODE(info.st_mode) != 0o710
    ):
        raise _error("capture_helper_destination_parent_unsafe")


def _validate_policy_runtime(policy: CaptureHelperPolicy) -> None:
    if platform.system() != policy.system:
        raise _error("capture_helper_runtime_platform_mismatch")
    if platform.release() != policy.kernel_release:
        raise _error("capture_helper_kernel_release_changed")
    _validate_root_leaf(
        policy.backend_path,
        field="capture_helper_backend",
        executable=True,
    )
    if _sha256_file(policy.backend_path) != policy.backend_sha256:
        raise _error("capture_helper_backend_digest_changed")
    _validate_root_directory(
        policy.bundle_root,
        field="capture_helper_bundle",
    )
    _validate_root_leaf(
        policy.python_path,
        field="capture_helper_python",
        executable=True,
    )
    _validate_root_leaf(
        policy.entrypoint_path,
        field="capture_helper_entrypoint",
    )
    try:
        _plan, digest = capture_plan.read_installed_capture_plan(
            policy.installed_plan_path,
            expected_owner_uid=0,
        )
    except capture_plan.CapturePlanError as exc:
        raise _error(exc.code) from exc
    if digest != policy.capture_plan_sha256:
        raise _error("capture_helper_plan_digest_changed")
    _validate_capture_parent_runtime(policy)
    for mount in policy.loader_mounts:
        if mount.kind == "file":
            _validate_root_leaf(
                mount.source,
                field="capture_helper_loader",
            )
        else:
            _validate_root_directory(
                mount.source,
                field="capture_helper_loader",
            )


def _validate_handoff_parent_runtime(
    policy: CaptureHandoffPolicyV2,
) -> None:
    _validate_trusted_parent_chain(policy.staging_parent.parent)
    _validate_trusted_parent_chain(policy.final_parent.parent)
    try:
        staging = policy.staging_parent.lstat()
        final = policy.final_parent.lstat()
    except OSError as exc:
        raise _error("capture_handoff_parent_unreadable") from exc
    if (
        not stat.S_ISDIR(staging.st_mode)
        or staging.st_uid != 0
        or staging.st_gid != 0
        or stat.S_IMODE(staging.st_mode)
        != capture_staging.SHARED_ROOT_MODE
    ):
        raise _error("capture_handoff_staging_root_unsafe")
    if (
        not stat.S_ISDIR(final.st_mode)
        or final.st_uid != 0
        or final.st_gid != policy.verifier_gid
        or stat.S_IMODE(final.st_mode) != 0o710
    ):
        raise _error("capture_handoff_final_parent_unsafe")
    if staging.st_dev != final.st_dev:
        raise _error("capture_handoff_cross_device_forbidden")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("capture_handoff_nofollow_unsupported")
    flags |= os.O_NOFOLLOW
    for path, field in (
        (policy.staging_parent, "capture_handoff_staging_root"),
        (policy.final_parent, "capture_handoff_final_parent"),
    ):
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise _error(f"{field}_unreadable") from exc
        try:
            _reject_fd_metadata(descriptor, field=field)
        finally:
            os.close(descriptor)


def _validate_handoff_policy_runtime(
    policy: CaptureHandoffPolicyV2,
) -> None:
    if platform.system() != policy.system:
        raise _error("capture_handoff_runtime_platform_mismatch")
    if platform.release() != policy.kernel_release:
        raise _error("capture_handoff_kernel_release_changed")
    _validate_root_leaf(
        policy.backend_path,
        field="capture_handoff_backend",
        executable=True,
    )
    if _sha256_file(policy.backend_path) != policy.backend_sha256:
        raise _error("capture_handoff_backend_digest_changed")
    _validate_root_directory(
        policy.bundle_root,
        field="capture_handoff_bundle",
    )
    _validate_root_leaf(
        policy.python_path,
        field="capture_handoff_python",
        executable=True,
    )
    _validate_root_leaf(
        policy.entrypoint_path,
        field="capture_handoff_entrypoint",
    )
    try:
        _plan, digest = capture_plan.read_installed_capture_plan(
            policy.installed_plan_path,
            expected_owner_uid=0,
        )
    except capture_plan.CapturePlanError as exc:
        raise _error(exc.code) from exc
    if digest != policy.capture_plan_sha256:
        raise _error("capture_handoff_plan_digest_changed")
    _validate_handoff_parent_runtime(policy)
    for mount in policy.loader_mounts:
        if mount.kind == "file":
            _validate_root_leaf(
                mount.source,
                field="capture_handoff_loader",
            )
        else:
            _validate_root_directory(
                mount.source,
                field="capture_handoff_loader",
            )


def normalize_activation_receipt(
    value: Any,
    *,
    policy: CaptureHelperPolicy,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _error("capture_helper_activation_receipt_invalid")
    expected_fields = {
        "schema_version",
        "status",
        "activation_policy_sha256",
        "system",
        "kernel_release",
        "backend_path",
        "backend_sha256",
        "bundle_sha256",
        "capture_plan_sha256",
        "helper_uid",
        "helper_gid",
        "assertions",
    }
    if set(value) != expected_fields:
        raise _error("capture_helper_activation_receipt_fields_invalid")
    assertions = value.get("assertions")
    if (
        not isinstance(assertions, Mapping)
        or set(assertions) != set(CANARY_ASSERTIONS)
        or any(assertions.get(name) is not True for name in CANARY_ASSERTIONS)
    ):
        raise _error("capture_helper_activation_assertions_incomplete")
    expected = {
        "schema_version": ACTIVATION_RECEIPT_SCHEMA,
        "status": ACTIVATION_STATUS,
        "activation_policy_sha256": policy.activation_policy_sha256(),
        "system": policy.system,
        "kernel_release": policy.kernel_release,
        "backend_path": str(policy.backend_path),
        "backend_sha256": policy.backend_sha256,
        "bundle_sha256": policy.bundle_sha256,
        "capture_plan_sha256": policy.capture_plan_sha256,
        "helper_uid": policy.helper_uid,
        "helper_gid": policy.helper_gid,
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            raise _error(f"capture_helper_activation_{field}_mismatch")
    return {
        **expected,
        "assertions": {name: True for name in CANARY_ASSERTIONS},
    }


def _read_activation_receipt(
    policy: CaptureHelperPolicy,
) -> dict[str, Any]:
    _validate_root_leaf(
        policy.activation_receipt_path,
        field="capture_helper_activation_receipt",
        exact_mode=0o600,
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(policy.activation_receipt_path, flags)
    except OSError as exc:
        raise _error(
            "capture_helper_activation_receipt_unreadable"
        ) from exc
    try:
        info = os.fstat(descriptor)
        if not 1 <= info.st_size <= MAX_RECEIPT_BYTES:
            raise _error("capture_helper_activation_receipt_size_invalid")
        chunks: list[bytes] = []
        observed_bytes = 0
        while observed_bytes <= MAX_RECEIPT_BYTES:
            try:
                chunk = os.read(
                    descriptor,
                    min(
                        64 * 1024,
                        MAX_RECEIPT_BYTES + 1 - observed_bytes,
                    ),
                )
            except InterruptedError:
                continue
            if not chunk:
                break
            chunks.append(chunk)
            observed_bytes += len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) != info.st_size
            or (
                info.st_dev,
                info.st_ino,
                info.st_mtime_ns,
                info.st_ctime_ns,
                info.st_size,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mtime_ns,
                after.st_ctime_ns,
                after.st_size,
            )
        ):
            raise _error("capture_helper_activation_receipt_changed")
    finally:
        os.close(descriptor)
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise _error("capture_helper_activation_receipt_encoding_invalid")
    value = _parse_canonical_json(
        raw[:-1],
        maximum_bytes=MAX_RECEIPT_BYTES,
        field="capture_helper_activation_receipt",
    )
    normalized = normalize_activation_receipt(value, policy=policy)
    if raw != _canonical_json(normalized) + b"\n":
        raise _error("capture_helper_activation_receipt_noncanonical")
    return normalized


# Compatibility names for the existing coordinator API and tests.  Importing
# this module does not import the child role; a child implementation is loaded
# only when an explicit child-only test seam below is invoked.  Production and
# canary execution use ``CaptureHelperPolicy.entrypoint_path`` directly.
_ProtocolMachine = capture_protocol.ProtocolMachine


def _capture_child_module() -> Any:
    from qualification_attestor import (
        john_lomein_persona_qualification_capture_child as capture_child,
    )

    return capture_child


def _normalize_initialization(
    value: Any,
) -> tuple[str, dict[str, Any], str, Path, int, int, int]:
    return _capture_child_module().normalize_initialization(value)


def _safe_child_error_code(exc: BaseException) -> str:
    return _capture_child_module().safe_child_error_code(exc)


def _verify_sealed(
    lease: opaque_capture.OpaqueCaptureLease,
    *,
    plan: Mapping[str, Any],
    helper_uid: int,
    helper_gid: int,
) -> None:
    _capture_child_module()._verify_sealed(
        lease,
        plan=plan,
        helper_uid=helper_uid,
        helper_gid=helper_gid,
    )


def _revalidate_live(
    lease: opaque_capture.OpaqueCaptureLease,
    *,
    plan: Mapping[str, Any],
    helper_uid: int,
    helper_gid: int,
) -> None:
    _capture_child_module()._revalidate_live(
        lease,
        plan=plan,
        helper_uid=helper_uid,
        helper_gid=helper_gid,
    )


def _serve_protocol_with_lease(
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
    return _capture_child_module().serve_protocol_with_lease(
        control_fd=control_fd,
        event_fd=event_fd,
        session_id=session_id,
        plan=plan,
        helper_uid=helper_uid,
        helper_gid=helper_gid,
        lease=lease,
        deadline=deadline,
        verify_sealed=verify_sealed,
        revalidate_live=revalidate_live,
        monotonic=monotonic,
    )


def _child_main() -> int:
    """Legacy test seam; this coordinator is never the exec entrypoint."""

    return _capture_child_module().child_main()


def _prctl(
    operation: int,
    arg2: int = 0,
    arg3: int = 0,
    arg4: int = 0,
    arg5: int = 0,
) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, "prctl"):
        raise OSError(errno.ENOSYS, "prctl unavailable")
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    libc.prctl.restype = ctypes.c_int
    result = libc.prctl(operation, arg2, arg3, arg4, arg5)
    if result < 0:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value))
    return result


class _CapabilityHeader(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("pid", ctypes.c_int),
    ]


class _CapabilityData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


def _linux_capability_words() -> tuple[int, ...]:
    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, "capget"):
        raise OSError(errno.ENOSYS, "capget unavailable")
    header = _CapabilityHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    values = (_CapabilityData * 2)()
    result = libc.capget(ctypes.byref(header), ctypes.byref(values))
    if result != 0:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value))
    return tuple(
        number
        for item in values
        for number in (item.effective, item.permitted, item.inheritable)
    )


def assert_linux_privilege_confinement() -> None:
    if platform.system() != "Linux":
        raise _error("capture_helper_linux_privilege_platform_mismatch")
    try:
        if any(_linux_capability_words()):
            raise _error("capture_helper_linux_capability_residue")
        for capability in range(64):
            try:
                if _prctl(_PR_CAPBSET_READ, capability) != 0:
                    raise _error(
                        "capture_helper_linux_bounding_capability_residue"
                    )
            except OSError as exc:
                if exc.errno == errno.EINVAL:
                    continue
                raise
            try:
                if (
                    _prctl(
                        _PR_CAP_AMBIENT,
                        _PR_CAP_AMBIENT_IS_SET,
                        capability,
                    )
                    != 0
                ):
                    raise _error(
                        "capture_helper_linux_ambient_capability_residue"
                    )
            except OSError as exc:
                if exc.errno == errno.EINVAL:
                    continue
                raise
        if _prctl(_PR_GET_NO_NEW_PRIVS) != 1:
            raise _error("capture_helper_linux_no_new_privs_missing")
    except CaptureHelperError:
        raise
    except OSError as exc:
        raise _error("capture_helper_linux_privilege_check_failed") from exc


def _drop_linux_capabilities() -> None:
    try:
        try:
            _prctl(_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_CLEAR_ALL)
        except OSError as exc:
            if exc.errno != errno.EINVAL:
                raise
        for capability in range(64):
            try:
                _prctl(_PR_CAPBSET_DROP, capability)
            except OSError as exc:
                if exc.errno == errno.EINVAL:
                    continue
                raise
        _prctl(_PR_SET_NO_NEW_PRIVS, 1)
    except OSError as exc:
        raise _error("capture_helper_linux_privilege_drop_failed") from exc


def _set_limit(kind: int, maximum: int) -> None:
    _soft, hard = resource.getrlimit(kind)
    selected = maximum if hard == resource.RLIM_INFINITY else min(
        maximum,
        hard,
    )
    resource.setrlimit(kind, (selected, selected))


def _resource_limits(
    policy: CaptureHelperPolicy | CaptureHandoffPolicyV2,
) -> None:
    plan_limits = policy.capture_plan["limits"]
    _set_limit(resource.RLIMIT_CORE, 0)
    _set_limit(
        resource.RLIMIT_CPU,
        min(policy.timeout_seconds + 2, MAX_TIMEOUT_SECONDS),
    )
    if hasattr(resource, "RLIMIT_AS"):
        _set_limit(resource.RLIMIT_AS, MAX_ADDRESS_SPACE_BYTES)
    # The helper, unlike the verifier, must write opaque evidence files.
    # Bound each file by the signed plan instead of accidentally constraining
    # valid captures to the much smaller stderr allowance.
    _set_limit(
        resource.RLIMIT_FSIZE,
        max(
            policy.maximum_stderr_bytes,
            plan_limits["max_file_bytes"],
            opaque_capture.MAX_MANIFEST_BYTES,
        )
        + 1,
    )
    # A depth-N descriptor-relative copy can legitimately retain roughly two
    # descriptors per level.  Keep the limit finite while honoring the plan's
    # supported maximum depth.
    _set_limit(
        resource.RLIMIT_NOFILE,
        min(
            MAX_OPEN_FILES,
            max(32, 2 * plan_limits["max_depth"] + 16),
        ),
    )
    if hasattr(resource, "RLIMIT_NPROC"):
        _set_limit(resource.RLIMIT_NPROC, MAX_HELPER_PROCESSES)


def _identity_tuple(kind: Literal["uid", "gid"]) -> tuple[int, ...]:
    getter = getattr(os, f"getres{kind}", None)
    if getter is not None:
        return tuple(int(value) for value in getter())
    if kind == "uid":
        return os.getuid(), os.geteuid()
    return os.getgid(), os.getegid()


def _regain_canary(kind: Literal["uid", "gid"]) -> None:
    setters: list[tuple[Callable[..., None], tuple[int, ...]]] = []
    for name, args in (
        (f"sete{kind}", (0,)),
        (f"set{kind}", (0,)),
        (f"setres{kind}", (0, 0, 0)),
    ):
        setter = getattr(os, name, None)
        if setter is not None:
            setters.append((setter, args))
    for setter, args in setters:
        try:
            setter(*args)
        except OSError:
            continue
        os._exit(126)


def _prepare_child_identity(
    policy: CaptureHelperPolicy | CaptureHandoffPolicyV2,
) -> None:
    child_uid, child_gid = _child_identity(policy)
    os.umask(0o077)
    _resource_limits(policy)
    if policy.system == "Linux":
        _drop_linux_capabilities()
    try:
        os.setgroups([])
        if hasattr(os, "setresgid"):
            os.setresgid(
                child_gid,
                child_gid,
                child_gid,
            )
        else:
            os.setgid(child_gid)
        if hasattr(os, "setresuid"):
            os.setresuid(
                child_uid,
                child_uid,
                child_uid,
            )
        else:
            os.setuid(child_uid)
    except OSError as exc:
        raise _error("capture_helper_identity_drop_failed") from exc
    if (
        _identity_tuple("uid")
        != (child_uid,) * len(_identity_tuple("uid"))
        or _identity_tuple("gid")
        != (child_gid,) * len(_identity_tuple("gid"))
        or os.getgroups()
    ):
        raise _error("capture_helper_identity_drop_incomplete")
    _regain_canary("gid")
    _regain_canary("uid")
    if policy.system == "Linux":
        assert_linux_privilege_confinement()


def _close_unrelated_fds(*, preserve_seccomp: bool) -> None:
    first = 4 if preserve_seccomp else 3
    _soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    maximum = (
        1_048_576
        if hard == resource.RLIM_INFINITY
        else max(first, int(hard))
    )
    os.closerange(first, maximum)


def _duplicate_child_fds(
    *,
    stdin_fd: int,
    stdout_fd: int,
    stderr_fd: int,
    seccomp_fd: int | None,
) -> None:
    sources = [stdin_fd, stdout_fd, stderr_fd]
    if seccomp_fd is not None:
        sources.append(seccomp_fd)
    safe: list[int] = []
    minimum = 64
    for source in sources:
        duplicate = fcntl.fcntl(
            source,
            fcntl.F_DUPFD_CLOEXEC,
            minimum,
        )
        safe.append(duplicate)
        minimum = duplicate + 1
    os.dup2(safe[0], 0, inheritable=True)
    os.dup2(safe[1], 1, inheritable=True)
    os.dup2(safe[2], 2, inheritable=True)
    if seccomp_fd is not None:
        os.dup2(safe[3], SECCOMP_FD, inheritable=True)
    for descriptor in safe:
        try:
            os.close(descriptor)
        except OSError:
            pass
    _close_unrelated_fds(preserve_seccomp=seccomp_fd is not None)


def _spawn_child(
    *,
    policy: CaptureHelperPolicy | CaptureHandoffPolicyV2,
    command: Sequence[str],
    control_read_fd: int,
    event_write_fd: int,
    stderr_fd: int,
    seccomp_fd: int | None,
) -> int:
    try:
        pid = os.fork()
    except OSError as exc:
        raise _error("capture_helper_fork_failed") from exc
    if pid != 0:
        return pid
    try:
        os.setsid()
        _duplicate_child_fds(
            stdin_fd=control_read_fd,
            stdout_fd=event_write_fd,
            stderr_fd=stderr_fd,
            seccomp_fd=seccomp_fd,
        )
        os.chdir(policy.bundle_root)
        _prepare_child_identity(policy)
        if policy.system == "Linux":
            # Credential changes clear PDEATHSIG, so install it only after the
            # permanent drop.  Bubblewrap --die-with-parent remains the
            # independent namespace-wrapper guard.
            _prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
            if os.getppid() == 1:
                os._exit(126)
        os.execve(
            command[0],
            list(command),
            policy.fixed_environment(),
        )
    except BaseException:
        try:
            os.write(2, b"capture helper child setup failed\n")
        except OSError:
            pass
        os._exit(126)


def _kill_and_reap(pid: int) -> int:
    cleanup_error: OSError | None = None
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError as exc:
        if not (
            os.geteuid() != 0
            and platform.system() == "Darwin"
        ):
            cleanup_error = exc
    except OSError as exc:
        cleanup_error = exc
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        cleanup_error = cleanup_error or exc
    while True:
        try:
            waited, status = os.waitpid(pid, 0)
            if waited == pid:
                break
        except InterruptedError:
            continue
        except ChildProcessError:
            returncode = 125
            break
    else:
        returncode = 125
    if "status" in locals():
        returncode = os.waitstatus_to_exitcode(status)
    if cleanup_error is not None:
        raise _error(
            "capture_helper_process_group_cleanup_failed"
        ) from cleanup_error
    return returncode


@dataclass(frozen=True)
class _WaitReapSyscalls:
    """Explicit syscall seam for zombie-pinned reaping tests."""

    waitid: Callable[[int, int, int], Any]
    killpg: Callable[[int, int], None]
    waitpid: Callable[[int, int], tuple[int, int]]
    waitstatus_to_exitcode: Callable[[int], int]
    sleep: Callable[[float], None]


class _DarwinWaitSigval(ctypes.Union):
    _fields_ = (
        ("sival_int", ctypes.c_int),
        ("sival_ptr", ctypes.c_void_p),
    )


class _DarwinWaitSiginfo(ctypes.Structure):
    _fields_ = (
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("si_pid", ctypes.c_int),
        ("si_uid", ctypes.c_uint),
        ("si_status", ctypes.c_int),
        ("si_addr", ctypes.c_void_p),
        ("si_value", _DarwinWaitSigval),
        ("si_band", ctypes.c_long),
        ("reserved", ctypes.c_ulong * 7),
    )


@dataclass(frozen=True)
class _HelperWaitidObservation:
    si_pid: int
    si_code: int
    si_status: int


def _darwin_waitid_callable() -> Callable[[int, int, int], Any]:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        waitid = libc.waitid
        waitid.argtypes = (
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.POINTER(_DarwinWaitSiginfo),
            ctypes.c_int,
        )
        waitid.restype = ctypes.c_int
    except (AttributeError, OSError) as exc:
        raise _error(
            "capture_helper_child_death_observation_unsupported"
        ) from exc

    def observe(idtype: int, child_pid: int, flags: int) -> Any:
        info = _DarwinWaitSiginfo()
        ctypes.set_errno(0)
        if waitid(idtype, child_pid, ctypes.byref(info), flags) != 0:
            error_number = ctypes.get_errno()
            if error_number == errno.ECHILD:
                raise ChildProcessError(
                    error_number,
                    os.strerror(error_number),
                )
            raise OSError(
                error_number,
                os.strerror(error_number),
            )
        if info.si_pid == 0:
            return None
        return _HelperWaitidObservation(
            si_pid=int(info.si_pid),
            si_code=int(info.si_code),
            si_status=int(info.si_status),
        )

    return observe


def _runtime_wait_reap_syscalls() -> _WaitReapSyscalls:
    required = (
        "P_PID",
        "WEXITED",
        "WNOHANG",
        "WNOWAIT",
        "CLD_EXITED",
        "CLD_KILLED",
        "CLD_DUMPED",
    )
    if not all(hasattr(os, name) for name in required):
        raise _error(
            "capture_helper_child_death_observation_unsupported"
        )
    if hasattr(os, "waitid"):
        waitid = os.waitid
    elif platform.system() == "Darwin":
        waitid = _darwin_waitid_callable()
    else:
        raise _error(
            "capture_helper_child_death_observation_unsupported"
        )
    return _WaitReapSyscalls(
        waitid=waitid,
        killpg=os.killpg,
        waitpid=os.waitpid,
        waitstatus_to_exitcode=os.waitstatus_to_exitcode,
        sleep=time.sleep,
    )


def _waitid_exitcode(observed: Any, *, pid: int) -> int | None:
    if observed is None:
        return None
    observed_pid = getattr(observed, "si_pid", None)
    if observed_pid == 0:
        return None
    code = getattr(observed, "si_code", None)
    status = getattr(observed, "si_status", None)
    if (
        observed_pid != pid
        or type(code) is not int
        or type(status) is not int
    ):
        raise _error(
            "capture_helper_child_death_observation_invalid"
        )
    if code == os.CLD_EXITED:
        return status
    if code in (os.CLD_KILLED, os.CLD_DUMPED):
        return -status
    raise _error("capture_helper_child_death_observation_invalid")


def _kill_pinned_process_group(
    pid: int,
    *,
    killpg: Callable[[int, int], None],
) -> CaptureHelperError | None:
    """Issue group cleanup before waitpid can release the numeric PGID."""

    try:
        killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return None
    except PermissionError:
        # Darwin reports EPERM for an unprivileged coordinator when the
        # pinned process group contains only its zombie leader.  This helper
        # always runs its child under a deny-fork sandbox, so there can be no
        # differently credentialed descendant hidden behind that result.
        if os.geteuid() != 0 and platform.system() == "Darwin":
            return None
        return _error("capture_helper_process_group_cleanup_failed")
    except OSError:
        return _error("capture_helper_process_group_cleanup_failed")
    return None


def _wait_reap(
    pid: int,
    *,
    deadline: float,
    monotonic: Callable[[], float] = time.monotonic,
    _syscalls: _WaitReapSyscalls | None = None,
) -> int:
    try:
        syscalls = (
            _runtime_wait_reap_syscalls()
            if _syscalls is None
            else _syscalls
        )
    except CaptureHelperError:
        # No wait has occurred, so the child still pins its identifier.
        _kill_and_reap(pid)
        raise

    observed_exitcode: int | None = None
    while True:
        try:
            observed = syscalls.waitid(
                os.P_PID,
                pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except InterruptedError:
            continue
        except ChildProcessError as exc:
            raise _error("capture_helper_child_wait_lost") from exc
        except OSError as exc:
            if exc.errno == errno.ECHILD:
                # The identifier is no longer pinned by a waitable child.
                # Signaling its numeric PGID here could hit a reused group.
                raise _error("capture_helper_child_wait_lost") from exc
            # The target has not been reaped by this supervisor, so forced
            # cleanup still operates on a pinned numeric identifier.
            _kill_and_reap(pid)
            raise _error("capture_helper_child_wait_failed") from exc
        try:
            observed_exitcode = _waitid_exitcode(observed, pid=pid)
        except CaptureHelperError:
            # WNOWAIT has not released the child, even when it returned a
            # malformed result, so forced cleanup still cannot hit reuse.
            _kill_and_reap(pid)
            raise
        if observed_exitcode is not None:
            break
        if monotonic() >= deadline:
            # Timeout cleanup kills the group before the final waitpid and
            # therefore has the same no-reuse ordering.
            _kill_and_reap(pid)
            raise _error("capture_helper_deadline_exceeded")
        syscalls.sleep(capture_protocol.POLL_INTERVAL_SECONDS)

    # WNOWAIT leaves the leader as a zombie.  Its PID continues to pin the
    # process-group identifier until this cleanup signal has been issued.
    cleanup_error = _kill_pinned_process_group(
        pid,
        killpg=syscalls.killpg,
    )
    while True:
        try:
            reaped_pid, status = syscalls.waitpid(pid, 0)
        except InterruptedError:
            continue
        except ChildProcessError as exc:
            raise _error("capture_helper_child_wait_lost") from exc
        except OSError as exc:
            raise _error("capture_helper_child_wait_failed") from exc
        if reaped_pid != pid:
            raise _error("capture_helper_child_wait_lost")
        break
    returncode = syscalls.waitstatus_to_exitcode(status)
    if cleanup_error is not None:
        raise cleanup_error
    if returncode != observed_exitcode:
        raise _error("capture_helper_child_death_observation_changed")
    # No PID/PGID syscall may occur below this point: waitpid released the
    # numeric identifier and another process group could now acquire it.
    return returncode


def recover_stale_capture_helpers(
    policy: CaptureHelperPolicy,
    *,
    now_unix: int | None = None,
    force_orphans: bool = False,
) -> list[str]:
    """Recover unlocked helper captures without ever reading their contents."""

    current = int(time.time()) if now_unix is None else now_unix
    if type(current) is not int or current < 1:
        raise _error("capture_helper_recovery_time_invalid")
    plan = policy.capture_plan
    if force_orphans:
        current += plan["lifecycle"]["max_orphan_age_seconds"]
    try:
        return opaque_capture.recover_stale_opaque_captures(
            policy.destination_parent,
            plan=plan,
            capture_uid=policy.helper_uid,
            now_unix=current,
        )
    except opaque_capture.OpaqueCaptureError as exc:
        raise _error(exc.code) from exc


class CaptureHelperSession:
    """Parent-side lifetime handle for one confined leased capture."""

    __slots__ = (
        "_policy",
        "_pid",
        "_control_fd",
        "_event_fd",
        "_stderr",
        "_deadline",
        "_session_id",
        "_sequence",
        "_state",
        "_ready",
        "_closed",
    )

    def __init__(
        self,
        *,
        policy: CaptureHelperPolicy,
        pid: int,
        control_fd: int,
        event_fd: int,
        stderr: Any,
        deadline: float,
        session_id: str,
        ready: CaptureReady,
    ) -> None:
        self._policy = policy
        self._pid = pid
        self._control_fd = control_fd
        self._event_fd = event_fd
        self._stderr = stderr
        self._deadline = deadline
        self._session_id = session_id
        self._sequence = 0
        self._state = "capture_ready"
        self._ready = ready
        self._closed = False
        os.set_inheritable(control_fd, False)
        os.set_inheritable(event_fd, False)

    @property
    def capture_root(self) -> Path:
        self._require_open()
        return self._ready.capture_root

    @property
    def capture_plan_sha256(self) -> str:
        self._require_open()
        return self._ready.capture_plan_sha256

    @property
    def capture_manifest_sha256(self) -> str:
        self._require_open()
        return self._ready.capture_manifest_sha256

    @property
    def active(self) -> bool:
        return not self._closed

    def _require_open(self) -> None:
        if self._closed:
            raise _error("capture_helper_session_closed")

    def _command(
        self,
        *,
        command: str,
        artifact_sha256: str | None = None,
        reason_code: str | None = None,
    ) -> str:
        self._require_open()
        transition = COMMAND_TRANSITIONS.get(command)
        if command == "abort":
            if self._state in {"cleaned", "aborted"}:
                return "aborted"
            expected_event = "aborted"
            next_state = "aborted"
        else:
            if transition is None or self._state != transition[0]:
                raise _error("capture_helper_session_transition_invalid")
            expected_event = transition[2]
            next_state = transition[1]
        self._sequence += 1
        record = {
            "schema_version": PROTOCOL_SCHEMA,
            "session_id": self._session_id,
            "sequence": self._sequence,
            "command": command,
            "artifact_sha256": artifact_sha256,
            "reason_code": reason_code,
        }
        try:
            _write_frame(
                self._control_fd,
                record,
                maximum_bytes=self._policy.maximum_control_frame_bytes,
                deadline=self._deadline,
            )
            response = _read_frame(
                self._event_fd,
                maximum_bytes=self._policy.maximum_event_frame_bytes,
                deadline=self._deadline,
            )
            if (
                isinstance(response, Mapping)
                and set(response) == ERROR_FIELDS
                and response.get("event") == "error"
            ):
                code = response.get("error_code")
                if not (
                    response.get("schema_version") == PROTOCOL_SCHEMA
                    and response.get("session_id") == self._session_id
                    and response.get("sequence") == self._sequence
                    and isinstance(code, str)
                    and REASON_CODE_RE.fullmatch(code)
                ):
                    raise _error("capture_helper_child_error_invalid")
                if isinstance(code, str):
                    raise _error(code)
            if (
                not isinstance(response, Mapping)
                or set(response) != EVENT_FIELDS
                or response.get("schema_version") != PROTOCOL_SCHEMA
                or response.get("session_id") != self._session_id
                or response.get("sequence") != self._sequence
                or response.get("event") != expected_event
                or response.get("artifact_sha256") != artifact_sha256
            ):
                raise _error("capture_helper_event_invalid")
            self._state = next_state
            if command in {"abort", "complete_publication"}:
                self._finish_child(expect_success=True, recover=False)
            return expected_event
        except BaseException:
            self._terminate_and_recover()
            raise

    def begin_verification(self) -> str:
        return self._command(command="begin_verification")

    def complete_verification(self, verifier_output_sha256: str) -> str:
        return self._command(
            command="complete_verification",
            artifact_sha256=_digest(
                verifier_output_sha256,
                field="capture_helper_verifier_output_sha256",
            ),
        )

    def complete_signing(self, attestation_envelope_sha256: str) -> str:
        return self._command(
            command="complete_signing",
            artifact_sha256=_digest(
                attestation_envelope_sha256,
                field="capture_helper_attestation_envelope_sha256",
            ),
        )

    def complete_publication(self, trust_projection_sha256: str) -> str:
        return self._command(
            command="complete_publication",
            artifact_sha256=_digest(
                trust_projection_sha256,
                field="capture_helper_trust_projection_sha256",
            ),
        )

    def abort(self, reason_code: str = "coordinator_abort") -> str:
        if self._closed:
            return "aborted"
        if (
            not isinstance(reason_code, str)
            or not REASON_CODE_RE.fullmatch(reason_code)
        ):
            raise _error("capture_helper_abort_reason_invalid")
        return self._command(command="abort", reason_code=reason_code)

    def _read_stderr(self) -> bytes:
        try:
            self._stderr.seek(0, os.SEEK_END)
            size = self._stderr.tell()
            if size > self._policy.maximum_stderr_bytes:
                raise _error("capture_helper_stderr_too_large")
            self._stderr.seek(0)
            raw = self._stderr.read(size)
        except CaptureHelperError:
            raise
        except (OSError, ValueError) as exc:
            raise _error("capture_helper_stderr_unreadable") from exc
        if not isinstance(raw, bytes) or len(raw) != size:
            raise _error("capture_helper_stderr_truncated")
        return raw

    def _close_descriptors(self) -> None:
        for name in ("_control_fd", "_event_fd"):
            descriptor = getattr(self, name)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, name, -1)
        try:
            self._stderr.close()
        except (OSError, ValueError):
            pass

    def _finish_child(
        self,
        *,
        expect_success: bool,
        recover: bool,
    ) -> None:
        if self._closed:
            return
        pid = self._pid
        self._pid = -1
        try:
            returncode = _wait_reap(pid, deadline=self._deadline)
            stderr = self._read_stderr()
            if expect_success and (returncode != 0 or stderr):
                raise _error("capture_helper_child_failed")
        except BaseException:
            if recover:
                recover_stale_capture_helpers(
                    self._policy,
                    force_orphans=True,
                )
            raise
        finally:
            self._closed = True
            self._close_descriptors()

    def _terminate_and_recover(self) -> None:
        if self._closed:
            return
        pid = self._pid
        self._pid = -1
        try:
            if pid > 0:
                _kill_and_reap(pid)
        finally:
            self._closed = True
            self._close_descriptors()
            recover_stale_capture_helpers(
                self._policy,
                force_orphans=True,
            )

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.abort("session_close")
        except BaseException:
            if not self._closed:
                self._terminate_and_recover()
            raise

    def __enter__(self) -> "CaptureHelperSession":
        self._require_open()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, exc, traceback
        self.close()
        return False

    def __del__(self) -> None:
        if not getattr(self, "_closed", True):
            try:
                self._terminate_and_recover()
            except BaseException:
                pass


def _normalize_ready(
    value: Any,
    *,
    policy: CaptureHelperPolicy,
    session_id: str,
) -> CaptureReady:
    if (
        not isinstance(value, Mapping)
        or set(value) != READY_FIELDS
        or value.get("schema_version") != PROTOCOL_SCHEMA
        or value.get("session_id") != session_id
        or value.get("sequence") != 0
        or value.get("event") != "capture_ready"
    ):
        raise _error("capture_helper_ready_invalid")
    root = _absolute_path(
        value.get("capture_root"),
        field="capture_helper_ready_capture_root",
    )
    if (
        root.parent != policy.destination_parent
        or not opaque_capture.CAPTURE_NAME_RE.fullmatch(root.name)
    ):
        raise _error("capture_helper_ready_capture_unbound")
    plan_digest = _digest(
        value.get("capture_plan_sha256"),
        field="capture_helper_ready_plan_sha256",
    )
    if plan_digest != policy.capture_plan_sha256:
        raise _error("capture_helper_ready_plan_digest_mismatch")
    return CaptureReady(
        capture_root=root,
        capture_plan_sha256=plan_digest,
        capture_manifest_sha256=_digest(
            value.get("capture_manifest_sha256"),
            field="capture_helper_ready_manifest_sha256",
        ),
    )


def _initialization_record(
    policy: CaptureHelperPolicy,
    *,
    session_id: str,
) -> dict[str, Any]:
    return {
        "schema_version": PROTOCOL_SCHEMA,
        "session_id": session_id,
        "sequence": 0,
        "command": "initialize",
        "capture_plan": policy.capture_plan,
        "capture_plan_sha256": policy.capture_plan_sha256,
        "destination_parent": str(policy.destination_parent),
        "helper_uid": policy.helper_uid,
        "helper_gid": policy.helper_gid,
        "timeout_seconds": policy.timeout_seconds,
    }


def _launch_validated_helper(
    policy: CaptureHelperPolicy,
) -> CaptureHelperSession:
    recover_stale_capture_helpers(policy, force_orphans=True)
    control_read, control_write = os.pipe()
    event_read, event_write = os.pipe()
    for descriptor in (control_read, control_write, event_read, event_write):
        os.set_inheritable(descriptor, False)
    stderr = tempfile.TemporaryFile(mode="w+b")
    seccomp: Any | None = None
    pid: int | None = None
    session_id = secrets.token_hex(32)
    deadline = time.monotonic() + policy.timeout_seconds
    try:
        if policy.system == "Linux":
            command = build_linux_command(policy)
            seccomp = tempfile.TemporaryFile(mode="w+b")
            seccomp.write(build_linux_seccomp_filter())
            seccomp.flush()
            seccomp.seek(0)
        else:
            command = build_darwin_command(policy)
        pid = _spawn_child(
            policy=policy,
            command=command,
            control_read_fd=control_read,
            event_write_fd=event_write,
            stderr_fd=stderr.fileno(),
            seccomp_fd=seccomp.fileno() if seccomp is not None else None,
        )
        os.close(control_read)
        control_read = -1
        os.close(event_write)
        event_write = -1
        _write_frame(
            control_write,
            _initialization_record(policy, session_id=session_id),
            maximum_bytes=MAX_INITIALIZATION_FRAME_BYTES,
            deadline=deadline,
        )
        ready_value = _read_frame(
            event_read,
            maximum_bytes=policy.maximum_event_frame_bytes,
            deadline=deadline,
        )
        if (
            isinstance(ready_value, Mapping)
            and set(ready_value) == ERROR_FIELDS
            and ready_value.get("event") == "error"
        ):
            code = ready_value.get("error_code")
            if not (
                ready_value.get("schema_version") == PROTOCOL_SCHEMA
                and ready_value.get("session_id") == session_id
                and ready_value.get("sequence") == 0
                and isinstance(code, str)
                and REASON_CODE_RE.fullmatch(code)
            ):
                raise _error("capture_helper_child_error_invalid")
            raise _error(code)
        ready = _normalize_ready(
            ready_value,
            policy=policy,
            session_id=session_id,
        )
        session = CaptureHelperSession(
            policy=policy,
            pid=pid,
            control_fd=control_write,
            event_fd=event_read,
            stderr=stderr,
            deadline=deadline,
            session_id=session_id,
            ready=ready,
        )
        pid = None
        control_write = -1
        event_read = -1
        return session
    except BaseException:
        if pid is not None:
            _kill_and_reap(pid)
        recover_stale_capture_helpers(policy, force_orphans=True)
        raise
    finally:
        if seccomp is not None:
            seccomp.close()
        for descriptor in (
            control_read,
            control_write,
            event_read,
            event_write,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if pid is not None:
            stderr.close()


def _capture_adoption_module() -> Any:
    """Load root-only adoption code without widening the child closure."""

    from qualification_attestor import (
        john_lomein_persona_qualification_capture_adoption as adoption,
    )

    return adoption


def _handoff_initialization_record(
    policy: CaptureHandoffPolicyV2,
    *,
    session_id: str,
    destination_parent: Path | None = None,
) -> dict[str, Any]:
    selected_destination = (
        policy.staging_parent
        if destination_parent is None
        else _sandbox_destination_parent(
            policy,
            staging_leaf=destination_parent,
        )
    )
    core = {
        "schema_version": HANDOFF_PROTOCOL_SCHEMA,
        "session_id": _session_id(session_id),
        "sequence": 0,
        "command": "initialize_handoff",
        "capture_plan": policy.capture_plan,
        "capture_plan_sha256": policy.capture_plan_sha256,
        "capture_selection_sha256": (
            policy.capture_selection_sha256
        ),
        "capture_boundary_policy_sha256": (
            policy.capture_boundary_policy_sha256
        ),
        "helper_activation_policy_sha256": (
            policy.activation_policy_sha256()
        ),
        "destination_parent": str(selected_destination),
        "evidence_uid": policy.evidence_uid,
        "capture_uid": policy.capture_uid,
        "export_gid": policy.export_gid,
        "verifier_uid": policy.verifier_uid,
        "verifier_gid": policy.verifier_gid,
        "timeout_seconds": policy.timeout_seconds,
    }
    return capture_protocol.bind_handoff_request(core)


def _normalize_handoff_ready(
    value: Any,
    *,
    policy: CaptureHandoffPolicyV2,
    session_id: str,
    request_sha256: str,
) -> CaptureStagedReadyV2:
    if (
        not isinstance(value, Mapping)
        or set(value) != capture_protocol.HANDOFF_READY_FIELDS
        or value.get("schema_version") != HANDOFF_PROTOCOL_SCHEMA
        or value.get("session_id") != session_id
        or value.get("sequence") != 0
        or value.get("event") != "capture_staged"
    ):
        raise _error("capture_handoff_ready_invalid")
    provisional_name = value.get("provisional_name")
    if (
        not isinstance(provisional_name, str)
        or not opaque_capture.CAPTURE_NAME_RE.fullmatch(
            provisional_name
        )
        or provisional_name.endswith(".building")
    ):
        raise _error("capture_handoff_ready_name_invalid")
    expected = {
        "capture_plan_sha256": policy.capture_plan_sha256,
        "capture_selection_sha256": (
            policy.capture_selection_sha256
        ),
        "capture_boundary_policy_sha256": (
            policy.capture_boundary_policy_sha256
        ),
        "helper_activation_policy_sha256": (
            policy.activation_policy_sha256()
        ),
        "request_sha256": request_sha256,
    }
    normalized: dict[str, str] = {}
    for field, expected_value in expected.items():
        observed = _digest(
            value.get(field),
            field=f"capture_handoff_ready_{field}",
        )
        if observed != expected_value:
            raise _error(f"capture_handoff_ready_{field}_mismatch")
        normalized[field] = observed
    return CaptureStagedReadyV2(
        provisional_name=provisional_name,
        capture_plan_sha256=normalized["capture_plan_sha256"],
        capture_selection_sha256=normalized[
            "capture_selection_sha256"
        ],
        capture_manifest_sha256=_digest(
            value.get("capture_manifest_sha256"),
            field="capture_handoff_ready_manifest_sha256",
        ),
        capture_boundary_policy_sha256=normalized[
            "capture_boundary_policy_sha256"
        ],
        helper_activation_policy_sha256=normalized[
            "helper_activation_policy_sha256"
        ],
        request_sha256=normalized["request_sha256"],
        object_identity_sha256=_digest(
            value.get("object_identity_sha256"),
            field="capture_handoff_ready_object_identity_sha256",
        ),
    )


def _handoff_adoption_policy(
    policy: CaptureHandoffPolicyV2,
    ready: CaptureStagedReadyV2,
    *,
    session_id: str,
    staging_parent: Path | None = None,
) -> Any:
    adoption = _capture_adoption_module()
    limits = policy.capture_plan["limits"]
    return adoption.CaptureAdoptionPolicy(
        session_id=session_id,
        staging_parent=(
            policy.staging_parent
            if staging_parent is None
            else _sandbox_destination_parent(
                policy,
                staging_leaf=staging_parent,
            )
        ),
        final_parent=policy.final_parent,
        provisional_name=ready.provisional_name,
        final_name=ready.provisional_name,
        expected_object_sha256=ready.object_identity_sha256,
        capture_uid=policy.capture_uid,
        capture_gid=policy.export_gid,
        verifier_uid=policy.verifier_uid,
        verifier_gid=policy.verifier_gid,
        capture_selection_sha256=ready.capture_selection_sha256,
        capture_plan_sha256=ready.capture_plan_sha256,
        capture_manifest_sha256=ready.capture_manifest_sha256,
        capture_boundary_policy_sha256=(
            ready.capture_boundary_policy_sha256
        ),
        helper_activation_policy_sha256=(
            ready.helper_activation_policy_sha256
        ),
        request_sha256=ready.request_sha256,
        max_files=limits["max_files"],
        max_directories=limits["max_directories"],
        max_bytes=limits["max_bytes"],
        max_file_bytes=limits["max_file_bytes"],
        max_depth=limits["max_depth"],
    )


_HANDOFF_SESSION_TOKEN = object()


class AdoptedCaptureSessionV2:
    """Coordinator-facing lifecycle that retains the root adoption lease."""

    __slots__ = (
        "_lease",
        "_policy",
        "_ready",
        "_session_id",
        "_adoption_receipt",
        "_adoption_receipt_sha256",
        "_strict_lease_type",
        "_signing_digest",
        "_publication_digest",
        "_ambiguity_requested_evidence_sha256",
        "_recovery_handoff_receipt",
        "_recovery_handoff_receipt_sha256",
        "_state",
        "_closed",
    )

    def __init__(
        self,
        *,
        _token: object,
        lease: Any,
        policy: CaptureHandoffPolicyV2,
        ready: CaptureStagedReadyV2,
        session_id: str,
        strict_lease_type: bool = True,
    ) -> None:
        if _token is not _HANDOFF_SESSION_TOKEN:
            raise TypeError(
                "AdoptedCaptureSessionV2 cannot be constructed directly"
            )
        if type(ready) is not CaptureStagedReadyV2:
            raise _error("capture_handoff_ready_invalid")
        if type(policy) is not CaptureHandoffPolicyV2:
            raise _error("capture_handoff_policy_invalid")
        if strict_lease_type:
            adoption = _capture_adoption_module()
            if type(lease) is not adoption.AdoptedCaptureLease:
                raise _error("capture_handoff_adopted_lease_invalid")
        if getattr(lease, "active", None) is not True:
            raise _error("capture_handoff_adopted_lease_inactive")
        receipt = lease.receipt
        if not isinstance(receipt, Mapping):
            raise _error("capture_handoff_adoption_receipt_invalid")
        receipt_digest = _digest(
            lease.receipt_sha256,
            field="capture_handoff_adoption_receipt_sha256",
        )
        self._lease = lease
        self._policy = policy
        self._ready = ready
        self._session_id = capture_protocol.session_id(session_id)
        self._adoption_receipt = dict(receipt)
        self._adoption_receipt_sha256 = receipt_digest
        self._strict_lease_type = strict_lease_type
        self._signing_digest: str | None = None
        self._publication_digest: str | None = None
        self._ambiguity_requested_evidence_sha256: str | None = None
        self._recovery_handoff_receipt: dict[str, Any] | None = None
        self._recovery_handoff_receipt_sha256: str | None = None
        self._state = "capture_ready"
        self._closed = False

    def _require_open(self) -> None:
        if (
            self._closed
            or getattr(self._lease, "active", False) is not True
        ):
            raise _error("capture_handoff_session_closed")

    def _require_identity_available(self) -> None:
        if self._state in {
            "attestation_committed_cleanup_pending",
            "attestation_committed_cleaned",
            "publication_completed",
            "publication_ambiguity_deferred",
        }:
            return
        self._require_open()

    @property
    def capture_root(self) -> Path:
        self._require_open()
        return Path(self._lease.capture_root)

    @property
    def capture_plan_sha256(self) -> str:
        self._require_identity_available()
        return self._ready.capture_plan_sha256

    @property
    def capture_manifest_sha256(self) -> str:
        self._require_identity_available()
        return self._ready.capture_manifest_sha256

    @property
    def capture_selection_sha256(self) -> str:
        self._require_identity_available()
        return self._ready.capture_selection_sha256

    @property
    def capture_session_id(self) -> str:
        self._require_identity_available()
        return self._session_id

    @property
    def capture_request_sha256(self) -> str:
        self._require_identity_available()
        return self._ready.request_sha256

    @property
    def capture_boundary_policy_sha256(self) -> str:
        self._require_identity_available()
        return self._ready.capture_boundary_policy_sha256

    @property
    def helper_activation_policy_sha256(self) -> str:
        self._require_identity_available()
        return self._ready.helper_activation_policy_sha256

    @property
    def adoption_receipt(self) -> dict[str, Any]:
        self._require_identity_available()
        return dict(self._adoption_receipt)

    @property
    def adoption_receipt_sha256(self) -> str:
        self._require_identity_available()
        return self._adoption_receipt_sha256

    @property
    def recovery_handoff_receipt(self) -> dict[str, Any]:
        if (
            self._state != "publication_ambiguity_deferred"
            or self._recovery_handoff_receipt is None
        ):
            raise _error(
                "capture_handoff_recovery_handoff_not_deferred"
            )
        return dict(self._recovery_handoff_receipt)

    @property
    def recovery_handoff_receipt_sha256(self) -> str:
        if (
            self._state != "publication_ambiguity_deferred"
            or self._recovery_handoff_receipt_sha256 is None
        ):
            raise _error(
                "capture_handoff_recovery_handoff_not_deferred"
            )
        return self._recovery_handoff_receipt_sha256

    @property
    def active(self) -> bool:
        return (
            not self._closed
            and getattr(self._lease, "active", False) is True
        )

    def begin_verification(self) -> str:
        self._require_open()
        if self._state != "capture_ready":
            raise _error("capture_handoff_session_transition_invalid")
        self._state = "verification_active"
        return "verification_authorized"

    def complete_verification(
        self,
        verifier_output_sha256: str,
    ) -> str | dict[str, Any]:
        self._require_open()
        if self._state != "verification_active":
            raise _error("capture_handoff_session_transition_invalid")
        if not self._strict_lease_type:
            # This branch is reachable only through the named unprivileged
            # coordination test seam.  The production launcher always creates
            # a strict, real adoption lease.
            _digest(
                verifier_output_sha256,
                field="capture_handoff_verifier_output_sha256",
            )
            self._state = "signing_authorized"
            return "signing_authorized"

        try:
            verifier_digest = _digest(
                verifier_output_sha256,
                field="capture_handoff_verifier_output_sha256",
            )
            if os.getuid() != 0 or os.geteuid() != 0:
                raise _error(
                    "capture_handoff_post_verifier_revalidation_requires_root"
                )
            pre_binding = (
                self._lease
                ._assert_post_verifier_revalidation_binding()
            )
            expected_binding_fields = {
                "snapshot_root",
                "capture_adoption_receipt_sha256",
                "capture_object_identity_sha256",
                "capture_plan_sha256",
                "capture_manifest_sha256",
            }
            if (
                not isinstance(pre_binding, Mapping)
                or set(pre_binding) != expected_binding_fields
                or Path(pre_binding["snapshot_root"])
                != Path(self._lease.capture_root)
                or _digest(
                    pre_binding["capture_adoption_receipt_sha256"],
                    field=(
                        "capture_handoff_post_verifier_adoption_"
                        "receipt_sha256"
                    ),
                )
                != self.adoption_receipt_sha256
                or _digest(
                    pre_binding["capture_object_identity_sha256"],
                    field=(
                        "capture_handoff_post_verifier_object_sha256"
                    ),
                )
                != self._ready.object_identity_sha256
                or _digest(
                    pre_binding["capture_plan_sha256"],
                    field=(
                        "capture_handoff_post_verifier_plan_sha256"
                    ),
                )
                != self._ready.capture_plan_sha256
                or _digest(
                    pre_binding["capture_manifest_sha256"],
                    field=(
                        "capture_handoff_post_verifier_manifest_sha256"
                    ),
                )
                != self._ready.capture_manifest_sha256
            ):
                raise _error(
                    "capture_handoff_post_verifier_binding_invalid"
                )

            adoption = _capture_adoption_module()
            opaque_capture.revalidate_live_opaque_sources(
                Path(pre_binding["snapshot_root"]),
                plan=self._policy.capture_plan,
                expected_plan_sha256=(
                    self._ready.capture_plan_sha256
                ),
                expected_capture_uid=0,
                expected_verifier_gid=self._policy.verifier_gid,
                expected_manifest_sha256=(
                    self._ready.capture_manifest_sha256
                ),
                expected_manifest_capture_uid=(
                    self._policy.capture_uid
                ),
                expected_snapshot_gid=self._policy.verifier_gid,
                expected_directory_mode=(
                    adoption.ADOPTED_DIRECTORY_MODE
                ),
                expected_file_mode=adoption.ADOPTED_FILE_MODE,
                source_gid=self._policy.export_gid,
                source_directory_mode=(
                    opaque_capture.EXPORT_SOURCE_DIRECTORY_MODE
                ),
                source_file_mode=(
                    opaque_capture.EXPORT_SOURCE_FILE_MODE
                ),
            )
            post_binding = (
                self._lease
                ._assert_post_verifier_revalidation_binding()
            )
            if post_binding != pre_binding:
                raise _error(
                    "capture_handoff_post_verifier_binding_changed"
                )
            completed_at = _integer(
                int(time.time()),
                field=(
                    "capture_handoff_post_verifier_revalidated_at_unix"
                ),
                minimum=1,
                maximum=(1 << 53) - 1,
            )
            receipt = (
                source_revalidation_binding
                .normalize_source_revalidation_receipt(
                    {
                        "schema_version": (
                            source_revalidation_binding
                            .SOURCE_REVALIDATION_RECEIPT_SCHEMA
                        ),
                        "status": (
                            source_revalidation_binding
                            .SOURCE_REVALIDATION_STATUS
                        ),
                        "capture_adoption_receipt_sha256": (
                            pre_binding[
                                "capture_adoption_receipt_sha256"
                            ]
                        ),
                        "capture_object_identity_sha256": (
                            pre_binding[
                                "capture_object_identity_sha256"
                            ]
                        ),
                        "capture_plan_sha256": (
                            self._ready.capture_plan_sha256
                        ),
                        "capture_manifest_sha256": (
                            self._ready.capture_manifest_sha256
                        ),
                        "verifier_output_sha256": verifier_digest,
                        "revalidator_uid": 0,
                        "revalidated_at_unix": completed_at,
                    }
                )
            )
            # Prove the result is canonical-JSON compatible before granting
            # signing.  The returned object contains only immutable scalars.
            _canonical_json(receipt)
        except BaseException as original:
            self._state = "post_verifier_revalidation_failed"
            try:
                self._lease.cleanup()
            except BaseException as cleanup_error:
                raise _error(
                    "capture_handoff_post_verifier_cleanup_failed"
                ) from cleanup_error
            self._closed = True
            if isinstance(original, CaptureHelperError):
                raise original
            code = getattr(original, "code", None)
            if (
                isinstance(code, str)
                and REASON_CODE_RE.fullmatch(code)
            ):
                raise _error(code) from original
            raise _error(
                "capture_handoff_post_verifier_revalidation_failed"
            ) from original
        self._state = "signing_authorized"
        return receipt

    def complete_signing(
        self,
        attestation_envelope_sha256: str,
    ) -> str:
        digest = _digest(
            attestation_envelope_sha256,
            field="capture_handoff_attestation_envelope_sha256",
        )
        if self._state in {
            "attestation_committed_cleanup_pending",
            "attestation_committed_cleaned",
            "publication_completed",
        }:
            if digest != self._signing_digest:
                raise _error("capture_handoff_signing_digest_mismatch")
            if self._state == "attestation_committed_cleanup_pending":
                return self._finish_attestation_commit_cleanup()
            return "publication_authorized"
        self._require_open()
        if self._state != "signing_authorized":
            raise _error("capture_handoff_session_transition_invalid")
        self._signing_digest = digest
        self._state = "attestation_committed_cleanup_pending"
        return self._finish_attestation_commit_cleanup()

    def _finish_attestation_commit_cleanup(self) -> str:
        if self._state != "attestation_committed_cleanup_pending":
            raise _error("capture_handoff_session_transition_invalid")
        try:
            self._lease.cleanup()
        except BaseException as original:
            if isinstance(original, CaptureHelperError):
                raise original
            code = getattr(original, "code", None)
            if isinstance(code, str) and REASON_CODE_RE.fullmatch(code):
                raise _error(code) from original
            raise _error(
                "capture_handoff_attestation_commit_cleanup_failed"
            ) from original
        self._state = "attestation_committed_cleaned"
        self._closed = True
        return "publication_authorized"

    def complete_publication(
        self,
        trust_projection_sha256: str,
    ) -> str:
        digest = _digest(
            trust_projection_sha256,
            field="capture_handoff_trust_projection_sha256",
        )
        if self._state == "attestation_committed_cleanup_pending":
            raise _error(
                "capture_handoff_attestation_commit_cleanup_pending"
            )
        if self._state == "publication_completed":
            if digest == self._publication_digest:
                return "cleaned"
            raise _error("capture_handoff_publication_digest_mismatch")
        if self._state != "attestation_committed_cleaned":
            raise _error("capture_handoff_session_transition_invalid")
        self._publication_digest = digest
        self._state = "publication_completed"
        return "cleaned"

    def defer_publication_ambiguity(
        self,
        requested_evidence_sha256: str,
    ) -> dict[str, Any]:
        """Transfer an exact adopted capture to durable recovery authority."""

        requested_digest = _digest(
            requested_evidence_sha256,
            field=(
                "capture_handoff_ambiguity_requested_evidence_sha256"
            ),
        )
        if self._ambiguity_requested_evidence_sha256 is not None:
            if (
                requested_digest
                != self._ambiguity_requested_evidence_sha256
            ):
                raise _error(
                    "capture_handoff_publication_ambiguity_digest_mismatch"
                )
            if self._state == "publication_ambiguity_deferred":
                return self.recovery_handoff_receipt
        if self._state not in {
            "signing_authorized",
            "attestation_committed_cleanup_pending",
        }:
            raise _error("capture_handoff_session_transition_invalid")
        self._require_open()
        if self._ambiguity_requested_evidence_sha256 is None:
            self._ambiguity_requested_evidence_sha256 = requested_digest
        defer = getattr(self._lease, "defer_to_recovery", None)
        if not callable(defer):
            raise _error(
                "capture_handoff_recovery_handoff_unsupported"
            )
        adoption = _capture_adoption_module()
        try:
            receipt_value = defer(
                expected_object_sha256=(
                    self._ready.object_identity_sha256
                ),
                expected_adoption_receipt_sha256=(
                    self._adoption_receipt_sha256
                ),
                requested_evidence_sha256=requested_digest,
            )
        except BaseException as original:
            # Descriptor close can report an error after the namespace
            # authority was durably transferred.  Preserve the truthful
            # detached state so close/exit/finalizers never relabel or unlink
            # the capture; the caller may retry the exact digest.
            if getattr(self._lease, "detached", False) is True:
                try:
                    receipt_value = (
                        self._lease.recovery_handoff_receipt
                    )
                    self._commit_recovery_handoff_receipt(
                        receipt_value,
                        adoption=adoption,
                        requested_digest=requested_digest,
                    )
                except BaseException:
                    raise original
            raise original
        return self._commit_recovery_handoff_receipt(
            receipt_value,
            adoption=adoption,
            requested_digest=requested_digest,
        )

    def _commit_recovery_handoff_receipt(
        self,
        receipt_value: Any,
        *,
        adoption: Any,
        requested_digest: str,
    ) -> dict[str, Any]:
        receipt = adoption.normalize_recovery_handoff_receipt(
            receipt_value
        )
        expected_final_name = self._adoption_receipt.get("final_name")
        if (
            receipt["capture_session_id"] != self._session_id
            or receipt["capture_adoption_receipt_sha256"]
            != self._adoption_receipt_sha256
            or receipt["capture_object_identity_sha256"]
            != self._ready.object_identity_sha256
            or receipt["capture_plan_sha256"]
            != self._ready.capture_plan_sha256
            or receipt["capture_manifest_sha256"]
            != self._ready.capture_manifest_sha256
            or receipt["capture_request_sha256"]
            != self._ready.request_sha256
            or receipt["requested_evidence_sha256"]
            != requested_digest
            or receipt["final_name"] != expected_final_name
            or receipt["final_name"] != self._ready.provisional_name
        ):
            raise _error(
                "capture_handoff_recovery_handoff_binding_invalid"
            )
        receipt_digest = _digest(
            adoption.recovery_handoff_receipt_sha256(receipt),
            field="capture_handoff_recovery_handoff_receipt_sha256",
        )
        self._recovery_handoff_receipt = dict(receipt)
        self._recovery_handoff_receipt_sha256 = receipt_digest
        self._state = "publication_ambiguity_deferred"
        self._closed = True
        return dict(receipt)

    def abort(self, reason_code: str = "coordinator_abort") -> str:
        if (
            not isinstance(reason_code, str)
            or not REASON_CODE_RE.fullmatch(reason_code)
        ):
            raise _error("capture_handoff_abort_reason_invalid")
        if self._state == "attestation_committed_cleanup_pending":
            self._finish_attestation_commit_cleanup()
            return "attestation_committed_cleaned"
        if self._state == "publication_ambiguity_deferred":
            return "publication_ambiguity_deferred"
        if self._state in {
            "attestation_committed_cleaned",
            "publication_completed",
        }:
            return "attestation_committed_cleaned"
        if self._closed:
            return "aborted"
        self._lease.cleanup()
        self._state = "aborted"
        self._closed = True
        return "aborted"

    def close(self) -> None:
        if self._state == "attestation_committed_cleanup_pending":
            self._finish_attestation_commit_cleanup()
            return
        if self._state == "publication_ambiguity_deferred":
            return
        if self._state in {
            "attestation_committed_cleaned",
            "publication_completed",
        }:
            return
        self.abort("session_close")

    def __enter__(self) -> "AdoptedCaptureSessionV2":
        self._require_open()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, exc, traceback
        self.close()
        return False

    def __reduce__(self) -> Any:
        raise TypeError("AdoptedCaptureSessionV2 is not serializable")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("AdoptedCaptureSessionV2 is not serializable")

    def __getstate__(self) -> Any:
        raise TypeError("AdoptedCaptureSessionV2 is not serializable")

    def __del__(self) -> None:
        state = getattr(self, "_state", "closed")
        if state == "publication_ambiguity_deferred":
            return
        if state == "attestation_committed_cleanup_pending":
            try:
                self._finish_attestation_commit_cleanup()
            except BaseException:
                pass
        elif not getattr(self, "_closed", True):
            try:
                self.abort("session_finalizer")
            except BaseException:
                pass


def _open_handoff_parent(path: Path, *, field: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("capture_handoff_nofollow_unsupported")
    flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    os.set_inheritable(descriptor, False)
    if os.get_inheritable(descriptor):
        os.close(descriptor)
        raise _error(f"{field}_cloexec_failed")
    return descriptor


def _adopt_ready_capture(
    *,
    policy: CaptureHandoffPolicyV2,
    ready: CaptureStagedReadyV2,
    session_id: str,
    proof: Any,
    staging_parent_fd: int,
    final_parent_fd: int,
    adopter: Callable[..., Any],
    strict_lease_type: bool,
    provisional_authority: Any | None = None,
    session_staging_parent: Path | None = None,
) -> AdoptedCaptureSessionV2:
    adoption: Any | None = None
    if strict_lease_type:
        adoption = _capture_adoption_module()
        if (
            type(provisional_authority)
            is not adoption.RetainedProvisionalCapture
        ):
            raise _error(
                "capture_handoff_provisional_authority_required"
            )
    adoption_policy = _handoff_adoption_policy(
        policy,
        ready,
        session_id=session_id,
        staging_parent=session_staging_parent,
    )
    try:
        adoption_arguments: dict[str, Any] = {
            "staging_parent_fd": staging_parent_fd,
            "final_parent_fd": final_parent_fd,
        }
        if strict_lease_type:
            adoption_arguments["provisional_authority"] = (
                provisional_authority
            )
        lease = adopter(
            adoption_policy,
            proof,
            **adoption_arguments,
        )
        if (
            strict_lease_type
            and provisional_authority.consumed is not True
        ):
            if getattr(lease, "active", False) is True:
                lease.cleanup()
            raise _error(
                "capture_handoff_provisional_authority_not_consumed"
            )
    except CaptureHelperError:
        raise
    except BaseException as exc:
        code = getattr(exc, "code", None)
        if isinstance(code, str) and REASON_CODE_RE.fullmatch(code):
            raise _error(code) from exc
        raise _error("capture_handoff_adoption_failed") from exc
    return AdoptedCaptureSessionV2(
        _token=_HANDOFF_SESSION_TOKEN,
        lease=lease,
        policy=policy,
        ready=ready,
        session_id=session_id,
        strict_lease_type=strict_lease_type,
    )


def _coordinate_handoff_for_test(
    *,
    policy: CaptureHandoffPolicyV2,
    ready_value: Mapping[str, Any],
    session_id: str,
    request_sha256: str,
    pid: int,
    staging_parent_fd: int,
    final_parent_fd: int,
    reaper: Callable[..., Any],
    adopter: Callable[..., Any],
) -> AdoptedCaptureSessionV2:
    """Unprivileged ordering seam; contains no production privilege bypass."""

    _validate_handoff_policy_shape(policy)
    ready = _normalize_handoff_ready(
        ready_value,
        policy=policy,
        session_id=session_id,
        request_sha256=request_sha256,
    )
    proof = reaper(
        session_id=session_id,
        capture_uid=policy.capture_uid,
        pid=pid,
        timeout_seconds=policy.timeout_seconds,
    )
    return _adopt_ready_capture(
        policy=policy,
        ready=ready,
        session_id=session_id,
        proof=proof,
        staging_parent_fd=staging_parent_fd,
        final_parent_fd=final_parent_fd,
        adopter=adopter,
        strict_lease_type=False,
    )


def _handoff_reap_timeout(policy: CaptureHandoffPolicyV2) -> int:
    """Keep the post-ready reap inside the adoption primitive's bound."""

    _validate_handoff_policy_shape(policy)
    adoption = _capture_adoption_module()
    return min(policy.timeout_seconds, adoption.MAX_REAP_SECONDS)


def _launch_validated_handoff(
    policy: CaptureHandoffPolicyV2,
    *,
    adopter: Callable[..., Any],
) -> AdoptedCaptureSessionV2:
    """Run v2 inside one root-created, journaled staging leaf."""

    adoption = _capture_adoption_module()
    staging_lease: Any | None = None
    adopted_session: AdoptedCaptureSessionV2 | None = None
    staging_fd = -1
    final_fd = -1
    control_read = -1
    control_write = -1
    event_read = -1
    event_write = -1
    stderr: Any | None = None
    seccomp: Any | None = None
    pid: int | None = None
    child_reaped = False
    provisional_authority: Any | None = None
    try:
        final_fd = _open_handoff_parent(
            policy.final_parent,
            field="capture_handoff_final_parent",
        )
        staging_lease = capture_staging.create_session_staging(
            policy.staging_parent,
            capture_uid=policy.capture_uid,
            export_gid=policy.export_gid,
            required_device=os.fstat(final_fd).st_dev,
        )
        staging_fd = staging_lease.duplicate_leaf_descriptor()
        staging_leaf = staging_lease.leaf_path
        session_id = staging_lease.session_id
        initialization = _handoff_initialization_record(
            policy,
            session_id=session_id,
            destination_parent=staging_leaf,
        )
        request_sha256 = initialization["request_sha256"]
        deadline = time.monotonic() + policy.timeout_seconds
        control_read, control_write = os.pipe()
        event_read, event_write = os.pipe()
        for descriptor in (
            control_read,
            control_write,
            event_read,
            event_write,
        ):
            os.set_inheritable(descriptor, False)
        stderr = tempfile.TemporaryFile(mode="w+b")
        if policy.system == "Linux":
            command = build_linux_command(
                policy,
                staging_leaf=staging_leaf,
            )
            seccomp = tempfile.TemporaryFile(mode="w+b")
            seccomp.write(build_linux_seccomp_filter())
            seccomp.flush()
            seccomp.seek(0)
        else:
            command = build_darwin_command(
                policy,
                staging_leaf=staging_leaf,
            )
        staging_lease.record_spawn_intent()
        try:
            pid = _spawn_child(
                policy=policy,
                command=command,
                control_read_fd=control_read,
                event_write_fd=event_write,
                stderr_fd=stderr.fileno(),
                seccomp_fd=(
                    seccomp.fileno()
                    if seccomp is not None
                    else None
                ),
            )
        except BaseException:
            staging_lease.record_spawn_failed()
            raise
        staging_lease.record_spawned()
        os.close(control_read)
        control_read = -1
        os.close(event_write)
        event_write = -1
        _write_frame(
            control_write,
            initialization,
            maximum_bytes=MAX_INITIALIZATION_FRAME_BYTES,
            deadline=deadline,
        )
        os.close(control_write)
        control_write = -1
        ready_value = _read_frame(
            event_read,
            maximum_bytes=policy.maximum_event_frame_bytes,
            deadline=deadline,
        )
        if (
            isinstance(ready_value, Mapping)
            and set(ready_value)
            == capture_protocol.HANDOFF_ERROR_FIELDS
            and ready_value.get("event") == "error"
        ):
            code = ready_value.get("error_code")
            if not (
                ready_value.get("schema_version")
                == HANDOFF_PROTOCOL_SCHEMA
                and ready_value.get("session_id") == session_id
                and ready_value.get("sequence") == 0
                and ready_value.get("request_sha256")
                == request_sha256
                and isinstance(code, str)
                and REASON_CODE_RE.fullmatch(code)
            ):
                raise _error("capture_handoff_child_error_invalid")
            raise _error(code)
        ready = _normalize_handoff_ready(
            ready_value,
            policy=policy,
            session_id=session_id,
            request_sha256=request_sha256,
        )
        provisional_authority = adoption.retain_provisional_capture(
            staging_parent_fd=staging_fd,
            session_id=session_id,
            capture_uid=policy.capture_uid,
            provisional_name=ready.provisional_name,
            expected_object_sha256=ready.object_identity_sha256,
        )
        staging_lease.record_ready_bound()
        try:
            proof = adoption.reap_capture_child(
                session_id=session_id,
                capture_uid=policy.capture_uid,
                pid=pid,
                timeout_seconds=_handoff_reap_timeout(policy),
            )
        except adoption.CaptureAdoptionError as exc:
            if exc.child_reaped:
                # The adoption reaper's final waitpid released the numeric
                # identifier.  Never feed it to fallback cleanup: a new,
                # unrelated process group may already own the same number.
                child_reaped = True
                pid = None
                staging_lease.mark_process_scope_dead()
            raise
        child_reaped = True
        pid = None
        staging_lease.mark_process_scope_dead()
        stderr.seek(0, os.SEEK_END)
        size = stderr.tell()
        if size > policy.maximum_stderr_bytes:
            raise _error("capture_handoff_stderr_too_large")
        stderr.seek(0)
        if stderr.read(size):
            raise _error("capture_handoff_child_failed")
        adopted_session = _adopt_ready_capture(
            policy=policy,
            ready=ready,
            session_id=session_id,
            proof=proof,
            staging_parent_fd=staging_fd,
            final_parent_fd=final_fd,
            adopter=adopter,
            strict_lease_type=True,
            provisional_authority=provisional_authority,
            session_staging_parent=staging_leaf,
        )
        staging_lease.finish_success()
        return adopted_session
    except BaseException as original:
        containment_failure: BaseException | None = None
        if pid is not None and not child_reaped:
            try:
                _kill_and_reap(pid)
            except BaseException as exc:
                containment_failure = exc
            else:
                child_reaped = True
                pid = None
                if (
                    staging_lease is not None
                    and staging_lease.active
                    and staging_lease.spawned
                ):
                    try:
                        staging_lease.mark_process_scope_dead()
                    except BaseException as exc:
                        containment_failure = exc
        if (
            adopted_session is not None
            and adopted_session.active
        ):
            try:
                adopted_session.abort(
                    "capture_handoff_staging_cleanup_failed"
                )
            except BaseException:
                pass
        staging_failure: BaseException | None = None
        if staging_lease is not None and staging_lease.active:
            if (
                containment_failure is not None
                or (
                    staging_lease.spawned
                    and not staging_lease.process_scope_dead
                )
            ):
                try:
                    staging_lease.abandon()
                except BaseException as exc:
                    staging_failure = exc
            else:
                try:
                    staging_lease.finish_failure()
                except BaseException as exc:
                    staging_failure = exc
        if containment_failure is not None:
            raise _error(
                "capture_handoff_process_containment_failed"
            ) from containment_failure
        if staging_failure is not None:
            code = getattr(staging_failure, "code", None)
            if isinstance(code, str) and REASON_CODE_RE.fullmatch(code):
                raise _error(code) from staging_failure
            raise _error(
                "capture_handoff_staging_cleanup_failed"
            ) from staging_failure
        if isinstance(original, CaptureHelperError):
            raise original
        if isinstance(original, adoption.CaptureAdoptionError):
            raise original
        code = getattr(original, "code", None)
        if isinstance(code, str) and REASON_CODE_RE.fullmatch(code):
            raise _error(code) from original
        raise
    finally:
        if provisional_authority is not None:
            provisional_authority.close()
        if seccomp is not None:
            seccomp.close()
        if stderr is not None:
            stderr.close()
        if staging_lease is not None and staging_lease.active:
            try:
                staging_lease.abandon()
            except BaseException:
                pass
        for descriptor in (
            control_read,
            control_write,
            event_read,
            event_write,
            staging_fd,
            final_fd,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def launch_protected_capture_handoff(
    policy: CaptureHandoffPolicyV2,
) -> AdoptedCaptureSessionV2:
    """Production v2 entrypoint; activation and adoption remain disabled."""

    if not PRODUCTION_ACTIVATION:
        raise _error("capture_handoff_production_disabled")
    if not CAPTURE_ADOPTION_IMPLEMENTED:
        raise _error("capture_adoption_not_implemented")
    if os.getuid() != 0 or os.geteuid() != 0:
        raise _error("capture_handoff_launcher_requires_root")
    _validate_handoff_policy_shape(policy)
    _validate_handoff_policy_runtime(policy)
    raise _error("capture_handoff_activation_receipt_not_implemented")


def launch_privileged_capture_handoff_canary(
    policy: CaptureHandoffPolicyV2,
) -> AdoptedCaptureSessionV2:
    """Exercise real root adoption without blessing production activation."""

    if os.getuid() != 0 or os.geteuid() != 0:
        raise _error("capture_handoff_canary_requires_root")
    _validate_handoff_policy_shape(policy)
    _validate_handoff_policy_runtime(policy)
    adoption = _capture_adoption_module()
    return _launch_validated_handoff(
        policy,
        adopter=adoption.adopt_staged_capture_canary,
    )


def launch_protected_capture_helper(
    policy: CaptureHelperPolicy,
) -> CaptureHelperSession:
    """Launch only after reviewed release activation and a privileged receipt."""

    if not PRODUCTION_ACTIVATION:
        raise _error("capture_helper_production_disabled")
    if not CAPTURE_ADOPTION_IMPLEMENTED:
        raise _error("capture_adoption_not_implemented")
    if os.getuid() != 0 or os.geteuid() != 0:
        raise _error("capture_helper_launcher_requires_root")
    _validate_policy_shape(policy)
    _validate_policy_runtime(policy)
    _read_activation_receipt(policy)
    return _launch_validated_helper(policy)


def launch_privileged_capture_helper_canary(
    policy: CaptureHelperPolicy,
) -> CaptureHelperSession:
    """Exercise the boundary without creating or blessing a receipt."""

    if os.getuid() != 0 or os.geteuid() != 0:
        raise _error("capture_helper_canary_requires_root")
    _validate_policy_shape(policy)
    _validate_policy_runtime(policy)
    return _launch_validated_helper(policy)


def _main(argv: Sequence[str]) -> int:
    del argv
    raise _error("capture_helper_direct_invocation_disabled")


if __name__ == "__main__":
    try:
        raise SystemExit(_main(sys.argv[1:]))
    except CaptureHelperError:
        raise SystemExit(2)
