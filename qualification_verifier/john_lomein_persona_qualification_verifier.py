#!/usr/bin/env python3
"""Reproduce one current persona qualification as an unprivileged identity.

This module is installed into a root-controlled verifier bundle.  It performs
no model calls and has no signing key access.  The root attestor invokes it
after dropping to a dedicated verifier UID, then signs only this module's
strict, successful output.  The executable accepts no caller-selected command
line paths: it reads one bounded, strict request from the root parent's stdin.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import hmac
import importlib.util
import json
import os
import platform
import re
import stat
import sys
import unicodedata
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any, Mapping, Sequence


BUNDLE_ROOT = Path(__file__).resolve().parents[1]
VENDOR_ROOT = BUNDLE_ROOT / "vendor"
if VENDOR_ROOT.is_dir():
    sys.path.insert(0, str(VENDOR_ROOT))
# The isolated installed interpreter has no ambient project path.  The only
# non-stdlib verifier dependencies are immutable, standard-library-only
# modules shipped in this same measured bundle.
if str(BUNDLE_ROOT) not in sys.path:
    sys.path.insert(0, str(BUNDLE_ROOT))
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_plan as capture_plan_contract,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_binding as adoption_binding_contract,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_result as adoption_result_contract,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_selection as capture_selection_contract,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_opaque_capture as opaque_capture_contract,
)


RUNNER_PATH = BUNDLE_ROOT / "scripts" / "john-lomein-persona-qualification.py"
LEGACY_VERIFIER_VERSION = "john-lomein.persona.operator-verifier.v1"
VERIFIER_VERSION = "john-lomein.persona.operator-verifier.v4"
OUTPUT_SCHEMA = "john-lomein.persona.operator-verification.v3"
REQUEST_SCHEMA = "john-lomein.persona.operator-verifier-request.v4"
# The executable entry point remains pinned to the historical v4/v3
# request-output pair above.  The v5 result-aware path is an explicit,
# side-by-side API until its coordinator, attestor, and installed-runtime
# contracts have independently migrated.
VERIFIER_V4_VERSION = VERIFIER_VERSION
OUTPUT_V4_SCHEMA = OUTPUT_SCHEMA
REQUEST_V4_SCHEMA = REQUEST_SCHEMA
VERIFIER_V5_VERSION = "john-lomein.persona.operator-verifier.v5"
OUTPUT_V5_SCHEMA = "john-lomein.persona.operator-verification.v4"
REQUEST_V5_SCHEMA = "john-lomein.persona.operator-verifier-request.v5"
V5_PRODUCTION_ACTIVATION = False
ATTESTATION_PROJECTION_SCHEMA = (
    "john-lomein.persona-qualification-attestation-projection.v1"
)
CAPTURE_SCHEMA = "john-lomein.persona-qualification-capture.v1"
OPAQUE_CAPTURE_SCHEMA = "john-lomein.persona-opaque-capture.v1"
QUALIFICATION_STATUS_SCHEMA = "john-lomein.persona-qualification-status.v1"
CLAIM_STRENGTH = "operator_verified_local_conformance"
MAX_CAPTURE_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_CAPTURE_FILE_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_FILES = 2_048
MAX_CAPTURE_DIRECTORIES = 4_096
MAX_CAPTURE_ENTRIES = MAX_CAPTURE_FILES + MAX_CAPTURE_DIRECTORIES
MAX_CAPTURE_BYTES = 128 * 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024
MAX_SAFE_INTEGER = (1 << 53) - 1
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
SESSION_ID_RE = re.compile(r"^[0-9a-f]{64}$")
SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_PR_CAPBSET_READ = 23
_PR_GET_NO_NEW_PRIVS = 39
_PR_CAP_AMBIENT = 47
_PR_CAP_AMBIENT_IS_SET = 1
_LINUX_CAPABILITY_VERSION_3 = 0x20080522
CAPTURE_FIELDS = {
    "schema_version",
    "instance_slug",
    "run_id",
    "captured_at_unix",
    "observed_evidence_uid",
    "capture_uid",
    "verifier_gid",
    "path_identities",
    "source_roots",
    "layout",
    "directories",
    "source_directories",
    "files",
    "file_count",
    "total_bytes",
}
SEALED_REQUEST_FIELDS = {
    "schema_version",
    "snapshot_root",
    "capture_manifest_sha256",
    "capture_plan_sha256",
    "capture_selection",
    "capture_selection_sha256",
    "capture_adoption_receipt",
    "capture_adoption_receipt_sha256",
    "capture_session_id",
    "capture_request_sha256",
    "capture_boundary_policy_sha256",
    "capture_helper_activation_policy_sha256",
    "capture_uid",
    "capture_export_gid",
    "adopted_uid",
    "instance_manifest_path",
    "instance_manifest_sha256",
    "qualification_private_root",
    "qualification_public_root",
    "evidence_home_path",
    "checkout_identity_path",
    "runtime_identity_path",
    "instance_slug",
    "evidence_uid",
    "verifier_uid",
    "verifier_gid",
    "verifier_bundle_sha256",
    "verification_policy_sha256",
    "operator_policy_sha256",
    "verified_at_unix",
}
SEALED_REQUEST_V5_FIELDS = frozenset(
    (
        SEALED_REQUEST_FIELDS
        - {
            "capture_adoption_receipt",
            "capture_adoption_receipt_sha256",
        }
    )
    | {
        "capture_adoption_result",
        "capture_adoption_result_sha256",
        "capture_adoption_policy_sha256",
        "adoption_verifier_limits",
        "expected_run_id",
    }
)
NORMAL_ADOPTION_VERIFIER_LIMITS = MappingProxyType(
    {
        "max_files": adoption_binding_contract.MAX_CAPTURE_FILES,
        "max_directories": (
            adoption_binding_contract.MAX_CAPTURE_DIRECTORIES
        ),
        "max_bytes": adoption_binding_contract.MAX_CAPTURE_BYTES,
        "max_file_bytes": (
            adoption_binding_contract.MAX_CAPTURE_FILE_BYTES
        ),
        "max_depth": adoption_binding_contract.MAX_CAPTURE_DEPTH,
    }
)
V4_ADOPTION_EVIDENCE_FIELDS = frozenset(
    adoption_binding_contract.ADOPTION_EVIDENCE_FIELDS
)
V5_ADOPTION_EVIDENCE_FIELDS = frozenset(
    adoption_binding_contract.CAPTURE_ADOPTION_RESULT_EVIDENCE_FIELDS
)
OPAQUE_PLAN_FIELDS = {
    "schema_version",
    "instance_slug",
    "evidence_uid",
    "verifier_gid",
    "sources",
    "limits",
    "lifecycle",
}


class QualificationVerifierError(ValueError):
    """Stable, public-safe verifier rejection."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _error(code: str) -> QualificationVerifierError:
    return QualificationVerifierError(code)


def deny_same_uid_debugging() -> None:
    """Reject same-UID debugger attachment before evidence is parsed."""

    system = platform.system()
    libc = ctypes.CDLL(None, use_errno=True)
    if system == "Darwin":
        # PT_DENY_ATTACH: future attach attempts fail and an existing tracer
        # terminates the process.  This is defense in depth; the signed claim
        # remains operator-verified local conformance.
        if libc.ptrace(31, 0, None, 0) != 0:
            raise _error("verifier_debug_protection_failed")
        return
    if system == "Linux":
        # PR_SET_DUMPABLE = 4.  Clearing dumpability prevents same-UID ptrace.
        if libc.prctl(4, 0, 0, 0, 0) != 0:
            raise _error("verifier_debug_protection_failed")
        return
    raise _error("verifier_debug_protection_unsupported")


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


def _linux_libc() -> Any:
    return ctypes.CDLL(None, use_errno=True)


def _linux_prctl(
    option: int,
    argument2: int = 0,
    argument3: int = 0,
    argument4: int = 0,
    argument5: int = 0,
) -> int:
    libc = _linux_libc()
    result = libc.prctl(
        option,
        argument2,
        argument3,
        argument4,
        argument5,
    )
    if result < 0:
        observed_errno = ctypes.get_errno()
        raise OSError(observed_errno, os.strerror(observed_errno))
    return int(result)


def _linux_capability_words() -> tuple[int, ...]:
    libc = _linux_libc()
    header = _CapabilityHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    data = (_CapabilityData * 2)()
    if libc.capget(ctypes.byref(header), ctypes.byref(data)) != 0:
        observed_errno = ctypes.get_errno()
        raise OSError(observed_errno, os.strerror(observed_errno))
    return tuple(
        value
        for row in data
        for value in (row.effective, row.permitted, row.inheritable)
    )


def _assert_linux_privilege_confinement() -> None:
    """Check every Linux capability set without requiring a procfs mount."""

    try:
        if any(_linux_capability_words()):
            raise _error("verifier_capability_residue")
        for capability in range(64):
            try:
                if _linux_prctl(_PR_CAPBSET_READ, capability) != 0:
                    raise _error("verifier_capability_residue")
            except OSError as exc:
                if exc.errno == errno.EINVAL:
                    continue
                raise
            try:
                if (
                    _linux_prctl(
                        _PR_CAP_AMBIENT,
                        _PR_CAP_AMBIENT_IS_SET,
                        capability,
                    )
                    != 0
                ):
                    raise _error("verifier_capability_residue")
            except OSError as exc:
                if exc.errno == errno.EINVAL:
                    continue
                raise
        if _linux_prctl(_PR_GET_NO_NEW_PRIVS) != 1:
            raise _error("verifier_no_new_privs_missing")
    except QualificationVerifierError:
        raise
    except (AttributeError, OSError) as exc:
        raise _error("verifier_privilege_check_failed") from exc


def assert_privilege_confinement() -> None:
    """Require a non-root child with no retained Linux privilege surface."""

    if os.getuid() == 0 or os.geteuid() == 0 or os.getgid() == 0 or os.getegid() == 0:
        raise _error("verifier_privilege_residue")
    if hasattr(os, "getresuid") and 0 in os.getresuid():
        raise _error("verifier_privilege_residue")
    if hasattr(os, "getresgid") and 0 in os.getresgid():
        raise _error("verifier_privilege_residue")
    if platform.system() != "Linux":
        return
    _assert_linux_privilege_confinement()


def _load_runner() -> Any:
    if not RUNNER_PATH.is_file():
        raise _error("installed_runner_missing")
    specification = importlib.util.spec_from_file_location(
        "john_lomein_installed_persona_qualification_runner",
        RUNNER_PATH,
    )
    if specification is None or specification.loader is None:
        raise _error("installed_runner_loader_unavailable")
    module = importlib.util.module_from_spec(specification)
    try:
        specification.loader.exec_module(module)
    except Exception as exc:
        raise _error("installed_runner_load_failed") from exc
    return module


def _integer(value: Any, *, field: str, minimum: int = 0) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > MAX_SAFE_INTEGER
    ):
        raise _error(f"{field}_invalid")
    return value


def _absolute_path(value: Any, *, field: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise _error(f"{field}_invalid")
    text = os.fspath(value)
    if not isinstance(text, str) or not text or len(text) > 4096:
        raise _error(f"{field}_invalid")
    path = Path(text)
    if (
        not path.is_absolute()
        or "\x00" in text
        or "." in path.parts
        or ".." in path.parts
        or text != str(path)
    ):
        raise _error(f"{field}_invalid")
    return path


def _digest(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise _error(f"{field}_invalid")
    return value


def _run_id(value: Any) -> str:
    if not isinstance(value, str) or not RUN_ID_RE.fullmatch(value):
        raise _error("projection_run_id_invalid")
    return value


def _slug(value: Any) -> str:
    if not isinstance(value, str) or not SLUG_RE.fullmatch(value):
        raise _error("expected_instance_slug_invalid")
    return value


def _session_id(value: Any) -> str:
    if not isinstance(value, str) or not SESSION_ID_RE.fullmatch(value):
        raise _error("sealed_request_capture_session_id_invalid")
    return value


def _strict_mapping(
    value: Any,
    *,
    field: str,
    expected: set[str],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _error(f"{field}_not_object")
    if set(value) != expected:
        raise _error(f"{field}_fields_invalid")
    return value


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _error("capture_manifest_not_canonical") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _error("capture_manifest_duplicate_field")
        result[key] = value
    return result


def _parse_json(raw: bytes, *, field: str) -> Any:
    if not raw or len(raw) > MAX_CAPTURE_MANIFEST_BYTES:
        raise _error(f"{field}_size_invalid")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(
                _error("capture_manifest_nonfinite")
            ),
        )
    except QualificationVerifierError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _error(f"{field}_invalid") from exc


def _path_key(path: Path | str) -> str:
    return unicodedata.normalize("NFC", str(path).rstrip(os.sep)).casefold()


def _path_overlaps(left: Path, right: Path) -> bool:
    left_key = _path_key(left)
    right_key = _path_key(right)
    return (
        left_key == right_key
        or left_key.startswith(right_key + os.sep)
        or right_key.startswith(left_key + os.sep)
    )


def _path_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _reject_fd_metadata(descriptor: int, *, field: str) -> None:
    """Inspect metadata on the already-open object, never a path alias."""

    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, "flistxattr"):
        raise _error(f"{field}_fd_metadata_unsupported")
    libc.flistxattr.restype = ctypes.c_ssize_t
    if sys.platform == "darwin":
        libc.flistxattr.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
        ]
        attribute_bytes = libc.flistxattr(descriptor, None, 0, 0)
        permitted_attributes = {
            b"com.apple.provenance",
            b"com.apple.rootless",
        }
    elif sys.platform.startswith("linux"):
        libc.flistxattr.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        attribute_bytes = libc.flistxattr(descriptor, None, 0)
        # A host SELinux label is immutable to the verifier and required on
        # enforcing systems.  POSIX ACLs, file capabilities, and every other
        # attribute remain rejected.
        permitted_attributes = {b"security.selinux"}
    else:
        raise _error(f"{field}_fd_metadata_unsupported")
    if attribute_bytes < 0:
        raise _error(f"{field}_metadata_unreadable")
    attributes: set[bytes] = set()
    if attribute_bytes:
        buffer = ctypes.create_string_buffer(attribute_bytes)
        if sys.platform == "darwin":
            observed = libc.flistxattr(
                descriptor,
                buffer,
                attribute_bytes,
                0,
            )
        else:
            observed = libc.flistxattr(
                descriptor,
                buffer,
                attribute_bytes,
            )
        if observed != attribute_bytes:
            raise _error(f"{field}_metadata_changed")
        attributes = {
            name
            for name in bytes(buffer.raw[:observed]).split(b"\x00")
            if name
        }
    if not attributes.issubset(permitted_attributes):
        raise _error(f"{field}_extended_metadata_unsupported")
    if sys.platform != "darwin":
        return
    if not hasattr(libc, "acl_get_fd_np"):
        raise _error(f"{field}_fd_acl_unsupported")
    libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    libc.acl_get_fd_np.restype = ctypes.c_void_p
    libc.acl_to_text.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ssize_t),
    ]
    libc.acl_to_text.restype = ctypes.c_void_p
    libc.acl_free.argtypes = [ctypes.c_void_p]
    acl = libc.acl_get_fd_np(descriptor, 0x100)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise _error(f"{field}_acl_unreadable")
    text_pointer = None
    try:
        length = ctypes.c_ssize_t()
        text_pointer = libc.acl_to_text(acl, ctypes.byref(length))
        if not text_pointer:
            raise _error(f"{field}_acl_unreadable")
        acl_text = ctypes.string_at(text_pointer, length.value)
        if b":allow:" in acl_text:
            raise _error(f"{field}_acl_grants_unsupported")
    finally:
        if text_pointer:
            libc.acl_free(text_pointer)
        libc.acl_free(acl)


def _reject_acl_or_xattrs(path: Path, *, field: str) -> None:
    """Compatibility wrapper using a no-follow descriptor and inode binding."""

    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("nofollow_unsupported")
    try:
        named = path.lstat()
    except OSError as exc:
        raise _error(f"{field}_metadata_unreadable") from exc
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if stat.S_ISDIR(named.st_mode) and hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _error(f"{field}_metadata_unreadable") from exc
    try:
        opened = os.fstat(descriptor)
        if _snapshot_stat_tuple(opened) != _snapshot_stat_tuple(named):
            raise _error(f"{field}_metadata_changed")
        _reject_fd_metadata(descriptor, field=field)
        if _snapshot_stat_tuple(os.fstat(descriptor)) != _snapshot_stat_tuple(
            opened
        ):
            raise _error(f"{field}_metadata_changed")
    finally:
        os.close(descriptor)


def _relative_capture_path(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise _error(f"{field}_invalid")
    path = Path(value)
    if (
        path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
        or value != path.as_posix()
        or unicodedata.normalize("NFC", value) != value
    ):
        raise _error(f"{field}_invalid")
    return value


def _snapshot_stat_tuple(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_uid),
        int(info.st_gid),
        int(info.st_nlink),
        int(info.st_size),
        int(getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000))),
        int(getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000))),
    )


def _read_file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return flags


def _read_sealed_file(
    path: Path,
    *,
    owner_uid: int,
    verifier_gid: int,
    maximum_bytes: int,
    field: str,
) -> bytes:
    try:
        descriptor = os.open(path, _read_file_flags())
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner_uid
            or before.st_gid != verifier_gid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o440
            or not 0 <= before.st_size <= maximum_bytes
        ):
            raise _error(f"{field}_unsafe")
        _reject_fd_metadata(descriptor, field=field)
        raw = bytearray()
        while len(raw) <= maximum_bytes:
            chunk = os.read(
                descriptor,
                min(64 * 1024, maximum_bytes + 1 - len(raw)),
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        _reject_fd_metadata(descriptor, field=field)
        try:
            named = path.lstat()
        except OSError as exc:
            raise _error(f"{field}_changed_during_read") from exc
        if (
            len(raw) != before.st_size
            or _snapshot_stat_tuple(before) != _snapshot_stat_tuple(after)
            or _snapshot_stat_tuple(after) != _snapshot_stat_tuple(named)
        ):
            raise _error(f"{field}_changed_during_read")
        return bytes(raw)
    finally:
        os.close(descriptor)


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.samefile(right)
    except OSError:
        return left.resolve(strict=False) == right.resolve(strict=False)


def _attestable_projection(
    installed_runner: Any,
    result: Any,
    exit_code: Any,
    *,
    verified_at_unix: int,
) -> dict[str, Any]:
    verification = _strict_mapping(
        result,
        field="qualification_verification",
        expected={
            "schema_version",
            "valid",
            "current",
            "status",
            "reason",
            "candidates",
            "attestation_projection",
            "public_reputation_eligible",
        },
    )
    if (
        exit_code != 0
        or verification.get("schema_version") != installed_runner.VERIFY_SCHEMA
        or verification.get("valid") is not True
        or verification.get("current") is not True
        or verification.get("status") != "qualified"
        or verification.get("reason") != "all-distinct-candidates-qualified"
        or verification.get("public_reputation_eligible") is not False
    ):
        raise _error("qualification_not_attestable")
    candidates = verification.get("candidates")
    if (
        not isinstance(candidates, list)
        or not candidates
        or any(
            not isinstance(item, dict)
            or set(item) != {"id", "reproducible"}
            or item.get("reproducible") is not True
            for item in candidates
        )
    ):
        raise _error("qualification_candidates_not_reproducible")

    projection = _strict_mapping(
        verification.get("attestation_projection"),
        field="attestation_projection",
        expected={
            "schema_version",
            "run_id",
            "summary_sha256",
            "binding_sha256",
            "qualified_at_unix",
            "expires_at_unix",
        },
    )
    if projection.get("schema_version") != ATTESTATION_PROJECTION_SCHEMA:
        raise _error("attestation_projection_schema_unsupported")
    qualified_at = _integer(
        projection.get("qualified_at_unix"),
        field="projection_qualified_at_unix",
    )
    expires_at = _integer(
        projection.get("expires_at_unix"),
        field="projection_expires_at_unix",
    )
    if not qualified_at <= verified_at_unix < expires_at:
        raise _error("attestation_projection_timing_invalid")
    return {
        "run_id": _run_id(projection.get("run_id")),
        "summary_sha256": _digest(
            projection.get("summary_sha256"),
            field="projection_summary_sha256",
        ),
        "binding_sha256": _digest(
            projection.get("binding_sha256"),
            field="projection_binding_sha256",
        ),
        "status": "qualified",
        "qualified_at_unix": qualified_at,
        "expires_at_unix": expires_at,
    }


def verify_configured_evidence(
    *,
    instance_manifest: Path,
    private_root: Path,
    expected_public_root: Path,
    expected_instance_slug: str,
    expected_evidence_uid: int,
    verified_at_unix: int,
    process_uid: int | None = None,
    runner: Any | None = None,
) -> dict[str, Any]:
    """Return the only evidence object the root attestor may sign."""

    instance_path = _absolute_path(
        instance_manifest, field="instance_manifest_path"
    )
    private_path = _absolute_path(private_root, field="qualification_private_root")
    public_path = _absolute_path(
        expected_public_root, field="qualification_public_root"
    )
    instance_slug = _slug(expected_instance_slug)
    evidence_uid = _integer(
        expected_evidence_uid,
        field="expected_evidence_uid",
        minimum=1,
    )
    observed_uid = os.geteuid() if process_uid is None else _integer(
        process_uid, field="process_uid"
    )
    if observed_uid == 0 or observed_uid != evidence_uid:
        raise _error("verifier_identity_mismatch")
    verified_at = _integer(
        verified_at_unix, field="verified_at_unix", minimum=1
    )

    installed_runner = _load_runner() if runner is None else runner
    try:
        instance = installed_runner.load_instance(instance_path)
    except Exception as exc:
        raise _error("instance_manifest_verification_failed") from exc
    if instance.get("slug") != instance_slug:
        raise _error("instance_slug_mismatch")
    derived_public_root = installed_runner._public_root(instance)
    if not _same_path(Path(derived_public_root), public_path):
        raise _error("qualification_public_root_mismatch")

    arguments = SimpleNamespace(
        instance=instance_path,
        private_root=private_path,
        scenarios=installed_runner.PERSONA_EVAL.DEFAULT_SCENARIOS,
        rubric=installed_runner.PERSONA_EVAL.DEFAULT_RUBRIC,
    )
    try:
        result, exit_code = installed_runner.verify_qualification(arguments)
    except Exception as exc:
        raise _error("qualification_reproduction_failed") from exc
    return {
        **_attestable_projection(
            installed_runner,
            result,
            exit_code,
            verified_at_unix=verified_at,
        ),
        "verifier_version": LEGACY_VERIFIER_VERSION,
        "verified_at_unix": verified_at,
        "observed_evidence_uid": observed_uid,
    }


def _validate_sealed_verifier_identity(
    *,
    expected_verifier_uid: int,
    expected_verifier_gid: int,
    expected_evidence_uid: int,
    process_uid: int | None,
    process_gid: int | None,
    process_groups: Sequence[int] | None,
    process_res_uids: Sequence[int] | None = None,
    process_res_gids: Sequence[int] | None = None,
) -> tuple[int, int]:
    verifier_uid = _integer(
        expected_verifier_uid,
        field="expected_verifier_uid",
        minimum=1,
    )
    verifier_gid = _integer(
        expected_verifier_gid,
        field="expected_verifier_gid",
        minimum=1,
    )
    evidence_uid = _integer(
        expected_evidence_uid,
        field="expected_evidence_uid",
        minimum=1,
    )
    if verifier_uid == evidence_uid:
        raise _error("verifier_identity_aliasing")
    observed_uid = (
        os.geteuid()
        if process_uid is None
        else _integer(process_uid, field="process_uid")
    )
    observed_gid = (
        os.getegid()
        if process_gid is None
        else _integer(process_gid, field="process_gid")
    )
    if observed_uid == 0 or observed_uid != verifier_uid:
        raise _error("verifier_identity_mismatch")
    if observed_gid == 0 or observed_gid != verifier_gid:
        raise _error("verifier_group_mismatch")
    raw_uids: Sequence[int]
    if process_res_uids is None:
        raw_uids = (
            os.getresuid()
            if process_uid is None and hasattr(os, "getresuid")
            else (os.getuid(), observed_uid)
            if process_uid is None
            else (observed_uid, observed_uid, observed_uid)
        )
    else:
        raw_uids = process_res_uids
    raw_gids: Sequence[int]
    if process_res_gids is None:
        raw_gids = (
            os.getresgid()
            if process_gid is None and hasattr(os, "getresgid")
            else (os.getgid(), observed_gid)
            if process_gid is None
            else (observed_gid, observed_gid, observed_gid)
        )
    else:
        raw_gids = process_res_gids
    if (
        isinstance(raw_uids, (str, bytes))
        or not isinstance(raw_uids, Sequence)
        or not raw_uids
        or any(
            _integer(uid, field="process_res_uid") != verifier_uid
            for uid in raw_uids
        )
    ):
        raise _error("verifier_saved_identity_mismatch")
    if (
        isinstance(raw_gids, (str, bytes))
        or not isinstance(raw_gids, Sequence)
        or not raw_gids
        or any(
            _integer(gid, field="process_res_gid") != verifier_gid
            for gid in raw_gids
        )
    ):
        raise _error("verifier_saved_group_mismatch")
    raw_groups: Sequence[int] = (
        os.getgroups() if process_groups is None else process_groups
    )
    if isinstance(raw_groups, (str, bytes)) or not isinstance(
        raw_groups, Sequence
    ):
        raise _error("verifier_supplementary_groups_invalid")
    groups = {
        _integer(group, field="process_group")
        for group in raw_groups
    }
    if groups - {verifier_gid}:
        raise _error("verifier_supplementary_groups_forbidden")
    return verifier_uid, verifier_gid


def _validate_snapshot_parent_chain(
    path: Path,
    *,
    snapshot_owner_uid: int,
) -> None:
    current = path
    trusted = {0, snapshot_owner_uid}
    while True:
        try:
            info = current.lstat()
        except OSError as exc:
            raise _error("sealed_snapshot_parent_unreadable") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise _error("sealed_snapshot_parent_unsafe")
        if info.st_uid not in trusted:
            raise _error("sealed_snapshot_parent_owner_mismatch")
        if info.st_mode & 0o022 and not (
            info.st_uid == 0
            and stat.S_ISDIR(info.st_mode)
            and info.st_mode & stat.S_ISVTX
        ):
            raise _error("sealed_snapshot_parent_writable")
        _reject_acl_or_xattrs(current, field="sealed_snapshot_parent")
        if current.parent == current:
            return
        current = current.parent


def _validate_sealed_capture(
    *,
    snapshot_root: Path,
    expected_capture_manifest_sha256: str,
    instance_manifest: Path,
    private_root: Path,
    expected_public_root: Path,
    expected_instance_slug: str,
    expected_evidence_uid: int,
    expected_verifier_gid: int,
    snapshot_owner_uid: int,
) -> tuple[dict[str, Any], str]:
    root = _absolute_path(snapshot_root, field="snapshot_root")
    instance_path = _absolute_path(
        instance_manifest,
        field="instance_manifest_path",
    )
    private_path = _absolute_path(
        private_root,
        field="qualification_private_root",
    )
    public_path = _absolute_path(
        expected_public_root,
        field="qualification_public_root",
    )
    runtime_path = public_path.parent.parent
    instance_slug = _slug(expected_instance_slug)
    evidence_uid = _integer(
        expected_evidence_uid,
        field="expected_evidence_uid",
        minimum=1,
    )
    verifier_gid = _integer(
        expected_verifier_gid,
        field="expected_verifier_gid",
        minimum=1,
    )
    owner_uid = _integer(
        snapshot_owner_uid,
        field="snapshot_owner_uid",
    )
    expected_manifest_digest = _digest(
        expected_capture_manifest_sha256,
        field="expected_capture_manifest_sha256",
    )
    if public_path != runtime_path / "state" / "persona-qualification":
        raise _error("qualification_public_root_layout_mismatch")
    if any(
        _path_overlaps(root, source)
        for source in (instance_path, runtime_path, private_path, BUNDLE_ROOT)
    ):
        raise _error("sealed_snapshot_path_overlap")
    if (
        _path_overlaps(private_path, runtime_path)
        or _path_overlaps(instance_path, runtime_path)
        or _path_overlaps(instance_path, private_path)
    ):
        raise _error("qualification_source_path_overlap")

    _validate_snapshot_parent_chain(
        root,
        snapshot_owner_uid=owner_uid,
    )
    root_info = root.lstat()
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != owner_uid
        or root_info.st_gid != verifier_gid
        or stat.S_IMODE(root_info.st_mode) != 0o550
    ):
        raise _error("sealed_snapshot_root_unsafe")
    _reject_acl_or_xattrs(root, field="sealed_snapshot_root")

    manifest_raw = _read_sealed_file(
        root / "capture-manifest.json",
        owner_uid=owner_uid,
        verifier_gid=verifier_gid,
        maximum_bytes=MAX_CAPTURE_MANIFEST_BYTES,
        field="capture_manifest",
    )
    manifest = _strict_mapping(
        _parse_json(manifest_raw, field="capture_manifest"),
        field="capture_manifest",
        expected=CAPTURE_FIELDS,
    )
    manifest_digest = hashlib.sha256(_canonical_json(manifest)).hexdigest()
    if manifest_digest != expected_manifest_digest:
        raise _error("capture_manifest_digest_mismatch")
    if manifest.get("schema_version") != CAPTURE_SCHEMA:
        raise _error("capture_manifest_schema_unsupported")
    if manifest.get("instance_slug") != instance_slug:
        raise _error("capture_manifest_instance_mismatch")
    _run_id(manifest.get("run_id"))
    _integer(
        manifest.get("captured_at_unix"),
        field="capture_manifest_captured_at_unix",
        minimum=1,
    )
    if (
        manifest.get("observed_evidence_uid") != evidence_uid
        or manifest.get("capture_uid") != owner_uid
        or manifest.get("verifier_gid") != verifier_gid
    ):
        raise _error("capture_manifest_identity_mismatch")

    source_roots = _strict_mapping(
        manifest.get("source_roots"),
        field="capture_source_roots",
        expected={
            "instance_manifest",
            "runtime",
            "qualification_public",
            "qualification_private",
        },
    )
    expected_source_roots = {
        "instance_manifest": str(instance_path),
        "runtime": str(runtime_path),
        "qualification_public": str(public_path),
        "qualification_private": str(private_path),
    }
    if source_roots != expected_source_roots:
        raise _error("capture_source_roots_mismatch")
    path_identities = _strict_mapping(
        manifest.get("path_identities"),
        field="capture_path_identities",
        expected={
            "evidence_home",
            "checkout_source",
            "runtime_source",
            "checkout",
            "runtime",
        },
    )
    normalized_path_identities = {
        name: str(
            _absolute_path(
                value,
                field=f"capture_{name}_identity",
            )
        )
        for name, value in path_identities.items()
    }
    if _path_overlaps(
        Path(normalized_path_identities["checkout"]),
        Path(normalized_path_identities["runtime"]),
    ):
        raise _error("capture_path_identities_overlap")
    manifest["path_identities"] = normalized_path_identities
    layout = _strict_mapping(
        manifest.get("layout"),
        field="capture_layout",
        expected={"instance_manifest", "checkout", "runtime", "private_root"},
    )
    expected_layout = {
        "instance_manifest": "instance/instance.yaml",
        "checkout": "checkout",
        "runtime": "runtime",
        "private_root": "private",
    }
    if layout != expected_layout:
        raise _error("capture_layout_mismatch")

    raw_files = manifest.get("files")
    raw_directories = manifest.get("directories")
    raw_source_directories = manifest.get("source_directories")
    if (
        not isinstance(raw_files, list)
        or not isinstance(raw_directories, list)
        or not isinstance(raw_source_directories, list)
        or not 1 <= len(raw_files) <= MAX_CAPTURE_FILES
        or len(raw_directories) > MAX_CAPTURE_DIRECTORIES
        or len(raw_source_directories) > MAX_CAPTURE_DIRECTORIES
        or manifest.get("file_count") != len(raw_files)
    ):
        raise _error("capture_inventory_invalid")

    expected_files = {"capture-manifest.json"}
    seen_paths: set[str] = set()
    total_bytes = 0
    previous_path = ""
    required_files = {
        "instance/instance.yaml",
        "runtime/instance.yaml",
        "runtime/state/john-lomein-persona.json",
        "runtime/state/persona-qualification/status.json",
        "runtime/state/persona-qualification/latest.json",
        f"private/{manifest['run_id']}/run-manifest.json",
    }
    for raw_entry in raw_files:
        entry = _strict_mapping(
            raw_entry,
            field="capture_file",
            expected={
                "path",
                "source",
                "source_class",
                "source_uid",
                "source_mode",
                "source_identity_sha256",
                "size",
                "sha256",
            },
        )
        relative = _relative_capture_path(
            entry.get("path"),
            field="capture_file_path",
        )
        identity = unicodedata.normalize("NFC", relative).casefold()
        if relative <= previous_path or identity in seen_paths:
            raise _error("capture_file_order_or_alias_invalid")
        previous_path = relative
        seen_paths.add(identity)
        expected_files.add(relative)
        source = _absolute_path(
            entry.get("source"),
            field="capture_file_source",
        )
        relative_path = Path(relative)
        if relative == "instance/instance.yaml":
            expected_source = instance_path
        elif relative_path.parts[0] == "runtime":
            expected_source = runtime_path.joinpath(*relative_path.parts[1:])
        elif relative_path.parts[0] == "private":
            expected_source = private_path.joinpath(*relative_path.parts[1:])
        else:
            raise _error("capture_file_outside_layout")
        if source != expected_source:
            raise _error("capture_file_source_mismatch")
        source_class = entry.get("source_class")
        if (
            not isinstance(source_class, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", source_class)
            or entry.get("source_uid") != evidence_uid
            or entry.get("source_mode") != 0o600
        ):
            raise _error("capture_file_provenance_invalid")
        _digest(
            entry.get("source_identity_sha256"),
            field="capture_file_source_identity_sha256",
        )
        size = _integer(
            entry.get("size"),
            field="capture_file_size",
        )
        if size > MAX_CAPTURE_FILE_BYTES:
            raise _error("capture_file_size_invalid")
        raw = _read_sealed_file(
            root / relative,
            owner_uid=owner_uid,
            verifier_gid=verifier_gid,
            maximum_bytes=MAX_CAPTURE_FILE_BYTES,
            field="capture_file",
        )
        if (
            len(raw) != size
            or hashlib.sha256(raw).hexdigest()
            != _digest(entry.get("sha256"), field="capture_file_sha256")
        ):
            raise _error("capture_file_mismatch")
        total_bytes += len(raw)
        if total_bytes > MAX_CAPTURE_BYTES:
            raise _error("capture_total_size_invalid")
    if not required_files <= expected_files:
        raise _error("capture_required_file_missing")
    if total_bytes != manifest.get("total_bytes"):
        raise _error("capture_total_size_mismatch")

    previous_source_directory = ""
    for raw_entry in raw_source_directories:
        entry = _strict_mapping(
            raw_entry,
            field="capture_source_directory",
            expected={
                "path",
                "source_uid",
                "source_mode",
                "source_identity_sha256",
                "entry_count",
                "entries_sha256",
            },
        )
        path = _absolute_path(
            entry.get("path"),
            field="capture_source_directory_path",
        )
        path_text = str(path)
        if path_text <= previous_source_directory:
            raise _error("capture_source_directory_order_invalid")
        previous_source_directory = path_text
        if (
            not (
                _path_within(path, public_path)
                or _path_within(path, private_path)
            )
            or
            entry.get("source_uid") != evidence_uid
            or entry.get("source_mode") != 0o700
        ):
            raise _error("capture_source_directory_provenance_invalid")
        _integer(
            entry.get("entry_count"),
            field="capture_source_directory_entry_count",
        )
        if entry["entry_count"] > MAX_CAPTURE_ENTRIES:
            raise _error("capture_source_directory_entry_count_invalid")
        _digest(
            entry.get("source_identity_sha256"),
            field="capture_source_directory_identity_sha256",
        )
        _digest(
            entry.get("entries_sha256"),
            field="capture_source_directory_entries_sha256",
        )

    expected_directories: set[str] = set()
    seen_directories: set[str] = set()
    previous_directory = ""
    for raw_directory in raw_directories:
        relative = _relative_capture_path(
            raw_directory,
            field="capture_directory_path",
        )
        identity = unicodedata.normalize("NFC", relative).casefold()
        if relative <= previous_directory or identity in seen_directories:
            raise _error("capture_directory_order_or_alias_invalid")
        previous_directory = relative
        seen_directories.add(identity)
        expected_directories.add(relative)
        path = root / relative
        try:
            info = path.lstat()
        except OSError as exc:
            raise _error("capture_directory_unreadable") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != owner_uid
            or info.st_gid != verifier_gid
            or stat.S_IMODE(info.st_mode) != 0o550
        ):
            raise _error("capture_directory_mismatch")
        _reject_acl_or_xattrs(path, field="capture_directory")
    if not {"instance", "checkout", "runtime", "private"} <= expected_directories:
        raise _error("capture_layout_directory_missing")

    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    try:
        observed = root.rglob("*")
        observed_count = 0
        for path in observed:
            observed_count += 1
            if observed_count > MAX_CAPTURE_ENTRIES + 1:
                raise _error("sealed_snapshot_inventory_too_large")
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                observed_files.add(relative)
            elif stat.S_ISDIR(info.st_mode):
                observed_directories.add(relative)
            else:
                raise _error("sealed_snapshot_entry_unsafe")
    except OSError as exc:
        raise _error("sealed_snapshot_inventory_unreadable") from exc
    if (
        observed_files != expected_files
        or observed_directories != expected_directories
    ):
        raise _error("sealed_snapshot_inventory_mismatch")
    return manifest, manifest_digest


def verify_sealed_snapshot_evidence(
    *,
    snapshot_root: Path,
    expected_capture_manifest_sha256: str,
    instance_manifest: Path,
    expected_instance_manifest_sha256: str,
    private_root: Path,
    expected_public_root: Path,
    expected_instance_slug: str,
    expected_evidence_uid: int,
    expected_verifier_uid: int,
    expected_verifier_gid: int,
    verifier_bundle_sha256: str,
    verification_policy_sha256: str,
    operator_policy_sha256: str,
    verified_at_unix: int,
    process_uid: int | None = None,
    process_gid: int | None = None,
    process_groups: Sequence[int] | None = None,
    process_res_uids: Sequence[int] | None = None,
    process_res_gids: Sequence[int] | None = None,
    snapshot_owner_uid: int = 0,
    runner: Any | None = None,
) -> dict[str, Any]:
    """Verify one root-sealed capture as a separate, group-confined identity."""

    verifier_uid, verifier_gid = _validate_sealed_verifier_identity(
        expected_verifier_uid=expected_verifier_uid,
        expected_verifier_gid=expected_verifier_gid,
        expected_evidence_uid=expected_evidence_uid,
        process_uid=process_uid,
        process_gid=process_gid,
        process_groups=process_groups,
        process_res_uids=process_res_uids,
        process_res_gids=process_res_gids,
    )
    verified_at = _integer(
        verified_at_unix,
        field="verified_at_unix",
        minimum=1,
    )
    bundle_digest = _digest(
        verifier_bundle_sha256,
        field="verifier_bundle_sha256",
    )
    policy_digest = _digest(
        verification_policy_sha256,
        field="verification_policy_sha256",
    )
    operator_digest = _digest(
        operator_policy_sha256,
        field="operator_policy_sha256",
    )
    instance_manifest_digest = _digest(
        expected_instance_manifest_sha256,
        field="expected_instance_manifest_sha256",
    )
    capture_manifest, capture_digest = _validate_sealed_capture(
        snapshot_root=snapshot_root,
        expected_capture_manifest_sha256=expected_capture_manifest_sha256,
        instance_manifest=instance_manifest,
        private_root=private_root,
        expected_public_root=expected_public_root,
        expected_instance_slug=expected_instance_slug,
        expected_evidence_uid=expected_evidence_uid,
        expected_verifier_gid=verifier_gid,
        snapshot_owner_uid=snapshot_owner_uid,
    )
    captured_instance_entries = [
        entry
        for entry in capture_manifest["files"]
        if entry["path"] == capture_manifest["layout"]["instance_manifest"]
        and entry["source_class"] == "instance_manifest"
    ]
    if (
        len(captured_instance_entries) != 1
        or captured_instance_entries[0]["sha256"]
        != instance_manifest_digest
    ):
        raise _error("captured_instance_manifest_digest_mismatch")
    installed_runner = _load_runner() if runner is None else runner
    if not hasattr(installed_runner, "verify_qualification_from_sealed_snapshot"):
        raise _error("installed_runner_snapshot_support_missing")
    source_roots = capture_manifest["source_roots"]
    try:
        result, exit_code = (
            installed_runner.verify_qualification_from_sealed_snapshot(
                snapshot_root=_absolute_path(
                    snapshot_root,
                    field="snapshot_root",
                ),
                capture_manifest=capture_manifest,
                source_manifest_path=Path(source_roots["instance_manifest"]),
                source_runtime_root=Path(source_roots["runtime"]),
                source_public_root=Path(source_roots["qualification_public"]),
                source_private_root=Path(source_roots["qualification_private"]),
                source_path_identities=capture_manifest["path_identities"],
                expected_instance_slug=expected_instance_slug,
                expected_evidence_uid=expected_evidence_uid,
                snapshot_owner_uid=snapshot_owner_uid,
                verifier_gid=verifier_gid,
                scenarios_path=installed_runner.PERSONA_EVAL.DEFAULT_SCENARIOS,
                rubric_path=installed_runner.PERSONA_EVAL.DEFAULT_RUBRIC,
            )
        )
    except QualificationVerifierError:
        raise
    except Exception as exc:
        raise _error("qualification_snapshot_reproduction_failed") from exc
    projection = _attestable_projection(
        installed_runner,
        result,
        exit_code,
        verified_at_unix=verified_at,
    )
    return {
        **projection,
        "verifier_version": LEGACY_VERIFIER_VERSION,
        "verifier_uid": verifier_uid,
        "verifier_bundle_sha256": bundle_digest,
        "verification_policy_sha256": policy_digest,
        "capture_manifest_sha256": capture_digest,
        "operator_policy_sha256": operator_digest,
        "claim_strength": CLAIM_STRENGTH,
        "public_reputation_eligible": False,
        "verified_at_unix": verified_at,
        "observed_evidence_uid": capture_manifest[
            "observed_evidence_uid"
        ],
    }


def _opaque_manifest_and_plan(
    *,
    snapshot_root: Path,
    expected_capture_manifest_sha256: str,
    expected_capture_plan_sha256: str,
    expected_evidence_uid: int,
    expected_verifier_gid: int,
    snapshot_owner_uid: int,
    expected_manifest_capture_uid: int | None = None,
    expected_source_directory_mode: int = (
        opaque_capture_contract.PRIVATE_SOURCE_DIRECTORY_MODE
    ),
    expected_source_file_mode: int = (
        opaque_capture_contract.PRIVATE_SOURCE_FILE_MODE
    ),
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    """Reconstruct the plan from sealed bytes, then verify the whole capture."""

    root = _absolute_path(snapshot_root, field="snapshot_root")
    manifest_digest = _digest(
        expected_capture_manifest_sha256,
        field="expected_capture_manifest_sha256",
    )
    plan_digest = _digest(
        expected_capture_plan_sha256,
        field="expected_capture_plan_sha256",
    )
    evidence_uid = _integer(
        expected_evidence_uid,
        field="expected_evidence_uid",
        minimum=1,
    )
    verifier_gid = _integer(
        expected_verifier_gid,
        field="expected_verifier_gid",
        minimum=1,
    )
    owner_uid = _integer(
        snapshot_owner_uid,
        field="snapshot_owner_uid",
    )
    manifest_raw = _read_sealed_file(
        root / opaque_capture_contract.OPAQUE_CAPTURE_MANIFEST,
        owner_uid=owner_uid,
        verifier_gid=verifier_gid,
        maximum_bytes=opaque_capture_contract.MAX_MANIFEST_BYTES,
        field="opaque_capture_manifest",
    )
    manifest_value = _strict_mapping(
        _parse_json(manifest_raw, field="opaque_capture_manifest"),
        field="opaque_capture_manifest",
        expected=opaque_capture_contract.MANIFEST_FIELDS,
    )
    if manifest_value.get("schema_version") != OPAQUE_CAPTURE_SCHEMA:
        raise _error("opaque_capture_manifest_schema_unsupported")
    if hashlib.sha256(_canonical_json(manifest_value)).hexdigest() != manifest_digest:
        raise _error("opaque_capture_manifest_digest_mismatch")

    reconstructed = {
        "schema_version": capture_plan_contract.CAPTURE_PLAN_SCHEMA,
        "instance_slug": manifest_value.get("instance_slug"),
        "evidence_uid": manifest_value.get("evidence_uid"),
        "verifier_gid": manifest_value.get("verifier_gid"),
        "sources": manifest_value.get("sources"),
        "limits": manifest_value.get("limits"),
        "lifecycle": manifest_value.get("lifecycle"),
    }
    if set(reconstructed) != OPAQUE_PLAN_FIELDS:
        raise _error("opaque_capture_plan_reconstruction_failed")
    try:
        normalized_plan = capture_plan_contract.normalize_capture_plan(
            reconstructed
        )
        reconstructed_digest = capture_plan_contract.capture_plan_sha256(
            normalized_plan
        )
    except capture_plan_contract.CapturePlanError as exc:
        raise _error(exc.code) from exc
    if normalized_plan != reconstructed:
        raise _error("opaque_capture_plan_not_normalized")
    if reconstructed_digest != plan_digest:
        raise _error("opaque_capture_plan_digest_mismatch")
    if (
        normalized_plan["evidence_uid"] != evidence_uid
        or normalized_plan["verifier_gid"] != verifier_gid
    ):
        raise _error("opaque_capture_plan_identity_mismatch")

    try:
        manifest = opaque_capture_contract.verify_sealed_opaque_capture(
            root,
            plan=normalized_plan,
            expected_plan_sha256=plan_digest,
            expected_capture_uid=owner_uid,
            expected_verifier_gid=verifier_gid,
            expected_manifest_sha256=manifest_digest,
            expected_manifest_capture_uid=(
                expected_manifest_capture_uid
            ),
            expected_source_directory_mode=expected_source_directory_mode,
            expected_source_file_mode=expected_source_file_mode,
        )
    except opaque_capture_contract.OpaqueCaptureError as exc:
        raise _error(exc.code) from exc
    if manifest != manifest_value:
        raise _error("opaque_capture_manifest_changed_during_verification")
    return manifest, normalized_plan, manifest_digest, plan_digest


def _bound_capture_selection(
    value: Any,
    *,
    expected_capture_selection_sha256: str,
    instance_manifest: Path,
    private_root: Path,
    expected_public_root: Path,
    evidence_home: Path,
    checkout_identity: Path,
    runtime_identity: Path,
) -> dict[str, Any]:
    """Bind one private selector policy to the independently supplied roots."""

    selection_digest = _digest(
        expected_capture_selection_sha256,
        field="expected_capture_selection_sha256",
    )
    try:
        normalized = (
            capture_selection_contract.normalize_capture_selection(value)
        )
        observed_digest = (
            capture_selection_contract.capture_selection_sha256(normalized)
        )
    except capture_selection_contract.CaptureSelectionError as exc:
        raise _error(exc.code) from exc
    if observed_digest != selection_digest:
        raise _error("capture_selection_digest_mismatch")
    instance_path = _absolute_path(
        instance_manifest,
        field="instance_manifest_path",
    )
    private_path = _absolute_path(
        private_root,
        field="qualification_private_root",
    )
    public_path = _absolute_path(
        expected_public_root,
        field="qualification_public_root",
    )
    home_path = _absolute_path(evidence_home, field="evidence_home_path")
    checkout_path = _absolute_path(
        checkout_identity,
        field="checkout_identity_path",
    )
    runtime_identity_path = _absolute_path(
        runtime_identity,
        field="runtime_identity_path",
    )
    runtime_path = public_path.parent.parent
    if public_path != runtime_path / "state" / "persona-qualification":
        raise _error("qualification_public_root_layout_mismatch")
    expected_roots = {
        "instance_manifest": str(instance_path),
        "qualification_private": str(private_path),
        "qualification_public": str(public_path),
        "runtime": str(runtime_path),
    }
    if normalized["source_roots"] != expected_roots:
        raise _error("capture_selection_source_roots_mismatch")
    expected_identities = {
        "evidence_home": str(home_path),
        "checkout": str(checkout_path),
        "runtime": str(runtime_identity_path),
    }
    if any(
        normalized["path_identities"][field] != expected
        for field, expected in expected_identities.items()
    ):
        raise _error("capture_selection_identity_paths_mismatch")
    return normalized


def _opaque_file_entry(
    manifest: Mapping[str, Any],
    relative_path: str,
    *,
    field: str,
) -> dict[str, Any]:
    matches = [
        entry
        for entry in manifest.get("files", [])
        if isinstance(entry, dict) and entry.get("path") == relative_path
    ]
    if len(matches) != 1:
        raise _error(f"{field}_missing")
    return matches[0]


def _extract_opaque_run_id(
    *,
    snapshot_root: Path,
    manifest: Mapping[str, Any],
    capture_selection: Mapping[str, Any],
    snapshot_owner_uid: int,
    verifier_gid: int,
) -> str:
    """Extract one run identity only after full opaque inventory verification."""

    status_relative = (
        "runtime/state/persona-qualification/status.json"
    )
    status_entry = _opaque_file_entry(
        manifest,
        status_relative,
        field="opaque_capture_status",
    )
    expected_status_source = str(
        Path(
            capture_selection["source_roots"]["qualification_public"]
        )
        / "status.json"
    )
    if (
        status_entry.get("source_id") != "public-status"
        or status_entry.get("source_class")
        != "qualification_public_status"
        or status_entry.get("source_path") != expected_status_source
        or status_entry.get("source_relative_path") != ""
    ):
        raise _error("opaque_capture_status_role_mismatch")
    status_raw = _read_sealed_file(
        snapshot_root / status_relative,
        owner_uid=snapshot_owner_uid,
        verifier_gid=verifier_gid,
        maximum_bytes=MAX_CAPTURE_FILE_BYTES,
        field="opaque_capture_status",
    )
    if (
        len(status_raw) != status_entry.get("size")
        or hashlib.sha256(status_raw).hexdigest()
        != status_entry.get("sha256")
    ):
        raise _error("opaque_capture_status_digest_mismatch")
    try:
        status = (
            capture_selection_contract.parse_terminal_qualified_status(
                status_raw
            )
        )
    except capture_selection_contract.CaptureSelectionError as exc:
        raise _error(exc.code) from exc
    run_id = status.get("run_id")
    required = {
        "runtime/state/persona-qualification/latest.json",
        (
            "runtime/state/persona-qualification/reports/"
            f"{run_id}/summary.json"
        ),
        f"private/{run_id}/run-manifest.json",
    }
    observed = {
        entry.get("path")
        for entry in manifest.get("files", [])
        if isinstance(entry, dict)
    }
    if not required.issubset(observed):
        raise _error("opaque_capture_run_evidence_missing")
    return str(run_id)


def verify_opaque_snapshot_evidence(
    *,
    snapshot_root: Path,
    expected_capture_manifest_sha256: str,
    expected_capture_plan_sha256: str,
    capture_selection: Any,
    expected_capture_selection_sha256: str,
    instance_manifest: Path,
    expected_instance_manifest_sha256: str,
    private_root: Path,
    expected_public_root: Path,
    evidence_home: Path,
    checkout_identity: Path,
    runtime_identity: Path,
    expected_instance_slug: str,
    expected_evidence_uid: int,
    expected_verifier_uid: int,
    expected_verifier_gid: int,
    verifier_bundle_sha256: str,
    verification_policy_sha256: str,
    operator_policy_sha256: str,
    verified_at_unix: int,
    expected_run_id: str | None = None,
    process_uid: int | None = None,
    process_gid: int | None = None,
    process_groups: Sequence[int] | None = None,
    process_res_uids: Sequence[int] | None = None,
    process_res_gids: Sequence[int] | None = None,
    snapshot_owner_uid: int = 0,
    manifest_capture_uid: int | None = None,
    source_directory_mode: int = (
        opaque_capture_contract.PRIVATE_SOURCE_DIRECTORY_MODE
    ),
    source_file_mode: int = (
        opaque_capture_contract.PRIVATE_SOURCE_FILE_MODE
    ),
    runner: Any | None = None,
) -> dict[str, Any]:
    """Verify opaque-v2 evidence under a distinct, group-confined identity."""

    verifier_uid, verifier_gid = _validate_sealed_verifier_identity(
        expected_verifier_uid=expected_verifier_uid,
        expected_verifier_gid=expected_verifier_gid,
        expected_evidence_uid=expected_evidence_uid,
        process_uid=process_uid,
        process_gid=process_gid,
        process_groups=process_groups,
        process_res_uids=process_res_uids,
        process_res_gids=process_res_gids,
    )
    verified_at = _integer(
        verified_at_unix,
        field="verified_at_unix",
        minimum=1,
    )
    bundle_digest = _digest(
        verifier_bundle_sha256,
        field="verifier_bundle_sha256",
    )
    policy_digest = _digest(
        verification_policy_sha256,
        field="verification_policy_sha256",
    )
    operator_digest = _digest(
        operator_policy_sha256,
        field="operator_policy_sha256",
    )
    instance_digest = _digest(
        expected_instance_manifest_sha256,
        field="expected_instance_manifest_sha256",
    )
    instance_slug = _slug(expected_instance_slug)
    requested_run_id = (
        None
        if expected_run_id is None
        else _run_id(expected_run_id)
    )
    root = _absolute_path(snapshot_root, field="snapshot_root")
    selection = _bound_capture_selection(
        capture_selection,
        expected_capture_selection_sha256=(
            expected_capture_selection_sha256
        ),
        instance_manifest=instance_manifest,
        private_root=private_root,
        expected_public_root=expected_public_root,
        evidence_home=evidence_home,
        checkout_identity=checkout_identity,
        runtime_identity=runtime_identity,
    )
    if (
        selection["instance_slug"] != instance_slug
        or selection["evidence_uid"] != expected_evidence_uid
        or selection["verifier_gid"] != verifier_gid
    ):
        raise _error("capture_selection_identity_mismatch")
    source_roots = selection["source_roots"]
    path_identities = selection["path_identities"]
    manifest, plan, capture_digest, plan_digest = _opaque_manifest_and_plan(
        snapshot_root=root,
        expected_capture_manifest_sha256=expected_capture_manifest_sha256,
        expected_capture_plan_sha256=expected_capture_plan_sha256,
        expected_evidence_uid=expected_evidence_uid,
        expected_verifier_gid=verifier_gid,
        snapshot_owner_uid=snapshot_owner_uid,
        expected_manifest_capture_uid=manifest_capture_uid,
        expected_source_directory_mode=source_directory_mode,
        expected_source_file_mode=source_file_mode,
    )
    if plan["instance_slug"] != instance_slug:
        raise _error("opaque_capture_instance_slug_mismatch")
    instance_entry = _opaque_file_entry(
        manifest,
        "instance/instance.yaml",
        field="opaque_capture_instance_manifest",
    )
    if (
        instance_entry.get("source_class") != "instance_manifest"
        or instance_entry.get("source_path")
        != source_roots["instance_manifest"]
        or instance_entry.get("sha256") != instance_digest
    ):
        raise _error("captured_instance_manifest_digest_mismatch")
    run_id = _extract_opaque_run_id(
        snapshot_root=root,
        manifest=manifest,
        capture_selection=selection,
        snapshot_owner_uid=snapshot_owner_uid,
        verifier_gid=verifier_gid,
    )
    if (
        requested_run_id is not None
        and run_id != requested_run_id
    ):
        raise _error(
            "qualification_opaque_expected_run_id_mismatch"
        )
    try:
        expected_plan, selected_plan_digest = (
            capture_selection_contract.validate_concrete_capture_plan(
                selection,
                plan,
                run_id,
            )
        )
    except capture_selection_contract.CaptureSelectionError as exc:
        raise _error(exc.code) from exc
    if expected_plan != plan or selected_plan_digest != plan_digest:
        raise _error("capture_selection_plan_digest_mismatch")

    installed_runner = _load_runner() if runner is None else runner
    if not hasattr(
        installed_runner,
        "verify_qualification_from_opaque_snapshot",
    ):
        raise _error("installed_runner_opaque_support_missing")
    try:
        result, exit_code = (
            installed_runner.verify_qualification_from_opaque_snapshot(
                snapshot_root=root,
                source_manifest_path=Path(
                    source_roots["instance_manifest"]
                ),
                source_runtime_root=Path(source_roots["runtime"]),
                source_private_root=Path(
                    source_roots["qualification_private"]
                ),
                source_path_identities=path_identities,
                expected_run_id=run_id,
                expected_instance_slug=instance_slug,
                expected_evidence_uid=expected_evidence_uid,
                snapshot_owner_uid=snapshot_owner_uid,
                verifier_gid=verifier_gid,
                scenarios_path=installed_runner.PERSONA_EVAL.DEFAULT_SCENARIOS,
                rubric_path=installed_runner.PERSONA_EVAL.DEFAULT_RUBRIC,
            )
        )
    except QualificationVerifierError:
        raise
    except Exception as exc:
        raise _error("qualification_opaque_reproduction_failed") from exc
    projection = _attestable_projection(
        installed_runner,
        result,
        exit_code,
        verified_at_unix=verified_at,
    )
    if projection["run_id"] != run_id:
        raise _error("qualification_opaque_run_id_mismatch")
    return {
        **projection,
        "verifier_version": VERIFIER_VERSION,
        "verifier_uid": verifier_uid,
        "verifier_bundle_sha256": bundle_digest,
        "verification_policy_sha256": policy_digest,
        "capture_manifest_sha256": capture_digest,
        "capture_plan_sha256": plan_digest,
        "operator_policy_sha256": operator_digest,
        "claim_strength": CLAIM_STRENGTH,
        "public_reputation_eligible": False,
        "verified_at_unix": verified_at,
        "observed_evidence_uid": manifest["evidence_uid"],
    }


def verify_adopted_opaque_snapshot_evidence(
    *,
    capture_adoption_receipt: Any,
    expected_capture_adoption_receipt_sha256: str,
    expected_capture_uid: int,
    expected_capture_export_gid: int,
    expected_adopted_uid: int,
    expected_capture_session_id: str,
    expected_capture_request_sha256: str,
    expected_capture_boundary_policy_sha256: str,
    expected_capture_helper_activation_policy_sha256: str,
    **verification_arguments: Any,
) -> dict[str, Any]:
    """Require root-adoption evidence before running the opaque verifier."""

    required = {
        "snapshot_root",
        "expected_capture_manifest_sha256",
        "expected_capture_plan_sha256",
        "expected_capture_selection_sha256",
        "expected_evidence_uid",
        "expected_verifier_uid",
        "expected_verifier_gid",
        "verified_at_unix",
    }
    if not required.issubset(verification_arguments):
        raise _error("adopted_opaque_verification_arguments_invalid")
    capture_uid = _integer(
        expected_capture_uid,
        field="adopted_opaque_expected_capture_uid",
        minimum=1,
    )
    capture_export_gid = _integer(
        expected_capture_export_gid,
        field="adopted_opaque_expected_capture_export_gid",
        minimum=1,
    )
    adopted_uid = _integer(
        expected_adopted_uid,
        field="adopted_opaque_expected_adopted_uid",
    )
    evidence_uid = _integer(
        verification_arguments.get("expected_evidence_uid"),
        field="adopted_opaque_expected_evidence_uid",
        minimum=1,
    )
    verifier_uid = _integer(
        verification_arguments["expected_verifier_uid"],
        field="adopted_opaque_expected_verifier_uid",
        minimum=1,
    )
    verifier_gid = _integer(
        verification_arguments["expected_verifier_gid"],
        field="adopted_opaque_expected_verifier_gid",
        minimum=1,
    )
    if adopted_uid != 0:
        raise _error("adopted_opaque_snapshot_owner_not_root")
    if (
        capture_uid in {evidence_uid, verifier_uid}
        or capture_export_gid == verifier_gid
    ):
        raise _error("adopted_opaque_capture_identity_not_separate")
    root = _absolute_path(
        verification_arguments["snapshot_root"],
        field="snapshot_root",
    )
    try:
        adoption_evidence = (
            adoption_binding_contract.verify_adoption_binding(
                capture_adoption_receipt,
                expected_receipt_sha256=(
                    expected_capture_adoption_receipt_sha256
                ),
                snapshot_root=root,
                expected_capture_uid=capture_uid,
                expected_export_gid=capture_export_gid,
                expected_adopted_uid=adopted_uid,
                expected_verifier_uid=verification_arguments[
                    "expected_verifier_uid"
                ],
                expected_verifier_gid=verification_arguments[
                    "expected_verifier_gid"
                ],
                expected_capture_selection_sha256=verification_arguments[
                    "expected_capture_selection_sha256"
                ],
                expected_capture_plan_sha256=verification_arguments[
                    "expected_capture_plan_sha256"
                ],
                expected_capture_manifest_sha256=verification_arguments[
                    "expected_capture_manifest_sha256"
                ],
                expected_request_sha256=(
                    expected_capture_request_sha256
                ),
                expected_capture_boundary_policy_sha256=(
                    expected_capture_boundary_policy_sha256
                ),
                expected_helper_activation_policy_sha256=(
                    expected_capture_helper_activation_policy_sha256
                ),
                expected_session_id=expected_capture_session_id,
                verified_at_unix=verification_arguments[
                    "verified_at_unix"
                ],
            )
        )
    except adoption_binding_contract.CaptureAdoptionBindingError as exc:
        raise _error(exc.code) from exc
    evidence = verify_opaque_snapshot_evidence(
        **verification_arguments,
        snapshot_owner_uid=adopted_uid,
        manifest_capture_uid=capture_uid,
        source_directory_mode=(
            opaque_capture_contract.EXPORT_SOURCE_DIRECTORY_MODE
        ),
        source_file_mode=(
            opaque_capture_contract.EXPORT_SOURCE_FILE_MODE
        ),
    )
    return {**evidence, **adoption_evidence}


def normalize_sealed_request(value: Any) -> dict[str, Any]:
    """Normalize the only request accepted by the installed executable."""

    request = _strict_mapping(
        value,
        field="sealed_request",
        expected=SEALED_REQUEST_FIELDS,
    )
    if request.get("schema_version") != REQUEST_SCHEMA:
        raise _error("sealed_request_schema_unsupported")
    try:
        normalized_selection = (
            capture_selection_contract.normalize_capture_selection(
                request.get("capture_selection")
            )
        )
        observed_selection_sha256 = (
            capture_selection_contract.capture_selection_sha256(
                normalized_selection
            )
        )
    except capture_selection_contract.CaptureSelectionError as exc:
        raise _error(exc.code) from exc
    try:
        normalized_adoption_receipt = (
            adoption_binding_contract.normalize_adoption_receipt(
                request.get("capture_adoption_receipt")
            )
        )
    except adoption_binding_contract.CaptureAdoptionBindingError as exc:
        raise _error(exc.code) from exc
    selection_sha256 = _digest(
        request.get("capture_selection_sha256"),
        field="sealed_request_capture_selection_sha256",
    )
    if observed_selection_sha256 != selection_sha256:
        raise _error("sealed_request_capture_selection_digest_mismatch")
    normalized = {
        "schema_version": REQUEST_SCHEMA,
        "snapshot_root": str(
            _absolute_path(
                request.get("snapshot_root"),
                field="sealed_request_snapshot_root",
            )
        ),
        "capture_manifest_sha256": _digest(
            request.get("capture_manifest_sha256"),
            field="sealed_request_capture_manifest_sha256",
        ),
        "capture_plan_sha256": _digest(
            request.get("capture_plan_sha256"),
            field="sealed_request_capture_plan_sha256",
        ),
        "capture_selection": normalized_selection,
        "capture_selection_sha256": selection_sha256,
        "capture_adoption_receipt": normalized_adoption_receipt,
        "capture_adoption_receipt_sha256": _digest(
            request.get("capture_adoption_receipt_sha256"),
            field="sealed_request_capture_adoption_receipt_sha256",
        ),
        "capture_session_id": _session_id(
            request.get("capture_session_id")
        ),
        "capture_request_sha256": _digest(
            request.get("capture_request_sha256"),
            field="sealed_request_capture_request_sha256",
        ),
        "capture_boundary_policy_sha256": _digest(
            request.get("capture_boundary_policy_sha256"),
            field="sealed_request_capture_boundary_policy_sha256",
        ),
        "capture_helper_activation_policy_sha256": _digest(
            request.get("capture_helper_activation_policy_sha256"),
            field=(
                "sealed_request_"
                "capture_helper_activation_policy_sha256"
            ),
        ),
        "capture_uid": _integer(
            request.get("capture_uid"),
            field="sealed_request_capture_uid",
            minimum=1,
        ),
        "capture_export_gid": _integer(
            request.get("capture_export_gid"),
            field="sealed_request_capture_export_gid",
            minimum=1,
        ),
        "adopted_uid": _integer(
            request.get("adopted_uid"),
            field="sealed_request_adopted_uid",
        ),
        "instance_manifest_path": str(
            _absolute_path(
                request.get("instance_manifest_path"),
                field="sealed_request_instance_manifest_path",
            )
        ),
        "instance_manifest_sha256": _digest(
            request.get("instance_manifest_sha256"),
            field="sealed_request_instance_manifest_sha256",
        ),
        "qualification_private_root": str(
            _absolute_path(
                request.get("qualification_private_root"),
                field="sealed_request_private_root",
            )
        ),
        "qualification_public_root": str(
            _absolute_path(
                request.get("qualification_public_root"),
                field="sealed_request_public_root",
            )
        ),
        "evidence_home_path": str(
            _absolute_path(
                request.get("evidence_home_path"),
                field="sealed_request_evidence_home_path",
            )
        ),
        "checkout_identity_path": str(
            _absolute_path(
                request.get("checkout_identity_path"),
                field="sealed_request_checkout_identity_path",
            )
        ),
        "runtime_identity_path": str(
            _absolute_path(
                request.get("runtime_identity_path"),
                field="sealed_request_runtime_identity_path",
            )
        ),
        "instance_slug": _slug(request.get("instance_slug")),
        "evidence_uid": _integer(
            request.get("evidence_uid"),
            field="sealed_request_evidence_uid",
            minimum=1,
        ),
        "verifier_uid": _integer(
            request.get("verifier_uid"),
            field="sealed_request_verifier_uid",
            minimum=1,
        ),
        "verifier_gid": _integer(
            request.get("verifier_gid"),
            field="sealed_request_verifier_gid",
            minimum=1,
        ),
        "verifier_bundle_sha256": _digest(
            request.get("verifier_bundle_sha256"),
            field="sealed_request_verifier_bundle_sha256",
        ),
        "verification_policy_sha256": _digest(
            request.get("verification_policy_sha256"),
            field="sealed_request_verification_policy_sha256",
        ),
        "operator_policy_sha256": _digest(
            request.get("operator_policy_sha256"),
            field="sealed_request_operator_policy_sha256",
        ),
        "verified_at_unix": _integer(
            request.get("verified_at_unix"),
            field="sealed_request_verified_at_unix",
            minimum=1,
        ),
    }
    if normalized["adopted_uid"] != 0:
        raise _error("sealed_request_adopted_uid_not_root")
    if (
        normalized["capture_uid"]
        in {normalized["evidence_uid"], normalized["verifier_uid"]}
        or normalized["capture_export_gid"] == normalized["verifier_gid"]
    ):
        raise _error("sealed_request_capture_identity_not_separate")
    return normalized


def verify_sealed_request(
    value: Any,
    *,
    process_uid: int | None = None,
    process_gid: int | None = None,
    process_groups: Sequence[int] | None = None,
    runner: Any | None = None,
) -> dict[str, Any]:
    """Verify a strict root-fed request without exposing a path-bearing CLI."""

    request = normalize_sealed_request(value)
    return verify_adopted_opaque_snapshot_evidence(
        snapshot_root=Path(request["snapshot_root"]),
        expected_capture_manifest_sha256=request[
            "capture_manifest_sha256"
        ],
        expected_capture_plan_sha256=request["capture_plan_sha256"],
        capture_selection=request["capture_selection"],
        expected_capture_selection_sha256=request[
            "capture_selection_sha256"
        ],
        capture_adoption_receipt=request[
            "capture_adoption_receipt"
        ],
        expected_capture_adoption_receipt_sha256=request[
            "capture_adoption_receipt_sha256"
        ],
        expected_capture_uid=request["capture_uid"],
        expected_capture_export_gid=request["capture_export_gid"],
        expected_adopted_uid=request["adopted_uid"],
        expected_capture_session_id=request["capture_session_id"],
        expected_capture_request_sha256=request[
            "capture_request_sha256"
        ],
        expected_capture_boundary_policy_sha256=request[
            "capture_boundary_policy_sha256"
        ],
        expected_capture_helper_activation_policy_sha256=request[
            "capture_helper_activation_policy_sha256"
        ],
        instance_manifest=Path(request["instance_manifest_path"]),
        expected_instance_manifest_sha256=request[
            "instance_manifest_sha256"
        ],
        private_root=Path(request["qualification_private_root"]),
        expected_public_root=Path(request["qualification_public_root"]),
        evidence_home=Path(request["evidence_home_path"]),
        checkout_identity=Path(request["checkout_identity_path"]),
        runtime_identity=Path(request["runtime_identity_path"]),
        expected_instance_slug=request["instance_slug"],
        expected_evidence_uid=request["evidence_uid"],
        expected_verifier_uid=request["verifier_uid"],
        expected_verifier_gid=request["verifier_gid"],
        verifier_bundle_sha256=request["verifier_bundle_sha256"],
        verification_policy_sha256=request[
            "verification_policy_sha256"
        ],
        operator_policy_sha256=request["operator_policy_sha256"],
        verified_at_unix=request["verified_at_unix"],
        process_uid=process_uid,
        process_gid=process_gid,
        process_groups=process_groups,
        runner=runner,
    )


def _normalize_adoption_verifier_limits_v5(
    value: Any,
    *,
    field: str = "sealed_request_adoption_verifier_limits",
) -> dict[str, int]:
    """Normalize v5 tree-verification bounds, not adoption-policy evidence."""

    def bounded(
        candidate: Any,
        *,
        value_field: str,
        maximum: int,
    ) -> int:
        observed = _integer(
            candidate,
            field=value_field,
            minimum=1,
        )
        if observed > maximum:
            raise _error(f"{value_field}_invalid")
        return observed

    limits = _strict_mapping(
        value,
        field=field,
        expected=set(adoption_binding_contract.ADOPTION_LIMIT_FIELDS),
    )
    normalized = {
        "max_files": bounded(
            limits.get("max_files"),
            value_field=f"{field}_max_files",
            maximum=adoption_binding_contract.MAX_CAPTURE_FILES,
        ),
        "max_directories": bounded(
            limits.get("max_directories"),
            value_field=f"{field}_max_directories",
            maximum=(
                adoption_binding_contract.MAX_CAPTURE_DIRECTORIES
            ),
        ),
        "max_bytes": bounded(
            limits.get("max_bytes"),
            value_field=f"{field}_max_bytes",
            maximum=adoption_binding_contract.MAX_CAPTURE_BYTES,
        ),
        "max_file_bytes": bounded(
            limits.get("max_file_bytes"),
            value_field=f"{field}_max_file_bytes",
            maximum=adoption_binding_contract.MAX_CAPTURE_FILE_BYTES,
        ),
        "max_depth": bounded(
            limits.get("max_depth"),
            value_field=f"{field}_max_depth",
            maximum=adoption_binding_contract.MAX_CAPTURE_DEPTH,
        ),
    }
    if normalized["max_file_bytes"] > normalized["max_bytes"]:
        raise _error(f"{field}_file_exceeds_total")
    return normalized


def _bind_sealed_request_v5_adoption_result(
    request: Mapping[str, Any],
) -> None:
    """Bind every duplicated result claim to its root-fed request field."""

    result = request["capture_adoption_result"]
    evidence = result["evidence"]
    common_bindings = {
        "capture_adoption_policy_sha256": (
            "capture_adoption_policy_sha256"
        ),
        "capture_selection_sha256": "capture_selection_sha256",
        "capture_plan_sha256": "capture_plan_sha256",
        "capture_manifest_sha256": "capture_manifest_sha256",
        "capture_boundary_policy_sha256": (
            "capture_boundary_policy_sha256"
        ),
        "capture_helper_activation_policy_sha256": (
            "helper_activation_policy_sha256"
        ),
        "capture_uid": "capture_uid",
    }
    if result["kind"] == adoption_result_contract.NORMAL_ADOPTION_KIND:
        bindings = {
            **common_bindings,
            "capture_export_gid": "capture_gid",
            "adopted_uid": "adopted_uid",
            "verifier_uid": "verifier_uid",
            "verifier_gid": "verifier_gid",
            "capture_session_id": "session_id",
            "capture_request_sha256": "request_sha256",
        }
        # Receipt v2 does not carry its policy's concrete limits.  Accepting
        # caller-selected values here would falsely present them as bound
        # adoption facts, so the normal arm uses only the verifier's hard
        # canonical maxima.  The values are never emitted as evidence.
        if (
            request["adoption_verifier_limits"]
            != NORMAL_ADOPTION_VERIFIER_LIMITS
        ):
            raise _error(
                "sealed_request_normal_adoption_verifier_limits_"
                "not_canonical"
            )
    else:
        bindings = {
            **common_bindings,
            "capture_export_gid": "capture_export_gid",
            "adopted_uid": "final_object_owner_uid",
            "verifier_gid": "verifier_gid",
            "capture_session_id": "capture_session_id",
            "capture_request_sha256": "capture_request_sha256",
            "instance_slug": "instance_slug",
            "adoption_verifier_limits": "adoption_limits",
        }
        if evidence["final_object_group_gid"] != request["verifier_gid"]:
            raise _error(
                "sealed_request_capture_adoption_result_"
                "final_object_group_gid_mismatch"
            )
    for request_field, evidence_field in bindings.items():
        if request[request_field] != evidence[evidence_field]:
            raise _error(
                "sealed_request_capture_adoption_result_"
                f"{request_field}_mismatch"
            )
    if Path(request["snapshot_root"]).name != evidence["final_name"]:
        raise _error(
            "sealed_request_capture_adoption_result_snapshot_root_mismatch"
        )


def normalize_sealed_request_v5(value: Any) -> dict[str, Any]:
    """Normalize a dormant result-aware verifier request.

    Unlike request v4, this contract accepts one exact tagged adoption result
    and cannot erase whether it came from the live or crash-recovery path.
    """

    request = _strict_mapping(
        value,
        field="sealed_request_v5",
        expected=set(SEALED_REQUEST_V5_FIELDS),
    )
    if request.get("schema_version") != REQUEST_V5_SCHEMA:
        raise _error("sealed_request_v5_schema_unsupported")
    try:
        normalized_selection = (
            capture_selection_contract.normalize_capture_selection(
                request.get("capture_selection")
            )
        )
        observed_selection_sha256 = (
            capture_selection_contract.capture_selection_sha256(
                normalized_selection
            )
        )
    except capture_selection_contract.CaptureSelectionError as exc:
        raise _error(exc.code) from exc
    try:
        normalized_adoption_result = (
            adoption_result_contract.normalize_capture_adoption_result(
                request.get("capture_adoption_result")
            )
        )
        observed_adoption_result_sha256 = (
            adoption_result_contract.capture_adoption_result_sha256(
                normalized_adoption_result
            )
        )
    except adoption_result_contract.CaptureAdoptionResultError as exc:
        raise _error(exc.code) from exc
    selection_sha256 = _digest(
        request.get("capture_selection_sha256"),
        field="sealed_request_v5_capture_selection_sha256",
    )
    if not hmac.compare_digest(
        observed_selection_sha256,
        selection_sha256,
    ):
        raise _error(
            "sealed_request_v5_capture_selection_digest_mismatch"
        )
    adoption_result_sha256 = _digest(
        request.get("capture_adoption_result_sha256"),
        field="sealed_request_v5_capture_adoption_result_sha256",
    )
    if not hmac.compare_digest(
        observed_adoption_result_sha256,
        adoption_result_sha256,
    ):
        raise _error(
            "sealed_request_v5_capture_adoption_result_digest_mismatch"
        )
    normalized = {
        "schema_version": REQUEST_V5_SCHEMA,
        "snapshot_root": str(
            _absolute_path(
                request.get("snapshot_root"),
                field="sealed_request_v5_snapshot_root",
            )
        ),
        "capture_manifest_sha256": _digest(
            request.get("capture_manifest_sha256"),
            field="sealed_request_v5_capture_manifest_sha256",
        ),
        "capture_plan_sha256": _digest(
            request.get("capture_plan_sha256"),
            field="sealed_request_v5_capture_plan_sha256",
        ),
        "capture_selection": normalized_selection,
        "capture_selection_sha256": selection_sha256,
        "capture_adoption_result": normalized_adoption_result,
        "capture_adoption_result_sha256": adoption_result_sha256,
        "capture_adoption_policy_sha256": _digest(
            request.get("capture_adoption_policy_sha256"),
            field=(
                "sealed_request_v5_"
                "capture_adoption_policy_sha256"
            ),
        ),
        "adoption_verifier_limits": (
            _normalize_adoption_verifier_limits_v5(
                request.get("adoption_verifier_limits")
            )
        ),
        "capture_session_id": _session_id(
            request.get("capture_session_id")
        ),
        "capture_request_sha256": _digest(
            request.get("capture_request_sha256"),
            field="sealed_request_v5_capture_request_sha256",
        ),
        "capture_boundary_policy_sha256": _digest(
            request.get("capture_boundary_policy_sha256"),
            field=(
                "sealed_request_v5_"
                "capture_boundary_policy_sha256"
            ),
        ),
        "capture_helper_activation_policy_sha256": _digest(
            request.get("capture_helper_activation_policy_sha256"),
            field=(
                "sealed_request_v5_"
                "capture_helper_activation_policy_sha256"
            ),
        ),
        "capture_uid": _integer(
            request.get("capture_uid"),
            field="sealed_request_v5_capture_uid",
            minimum=1,
        ),
        "capture_export_gid": _integer(
            request.get("capture_export_gid"),
            field="sealed_request_v5_capture_export_gid",
            minimum=1,
        ),
        "adopted_uid": _integer(
            request.get("adopted_uid"),
            field="sealed_request_v5_adopted_uid",
        ),
        "instance_manifest_path": str(
            _absolute_path(
                request.get("instance_manifest_path"),
                field="sealed_request_v5_instance_manifest_path",
            )
        ),
        "instance_manifest_sha256": _digest(
            request.get("instance_manifest_sha256"),
            field="sealed_request_v5_instance_manifest_sha256",
        ),
        "qualification_private_root": str(
            _absolute_path(
                request.get("qualification_private_root"),
                field="sealed_request_v5_private_root",
            )
        ),
        "qualification_public_root": str(
            _absolute_path(
                request.get("qualification_public_root"),
                field="sealed_request_v5_public_root",
            )
        ),
        "evidence_home_path": str(
            _absolute_path(
                request.get("evidence_home_path"),
                field="sealed_request_v5_evidence_home_path",
            )
        ),
        "checkout_identity_path": str(
            _absolute_path(
                request.get("checkout_identity_path"),
                field="sealed_request_v5_checkout_identity_path",
            )
        ),
        "runtime_identity_path": str(
            _absolute_path(
                request.get("runtime_identity_path"),
                field="sealed_request_v5_runtime_identity_path",
            )
        ),
        "expected_run_id": _run_id(
            request.get("expected_run_id")
        ),
        "instance_slug": _slug(request.get("instance_slug")),
        "evidence_uid": _integer(
            request.get("evidence_uid"),
            field="sealed_request_v5_evidence_uid",
            minimum=1,
        ),
        "verifier_uid": _integer(
            request.get("verifier_uid"),
            field="sealed_request_v5_verifier_uid",
            minimum=1,
        ),
        "verifier_gid": _integer(
            request.get("verifier_gid"),
            field="sealed_request_v5_verifier_gid",
            minimum=1,
        ),
        "verifier_bundle_sha256": _digest(
            request.get("verifier_bundle_sha256"),
            field="sealed_request_v5_verifier_bundle_sha256",
        ),
        "verification_policy_sha256": _digest(
            request.get("verification_policy_sha256"),
            field="sealed_request_v5_verification_policy_sha256",
        ),
        "operator_policy_sha256": _digest(
            request.get("operator_policy_sha256"),
            field="sealed_request_v5_operator_policy_sha256",
        ),
        "verified_at_unix": _integer(
            request.get("verified_at_unix"),
            field="sealed_request_v5_verified_at_unix",
            minimum=1,
        ),
    }
    if normalized["adopted_uid"] != 0:
        raise _error("sealed_request_v5_adopted_uid_not_root")
    if (
        normalized["capture_uid"]
        in {normalized["evidence_uid"], normalized["verifier_uid"]}
        or normalized["capture_export_gid"] == normalized["verifier_gid"]
    ):
        raise _error(
            "sealed_request_v5_capture_identity_not_separate"
        )
    if normalized["evidence_uid"] == normalized["verifier_uid"]:
        raise _error(
            "sealed_request_v5_verifier_identity_not_separate"
        )
    bound_selection = _bound_capture_selection(
        normalized["capture_selection"],
        expected_capture_selection_sha256=(
            normalized["capture_selection_sha256"]
        ),
        instance_manifest=Path(normalized["instance_manifest_path"]),
        private_root=Path(normalized["qualification_private_root"]),
        expected_public_root=Path(
            normalized["qualification_public_root"]
        ),
        evidence_home=Path(normalized["evidence_home_path"]),
        checkout_identity=Path(normalized["checkout_identity_path"]),
        runtime_identity=Path(normalized["runtime_identity_path"]),
    )
    if (
        bound_selection["instance_slug"] != normalized["instance_slug"]
        or bound_selection["evidence_uid"] != normalized["evidence_uid"]
        or bound_selection["verifier_gid"] != normalized["verifier_gid"]
    ):
        raise _error(
            "sealed_request_v5_capture_selection_identity_mismatch"
        )
    _bind_sealed_request_v5_adoption_result(normalized)
    return normalized


def verify_adopted_opaque_snapshot_result(
    *,
    capture_adoption_result: Any,
    expected_capture_adoption_result_sha256: str,
    expected_capture_adoption_policy_sha256: str,
    expected_adoption_verifier_limits: Mapping[str, Any],
    expected_capture_uid: int,
    expected_capture_export_gid: int,
    expected_adopted_uid: int,
    expected_capture_session_id: str,
    expected_capture_request_sha256: str,
    expected_capture_boundary_policy_sha256: str,
    expected_capture_helper_activation_policy_sha256: str,
    **verification_arguments: Any,
) -> dict[str, Any]:
    """Verify a tagged adoption result, then reproduce its opaque snapshot."""

    required = {
        "snapshot_root",
        "expected_capture_manifest_sha256",
        "expected_capture_plan_sha256",
        "expected_capture_selection_sha256",
        "expected_instance_slug",
        "expected_evidence_uid",
        "expected_verifier_uid",
        "expected_verifier_gid",
        "expected_run_id",
        "verified_at_unix",
    }
    if not required.issubset(verification_arguments):
        raise _error(
            "adopted_opaque_result_verification_arguments_invalid"
        )
    try:
        normalized_adoption_result = (
            adoption_result_contract.normalize_capture_adoption_result(
                capture_adoption_result
            )
        )
    except adoption_result_contract.CaptureAdoptionResultError as exc:
        raise _error(exc.code) from exc
    verifier_limits = _normalize_adoption_verifier_limits_v5(
        expected_adoption_verifier_limits,
        field="adopted_opaque_result_adoption_verifier_limits",
    )
    if (
        normalized_adoption_result["kind"]
        == adoption_result_contract.NORMAL_ADOPTION_KIND
        and verifier_limits != NORMAL_ADOPTION_VERIFIER_LIMITS
    ):
        raise _error(
            "adopted_opaque_result_normal_adoption_verifier_limits_"
            "not_canonical"
        )
    capture_uid = _integer(
        expected_capture_uid,
        field="adopted_opaque_result_expected_capture_uid",
        minimum=1,
    )
    capture_export_gid = _integer(
        expected_capture_export_gid,
        field="adopted_opaque_result_expected_capture_export_gid",
        minimum=1,
    )
    adopted_uid = _integer(
        expected_adopted_uid,
        field="adopted_opaque_result_expected_adopted_uid",
    )
    evidence_uid = _integer(
        verification_arguments.get("expected_evidence_uid"),
        field="adopted_opaque_result_expected_evidence_uid",
        minimum=1,
    )
    verifier_uid = _integer(
        verification_arguments["expected_verifier_uid"],
        field="adopted_opaque_result_expected_verifier_uid",
        minimum=1,
    )
    verifier_gid = _integer(
        verification_arguments["expected_verifier_gid"],
        field="adopted_opaque_result_expected_verifier_gid",
        minimum=1,
    )
    if adopted_uid != 0:
        raise _error("adopted_opaque_result_snapshot_owner_not_root")
    if (
        capture_uid in {evidence_uid, verifier_uid}
        or evidence_uid == verifier_uid
        or capture_export_gid == verifier_gid
    ):
        raise _error(
            "adopted_opaque_result_identity_not_separate"
        )
    root = _absolute_path(
        verification_arguments["snapshot_root"],
        field="snapshot_root",
    )
    try:
        adoption_evidence = (
            adoption_binding_contract.verify_capture_adoption_result(
                normalized_adoption_result,
                expected_result_sha256=(
                    expected_capture_adoption_result_sha256
                ),
                snapshot_root=root,
                expected_instance_slug=verification_arguments[
                    "expected_instance_slug"
                ],
                expected_capture_uid=capture_uid,
                expected_export_gid=capture_export_gid,
                expected_adopted_uid=adopted_uid,
                expected_verifier_uid=verifier_uid,
                expected_verifier_gid=verifier_gid,
                expected_capture_adoption_policy_sha256=(
                    expected_capture_adoption_policy_sha256
                ),
                expected_capture_selection_sha256=(
                    verification_arguments[
                        "expected_capture_selection_sha256"
                    ]
                ),
                expected_capture_plan_sha256=(
                    verification_arguments[
                        "expected_capture_plan_sha256"
                    ]
                ),
                expected_capture_manifest_sha256=(
                    verification_arguments[
                        "expected_capture_manifest_sha256"
                    ]
                ),
                expected_request_sha256=(
                    expected_capture_request_sha256
                ),
                expected_capture_boundary_policy_sha256=(
                    expected_capture_boundary_policy_sha256
                ),
                expected_helper_activation_policy_sha256=(
                    expected_capture_helper_activation_policy_sha256
                ),
                expected_session_id=expected_capture_session_id,
                expected_adoption_limits=(
                    verifier_limits
                ),
                verified_at_unix=verification_arguments[
                    "verified_at_unix"
                ],
            )
        )
    except adoption_binding_contract.CaptureAdoptionBindingError as exc:
        raise _error(exc.code) from exc
    if set(adoption_evidence) != V5_ADOPTION_EVIDENCE_FIELDS:
        raise _error("adopted_opaque_result_evidence_fields_invalid")
    opaque_evidence = verify_opaque_snapshot_evidence(
        **verification_arguments,
        snapshot_owner_uid=adopted_uid,
        manifest_capture_uid=capture_uid,
        source_directory_mode=(
            opaque_capture_contract.EXPORT_SOURCE_DIRECTORY_MODE
        ),
        source_file_mode=(
            opaque_capture_contract.EXPORT_SOURCE_FILE_MODE
        ),
    )
    overlap = set(opaque_evidence) & V5_ADOPTION_EVIDENCE_FIELDS
    if overlap:
        raise _error("adopted_opaque_result_evidence_collision")
    result = dict(opaque_evidence)
    result["verifier_version"] = VERIFIER_V5_VERSION
    result.update(adoption_evidence)
    return result


def verify_sealed_request_v5(
    value: Any,
    *,
    process_uid: int | None = None,
    process_gid: int | None = None,
    process_groups: Sequence[int] | None = None,
    runner: Any | None = None,
) -> dict[str, Any]:
    """Verify the dormant v5 request without changing executable dispatch."""

    request = normalize_sealed_request_v5(value)
    return verify_adopted_opaque_snapshot_result(
        snapshot_root=Path(request["snapshot_root"]),
        expected_capture_manifest_sha256=request[
            "capture_manifest_sha256"
        ],
        expected_capture_plan_sha256=request["capture_plan_sha256"],
        capture_selection=request["capture_selection"],
        expected_capture_selection_sha256=request[
            "capture_selection_sha256"
        ],
        capture_adoption_result=request["capture_adoption_result"],
        expected_capture_adoption_result_sha256=request[
            "capture_adoption_result_sha256"
        ],
        expected_capture_adoption_policy_sha256=request[
            "capture_adoption_policy_sha256"
        ],
        expected_adoption_verifier_limits=request[
            "adoption_verifier_limits"
        ],
        expected_capture_uid=request["capture_uid"],
        expected_capture_export_gid=request["capture_export_gid"],
        expected_adopted_uid=request["adopted_uid"],
        expected_capture_session_id=request["capture_session_id"],
        expected_capture_request_sha256=request[
            "capture_request_sha256"
        ],
        expected_capture_boundary_policy_sha256=request[
            "capture_boundary_policy_sha256"
        ],
        expected_capture_helper_activation_policy_sha256=request[
            "capture_helper_activation_policy_sha256"
        ],
        instance_manifest=Path(request["instance_manifest_path"]),
        expected_instance_manifest_sha256=request[
            "instance_manifest_sha256"
        ],
        private_root=Path(request["qualification_private_root"]),
        expected_public_root=Path(request["qualification_public_root"]),
        evidence_home=Path(request["evidence_home_path"]),
        checkout_identity=Path(request["checkout_identity_path"]),
        runtime_identity=Path(request["runtime_identity_path"]),
        expected_instance_slug=request["instance_slug"],
        expected_evidence_uid=request["evidence_uid"],
        expected_verifier_uid=request["verifier_uid"],
        expected_verifier_gid=request["verifier_gid"],
        expected_run_id=request["expected_run_id"],
        verifier_bundle_sha256=request["verifier_bundle_sha256"],
        verification_policy_sha256=request[
            "verification_policy_sha256"
        ],
        operator_policy_sha256=request["operator_policy_sha256"],
        verified_at_unix=request["verified_at_unix"],
        process_uid=process_uid,
        process_gid=process_gid,
        process_groups=process_groups,
        runner=runner,
    )


def _read_request_stdin() -> Any:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if not raw or len(raw) > MAX_REQUEST_BYTES:
        raise _error("sealed_request_size_invalid")
    return _parse_json(raw, field="sealed_request")


def main(argv: Sequence[str] | None = None) -> int:
    try:
        if list(sys.argv[1:] if argv is None else argv):
            raise _error("command_arguments_unsupported")
        deny_same_uid_debugging()
        assert_privilege_confinement()
        result = verify_sealed_request(_read_request_stdin())
    except QualificationVerifierError as exc:
        print(
            json.dumps(
                {
                    "schema_version": OUTPUT_SCHEMA,
                    "status": "invalid",
                    "reason": exc.code,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2
    print(
        json.dumps(
            {
                "schema_version": OUTPUT_SCHEMA,
                "status": "verified",
                "evidence": result,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
