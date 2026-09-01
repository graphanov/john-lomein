#!/usr/bin/env python3
"""Fail-closed Ed25519 attestation for persona qualification evidence.

The public command intentionally accepts no payload, output, or key paths.
Those paths belong to root-owned, installer-generated control material.  The
signed v5 payload binds a sealed-capture digest, installed verifier/policy
digests, an explicit local-conformance claim, and a monotonic hash chain.

The zero-argument repository command remains fail-closed.  Production
activation depends on an installer-provisioned, hermetic attestor, capture,
verifier, and signer boundary; this repository script is not itself a
privileged entrypoint.  The signature, archive reconciliation, rollback
rejection, and atomic publication primitives remain independently testable.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import errno
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from qualification_attestor import (
    john_lomein_persona_qualification_adoption_binding as adoption_binding,
)
from qualification_attestor import (
    john_lomein_persona_qualification_adoption_result as adoption_result,
)
from qualification_attestor import (
    john_lomein_persona_qualification_source_revalidation_binding
    as source_revalidation_binding,
)


CONFIG_SCHEMA_VERSION = 1
HISTORICAL_PAYLOAD_SCHEMA_VERSION = 4
PAYLOAD_SCHEMA_VERSION = 5
FUTURE_PAYLOAD_SCHEMA_VERSION = 6
SUPPORTED_PAYLOAD_SCHEMA_VERSIONS = frozenset(
    {
        HISTORICAL_PAYLOAD_SCHEMA_VERSION,
        PAYLOAD_SCHEMA_VERSION,
        FUTURE_PAYLOAD_SCHEMA_VERSION,
    }
)
V6_PRODUCTION_ACTIVATION = False
ENVELOPE_SCHEMA_VERSION = 1
HEAD_SCHEMA_VERSION = 2

PURPOSE = "john-lomein-persona-qualification-attestation"
SCOPE = "persona-qualification"
ALGORITHM = "Ed25519"
EVIDENCE_CLASS = "private-raw-public-aggregate"
VERIFICATION_RESULT = "verified"
CLAIM_STRENGTH = "operator_verified_local_conformance"

DEFAULT_CONFIG_PATH = Path(
    (
        "/private/etc/john-lomein/"
        "persona-qualification-attestor.json"
        if sys.platform == "darwin"
        else "/etc/john-lomein/"
        "persona-qualification-attestor.json"
    )
)

MAX_JSON_BYTES = 2_000_000
MAX_KEY_BYTES = 64 * 1024
MAX_VERIFIER_ARTIFACT_BYTES = 20_000_000
MAX_VERIFIER_BUNDLE_FILES = 20_000
MAX_VERIFIER_BUNDLE_DIRECTORIES = 20_000
MAX_VERIFIER_BUNDLE_ENTRIES = 40_000
MAX_VERIFIER_BUNDLE_DEPTH = 64
MAX_VERIFIER_BUNDLE_BYTES = 1_000_000_000
MAX_ATTESTATION_ARCHIVE_FILES = 1_024
MAX_ATTESTATION_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_INTERRUPTED_PUBLICATION_FILES = 64
MAX_AUTHORITY_METADATA_BYTES = 64 * 1024
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_VERIFIER_TIMEOUT_SECONDS = 3_600
INSTALLATION_OWNER_UID = 0

INSTALLED_BINDING_SCHEMA_VERSION = 3
VERIFIER_BUNDLE_MANIFEST_SCHEMA_VERSION = 2
VERIFIER_OUTPUT_SCHEMA = "john-lomein.persona.operator-verification.v3"
VERIFIER_OUTPUT_V4_SCHEMA = (
    "john-lomein.persona.operator-verification.v4"
)
VERIFIER_REQUEST_V5_SCHEMA = (
    "john-lomein.persona.operator-verifier-request.v5"
)
VERIFIER_V5_VERSION = "john-lomein.persona.operator-verifier.v5"
OPERATOR_POLICY_SCHEMA = "john-lomein.persona-qualification-operator-policy.v3"
FUTURE_OPERATOR_POLICY_SCHEMA = (
    "john-lomein.persona-qualification-operator-policy.v4"
)
VERIFICATION_EXECUTION_POLICY_SCHEMA = (
    "john-lomein.persona-qualification-verification-execution-policy.v5"
)
VERIFICATION_EXECUTION_POLICY_V6_SCHEMA = (
    "john-lomein.persona-qualification-verification-execution-policy.v6"
)
VERIFICATION_EXECUTION_POLICY = {
    "schema_version": VERIFICATION_EXECUTION_POLICY_SCHEMA,
    "argv": ["pinned-python", "-I", "-S", "-B", "pinned-entrypoint"],
    "request_transport": "bounded-root-stdin",
    "environment": ["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR", "TZ"],
    "python_hash_randomization": "isolated-runtime-default",
    "bundle_inventory": "complete-declared-root-owned-files",
    "native_dependency_closure": "not-claimed-by-repository-primitive",
    "activation_state": "disabled-pending-protected-installer-canary",
    "working_directory": "root-owned-bundle",
    "close_inherited_fds": True,
    "separate_verifier_uid": True,
    "supplementary_groups_cleared": True,
    "real_effective_saved_ids_equal": True,
    "linux_capability_bounding_set_empty": True,
    "linux_no_new_privs": True,
    "same_uid_debugging_denied": True,
    "network_credentials_present": False,
    "signing_key_opened_after_child": True,
    "sealed_capture_revalidated_after_child": True,
    "live_sources_revalidated_before_child_relinquish": True,
    "post_verifier_live_source_revalidation": True,
    "post_verifier_live_source_revalidation_receipt_schema": (
        source_revalidation_binding.SOURCE_REVALIDATION_RECEIPT_SCHEMA
    ),
    "post_verifier_live_source_revalidation_order": [
        "verifier_process_reaped",
        "verifier_output_canonicalized_and_adoption_bound",
        "live_sources_revalidated_against_adopted_manifest",
        "private_key_opened",
    ],
    "capture_adoption_receipt_required": True,
    "capture_creator_identity_bound": True,
    "adopted_snapshot_owner_uid": 0,
    "adoption_tree_reobserved_by_verifier": True,
    "child_stdout_max_bytes": 1_000_000,
    "child_stderr_max_bytes": 1_000_000,
    "address_space_max_bytes": 2_147_483_648,
    "file_size_max_bytes": 1_000_000,
    "open_files_max": 64,
    "processes_max": 16,
}
FUTURE_CAPTURE_ADOPTION_PERMITTED_KINDS = [
    adoption_result.NORMAL_ADOPTION_KIND,
    adoption_result.RECOVERED_ADOPTION_KIND,
]
VERIFICATION_EXECUTION_POLICY_V6 = {
    "schema_version": VERIFICATION_EXECUTION_POLICY_V6_SCHEMA,
    "argv": ["pinned-python", "-I", "-S", "-B", "pinned-entrypoint"],
    "request_transport": "bounded-root-stdin",
    "verifier_request_schema": VERIFIER_REQUEST_V5_SCHEMA,
    "verifier_output_schema": VERIFIER_OUTPUT_V4_SCHEMA,
    "environment": ["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR", "TZ"],
    "python_hash_randomization": "isolated-runtime-default",
    "bundle_inventory": "complete-declared-root-owned-files",
    "native_dependency_closure": "not-claimed-by-repository-primitive",
    "activation_state": "disabled-pending-protected-installer-canary",
    "working_directory": "root-owned-bundle",
    "close_inherited_fds": True,
    "separate_verifier_uid": True,
    "supplementary_groups_cleared": True,
    "real_effective_saved_ids_equal": True,
    "linux_capability_bounding_set_empty": True,
    "linux_no_new_privs": True,
    "same_uid_debugging_denied": True,
    "network_credentials_present": False,
    "signing_key_opened_after_child": True,
    "sealed_capture_revalidated_after_child": True,
    "live_sources_revalidated_before_child_relinquish": True,
    "post_verifier_live_source_revalidation": True,
    "post_verifier_live_source_revalidation_receipt_schema": (
        source_revalidation_binding.SOURCE_REVALIDATION_RECEIPT_V2_SCHEMA
    ),
    "post_verifier_live_source_revalidation_order": [
        "verifier_process_reaped",
        "verifier_output_canonicalized_and_adoption_bound",
        "live_sources_revalidated_against_adopted_manifest",
        "private_key_opened",
    ],
    "capture_adoption_result_required": True,
    "capture_adoption_result_schema": (
        adoption_result.CAPTURE_ADOPTION_RESULT_SCHEMA
    ),
    "capture_adoption_provenance_schema": (
        adoption_result.CAPTURE_ADOPTION_PROVENANCE_SCHEMA
    ),
    "capture_adoption_permitted_kinds": list(
        FUTURE_CAPTURE_ADOPTION_PERMITTED_KINDS
    ),
    "recovered_outer_ack_clearance_required": True,
    "pre_post_descriptor_binding_equality_required": True,
    "capture_creator_identity_bound": True,
    "adopted_snapshot_owner_uid": 0,
    "adoption_tree_reobserved_by_verifier": True,
    "child_stdout_journal_safe": True,
    "child_stdout_max_bytes": 48 * 1024,
    "child_stderr_max_bytes": 1_000_000,
    "address_space_max_bytes": 2_147_483_648,
    "file_size_max_bytes": 1_000_000,
    "open_files_max": 64,
    "processes_max": 16,
}

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,127}$")
SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
INTERRUPTED_PUBLICATION_RE = re.compile(
    r"^\.(?P<target>.+\.json)\.[0-9a-f]{32}\.tmp$"
)

CONFIG_FIELDS = {
    "schema_version",
    "instance_slug",
    "qualification_public_root",
    "qualification_private_root",
    "expected_evidence_uid",
    "attestor_key_id",
    "private_key_path",
    "public_key_path",
    "public_key_sha256",
    "head_path",
}

INSTALLED_VERIFIER_BINDING_FIELDS = {
    "schema_version",
    "instance_manifest_path",
    "instance_manifest_sha256",
    "capture_uid",
    "capture_export_gid",
    "verifier_uid",
    "verifier_gid",
    "verifier_python_path",
    "verifier_python_sha256",
    "verifier_bundle_root",
    "verifier_manifest_path",
    "verifier_manifest_sha256",
    "verifier_entrypoint_path",
    "verifier_version",
    "verifier_timeout_seconds",
    "capture_parent_path",
    "evidence_home_path",
    "runtime_identity_path",
    "checkout_identity_path",
}


class QualificationAttestorError(ValueError):
    """A stable, public-safe attestor rejection."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _error(code: str) -> QualificationAttestorError:
    return QualificationAttestorError(code)


def _validate_canonical_value(value: Any) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if isinstance(value, bool) or abs(value) > MAX_SAFE_INTEGER:
            raise _error("canonical_json_integer_invalid")
        return
    if isinstance(value, list):
        for item in value:
            _validate_canonical_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _error("canonical_json_key_invalid")
            _validate_canonical_value(item)
        return
    raise _error("canonical_json_type_invalid")


def canonical_json(value: Any) -> bytes:
    """Return the only byte representation accepted for signatures."""

    _validate_canonical_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _error("duplicate_json_field")
        result[key] = value
    return result


def _reject_nonfinite(_: str) -> None:
    raise _error("nonfinite_json_number")


def parse_json_bytes(
    raw: bytes,
    *,
    field: str,
    maximum_bytes: int = MAX_JSON_BYTES,
) -> Any:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum_bytes:
        raise _error(f"{field}_size_invalid")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except QualificationAttestorError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _error(f"{field}_json_invalid") from exc
    _validate_canonical_value(value)
    return value


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _error(f"{field}_not_object")
    return value


def _strict_fields(
    value: Mapping[str, Any], *, field: str, expected: set[str]
) -> None:
    if set(value) != expected:
        raise _error(f"{field}_fields_invalid")


def _integer(value: Any, *, field: str, minimum: int = 0) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > MAX_SAFE_INTEGER
    ):
        raise _error(f"{field}_invalid")
    return value


def _token(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise _error(f"{field}_invalid")
    return value


def _slug(value: Any, *, field: str = "instance_slug") -> str:
    if not isinstance(value, str) or not SLUG_RE.fullmatch(value):
        raise _error(f"{field}_invalid")
    return value


def _digest(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise _error(f"{field}_invalid")
    return value


def _absolute_path(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or len(value) > 4096:
        raise _error(f"{field}_invalid")
    path = Path(value)
    if (
        not path.is_absolute()
        or "\x00" in value
        or "." in path.parts
        or ".." in path.parts
        or value != str(path)
    ):
        raise _error(f"{field}_invalid")
    return value


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _lexically_overlaps(left: Path, right: Path) -> bool:
    left_text = unicodedata.normalize("NFC", str(left).rstrip(os.sep)).casefold()
    right_text = unicodedata.normalize("NFC", str(right).rstrip(os.sep)).casefold()
    return (
        left_text == right_text
        or left_text.startswith(right_text + os.sep)
        or right_text.startswith(left_text + os.sep)
    )


def _same_lexical_path(left: Path, right: Path) -> bool:
    return (
        unicodedata.normalize("NFC", str(left)).casefold()
        == unicodedata.normalize("NFC", str(right)).casefold()
    )


def _publication_namespace_paths(head: Path) -> tuple[Path, Path]:
    return (
        head.parent / "attestations",
        head.parent / f".{head.name}.lock",
    )


def _inside_publication_namespace(path: Path, *, head: Path) -> bool:
    archive, lock = _publication_namespace_paths(head)
    if _lexically_overlaps(path, archive) or _lexically_overlaps(path, lock):
        return True
    if not _same_lexical_path(path.parent, head.parent):
        return False
    normalized_name = unicodedata.normalize("NFC", path.name).casefold()
    normalized_prefix = unicodedata.normalize(
        "NFC", f".{head.name}."
    ).casefold()
    return normalized_name.startswith(normalized_prefix) and normalized_name.endswith(
        ".tmp"
    )


def _fd_xattrs(descriptor: int, *, field: str) -> set[bytes]:
    """Enumerate xattrs natively even when Python omits ``os.listxattr``."""

    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        if not hasattr(libc, "flistxattr"):
            raise _error(f"{field}_fd_metadata_unsupported")
        libc.flistxattr.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
        ]
        libc.flistxattr.restype = ctypes.c_ssize_t
        size = libc.flistxattr(descriptor, None, 0, 0)
    elif sys.platform.startswith("linux"):
        if not hasattr(libc, "flistxattr"):
            raise _error(f"{field}_fd_metadata_unsupported")
        libc.flistxattr.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        libc.flistxattr.restype = ctypes.c_ssize_t
        size = libc.flistxattr(descriptor, None, 0)
    else:
        raise _error(f"{field}_fd_metadata_unsupported")
    if size < 0:
        observed_errno = ctypes.get_errno()
        raise _error(f"{field}_metadata_unreadable") from OSError(
            observed_errno,
            os.strerror(observed_errno),
        )
    if size > MAX_AUTHORITY_METADATA_BYTES:
        raise _error(f"{field}_metadata_too_large")
    if size == 0:
        return set()
    buffer = ctypes.create_string_buffer(size)
    if sys.platform == "darwin":
        observed = libc.flistxattr(descriptor, buffer, size, 0)
    else:
        observed = libc.flistxattr(descriptor, buffer, size)
    if observed != size:
        raise _error(f"{field}_metadata_changed")
    return {
        name
        for name in bytes(buffer.raw[:observed]).split(b"\x00")
        if name
    }


def _permitted_non_authorizing_xattrs() -> frozenset[bytes]:
    if sys.platform == "darwin":
        # SIP/rootless and provenance annotations do not grant DAC access or
        # influence JSON/key parsing. Other Apple metadata remains rejected.
        return frozenset(
            {
                b"com.apple.provenance",
                b"com.apple.rootless",
            }
        )
    if sys.platform.startswith("linux"):
        # SELinux is an additional mandatory-access-control label: ordinary
        # access must still pass the checked Unix DAC permissions. POSIX ACL,
        # file-capability, and arbitrary user attributes remain rejected.
        return frozenset({b"security.selinux"})
    return frozenset()


def _reject_acl_or_xattrs(path: Path, *, field: str) -> None:
    """Reject metadata that can grant authority beyond checked mode bits."""

    if not hasattr(os, "O_NOFOLLOW"):
        raise _error(f"{field}_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _error(f"{field}_metadata_unreadable") from exc
    try:
        attributes = _fd_xattrs(descriptor, field=field)
        if not attributes.issubset(_permitted_non_authorizing_xattrs()):
            raise _error(f"{field}_extended_metadata_unsupported")
        if sys.platform != "darwin":
            return
        libc = ctypes.CDLL(None, use_errno=True)
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
    finally:
        os.close(descriptor)


def normalize_config(value: Any) -> dict[str, Any]:
    """Normalize the strict root-owned v1 configuration body."""

    config = _mapping(value, field="config")
    _strict_fields(config, field="config", expected=CONFIG_FIELDS)
    if type(config.get("schema_version")) is not int or config.get("schema_version") != CONFIG_SCHEMA_VERSION:
        raise _error("config_schema_unsupported")

    public_root = Path(
        _absolute_path(
            config.get("qualification_public_root"),
            field="qualification_public_root",
        )
    )
    private_root = Path(
        _absolute_path(
            config.get("qualification_private_root"),
            field="qualification_private_root",
        )
    )
    private_key = Path(
        _absolute_path(config.get("private_key_path"), field="private_key_path")
    )
    public_key = Path(
        _absolute_path(config.get("public_key_path"), field="public_key_path")
    )
    head = Path(_absolute_path(config.get("head_path"), field="head_path"))

    if _lexically_overlaps(public_root, private_root):
        raise _error("qualification_roots_overlap")
    control_paths = (private_key, public_key, head)
    control_path_keys = {
        unicodedata.normalize("NFC", str(path)).casefold()
        for path in control_paths
    }
    if len(control_path_keys) != len(control_paths):
        raise _error("attestor_control_paths_overlap")
    for protected in (private_key, public_key, head):
        if _lexically_overlaps(protected, public_root) or _lexically_overlaps(
            protected, private_root
        ):
            raise _error("attestor_control_path_inside_evidence_root")
    for configured_path in (
        public_root,
        private_root,
        private_key,
        public_key,
        head,
    ):
        if _inside_publication_namespace(configured_path, head=head):
            raise _error("attestor_publication_namespace_overlap")

    return {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "instance_slug": _slug(config.get("instance_slug")),
        "qualification_public_root": str(public_root),
        "qualification_private_root": str(private_root),
        "expected_evidence_uid": _integer(
            config.get("expected_evidence_uid"),
            field="expected_evidence_uid",
            minimum=1,
        ),
        "attestor_key_id": _token(
            config.get("attestor_key_id"), field="attestor_key_id"
        ),
        "private_key_path": str(private_key),
        "public_key_path": str(public_key),
        "public_key_sha256": _digest(
            config.get("public_key_sha256"), field="public_key_sha256"
        ),
        "head_path": str(head),
    }


def normalize_installed_verifier_binding(
    value: Any,
    *,
    config: Any,
) -> dict[str, Any]:
    """Normalize the root-generated, per-instance verifier binding."""

    normalized_config = normalize_config(config)
    binding = _mapping(value, field="installed_verifier_binding")
    _strict_fields(
        binding,
        field="installed_verifier_binding",
        expected=INSTALLED_VERIFIER_BINDING_FIELDS,
    )
    if (
        type(binding.get("schema_version")) is not int
        or binding.get("schema_version") != INSTALLED_BINDING_SCHEMA_VERSION
    ):
        raise _error("installed_verifier_binding_schema_unsupported")

    instance_manifest = Path(
        _absolute_path(
            binding.get("instance_manifest_path"),
            field="instance_manifest_path",
        )
    )
    python_path = Path(
        _absolute_path(
            binding.get("verifier_python_path"),
            field="verifier_python_path",
        )
    )
    bundle_root = Path(
        _absolute_path(
            binding.get("verifier_bundle_root"),
            field="verifier_bundle_root",
        )
    )
    manifest_path = Path(
        _absolute_path(
            binding.get("verifier_manifest_path"),
            field="verifier_manifest_path",
        )
    )
    entrypoint = Path(
        _absolute_path(
            binding.get("verifier_entrypoint_path"),
            field="verifier_entrypoint_path",
        )
    )
    capture_parent = Path(
        _absolute_path(
            binding.get("capture_parent_path"),
            field="capture_parent_path",
        )
    )
    evidence_home = Path(
        _absolute_path(
            binding.get("evidence_home_path"),
            field="evidence_home_path",
        )
    )
    runtime_identity = Path(
        _absolute_path(
            binding.get("runtime_identity_path"),
            field="runtime_identity_path",
        )
    )
    checkout_identity = Path(
        _absolute_path(
            binding.get("checkout_identity_path"),
            field="checkout_identity_path",
        )
    )
    if _lexically_overlaps(runtime_identity, checkout_identity):
        raise _error("runtime_checkout_identity_overlap")
    if not _within(entrypoint, bundle_root) or entrypoint == bundle_root:
        raise _error("verifier_entrypoint_outside_bundle")
    if not _within(python_path, bundle_root) or python_path == bundle_root:
        raise _error("verifier_python_outside_bundle")
    if _within(manifest_path, bundle_root):
        raise _error("verifier_manifest_inside_bundle")

    public_root = Path(normalized_config["qualification_public_root"])
    private_root = Path(normalized_config["qualification_private_root"])
    head = Path(normalized_config["head_path"])
    all_binding_paths = (
        instance_manifest,
        python_path,
        bundle_root,
        manifest_path,
        entrypoint,
        capture_parent,
        evidence_home,
        runtime_identity,
        checkout_identity,
    )
    for control in all_binding_paths:
        if _inside_publication_namespace(control, head=head):
            raise _error("verifier_control_inside_publication_namespace")
    for control in (
        python_path,
        bundle_root,
        manifest_path,
        entrypoint,
        capture_parent,
    ):
        if _lexically_overlaps(control, public_root) or _lexically_overlaps(
            control, private_root
        ):
            raise _error("verifier_control_path_inside_evidence_root")
    for attestor_control in (
        Path(normalized_config["private_key_path"]),
        Path(normalized_config["public_key_path"]),
        Path(normalized_config["head_path"]),
    ):
        if _lexically_overlaps(capture_parent, attestor_control):
            raise _error("capture_parent_overlaps_attestor_control")
    if any(
        _lexically_overlaps(capture_parent, immutable_control)
        for immutable_control in (
            python_path,
            bundle_root,
            manifest_path,
            entrypoint,
            instance_manifest,
            evidence_home,
            runtime_identity,
            checkout_identity,
        )
    ):
        raise _error("capture_parent_overlaps_verifier_control")
    control_keys = {
        unicodedata.normalize("NFC", str(path)).casefold()
        for path in (
            python_path,
            bundle_root,
            manifest_path,
            entrypoint,
            capture_parent,
            evidence_home,
            runtime_identity,
            checkout_identity,
        )
    }
    if len(control_keys) != 8:
        raise _error("verifier_control_paths_overlap")

    verifier_uid = _integer(
        binding.get("verifier_uid"),
        field="verifier_uid",
        minimum=1,
    )
    if verifier_uid == normalized_config["expected_evidence_uid"]:
        raise _error("verifier_uid_not_separate")
    verifier_gid = _integer(
        binding.get("verifier_gid"),
        field="verifier_gid",
        minimum=1,
    )
    capture_uid = _integer(
        binding.get("capture_uid"),
        field="capture_uid",
        minimum=1,
    )
    capture_export_gid = _integer(
        binding.get("capture_export_gid"),
        field="capture_export_gid",
        minimum=1,
    )
    if len(
        {
            normalized_config["expected_evidence_uid"],
            capture_uid,
            verifier_uid,
        }
    ) != 3:
        raise _error("capture_uid_not_separate")
    if capture_export_gid == verifier_gid:
        raise _error("capture_export_group_not_separate")

    timeout = _integer(
        binding.get("verifier_timeout_seconds"),
        field="verifier_timeout_seconds",
        minimum=1,
    )
    if timeout > MAX_VERIFIER_TIMEOUT_SECONDS:
        raise _error("verifier_timeout_seconds_invalid")
    return {
        "schema_version": INSTALLED_BINDING_SCHEMA_VERSION,
        "instance_manifest_path": str(instance_manifest),
        "instance_manifest_sha256": _digest(
            binding.get("instance_manifest_sha256"),
            field="instance_manifest_sha256",
        ),
        "capture_uid": capture_uid,
        "capture_export_gid": capture_export_gid,
        "verifier_uid": verifier_uid,
        "verifier_gid": verifier_gid,
        "verifier_python_path": str(python_path),
        "verifier_python_sha256": _digest(
            binding.get("verifier_python_sha256"),
            field="verifier_python_sha256",
        ),
        "verifier_bundle_root": str(bundle_root),
        "verifier_manifest_path": str(manifest_path),
        "verifier_manifest_sha256": _digest(
            binding.get("verifier_manifest_sha256"),
            field="verifier_manifest_sha256",
        ),
        "verifier_entrypoint_path": str(entrypoint),
        "verifier_version": _token(
            binding.get("verifier_version"),
            field="verifier_version",
        ),
        "verifier_timeout_seconds": timeout,
        "capture_parent_path": str(capture_parent),
        "evidence_home_path": str(evidence_home),
        "runtime_identity_path": str(runtime_identity),
        "checkout_identity_path": str(checkout_identity),
    }


VERIFIER_EVIDENCE_FIELDS = {
    "run_id",
    "summary_sha256",
    "binding_sha256",
    "status",
    "qualified_at_unix",
    "expires_at_unix",
    "verifier_version",
    "verifier_uid",
    "verifier_bundle_sha256",
    "verification_policy_sha256",
    "capture_manifest_sha256",
    "capture_plan_sha256",
    "operator_policy_sha256",
    "claim_strength",
    "public_reputation_eligible",
    "verified_at_unix",
    "observed_evidence_uid",
    *adoption_binding.ADOPTION_EVIDENCE_FIELDS,
}


def normalize_verifier_evidence(
    value: Any, *, expected_evidence_uid: int
) -> dict[str, Any]:
    """Normalize only the evidence emitted by the independent verifier."""

    evidence = _mapping(value, field="verified_evidence")
    _strict_fields(
        evidence,
        field="verified_evidence",
        expected=VERIFIER_EVIDENCE_FIELDS,
    )
    run_id = evidence.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise _error("verified_evidence_run_id_invalid")
    if evidence.get("status") != "qualified":
        raise _error("verified_evidence_not_qualified")
    if evidence.get("claim_strength") != CLAIM_STRENGTH:
        raise _error("verified_evidence_claim_strength_invalid")
    if evidence.get("public_reputation_eligible") is not False:
        raise _error("verified_evidence_reputation_claim_invalid")
    qualified = _integer(
        evidence.get("qualified_at_unix"),
        field="verified_evidence_qualified_at_unix",
    )
    expires = _integer(
        evidence.get("expires_at_unix"),
        field="verified_evidence_expires_at_unix",
    )
    verified = _integer(
        evidence.get("verified_at_unix"),
        field="verified_evidence_verified_at_unix",
    )
    observed_uid = _integer(
        evidence.get("observed_evidence_uid"),
        field="verified_evidence_observed_evidence_uid",
        minimum=1,
    )
    verifier_uid = _integer(
        evidence.get("verifier_uid"),
        field="verified_evidence_verifier_uid",
        minimum=1,
    )
    capture_creator_uid = _integer(
        evidence.get("capture_creator_uid"),
        field="verified_evidence_capture_creator_uid",
        minimum=1,
    )
    capture_export_gid = _integer(
        evidence.get("capture_export_gid"),
        field="verified_evidence_capture_export_gid",
        minimum=1,
    )
    capture_adopted_uid = _integer(
        evidence.get("capture_adopted_uid"),
        field="verified_evidence_capture_adopted_uid",
    )
    capture_adopted_at = _integer(
        evidence.get("capture_adopted_at_unix"),
        field="verified_evidence_capture_adopted_at_unix",
        minimum=1,
    )
    if observed_uid != expected_evidence_uid:
        raise _error("verification_evidence_uid_mismatch")
    if verifier_uid == expected_evidence_uid:
        raise _error("verification_identity_not_separate")
    if (
        capture_creator_uid in {expected_evidence_uid, verifier_uid}
        or capture_adopted_uid != 0
        or capture_adopted_at > verified
    ):
        raise _error("verification_capture_adoption_identity_invalid")
    if not qualified <= verified < expires:
        raise _error("verification_timing_invalid")
    return {
        "run_id": run_id,
        "summary_sha256": _digest(
            evidence.get("summary_sha256"),
            field="verified_evidence_summary_sha256",
        ),
        "binding_sha256": _digest(
            evidence.get("binding_sha256"),
            field="verified_evidence_binding_sha256",
        ),
        "status": "qualified",
        "qualified_at_unix": qualified,
        "expires_at_unix": expires,
        "verifier_version": _token(
            evidence.get("verifier_version"),
            field="verified_evidence_verifier_version",
        ),
        "verifier_uid": verifier_uid,
        "verifier_bundle_sha256": _digest(
            evidence.get("verifier_bundle_sha256"),
            field="verified_evidence_verifier_bundle_sha256",
        ),
        "verification_policy_sha256": _digest(
            evidence.get("verification_policy_sha256"),
            field="verified_evidence_verification_policy_sha256",
        ),
        "capture_manifest_sha256": _digest(
            evidence.get("capture_manifest_sha256"),
            field="verified_evidence_capture_manifest_sha256",
        ),
        "capture_plan_sha256": _digest(
            evidence.get("capture_plan_sha256"),
            field="verified_evidence_capture_plan_sha256",
        ),
        "operator_policy_sha256": _digest(
            evidence.get("operator_policy_sha256"),
            field="verified_evidence_operator_policy_sha256",
        ),
        "claim_strength": CLAIM_STRENGTH,
        "public_reputation_eligible": False,
        "verified_at_unix": verified,
        "observed_evidence_uid": observed_uid,
        "capture_creator_uid": capture_creator_uid,
        "capture_export_gid": capture_export_gid,
        "capture_adopted_uid": 0,
        "capture_adoption_receipt_sha256": _digest(
            evidence.get("capture_adoption_receipt_sha256"),
            field="verified_evidence_capture_adoption_receipt_sha256",
        ),
        "capture_adoption_policy_sha256": _digest(
            evidence.get("capture_adoption_policy_sha256"),
            field="verified_evidence_capture_adoption_policy_sha256",
        ),
        "capture_object_identity_sha256": _digest(
            evidence.get("capture_object_identity_sha256"),
            field="verified_evidence_capture_object_identity_sha256",
        ),
        "capture_content_inventory_sha256": _digest(
            evidence.get("capture_content_inventory_sha256"),
            field="verified_evidence_capture_content_inventory_sha256",
        ),
        "capture_adopted_at_unix": capture_adopted_at,
        "capture_request_sha256": _digest(
            evidence.get("capture_request_sha256"),
            field="verified_evidence_capture_request_sha256",
        ),
        "capture_boundary_policy_sha256": _digest(
            evidence.get("capture_boundary_policy_sha256"),
            field="verified_evidence_capture_boundary_policy_sha256",
        ),
        "capture_helper_activation_policy_sha256": _digest(
            evidence.get("capture_helper_activation_policy_sha256"),
            field=(
                "verified_evidence_"
                "capture_helper_activation_policy_sha256"
            ),
        ),
    }


VERIFIER_EVIDENCE_V4_FIELDS = (
    (
        VERIFIER_EVIDENCE_FIELDS
        - adoption_binding.ADOPTION_EVIDENCE_FIELDS
    )
    | adoption_binding.CAPTURE_ADOPTION_RESULT_EVIDENCE_FIELDS
)


def normalize_verifier_evidence_v4(
    value: Any,
    *,
    expected_evidence_uid: int,
) -> dict[str, Any]:
    """Normalize result-aware verifier output without erasing its kind."""

    evidence = _mapping(value, field="verified_evidence_v4")
    _strict_fields(
        evidence,
        field="verified_evidence_v4",
        expected=VERIFIER_EVIDENCE_V4_FIELDS,
    )
    run_id = evidence.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise _error("verified_evidence_v4_run_id_invalid")
    if evidence.get("status") != "qualified":
        raise _error("verified_evidence_v4_not_qualified")
    if evidence.get("claim_strength") != CLAIM_STRENGTH:
        raise _error("verified_evidence_v4_claim_strength_invalid")
    if evidence.get("public_reputation_eligible") is not False:
        raise _error(
            "verified_evidence_v4_reputation_claim_invalid"
        )
    qualified = _integer(
        evidence.get("qualified_at_unix"),
        field="verified_evidence_v4_qualified_at_unix",
    )
    expires = _integer(
        evidence.get("expires_at_unix"),
        field="verified_evidence_v4_expires_at_unix",
    )
    verified = _integer(
        evidence.get("verified_at_unix"),
        field="verified_evidence_v4_verified_at_unix",
    )
    observed_uid = _integer(
        evidence.get("observed_evidence_uid"),
        field="verified_evidence_v4_observed_evidence_uid",
        minimum=1,
    )
    verifier_uid = _integer(
        evidence.get("verifier_uid"),
        field="verified_evidence_v4_verifier_uid",
        minimum=1,
    )
    capture_creator_uid = _integer(
        evidence.get("capture_creator_uid"),
        field="verified_evidence_v4_capture_creator_uid",
        minimum=1,
    )
    capture_export_gid = _integer(
        evidence.get("capture_export_gid"),
        field="verified_evidence_v4_capture_export_gid",
        minimum=1,
    )
    capture_adopted_uid = _integer(
        evidence.get("capture_adopted_uid"),
        field="verified_evidence_v4_capture_adopted_uid",
    )
    if observed_uid != expected_evidence_uid:
        raise _error("verification_evidence_v4_uid_mismatch")
    if verifier_uid == expected_evidence_uid:
        raise _error("verification_v4_identity_not_separate")
    if (
        capture_creator_uid in {expected_evidence_uid, verifier_uid}
        or capture_adopted_uid != 0
    ):
        raise _error(
            "verification_v4_capture_adoption_identity_invalid"
        )
    if not qualified <= verified < expires:
        raise _error("verification_v4_timing_invalid")
    try:
        provenance = (
            adoption_result.normalize_capture_adoption_provenance(
                evidence.get("capture_adoption_provenance")
            )
        )
        observed_provenance_sha256 = (
            adoption_result.capture_adoption_provenance_sha256(
                provenance
            )
        )
    except adoption_result.CaptureAdoptionResultError as exc:
        raise _error(
            "verified_evidence_v4_adoption_provenance_invalid"
        ) from exc
    claimed_provenance_sha256 = _digest(
        evidence.get("capture_adoption_provenance_sha256"),
        field=(
            "verified_evidence_v4_"
            "capture_adoption_provenance_sha256"
        ),
    )
    if not hmac.compare_digest(
        observed_provenance_sha256,
        claimed_provenance_sha256,
    ):
        raise _error(
            "verified_evidence_v4_adoption_provenance_digest_mismatch"
        )
    if (
        provenance["kind"] == adoption_result.NORMAL_ADOPTION_KIND
        and provenance["details"]["adopted_at_unix"] > verified
    ):
        raise _error(
            "verification_v4_capture_adoption_time_invalid"
        )
    return {
        "run_id": run_id,
        "summary_sha256": _digest(
            evidence.get("summary_sha256"),
            field="verified_evidence_v4_summary_sha256",
        ),
        "binding_sha256": _digest(
            evidence.get("binding_sha256"),
            field="verified_evidence_v4_binding_sha256",
        ),
        "status": "qualified",
        "qualified_at_unix": qualified,
        "expires_at_unix": expires,
        "verifier_version": _token(
            evidence.get("verifier_version"),
            field="verified_evidence_v4_verifier_version",
        ),
        "verifier_uid": verifier_uid,
        "verifier_bundle_sha256": _digest(
            evidence.get("verifier_bundle_sha256"),
            field="verified_evidence_v4_verifier_bundle_sha256",
        ),
        "verification_policy_sha256": _digest(
            evidence.get("verification_policy_sha256"),
            field="verified_evidence_v4_verification_policy_sha256",
        ),
        "capture_manifest_sha256": _digest(
            evidence.get("capture_manifest_sha256"),
            field="verified_evidence_v4_capture_manifest_sha256",
        ),
        "capture_plan_sha256": _digest(
            evidence.get("capture_plan_sha256"),
            field="verified_evidence_v4_capture_plan_sha256",
        ),
        "operator_policy_sha256": _digest(
            evidence.get("operator_policy_sha256"),
            field="verified_evidence_v4_operator_policy_sha256",
        ),
        "claim_strength": CLAIM_STRENGTH,
        "public_reputation_eligible": False,
        "verified_at_unix": verified,
        "observed_evidence_uid": observed_uid,
        "capture_creator_uid": capture_creator_uid,
        "capture_export_gid": capture_export_gid,
        "capture_adopted_uid": 0,
        "capture_adoption_policy_sha256": _digest(
            evidence.get("capture_adoption_policy_sha256"),
            field=(
                "verified_evidence_v4_"
                "capture_adoption_policy_sha256"
            ),
        ),
        "capture_object_identity_sha256": _digest(
            evidence.get("capture_object_identity_sha256"),
            field=(
                "verified_evidence_v4_"
                "capture_object_identity_sha256"
            ),
        ),
        "capture_content_inventory_sha256": _digest(
            evidence.get("capture_content_inventory_sha256"),
            field=(
                "verified_evidence_v4_"
                "capture_content_inventory_sha256"
            ),
        ),
        "capture_request_sha256": _digest(
            evidence.get("capture_request_sha256"),
            field="verified_evidence_v4_capture_request_sha256",
        ),
        "capture_boundary_policy_sha256": _digest(
            evidence.get("capture_boundary_policy_sha256"),
            field=(
                "verified_evidence_v4_"
                "capture_boundary_policy_sha256"
            ),
        ),
        "capture_helper_activation_policy_sha256": _digest(
            evidence.get(
                "capture_helper_activation_policy_sha256"
            ),
            field=(
                "verified_evidence_v4_"
                "capture_helper_activation_policy_sha256"
            ),
        ),
        "capture_adoption_provenance": provenance,
        "capture_adoption_provenance_sha256": (
            observed_provenance_sha256
        ),
    }


VERIFIED_EVIDENCE_FIELDS = (
    VERIFIER_EVIDENCE_FIELDS
    | source_revalidation_binding.SOURCE_REVALIDATION_EVIDENCE_FIELDS
)
EQUIVALENT_RECAPTURE_VARIANT_FIELDS = frozenset(
    {
        "capture_manifest_sha256",
        "capture_adoption_receipt_sha256",
        "capture_adoption_policy_sha256",
        "capture_object_identity_sha256",
        "capture_content_inventory_sha256",
        "capture_adopted_at_unix",
        "capture_request_sha256",
        "verified_at_unix",
        "post_verifier_live_source_revalidation_receipt",
        "post_verifier_live_source_revalidation_receipt_sha256",
    }
)


def normalize_verified_evidence(
    value: Any, *, expected_evidence_uid: int
) -> dict[str, Any]:
    """Normalize final signable evidence, including the root receipt."""

    evidence = _mapping(value, field="verified_evidence")
    _strict_fields(
        evidence,
        field="verified_evidence",
        expected=VERIFIED_EVIDENCE_FIELDS,
    )
    verifier_evidence = normalize_verifier_evidence(
        {
            field: evidence[field]
            for field in VERIFIER_EVIDENCE_FIELDS
        },
        expected_evidence_uid=expected_evidence_uid,
    )
    receipt_value = evidence[
        "post_verifier_live_source_revalidation_receipt"
    ]
    try:
        receipt = (
            source_revalidation_binding.normalize_source_revalidation_receipt(
                receipt_value
            )
        )
        bound_receipt = (
            source_revalidation_binding.bind_source_revalidation_receipt(
                receipt,
                expected_receipt_sha256=evidence[
                    "post_verifier_live_source_"
                    "revalidation_receipt_sha256"
                ],
                expected_capture_adoption_receipt_sha256=(
                    verifier_evidence[
                        "capture_adoption_receipt_sha256"
                    ]
                ),
                expected_capture_object_identity_sha256=(
                    verifier_evidence[
                        "capture_object_identity_sha256"
                    ]
                ),
                expected_capture_plan_sha256=verifier_evidence[
                    "capture_plan_sha256"
                ],
                expected_capture_manifest_sha256=verifier_evidence[
                    "capture_manifest_sha256"
                ],
                # The orchestrator binds this field to its independently
                # computed canonical stdout digest before constructing final
                # evidence.  A published payload preserves that exact value,
                # but intentionally does not preserve raw verifier stdout.
                expected_verifier_output_sha256=receipt[
                    "verifier_output_sha256"
                ],
                verified_at_unix=verifier_evidence[
                    "verified_at_unix"
                ],
                expires_at_unix=verifier_evidence[
                    "expires_at_unix"
                ],
            )
        )
    except (
        source_revalidation_binding.SourceRevalidationBindingError
    ) as exc:
        raise _error(exc.code) from exc
    return {**verifier_evidence, **bound_receipt}


VERIFIED_EVIDENCE_V6_FIELDS = (
    VERIFIER_EVIDENCE_V4_FIELDS
    | source_revalidation_binding.SOURCE_REVALIDATION_EVIDENCE_FIELDS
)
EQUIVALENT_RECAPTURE_V6_VARIANT_FIELDS = frozenset(
    {
        "capture_manifest_sha256",
        "capture_adoption_policy_sha256",
        "capture_object_identity_sha256",
        "capture_content_inventory_sha256",
        "capture_request_sha256",
        "capture_adoption_provenance",
        "capture_adoption_provenance_sha256",
        "verified_at_unix",
        "post_verifier_live_source_revalidation_receipt",
        "post_verifier_live_source_revalidation_receipt_sha256",
    }
)


def normalize_verified_evidence_v6(
    value: Any,
    *,
    expected_evidence_uid: int,
) -> dict[str, Any]:
    """Normalize dormant v6 evidence with a provenance-aware root receipt."""

    evidence = _mapping(value, field="verified_evidence_v6")
    _strict_fields(
        evidence,
        field="verified_evidence_v6",
        expected=VERIFIED_EVIDENCE_V6_FIELDS,
    )
    verifier_evidence = normalize_verifier_evidence_v4(
        {
            field: evidence[field]
            for field in VERIFIER_EVIDENCE_V4_FIELDS
        },
        expected_evidence_uid=expected_evidence_uid,
    )
    receipt_value = evidence[
        "post_verifier_live_source_revalidation_receipt"
    ]
    try:
        receipt = (
            source_revalidation_binding
            .normalize_source_revalidation_receipt_v2(
                receipt_value
            )
        )
        bound_receipt = (
            source_revalidation_binding
            .bind_source_revalidation_receipt_v2(
                receipt,
                expected_receipt_sha256=evidence[
                    "post_verifier_live_source_"
                    "revalidation_receipt_sha256"
                ],
                expected_capture_adoption_provenance=(
                    verifier_evidence[
                        "capture_adoption_provenance"
                    ]
                ),
                expected_capture_adoption_provenance_sha256=(
                    verifier_evidence[
                        "capture_adoption_provenance_sha256"
                    ]
                ),
                expected_capture_object_identity_sha256=(
                    verifier_evidence[
                        "capture_object_identity_sha256"
                    ]
                ),
                expected_capture_plan_sha256=verifier_evidence[
                    "capture_plan_sha256"
                ],
                expected_capture_manifest_sha256=verifier_evidence[
                    "capture_manifest_sha256"
                ],
                # The future orchestrator must bind this to canonical child
                # stdout before constructing v6 evidence.  As in v5, raw
                # stdout is deliberately not copied into the payload.
                expected_verifier_output_sha256=receipt[
                    "verifier_output_sha256"
                ],
                verified_at_unix=verifier_evidence[
                    "verified_at_unix"
                ],
                expires_at_unix=verifier_evidence[
                    "expires_at_unix"
                ],
            )
        )
    except (
        source_revalidation_binding.SourceRevalidationBindingError
    ) as exc:
        raise _error(exc.code) from exc
    return {**verifier_evidence, **bound_receipt}


def equivalent_verified_evidence_recapture_v6(
    left: Any,
    right: Any,
    *,
    expected_evidence_uid: int,
) -> bool:
    """Compare same-kind v6 recaptures without collapsing provenance kinds."""

    normalized_left = normalize_verified_evidence_v6(
        left,
        expected_evidence_uid=expected_evidence_uid,
    )
    normalized_right = normalize_verified_evidence_v6(
        right,
        expected_evidence_uid=expected_evidence_uid,
    )
    left_kind = normalized_left[
        "capture_adoption_provenance"
    ]["kind"]
    right_kind = normalized_right[
        "capture_adoption_provenance"
    ]["kind"]
    if left_kind != right_kind:
        return False
    return all(
        normalized_left[field] == normalized_right[field]
        for field in (
            VERIFIED_EVIDENCE_V6_FIELDS
            - EQUIVALENT_RECAPTURE_V6_VARIANT_FIELDS
        )
    )


def equivalent_verified_evidence_recapture(
    left: Any,
    right: Any,
    *,
    expected_evidence_uid: int,
) -> bool:
    """Compare signable evidence under the explicit recapture exception."""

    normalized_left = normalize_verified_evidence(
        left,
        expected_evidence_uid=expected_evidence_uid,
    )
    normalized_right = normalize_verified_evidence(
        right,
        expected_evidence_uid=expected_evidence_uid,
    )
    return all(
        normalized_left[field] == normalized_right[field]
        for field in (
            VERIFIED_EVIDENCE_FIELDS
            - EQUIVALENT_RECAPTURE_VARIANT_FIELDS
        )
    )


def public_key_fingerprint(public_key_bytes: bytes) -> str:
    _load_public_key(public_key_bytes)
    return sha256_bytes(public_key_bytes)


def build_attestation_payload(
    config: Any,
    verified_evidence: Any,
    *,
    public_key_bytes: bytes,
    chain_sequence: int,
    previous_attestation_sha256: str | None,
) -> dict[str, Any]:
    """Derive the exact payload from pinned config and verified evidence."""

    normalized_config = normalize_config(config)
    evidence = normalize_verified_evidence(
        verified_evidence,
        expected_evidence_uid=normalized_config["expected_evidence_uid"],
    )
    fingerprint = public_key_fingerprint(public_key_bytes)
    if not hmac.compare_digest(
        fingerprint, normalized_config["public_key_sha256"]
    ):
        raise _error("configured_public_key_fingerprint_mismatch")
    sequence = _integer(
        chain_sequence,
        field="attestation_chain_sequence",
        minimum=1,
    )
    if sequence == 1:
        if previous_attestation_sha256 is not None:
            raise _error("attestation_chain_genesis_previous_invalid")
        previous_digest = None
    else:
        previous_digest = _digest(
            previous_attestation_sha256,
            field="previous_attestation_sha256",
        )
    return normalize_payload(
        {
            "schema_version": PAYLOAD_SCHEMA_VERSION,
            "purpose": PURPOSE,
            "scope": SCOPE,
            "attestor": {
                "key_id": normalized_config["attestor_key_id"],
                "algorithm": ALGORITHM,
                "public_key_sha256": fingerprint,
            },
            "instance": {"slug": normalized_config["instance_slug"]},
            "chain": {
                "sequence": sequence,
                "previous_attestation_sha256": previous_digest,
            },
            "qualification": {
                "run_id": evidence["run_id"],
                "summary_sha256": evidence["summary_sha256"],
                "binding_sha256": evidence["binding_sha256"],
                "status": "qualified",
                "qualified_at_unix": evidence["qualified_at_unix"],
                "expires_at_unix": evidence["expires_at_unix"],
                "evidence_class": EVIDENCE_CLASS,
            },
            "verification": {
                "verifier_version": evidence["verifier_version"],
                "verifier_uid": evidence["verifier_uid"],
                "verifier_bundle_sha256": evidence[
                    "verifier_bundle_sha256"
                ],
                "verification_policy_sha256": evidence[
                    "verification_policy_sha256"
                ],
                "capture_manifest_sha256": evidence[
                    "capture_manifest_sha256"
                ],
                "capture_plan_sha256": evidence[
                    "capture_plan_sha256"
                ],
                "operator_policy_sha256": evidence[
                    "operator_policy_sha256"
                ],
                "claim_strength": CLAIM_STRENGTH,
                "public_reputation_eligible": False,
                "verified_at_unix": evidence["verified_at_unix"],
                "expected_evidence_uid": normalized_config[
                    "expected_evidence_uid"
                ],
                "observed_evidence_uid": evidence["observed_evidence_uid"],
                "capture_creator_uid": evidence["capture_creator_uid"],
                "capture_export_gid": evidence["capture_export_gid"],
                "capture_adopted_uid": evidence["capture_adopted_uid"],
                "capture_adoption_receipt_sha256": evidence[
                    "capture_adoption_receipt_sha256"
                ],
                "capture_adoption_policy_sha256": evidence[
                    "capture_adoption_policy_sha256"
                ],
                "capture_object_identity_sha256": evidence[
                    "capture_object_identity_sha256"
                ],
                "capture_content_inventory_sha256": evidence[
                    "capture_content_inventory_sha256"
                ],
                "capture_adopted_at_unix": evidence[
                    "capture_adopted_at_unix"
                ],
                "capture_request_sha256": evidence[
                    "capture_request_sha256"
                ],
                "capture_boundary_policy_sha256": evidence[
                    "capture_boundary_policy_sha256"
                ],
                "capture_helper_activation_policy_sha256": evidence[
                    "capture_helper_activation_policy_sha256"
                ],
                "post_verifier_live_source_revalidation_receipt": (
                    evidence[
                        "post_verifier_live_source_"
                        "revalidation_receipt"
                    ]
                ),
                "post_verifier_live_source_revalidation_receipt_sha256": (
                    evidence[
                        "post_verifier_live_source_"
                        "revalidation_receipt_sha256"
                    ]
                ),
                "result": VERIFICATION_RESULT,
            },
        },
        require_current=True,
    )


def build_attestation_payload_v6(
    config: Any,
    verified_evidence: Any,
    *,
    public_key_bytes: bytes,
    chain_sequence: int,
    previous_attestation_sha256: str | None,
) -> dict[str, Any]:
    """Build an offline-only provenance-aware payload.

    The production signer deliberately rejects this future schema until the
    installed verifier, orchestrator, journal, and public-verifier route have
    migrated together.
    """

    normalized_config = normalize_config(config)
    evidence = normalize_verified_evidence_v6(
        verified_evidence,
        expected_evidence_uid=normalized_config[
            "expected_evidence_uid"
        ],
    )
    fingerprint = public_key_fingerprint(public_key_bytes)
    if not hmac.compare_digest(
        fingerprint, normalized_config["public_key_sha256"]
    ):
        raise _error("configured_public_key_fingerprint_mismatch")
    sequence = _integer(
        chain_sequence,
        field="attestation_chain_sequence",
        minimum=1,
    )
    if sequence == 1:
        if previous_attestation_sha256 is not None:
            raise _error(
                "attestation_chain_genesis_previous_invalid"
            )
        previous_digest = None
    else:
        previous_digest = _digest(
            previous_attestation_sha256,
            field="previous_attestation_sha256",
        )
    return normalize_payload(
        {
            "schema_version": FUTURE_PAYLOAD_SCHEMA_VERSION,
            "purpose": PURPOSE,
            "scope": SCOPE,
            "attestor": {
                "key_id": normalized_config["attestor_key_id"],
                "algorithm": ALGORITHM,
                "public_key_sha256": fingerprint,
            },
            "instance": {"slug": normalized_config["instance_slug"]},
            "chain": {
                "sequence": sequence,
                "previous_attestation_sha256": previous_digest,
            },
            "qualification": {
                "run_id": evidence["run_id"],
                "summary_sha256": evidence["summary_sha256"],
                "binding_sha256": evidence["binding_sha256"],
                "status": "qualified",
                "qualified_at_unix": evidence["qualified_at_unix"],
                "expires_at_unix": evidence["expires_at_unix"],
                "evidence_class": EVIDENCE_CLASS,
            },
            "verification": {
                "verifier_version": evidence["verifier_version"],
                "verifier_uid": evidence["verifier_uid"],
                "verifier_bundle_sha256": evidence[
                    "verifier_bundle_sha256"
                ],
                "verification_policy_sha256": evidence[
                    "verification_policy_sha256"
                ],
                "capture_manifest_sha256": evidence[
                    "capture_manifest_sha256"
                ],
                "capture_plan_sha256": evidence[
                    "capture_plan_sha256"
                ],
                "operator_policy_sha256": evidence[
                    "operator_policy_sha256"
                ],
                "claim_strength": CLAIM_STRENGTH,
                "public_reputation_eligible": False,
                "verified_at_unix": evidence["verified_at_unix"],
                "expected_evidence_uid": normalized_config[
                    "expected_evidence_uid"
                ],
                "observed_evidence_uid": evidence[
                    "observed_evidence_uid"
                ],
                "capture_creator_uid": evidence[
                    "capture_creator_uid"
                ],
                "capture_export_gid": evidence["capture_export_gid"],
                "capture_adopted_uid": evidence[
                    "capture_adopted_uid"
                ],
                "capture_adoption_policy_sha256": evidence[
                    "capture_adoption_policy_sha256"
                ],
                "capture_object_identity_sha256": evidence[
                    "capture_object_identity_sha256"
                ],
                "capture_content_inventory_sha256": evidence[
                    "capture_content_inventory_sha256"
                ],
                "capture_request_sha256": evidence[
                    "capture_request_sha256"
                ],
                "capture_boundary_policy_sha256": evidence[
                    "capture_boundary_policy_sha256"
                ],
                "capture_helper_activation_policy_sha256": evidence[
                    "capture_helper_activation_policy_sha256"
                ],
                "capture_adoption_provenance": evidence[
                    "capture_adoption_provenance"
                ],
                "capture_adoption_provenance_sha256": evidence[
                    "capture_adoption_provenance_sha256"
                ],
                "post_verifier_live_source_revalidation_receipt": (
                    evidence[
                        "post_verifier_live_source_"
                        "revalidation_receipt"
                    ]
                ),
                "post_verifier_live_source_revalidation_receipt_sha256": (
                    evidence[
                        "post_verifier_live_source_"
                        "revalidation_receipt_sha256"
                    ]
                ),
                "result": VERIFICATION_RESULT,
            },
        }
    )


def _verified_evidence_from_payload(
    value: Any,
    *,
    expected_evidence_uid: int,
) -> dict[str, Any]:
    """Recover the exact normalized verifier evidence bound by a payload."""

    payload = normalize_payload(value)
    qualification = payload["qualification"]
    verification = payload["verification"]
    if verification["expected_evidence_uid"] != expected_evidence_uid:
        raise _error("configured_evidence_uid_mismatch")
    if payload["schema_version"] == FUTURE_PAYLOAD_SCHEMA_VERSION:
        qualification_fields = frozenset(
            {
                "run_id",
                "summary_sha256",
                "binding_sha256",
                "status",
                "qualified_at_unix",
                "expires_at_unix",
            }
        )
        return normalize_verified_evidence_v6(
            {
                **{
                    field: qualification[field]
                    for field in qualification_fields
                },
                **{
                    field: verification[field]
                    for field in (
                        VERIFIER_EVIDENCE_V4_FIELDS
                        - qualification_fields
                    )
                },
                "post_verifier_live_source_revalidation_receipt": (
                    verification[
                        "post_verifier_live_source_"
                        "revalidation_receipt"
                    ]
                ),
                "post_verifier_live_source_revalidation_receipt_sha256": (
                    verification[
                        "post_verifier_live_source_"
                        "revalidation_receipt_sha256"
                    ]
                ),
            },
            expected_evidence_uid=expected_evidence_uid,
        )
    verifier_evidence = normalize_verifier_evidence(
        {
            "run_id": qualification["run_id"],
            "summary_sha256": qualification["summary_sha256"],
            "binding_sha256": qualification["binding_sha256"],
            "status": qualification["status"],
            "qualified_at_unix": qualification["qualified_at_unix"],
            "expires_at_unix": qualification["expires_at_unix"],
            "verifier_version": verification["verifier_version"],
            "verifier_uid": verification["verifier_uid"],
            "verifier_bundle_sha256": verification[
                "verifier_bundle_sha256"
            ],
            "verification_policy_sha256": verification[
                "verification_policy_sha256"
            ],
            "capture_manifest_sha256": verification[
                "capture_manifest_sha256"
            ],
            "capture_plan_sha256": verification[
                "capture_plan_sha256"
            ],
            "operator_policy_sha256": verification[
                "operator_policy_sha256"
            ],
            "claim_strength": verification["claim_strength"],
            "public_reputation_eligible": verification[
                "public_reputation_eligible"
            ],
            "verified_at_unix": verification["verified_at_unix"],
            "observed_evidence_uid": verification[
                "observed_evidence_uid"
            ],
            "capture_creator_uid": verification[
                "capture_creator_uid"
            ],
            "capture_export_gid": verification["capture_export_gid"],
            "capture_adopted_uid": verification[
                "capture_adopted_uid"
            ],
            "capture_adoption_receipt_sha256": verification[
                "capture_adoption_receipt_sha256"
            ],
            "capture_adoption_policy_sha256": verification[
                "capture_adoption_policy_sha256"
            ],
            "capture_object_identity_sha256": verification[
                "capture_object_identity_sha256"
            ],
            "capture_content_inventory_sha256": verification[
                "capture_content_inventory_sha256"
            ],
            "capture_adopted_at_unix": verification[
                "capture_adopted_at_unix"
            ],
            "capture_request_sha256": verification[
                "capture_request_sha256"
            ],
            "capture_boundary_policy_sha256": verification[
                "capture_boundary_policy_sha256"
            ],
            "capture_helper_activation_policy_sha256": verification[
                "capture_helper_activation_policy_sha256"
            ],
        },
        expected_evidence_uid=expected_evidence_uid,
    )
    if payload["schema_version"] == HISTORICAL_PAYLOAD_SCHEMA_VERSION:
        return verifier_evidence
    return normalize_verified_evidence(
        {
            **verifier_evidence,
            "post_verifier_live_source_revalidation_receipt": (
                verification[
                    "post_verifier_live_source_revalidation_receipt"
                ]
            ),
            "post_verifier_live_source_revalidation_receipt_sha256": (
                verification[
                    "post_verifier_live_source_"
                    "revalidation_receipt_sha256"
                ]
            ),
        },
        expected_evidence_uid=expected_evidence_uid,
    )


PAYLOAD_VERIFICATION_FIELDS_V4 = frozenset(
    {
        "verifier_version",
        "verifier_uid",
        "verifier_bundle_sha256",
        "verification_policy_sha256",
        "capture_manifest_sha256",
        "capture_plan_sha256",
        "operator_policy_sha256",
        "claim_strength",
        "public_reputation_eligible",
        "verified_at_unix",
        "expected_evidence_uid",
        "observed_evidence_uid",
        "capture_creator_uid",
        "capture_export_gid",
        "capture_adopted_uid",
        "capture_adoption_receipt_sha256",
        "capture_adoption_policy_sha256",
        "capture_object_identity_sha256",
        "capture_content_inventory_sha256",
        "capture_adopted_at_unix",
        "capture_request_sha256",
        "capture_boundary_policy_sha256",
        "capture_helper_activation_policy_sha256",
        "result",
    }
)
PAYLOAD_VERIFICATION_FIELDS_V5 = (
    PAYLOAD_VERIFICATION_FIELDS_V4
    | source_revalidation_binding.SOURCE_REVALIDATION_EVIDENCE_FIELDS
)
PAYLOAD_VERIFICATION_FIELDS_V6 = (
    (
        PAYLOAD_VERIFICATION_FIELDS_V4
        - {
            "capture_adoption_receipt_sha256",
            "capture_adopted_at_unix",
        }
    )
    | {
        "capture_adoption_provenance",
        "capture_adoption_provenance_sha256",
    }
    | source_revalidation_binding.SOURCE_REVALIDATION_EVIDENCE_FIELDS
)


def _normalize_payload_v6(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize future v6 without changing the historical v4/v5 path."""

    if payload.get("purpose") != PURPOSE or payload.get("scope") != SCOPE:
        raise _error("payload_v6_domain_invalid")

    attestor = _mapping(
        payload.get("attestor"),
        field="payload_v6_attestor",
    )
    _strict_fields(
        attestor,
        field="payload_v6_attestor",
        expected={"key_id", "algorithm", "public_key_sha256"},
    )
    if attestor.get("algorithm") != ALGORITHM:
        raise _error("payload_v6_algorithm_unsupported")

    instance = _mapping(
        payload.get("instance"),
        field="payload_v6_instance",
    )
    _strict_fields(
        instance,
        field="payload_v6_instance",
        expected={"slug"},
    )

    chain = _mapping(payload.get("chain"), field="payload_v6_chain")
    _strict_fields(
        chain,
        field="payload_v6_chain",
        expected={"sequence", "previous_attestation_sha256"},
    )
    sequence = _integer(
        chain.get("sequence"),
        field="payload_v6_chain_sequence",
        minimum=1,
    )
    raw_previous_digest = chain.get("previous_attestation_sha256")
    if sequence == 1:
        if raw_previous_digest is not None:
            raise _error(
                "payload_v6_chain_genesis_previous_invalid"
            )
        previous_digest = None
    else:
        previous_digest = _digest(
            raw_previous_digest,
            field="payload_v6_previous_attestation_sha256",
        )

    qualification = _mapping(
        payload.get("qualification"),
        field="payload_v6_qualification",
    )
    _strict_fields(
        qualification,
        field="payload_v6_qualification",
        expected={
            "run_id",
            "summary_sha256",
            "binding_sha256",
            "status",
            "qualified_at_unix",
            "expires_at_unix",
            "evidence_class",
        },
    )
    if qualification.get("evidence_class") != EVIDENCE_CLASS:
        raise _error("payload_v6_evidence_class_invalid")

    verification = _mapping(
        payload.get("verification"),
        field="payload_v6_verification",
    )
    _strict_fields(
        verification,
        field="payload_v6_verification",
        expected=PAYLOAD_VERIFICATION_FIELDS_V6,
    )
    if verification.get("result") != VERIFICATION_RESULT:
        raise _error("payload_v6_verification_result_invalid")
    expected_uid = _integer(
        verification.get("expected_evidence_uid"),
        field="payload_v6_expected_evidence_uid",
        minimum=1,
    )
    evidence = normalize_verified_evidence_v6(
        {
            "run_id": qualification.get("run_id"),
            "summary_sha256": qualification.get("summary_sha256"),
            "binding_sha256": qualification.get("binding_sha256"),
            "status": qualification.get("status"),
            "qualified_at_unix": qualification.get(
                "qualified_at_unix"
            ),
            "expires_at_unix": qualification.get("expires_at_unix"),
            "verifier_version": verification.get(
                "verifier_version"
            ),
            "verifier_uid": verification.get("verifier_uid"),
            "verifier_bundle_sha256": verification.get(
                "verifier_bundle_sha256"
            ),
            "verification_policy_sha256": verification.get(
                "verification_policy_sha256"
            ),
            "capture_manifest_sha256": verification.get(
                "capture_manifest_sha256"
            ),
            "capture_plan_sha256": verification.get(
                "capture_plan_sha256"
            ),
            "operator_policy_sha256": verification.get(
                "operator_policy_sha256"
            ),
            "claim_strength": verification.get("claim_strength"),
            "public_reputation_eligible": verification.get(
                "public_reputation_eligible"
            ),
            "verified_at_unix": verification.get(
                "verified_at_unix"
            ),
            "observed_evidence_uid": verification.get(
                "observed_evidence_uid"
            ),
            "capture_creator_uid": verification.get(
                "capture_creator_uid"
            ),
            "capture_export_gid": verification.get(
                "capture_export_gid"
            ),
            "capture_adopted_uid": verification.get(
                "capture_adopted_uid"
            ),
            "capture_adoption_policy_sha256": verification.get(
                "capture_adoption_policy_sha256"
            ),
            "capture_object_identity_sha256": verification.get(
                "capture_object_identity_sha256"
            ),
            "capture_content_inventory_sha256": verification.get(
                "capture_content_inventory_sha256"
            ),
            "capture_request_sha256": verification.get(
                "capture_request_sha256"
            ),
            "capture_boundary_policy_sha256": verification.get(
                "capture_boundary_policy_sha256"
            ),
            "capture_helper_activation_policy_sha256": (
                verification.get(
                    "capture_helper_activation_policy_sha256"
                )
            ),
            "capture_adoption_provenance": verification.get(
                "capture_adoption_provenance"
            ),
            "capture_adoption_provenance_sha256": verification.get(
                "capture_adoption_provenance_sha256"
            ),
            "post_verifier_live_source_revalidation_receipt": (
                verification.get(
                    "post_verifier_live_source_"
                    "revalidation_receipt"
                )
            ),
            "post_verifier_live_source_revalidation_receipt_sha256": (
                verification.get(
                    "post_verifier_live_source_"
                    "revalidation_receipt_sha256"
                )
            ),
        },
        expected_evidence_uid=expected_uid,
    )
    return {
        "schema_version": FUTURE_PAYLOAD_SCHEMA_VERSION,
        "purpose": PURPOSE,
        "scope": SCOPE,
        "attestor": {
            "key_id": _token(
                attestor.get("key_id"),
                field="payload_v6_key_id",
            ),
            "algorithm": ALGORITHM,
            "public_key_sha256": _digest(
                attestor.get("public_key_sha256"),
                field="payload_v6_public_key_sha256",
            ),
        },
        "instance": {
            "slug": _slug(
                instance.get("slug"),
                field="payload_v6_slug",
            )
        },
        "chain": {
            "sequence": sequence,
            "previous_attestation_sha256": previous_digest,
        },
        "qualification": {
            "run_id": evidence["run_id"],
            "summary_sha256": evidence["summary_sha256"],
            "binding_sha256": evidence["binding_sha256"],
            "status": "qualified",
            "qualified_at_unix": evidence["qualified_at_unix"],
            "expires_at_unix": evidence["expires_at_unix"],
            "evidence_class": EVIDENCE_CLASS,
        },
        "verification": {
            "verifier_version": evidence["verifier_version"],
            "verifier_uid": evidence["verifier_uid"],
            "verifier_bundle_sha256": evidence[
                "verifier_bundle_sha256"
            ],
            "verification_policy_sha256": evidence[
                "verification_policy_sha256"
            ],
            "capture_manifest_sha256": evidence[
                "capture_manifest_sha256"
            ],
            "capture_plan_sha256": evidence["capture_plan_sha256"],
            "operator_policy_sha256": evidence[
                "operator_policy_sha256"
            ],
            "claim_strength": CLAIM_STRENGTH,
            "public_reputation_eligible": False,
            "verified_at_unix": evidence["verified_at_unix"],
            "expected_evidence_uid": expected_uid,
            "observed_evidence_uid": evidence[
                "observed_evidence_uid"
            ],
            "capture_creator_uid": evidence["capture_creator_uid"],
            "capture_export_gid": evidence["capture_export_gid"],
            "capture_adopted_uid": evidence["capture_adopted_uid"],
            "capture_adoption_policy_sha256": evidence[
                "capture_adoption_policy_sha256"
            ],
            "capture_object_identity_sha256": evidence[
                "capture_object_identity_sha256"
            ],
            "capture_content_inventory_sha256": evidence[
                "capture_content_inventory_sha256"
            ],
            "capture_request_sha256": evidence[
                "capture_request_sha256"
            ],
            "capture_boundary_policy_sha256": evidence[
                "capture_boundary_policy_sha256"
            ],
            "capture_helper_activation_policy_sha256": evidence[
                "capture_helper_activation_policy_sha256"
            ],
            "capture_adoption_provenance": evidence[
                "capture_adoption_provenance"
            ],
            "capture_adoption_provenance_sha256": evidence[
                "capture_adoption_provenance_sha256"
            ],
            "post_verifier_live_source_revalidation_receipt": (
                evidence[
                    "post_verifier_live_source_"
                    "revalidation_receipt"
                ]
            ),
            "post_verifier_live_source_revalidation_receipt_sha256": (
                evidence[
                    "post_verifier_live_source_"
                    "revalidation_receipt_sha256"
                ]
            ),
            "result": VERIFICATION_RESULT,
        },
    }


def normalize_payload(
    value: Any,
    *,
    require_current: bool = False,
) -> dict[str, Any]:
    payload = _mapping(value, field="payload")
    _strict_fields(
        payload,
        field="payload",
        expected={
            "schema_version",
            "purpose",
            "scope",
            "attestor",
            "instance",
            "chain",
            "qualification",
            "verification",
        },
    )
    if type(require_current) is not bool:
        raise _error("payload_current_requirement_invalid")
    payload_schema = payload.get("schema_version")
    if (
        type(payload_schema) is not int
        or payload_schema not in SUPPORTED_PAYLOAD_SCHEMA_VERSIONS
    ):
        raise _error("payload_schema_unsupported")
    if require_current and payload_schema != PAYLOAD_SCHEMA_VERSION:
        raise _error("payload_schema_not_signable")
    if payload_schema == FUTURE_PAYLOAD_SCHEMA_VERSION:
        return _normalize_payload_v6(payload)
    if payload.get("purpose") != PURPOSE or payload.get("scope") != SCOPE:
        raise _error("payload_domain_invalid")

    attestor = _mapping(payload.get("attestor"), field="payload_attestor")
    _strict_fields(
        attestor,
        field="payload_attestor",
        expected={"key_id", "algorithm", "public_key_sha256"},
    )
    if attestor.get("algorithm") != ALGORITHM:
        raise _error("payload_algorithm_unsupported")

    instance = _mapping(payload.get("instance"), field="payload_instance")
    _strict_fields(instance, field="payload_instance", expected={"slug"})

    chain = _mapping(payload.get("chain"), field="payload_chain")
    _strict_fields(
        chain,
        field="payload_chain",
        expected={"sequence", "previous_attestation_sha256"},
    )
    sequence = _integer(
        chain.get("sequence"),
        field="payload_chain_sequence",
        minimum=1,
    )
    raw_previous_digest = chain.get("previous_attestation_sha256")
    if sequence == 1:
        if raw_previous_digest is not None:
            raise _error("payload_chain_genesis_previous_invalid")
        previous_digest = None
    else:
        previous_digest = _digest(
            raw_previous_digest,
            field="payload_previous_attestation_sha256",
        )

    qualification = _mapping(
        payload.get("qualification"), field="payload_qualification"
    )
    _strict_fields(
        qualification,
        field="payload_qualification",
        expected={
            "run_id",
            "summary_sha256",
            "binding_sha256",
            "status",
            "qualified_at_unix",
            "expires_at_unix",
            "evidence_class",
        },
    )
    run_id = qualification.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise _error("payload_run_id_invalid")
    if qualification.get("status") != "qualified":
        raise _error("payload_status_invalid")
    if qualification.get("evidence_class") != EVIDENCE_CLASS:
        raise _error("payload_evidence_class_invalid")
    qualified = _integer(
        qualification.get("qualified_at_unix"),
        field="payload_qualified_at_unix",
    )
    expires = _integer(
        qualification.get("expires_at_unix"),
        field="payload_expires_at_unix",
    )

    verification = _mapping(
        payload.get("verification"), field="payload_verification"
    )
    _strict_fields(
        verification,
        field="payload_verification",
        expected=(
            PAYLOAD_VERIFICATION_FIELDS_V5
            if payload_schema == PAYLOAD_SCHEMA_VERSION
            else PAYLOAD_VERIFICATION_FIELDS_V4
        ),
    )
    if verification.get("result") != VERIFICATION_RESULT:
        raise _error("payload_verification_result_invalid")
    if verification.get("claim_strength") != CLAIM_STRENGTH:
        raise _error("payload_claim_strength_invalid")
    if verification.get("public_reputation_eligible") is not False:
        raise _error("payload_reputation_claim_invalid")
    expected_uid = _integer(
        verification.get("expected_evidence_uid"),
        field="payload_expected_evidence_uid",
        minimum=1,
    )
    observed_uid = _integer(
        verification.get("observed_evidence_uid"),
        field="payload_observed_evidence_uid",
        minimum=1,
    )
    verified = _integer(
        verification.get("verified_at_unix"),
        field="payload_verified_at_unix",
    )
    verifier_uid = _integer(
        verification.get("verifier_uid"),
        field="payload_verifier_uid",
        minimum=1,
    )
    capture_creator_uid = _integer(
        verification.get("capture_creator_uid"),
        field="payload_capture_creator_uid",
        minimum=1,
    )
    capture_export_gid = _integer(
        verification.get("capture_export_gid"),
        field="payload_capture_export_gid",
        minimum=1,
    )
    capture_adopted_uid = _integer(
        verification.get("capture_adopted_uid"),
        field="payload_capture_adopted_uid",
    )
    capture_adopted_at = _integer(
        verification.get("capture_adopted_at_unix"),
        field="payload_capture_adopted_at_unix",
        minimum=1,
    )
    if expected_uid != observed_uid:
        raise _error("payload_evidence_uid_mismatch")
    if verifier_uid == expected_uid:
        raise _error("payload_verification_identity_not_separate")
    if (
        capture_creator_uid in {expected_uid, verifier_uid}
        or capture_adopted_uid != 0
        or capture_adopted_at > verified
    ):
        raise _error("payload_capture_adoption_identity_invalid")
    if not qualified <= verified < expires:
        raise _error("payload_timing_invalid")
    source_revalidation_evidence: dict[str, Any] = {}
    if payload_schema == PAYLOAD_SCHEMA_VERSION:
        raw_receipt = verification.get(
            "post_verifier_live_source_revalidation_receipt"
        )
        try:
            normalized_receipt = (
                source_revalidation_binding
                .normalize_source_revalidation_receipt(raw_receipt)
            )
            source_revalidation_evidence = (
                source_revalidation_binding
                .bind_source_revalidation_receipt(
                    normalized_receipt,
                    expected_receipt_sha256=verification.get(
                        "post_verifier_live_source_"
                        "revalidation_receipt_sha256"
                    ),
                    expected_capture_adoption_receipt_sha256=(
                        verification.get(
                            "capture_adoption_receipt_sha256"
                        )
                    ),
                    expected_capture_object_identity_sha256=(
                        verification.get(
                            "capture_object_identity_sha256"
                        )
                    ),
                    expected_capture_plan_sha256=verification.get(
                        "capture_plan_sha256"
                    ),
                    expected_capture_manifest_sha256=verification.get(
                        "capture_manifest_sha256"
                    ),
                    # Historical raw stdout is deliberately not published.
                    # The orchestrator performed this independent comparison
                    # before constructing final signable evidence.
                    expected_verifier_output_sha256=normalized_receipt[
                        "verifier_output_sha256"
                    ],
                    verified_at_unix=verified,
                    expires_at_unix=expires,
                )
            )
        except (
            source_revalidation_binding.SourceRevalidationBindingError
        ) as exc:
            raise _error(exc.code) from exc

    return {
        "schema_version": payload_schema,
        "purpose": PURPOSE,
        "scope": SCOPE,
        "attestor": {
            "key_id": _token(attestor.get("key_id"), field="payload_key_id"),
            "algorithm": ALGORITHM,
            "public_key_sha256": _digest(
                attestor.get("public_key_sha256"),
                field="payload_public_key_sha256",
            ),
        },
        "instance": {"slug": _slug(instance.get("slug"), field="payload_slug")},
        "chain": {
            "sequence": sequence,
            "previous_attestation_sha256": previous_digest,
        },
        "qualification": {
            "run_id": run_id,
            "summary_sha256": _digest(
                qualification.get("summary_sha256"),
                field="payload_summary_sha256",
            ),
            "binding_sha256": _digest(
                qualification.get("binding_sha256"),
                field="payload_binding_sha256",
            ),
            "status": "qualified",
            "qualified_at_unix": qualified,
            "expires_at_unix": expires,
            "evidence_class": EVIDENCE_CLASS,
        },
        "verification": {
            "verifier_version": _token(
                verification.get("verifier_version"),
                field="payload_verifier_version",
            ),
            "verifier_uid": verifier_uid,
            "verifier_bundle_sha256": _digest(
                verification.get("verifier_bundle_sha256"),
                field="payload_verifier_bundle_sha256",
            ),
            "verification_policy_sha256": _digest(
                verification.get("verification_policy_sha256"),
                field="payload_verification_policy_sha256",
            ),
            "capture_manifest_sha256": _digest(
                verification.get("capture_manifest_sha256"),
                field="payload_capture_manifest_sha256",
            ),
            "capture_plan_sha256": _digest(
                verification.get("capture_plan_sha256"),
                field="payload_capture_plan_sha256",
            ),
            "operator_policy_sha256": _digest(
                verification.get("operator_policy_sha256"),
                field="payload_operator_policy_sha256",
            ),
            "claim_strength": CLAIM_STRENGTH,
            "public_reputation_eligible": False,
            "verified_at_unix": verified,
            "expected_evidence_uid": expected_uid,
            "observed_evidence_uid": observed_uid,
            "capture_creator_uid": capture_creator_uid,
            "capture_export_gid": capture_export_gid,
            "capture_adopted_uid": 0,
            "capture_adoption_receipt_sha256": _digest(
                verification.get("capture_adoption_receipt_sha256"),
                field="payload_capture_adoption_receipt_sha256",
            ),
            "capture_adoption_policy_sha256": _digest(
                verification.get("capture_adoption_policy_sha256"),
                field="payload_capture_adoption_policy_sha256",
            ),
            "capture_object_identity_sha256": _digest(
                verification.get("capture_object_identity_sha256"),
                field="payload_capture_object_identity_sha256",
            ),
            "capture_content_inventory_sha256": _digest(
                verification.get("capture_content_inventory_sha256"),
                field="payload_capture_content_inventory_sha256",
            ),
            "capture_adopted_at_unix": capture_adopted_at,
            "capture_request_sha256": _digest(
                verification.get("capture_request_sha256"),
                field="payload_capture_request_sha256",
            ),
            "capture_boundary_policy_sha256": _digest(
                verification.get("capture_boundary_policy_sha256"),
                field="payload_capture_boundary_policy_sha256",
            ),
            "capture_helper_activation_policy_sha256": _digest(
                verification.get(
                    "capture_helper_activation_policy_sha256"
                ),
                field=(
                    "payload_capture_helper_activation_policy_sha256"
                ),
            ),
            **source_revalidation_evidence,
            "result": VERIFICATION_RESULT,
        },
    }


def _assert_payload_schema_activated(
    payload: Mapping[str, Any],
) -> None:
    """Reject dormant schemas at every authoritative state boundary.

    Future payloads remain normalizable and cryptographically verifiable for
    offline migration work.  They must not enter an archive, bind a live head,
    or become a public trust object until the whole production route has been
    activated together.
    """

    if (
        payload["schema_version"] == FUTURE_PAYLOAD_SCHEMA_VERSION
        and not V6_PRODUCTION_ACTIVATION
    ):
        raise _error("payload_schema_not_activated")


def effective_verified_at_unix(value: Any) -> int:
    """Return the claim time used by publication and freshness checks."""

    payload = normalize_payload(value)
    if payload["schema_version"] == HISTORICAL_PAYLOAD_SCHEMA_VERSION:
        return payload["verification"]["verified_at_unix"]
    return payload["verification"][
        "post_verifier_live_source_revalidation_receipt"
    ]["revalidated_at_unix"]


def _load_public_key(raw: bytes) -> Ed25519PublicKey:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_KEY_BYTES:
        raise _error("public_key_size_invalid")
    try:
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise _error("public_key_invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise _error("public_key_not_ed25519")
    return key


def _load_private_key(raw: bytes) -> Ed25519PrivateKey:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_KEY_BYTES:
        raise _error("private_key_size_invalid")
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise _error("private_key_invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise _error("private_key_not_ed25519")
    return key


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str) or not SIGNATURE_RE.fullmatch(value):
        raise _error("signature_encoding_invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + "==")
    except (ValueError, TypeError, binascii.Error) as exc:
        raise _error("signature_encoding_invalid") from exc
    if len(decoded) != 64:
        raise _error("signature_size_invalid")
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if not hmac.compare_digest(canonical, value):
        raise _error("signature_encoding_noncanonical")
    return decoded


def normalize_envelope(value: Any) -> dict[str, Any]:
    envelope = _mapping(value, field="envelope")
    _strict_fields(
        envelope,
        field="envelope",
        expected={"schema_version", "payload", "signature"},
    )
    if type(envelope.get("schema_version")) is not int or envelope.get("schema_version") != ENVELOPE_SCHEMA_VERSION:
        raise _error("envelope_schema_unsupported")
    payload = normalize_payload(envelope.get("payload"))
    signature = _mapping(envelope.get("signature"), field="envelope_signature")
    _strict_fields(
        signature,
        field="envelope_signature",
        expected={"algorithm", "key_id", "value_base64"},
    )
    if signature.get("algorithm") != ALGORITHM:
        raise _error("envelope_algorithm_unsupported")
    key_id = _token(signature.get("key_id"), field="envelope_key_id")
    if key_id != payload["attestor"]["key_id"]:
        raise _error("envelope_key_id_mismatch")
    signature_value = signature.get("value_base64")
    _decode_signature(signature_value)
    normalized = {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "payload": payload,
        "signature": {
            "algorithm": ALGORITHM,
            "key_id": key_id,
            "value_base64": signature_value,
        },
    }
    if len(canonical_json(normalized)) > MAX_JSON_BYTES:
        raise _error("envelope_size_invalid")
    return normalized


def sign_attestation_payload(
    payload: Any,
    *,
    private_key_bytes: bytes,
    public_key_bytes: bytes,
) -> dict[str, Any]:
    """Sign one already-derived strict payload; not exposed by the command."""

    normalized = normalize_payload(payload, require_current=True)
    private_key = _load_private_key(private_key_bytes)
    public_key = _load_public_key(public_key_bytes)
    fingerprint = sha256_bytes(public_key_bytes)
    if not hmac.compare_digest(
        normalized["attestor"]["public_key_sha256"], fingerprint
    ):
        raise _error("public_key_fingerprint_mismatch")
    derived = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    configured = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if not hmac.compare_digest(derived, configured):
        raise _error("attestor_key_pair_mismatch")
    try:
        signature = private_key.sign(canonical_json(normalized))
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise _error("attestation_signing_failed") from exc
    envelope = {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "payload": normalized,
        "signature": {
            "algorithm": ALGORITHM,
            "key_id": normalized["attestor"]["key_id"],
            "value_base64": base64.urlsafe_b64encode(signature)
            .decode("ascii")
            .rstrip("="),
        },
    }
    verified = _verify_attestation_signature(
        envelope,
        public_key_bytes=public_key_bytes,
        expected_key_id=normalized["attestor"]["key_id"],
        expected_public_key_sha256=fingerprint,
        expected_instance_slug=normalized["instance"]["slug"],
    )
    return verified


def _verify_attestation_signature(
    value: Any,
    *,
    public_key_bytes: bytes,
    expected_key_id: str,
    expected_public_key_sha256: str,
    expected_instance_slug: str | None = None,
) -> dict[str, Any]:
    envelope = normalize_envelope(value)
    pinned_key_id = _token(expected_key_id, field="expected_key_id")
    pinned_fingerprint = _digest(
        expected_public_key_sha256, field="expected_public_key_sha256"
    )
    actual_fingerprint = sha256_bytes(public_key_bytes)
    if not hmac.compare_digest(actual_fingerprint, pinned_fingerprint):
        raise _error("public_key_fingerprint_mismatch")
    payload = envelope["payload"]
    if (
        envelope["signature"]["key_id"] != pinned_key_id
        or payload["attestor"]["key_id"] != pinned_key_id
    ):
        raise _error("attestor_key_id_not_pinned")
    if not hmac.compare_digest(
        payload["attestor"]["public_key_sha256"], pinned_fingerprint
    ):
        raise _error("attestor_fingerprint_not_pinned")
    if expected_instance_slug is not None and payload["instance"]["slug"] != _slug(
        expected_instance_slug, field="expected_instance_slug"
    ):
        raise _error("attestation_instance_mismatch")
    key = _load_public_key(public_key_bytes)
    signature = _decode_signature(envelope["signature"]["value_base64"])
    try:
        key.verify(signature, canonical_json(payload))
    except InvalidSignature as exc:
        raise _error("attestation_signature_invalid") from exc
    return envelope


def verify_attestation_envelope(
    value: Any,
    *,
    public_key_bytes: bytes,
    expected_key_id: str,
    expected_public_key_sha256: str,
    expected_instance_slug: str | None = None,
    now_unix: int,
) -> dict[str, Any]:
    """Verify a signature and require the attestation to be current now."""

    envelope = _verify_attestation_signature(
        value,
        public_key_bytes=public_key_bytes,
        expected_key_id=expected_key_id,
        expected_public_key_sha256=expected_public_key_sha256,
        expected_instance_slug=expected_instance_slug,
    )
    now = _integer(now_unix, field="verification_clock")
    verified_at = effective_verified_at_unix(envelope["payload"])
    expires_at = envelope["payload"]["qualification"]["expires_at_unix"]
    if now < verified_at:
        raise _error("attestation_verification_in_future")
    if now >= expires_at:
        raise _error("attestation_expired")
    return envelope


HEAD_BASE_FIELDS = {"schema_version", "state", "instance_slug", "updated_at_unix"}
HEAD_VERIFIED_FIELDS = HEAD_BASE_FIELDS | {
    "chain_sequence",
    "previous_attestation_sha256",
    "run_id",
    "summary_sha256",
    "binding_sha256",
    "expires_at_unix",
    "attestation_path",
    "attestation_sha256",
}
HEAD_REASON_FIELDS = HEAD_BASE_FIELDS | {"reason"}


def normalize_head(value: Any) -> dict[str, Any]:
    head = _mapping(value, field="head")
    state = head.get("state")
    if state not in {"not_enrolled", "pending", "verified", "invalid"}:
        raise _error("head_state_invalid")
    expected = HEAD_BASE_FIELDS
    if state == "verified":
        expected = HEAD_VERIFIED_FIELDS
    elif state in {"pending", "invalid"} and "reason" in head:
        expected = HEAD_REASON_FIELDS
    _strict_fields(head, field="head", expected=expected)
    if type(head.get("schema_version")) is not int or head.get("schema_version") != HEAD_SCHEMA_VERSION:
        raise _error("head_schema_unsupported")
    normalized: dict[str, Any] = {
        "schema_version": HEAD_SCHEMA_VERSION,
        "state": state,
        "instance_slug": _slug(head.get("instance_slug"), field="head_instance_slug"),
        "updated_at_unix": _integer(
            head.get("updated_at_unix"), field="head_updated_at_unix"
        ),
    }
    if state in {"pending", "invalid"} and "reason" in head:
        reason = head.get("reason")
        if not isinstance(reason, str) or not REASON_RE.fullmatch(reason):
            raise _error("head_reason_invalid")
        normalized["reason"] = reason
    elif state == "verified":
        sequence = _integer(
            head.get("chain_sequence"),
            field="head_chain_sequence",
            minimum=1,
        )
        raw_previous_digest = head.get("previous_attestation_sha256")
        if sequence == 1:
            if raw_previous_digest is not None:
                raise _error("head_chain_genesis_previous_invalid")
            previous_digest = None
        else:
            previous_digest = _digest(
                raw_previous_digest,
                field="head_previous_attestation_sha256",
            )
        run_id = head.get("run_id")
        if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
            raise _error("head_run_id_invalid")
        normalized.update(
            {
                "chain_sequence": sequence,
                "previous_attestation_sha256": previous_digest,
                "run_id": run_id,
                "summary_sha256": _digest(
                    head.get("summary_sha256"), field="head_summary_sha256"
                ),
                "binding_sha256": _digest(
                    head.get("binding_sha256"), field="head_binding_sha256"
                ),
                "expires_at_unix": _integer(
                    head.get("expires_at_unix"), field="head_expires_at_unix"
                ),
                "attestation_path": _absolute_path(
                    head.get("attestation_path"), field="head_attestation_path"
                ),
                "attestation_sha256": _digest(
                    head.get("attestation_sha256"),
                    field="head_attestation_sha256",
                ),
            }
        )
    return normalized


def initial_head(instance_slug: str, *, updated_at_unix: int) -> dict[str, Any]:
    return normalize_head(
        {
            "schema_version": HEAD_SCHEMA_VERSION,
            "state": "not_enrolled",
            "instance_slug": instance_slug,
            "updated_at_unix": updated_at_unix,
        }
    )


def _assert_head_attestation_binding(
    head: Any, envelope: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized_head = normalize_head(head)
    normalized_envelope = normalize_envelope(envelope)
    if normalized_head["state"] != "verified":
        raise _error("head_not_verified")
    payload = normalized_envelope["payload"]
    _assert_payload_schema_activated(payload)
    chain = payload["chain"]
    qualification = payload["qualification"]
    expected = {
        "instance_slug": payload["instance"]["slug"],
        "chain_sequence": chain["sequence"],
        "previous_attestation_sha256": chain[
            "previous_attestation_sha256"
        ],
        "run_id": qualification["run_id"],
        "summary_sha256": qualification["summary_sha256"],
        "binding_sha256": qualification["binding_sha256"],
        "expires_at_unix": qualification["expires_at_unix"],
        "attestation_sha256": sha256_json(normalized_envelope),
    }
    for field, value in expected.items():
        if normalized_head[field] != value:
            raise _error("head_attestation_binding_mismatch")
    if (
        normalized_head["updated_at_unix"]
        < effective_verified_at_unix(payload)
    ):
        raise _error("head_attestation_binding_mismatch")
    return normalized_head, normalized_envelope


def _plan_verified_head_transition(
    current_head: Any,
    proposed_envelope: Any,
    *,
    attestation_path: str,
    updated_at_unix: int,
    current_envelope: Any | None = None,
) -> tuple[dict[str, Any], bool]:
    """Return ``(head, changed)`` or reject conflict/rollback."""

    current = normalize_head(current_head)
    proposed = normalize_envelope(proposed_envelope)
    proposed_payload = proposed["payload"]
    _assert_payload_schema_activated(proposed_payload)
    proposed_chain = proposed_payload["chain"]
    proposed_qualification = proposed_payload["qualification"]
    updated = _integer(updated_at_unix, field="head_transition_updated_at_unix")
    if proposed_payload["instance"]["slug"] != current["instance_slug"]:
        raise _error("head_instance_mismatch")
    if current["state"] == "invalid":
        raise _error("invalid_head_requires_operator_recovery")
    if updated < current["updated_at_unix"]:
        raise _error("head_update_rollback_rejected")
    if updated < effective_verified_at_unix(proposed_payload):
        raise _error("head_update_precedes_verification")
    if updated >= proposed_qualification["expires_at_unix"]:
        raise _error("expired_attestation_publication_rejected")

    proposed_path = _absolute_path(
        attestation_path, field="proposed_attestation_path"
    )
    proposed_digest = sha256_json(proposed)
    next_head = normalize_head(
        {
            "schema_version": HEAD_SCHEMA_VERSION,
            "state": "verified",
            "instance_slug": current["instance_slug"],
            "chain_sequence": proposed_chain["sequence"],
            "previous_attestation_sha256": proposed_chain[
                "previous_attestation_sha256"
            ],
            "run_id": proposed_qualification["run_id"],
            "summary_sha256": proposed_qualification["summary_sha256"],
            "binding_sha256": proposed_qualification["binding_sha256"],
            "expires_at_unix": proposed_qualification["expires_at_unix"],
            "attestation_path": proposed_path,
            "attestation_sha256": proposed_digest,
            "updated_at_unix": updated,
        }
    )

    if current["state"] != "verified":
        if (
            proposed_chain["sequence"] != 1
            or proposed_chain["previous_attestation_sha256"] is not None
        ):
            raise _error("attestation_chain_genesis_invalid")
        return next_head, True
    if current_envelope is None:
        raise _error("current_attestation_required")
    bound_head, bound_envelope = _assert_head_attestation_binding(
        current, current_envelope
    )
    current_payload = bound_envelope["payload"]
    current_chain = current_payload["chain"]
    current_qualification = current_payload["qualification"]

    if proposed_chain["sequence"] == current_chain["sequence"]:
        if (
            proposed_digest != bound_head["attestation_sha256"]
            or proposed_path != bound_head["attestation_path"]
        ):
            raise _error("same_sequence_different_attestation_rejected")
        return bound_head, False

    if (
        proposed_qualification["run_id"].casefold()
        == current_qualification["run_id"].casefold()
    ):
        raise _error("same_run_different_attestation_rejected")
    if proposed_chain["sequence"] != current_chain["sequence"] + 1:
        raise _error("attestation_chain_sequence_invalid")
    if not hmac.compare_digest(
        proposed_chain["previous_attestation_sha256"],
        bound_head["attestation_sha256"],
    ):
        raise _error("attestation_chain_previous_mismatch")
    if (
        proposed_qualification["qualified_at_unix"]
        <= current_qualification["qualified_at_unix"]
        or effective_verified_at_unix(proposed_payload)
        <= effective_verified_at_unix(current_payload)
    ):
        raise _error("qualification_rollback_rejected")
    return next_head, True


def _assert_envelope_matches_config(
    config: dict[str, Any], envelope: dict[str, Any]
) -> None:
    payload = envelope["payload"]
    verification = payload["verification"]
    if payload["instance"]["slug"] != config["instance_slug"]:
        raise _error("attestation_instance_mismatch")
    if payload["attestor"]["key_id"] != config["attestor_key_id"]:
        raise _error("attestor_key_id_not_pinned")
    if not hmac.compare_digest(
        payload["attestor"]["public_key_sha256"],
        config["public_key_sha256"],
    ):
        raise _error("attestor_fingerprint_not_pinned")
    if (
        verification["expected_evidence_uid"] != config["expected_evidence_uid"]
        or verification["observed_evidence_uid"] != config["expected_evidence_uid"]
    ):
        raise _error("configured_evidence_uid_mismatch")


def _expected_attestation_path(
    config: dict[str, Any], envelope: dict[str, Any]
) -> str:
    chain = envelope["payload"]["chain"]
    qualification = envelope["payload"]["qualification"]
    name = (
        f"{chain['sequence']:016d}.{qualification['run_id']}."
        f"{qualification['summary_sha256']}.json"
    )
    return str(Path(config["head_path"]).parent / "attestations" / name)


def _assert_canonical_attestation_path(
    config: dict[str, Any],
    envelope: dict[str, Any],
    attestation_path: Any,
) -> str:
    normalized_path = _absolute_path(
        attestation_path, field="attestation_path"
    )
    if normalized_path != _expected_attestation_path(config, envelope):
        raise _error("attestation_path_not_canonical")
    return normalized_path


def verify_published_attestation_head(
    config: Any,
    head: Any,
    envelope: Any,
    *,
    public_key_bytes: bytes,
    now_unix: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify config, current signature, UID binding, expiry, and head binding."""

    normalized_config = normalize_config(config)
    fingerprint = sha256_bytes(public_key_bytes)
    if not hmac.compare_digest(
        fingerprint, normalized_config["public_key_sha256"]
    ):
        raise _error("configured_public_key_fingerprint_mismatch")
    verified = verify_attestation_envelope(
        envelope,
        public_key_bytes=public_key_bytes,
        expected_key_id=normalized_config["attestor_key_id"],
        expected_public_key_sha256=normalized_config["public_key_sha256"],
        expected_instance_slug=normalized_config["instance_slug"],
        now_unix=now_unix,
    )
    _assert_payload_schema_activated(verified["payload"])
    _assert_envelope_matches_config(normalized_config, verified)
    normalized_head, normalized_envelope = _assert_head_attestation_binding(
        head, verified
    )
    _assert_canonical_attestation_path(
        normalized_config,
        normalized_envelope,
        normalized_head["attestation_path"],
    )
    if normalized_head["updated_at_unix"] > _integer(
        now_unix, field="verification_clock"
    ):
        raise _error("head_update_in_future")
    return normalized_head, normalized_envelope


def plan_verified_head_transition(
    config: Any,
    current_head: Any,
    proposed_envelope: Any,
    *,
    public_key_bytes: bytes,
    attestation_path: str,
    updated_at_unix: int,
    current_envelope: Any | None = None,
) -> tuple[dict[str, Any], bool]:
    """Plan a head transition only from config-bound, signed evidence."""

    normalized_config = normalize_config(config)
    fingerprint = sha256_bytes(public_key_bytes)
    if not hmac.compare_digest(
        fingerprint, normalized_config["public_key_sha256"]
    ):
        raise _error("configured_public_key_fingerprint_mismatch")
    proposed = verify_attestation_envelope(
        proposed_envelope,
        public_key_bytes=public_key_bytes,
        expected_key_id=normalized_config["attestor_key_id"],
        expected_public_key_sha256=normalized_config["public_key_sha256"],
        expected_instance_slug=normalized_config["instance_slug"],
        now_unix=updated_at_unix,
    )
    _assert_envelope_matches_config(normalized_config, proposed)
    canonical_path = _assert_canonical_attestation_path(
        normalized_config, proposed, attestation_path
    )
    verified_current = None
    normalized_current = normalize_head(current_head)
    if normalized_current["state"] == "verified":
        if current_envelope is None:
            raise _error("current_attestation_required")
        verified_current = _verify_attestation_signature(
            current_envelope,
            public_key_bytes=public_key_bytes,
            expected_key_id=normalized_config["attestor_key_id"],
            expected_public_key_sha256=normalized_config["public_key_sha256"],
            expected_instance_slug=normalized_config["instance_slug"],
        )
        _assert_envelope_matches_config(normalized_config, verified_current)
        bound_head, _ = _assert_head_attestation_binding(
            normalized_current, verified_current
        )
        _assert_canonical_attestation_path(
            normalized_config,
            verified_current,
            bound_head["attestation_path"],
        )
    return _plan_verified_head_transition(
        normalized_current,
        proposed,
        attestation_path=canonical_path,
        updated_at_unix=updated_at_unix,
        current_envelope=verified_current,
    )


def _validate_parent_chain(path: Path, *, expected_owner_uid: int) -> None:
    current = path
    trusted = {0, expected_owner_uid}
    while True:
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise _error("trusted_parent_unreadable") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise _error("trusted_parent_unsafe")
        if info.st_uid not in trusted or info.st_mode & 0o022:
            raise _error("trusted_parent_untrusted")
        _reject_acl_or_xattrs(current, field="trusted_parent")
        if current.parent == current:
            return
        current = current.parent


def _file_snapshot(info: os.stat_result) -> tuple[int, ...]:
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


def _read_trusted_file(
    path: Path,
    *,
    field: str,
    expected_owner_uid: int,
    maximum_bytes: int,
    private: bool = False,
) -> bytes:
    if not path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise _error(f"{field}_path_invalid")
    _validate_parent_chain(path.parent, expected_owner_uid=expected_owner_uid)
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    try:
        before = os.fstat(descriptor)
        _reject_acl_or_xattrs(path, field=field)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_owner_uid
            or before.st_nlink != 1
            or (mode & 0o077 if private else mode & 0o022)
            or before.st_size < 1
            or before.st_size > maximum_bytes
        ):
            raise _error(f"{field}_unsafe")
        raw = bytearray()
        while len(raw) <= maximum_bytes:
            chunk = os.read(
                descriptor, min(64 * 1024, maximum_bytes + 1 - len(raw))
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        named = os.lstat(path)
        if (
            len(raw) != before.st_size
            or _file_snapshot(before) != _file_snapshot(after)
            or _file_snapshot(after) != _file_snapshot(named)
        ):
            raise _error(f"{field}_changed_during_read")
        return bytes(raw)
    finally:
        os.close(descriptor)


def _relative_bundle_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise _error("verifier_bundle_file_path_invalid")
    path = Path(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or "." in path.parts
        or ".." in path.parts
        or any(not part for part in path.parts)
        or len(path.parts) > MAX_VERIFIER_BUNDLE_DEPTH
    ):
        raise _error("verifier_bundle_file_path_invalid")
    return value


def _bounded_verifier_bundle_inventory(
    bundle_root: Path,
    *,
    expected_owner_uid: int,
    expected_group_gid: int,
) -> tuple[set[str], dict[str, int]]:
    """Walk a trusted bundle descriptor-relatively under hard resource caps."""

    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("nofollow_unsupported")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        root_fd = os.open(bundle_root, flags)
    except OSError as exc:
        raise _error("verifier_bundle_inventory_unreadable") from exc

    observed_paths: set[str] = set()
    observed_directories: dict[str, int] = {}
    entry_count = 0
    directory_count = 1
    observed_bytes = 0

    def walk(directory_fd: int, parts: tuple[str, ...]) -> None:
        nonlocal entry_count, directory_count, observed_bytes
        try:
            iterator = os.scandir(directory_fd)
        except OSError as exc:
            raise _error("verifier_bundle_inventory_unreadable") from exc
        with iterator:
            try:
                for directory_entry in iterator:
                    entry_count += 1
                    if entry_count > MAX_VERIFIER_BUNDLE_ENTRIES:
                        raise _error("verifier_bundle_entry_count_exceeded")
                    name = directory_entry.name
                    relative_parts = (*parts, name)
                    if len(relative_parts) > MAX_VERIFIER_BUNDLE_DEPTH:
                        raise _error("verifier_bundle_depth_exceeded")
                    relative = _relative_bundle_path(
                        Path(*relative_parts).as_posix()
                    )
                    full_path = bundle_root / relative
                    try:
                        info = os.stat(
                            name,
                            dir_fd=directory_fd,
                            follow_symlinks=False,
                        )
                    except OSError as exc:
                        raise _error(
                            "verifier_bundle_entry_unreadable"
                        ) from exc
                    if (
                        stat.S_ISLNK(info.st_mode)
                        or info.st_uid != expected_owner_uid
                        or info.st_gid != expected_group_gid
                    ):
                        raise _error("verifier_bundle_entry_unsafe")
                    _reject_acl_or_xattrs(
                        full_path,
                        field="verifier_bundle_entry",
                    )
                    if stat.S_ISDIR(info.st_mode):
                        if stat.S_IMODE(info.st_mode) != 0o550:
                            raise _error("verifier_bundle_entry_unsafe")
                        directory_count += 1
                        if directory_count > MAX_VERIFIER_BUNDLE_DIRECTORIES:
                            raise _error(
                                "verifier_bundle_directory_count_exceeded"
                            )
                        try:
                            child_fd = os.open(
                                name,
                                flags,
                                dir_fd=directory_fd,
                            )
                        except OSError as exc:
                            raise _error(
                                "verifier_bundle_entry_unreadable"
                            ) from exc
                        try:
                            if _file_snapshot(os.fstat(child_fd)) != _file_snapshot(
                                info
                            ):
                                raise _error(
                                    "verifier_bundle_entry_changed"
                                )
                            walk(child_fd, relative_parts)
                        finally:
                            os.close(child_fd)
                        observed_directories[relative] = 0o550
                        continue
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_nlink != 1
                        or info.st_size < 1
                        or stat.S_IMODE(info.st_mode) not in {0o440, 0o550}
                    ):
                        raise _error("verifier_bundle_entry_unsafe")
                    observed_bytes += info.st_size
                    if observed_bytes > MAX_VERIFIER_BUNDLE_BYTES:
                        raise _error("verifier_bundle_size_exceeded")
                    observed_paths.add(relative)
            except OSError as exc:
                raise _error("verifier_bundle_inventory_unreadable") from exc

    try:
        walk(root_fd, ())
        return observed_paths, observed_directories
    finally:
        os.close(root_fd)


def verify_installed_verifier_bundle(
    config: Any,
    installed_binding: Any,
    *,
    capture_selection_sha256: str,
) -> dict[str, Any]:
    """Verify every installed verifier byte before invoking it."""

    selection_digest = _digest(
        capture_selection_sha256,
        field="capture_selection_sha256",
    )
    normalized_config = normalize_config(config)
    binding = normalize_installed_verifier_binding(
        installed_binding,
        config=normalized_config,
    )
    python_bytes = _read_trusted_file(
        Path(binding["verifier_python_path"]),
        field="verifier_python",
        expected_owner_uid=INSTALLATION_OWNER_UID,
        maximum_bytes=MAX_VERIFIER_ARTIFACT_BYTES,
    )
    if not hmac.compare_digest(
        sha256_bytes(python_bytes),
        binding["verifier_python_sha256"],
    ):
        raise _error("verifier_python_digest_mismatch")
    if python_bytes.startswith(b"#!"):
        raise _error("verifier_python_not_binary")

    instance_bytes = _read_trusted_file(
        Path(binding["instance_manifest_path"]),
        field="instance_manifest",
        expected_owner_uid=normalized_config["expected_evidence_uid"],
        maximum_bytes=MAX_JSON_BYTES,
        private=True,
    )
    if not hmac.compare_digest(
        sha256_bytes(instance_bytes),
        binding["instance_manifest_sha256"],
    ):
        raise _error("instance_manifest_digest_mismatch")

    manifest_bytes = _read_trusted_file(
        Path(binding["verifier_manifest_path"]),
        field="verifier_manifest",
        expected_owner_uid=INSTALLATION_OWNER_UID,
        maximum_bytes=MAX_JSON_BYTES,
        private=True,
    )
    if not hmac.compare_digest(
        sha256_bytes(manifest_bytes),
        binding["verifier_manifest_sha256"],
    ):
        raise _error("verifier_manifest_digest_mismatch")
    manifest = _mapping(
        parse_json_bytes(manifest_bytes, field="verifier_manifest"),
        field="verifier_manifest",
    )
    _strict_fields(
        manifest,
        field="verifier_manifest",
        expected={
            "schema_version",
            "verifier_version",
            "bundle_root",
            "entrypoint_path",
            "root_mode",
            "directories",
            "files",
        },
    )
    if (
        type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version")
        != VERIFIER_BUNDLE_MANIFEST_SCHEMA_VERSION
    ):
        raise _error("verifier_manifest_schema_unsupported")
    if manifest.get("verifier_version") != binding["verifier_version"]:
        raise _error("verifier_manifest_version_mismatch")
    if (
        manifest.get("bundle_root") != binding["verifier_bundle_root"]
        or manifest.get("entrypoint_path")
        != binding["verifier_entrypoint_path"]
    ):
        raise _error("verifier_manifest_path_binding_mismatch")
    root_mode = _integer(
        manifest.get("root_mode"),
        field="verifier_manifest_root_mode",
    )
    if root_mode != 0o550:
        raise _error("verifier_manifest_root_mode_invalid")

    raw_files = manifest.get("files")
    if (
        not isinstance(raw_files, list)
        or not raw_files
        or len(raw_files) > MAX_VERIFIER_BUNDLE_FILES
    ):
        raise _error("verifier_manifest_file_count_invalid")
    normalized_files: list[dict[str, Any]] = []
    seen: set[str] = set()
    declared_bundle_bytes = 0
    for raw_entry in raw_files:
        entry = _mapping(raw_entry, field="verifier_manifest_file")
        _strict_fields(
            entry,
            field="verifier_manifest_file",
            expected={"path", "sha256", "size", "mode"},
        )
        relative = _relative_bundle_path(entry.get("path"))
        identity = unicodedata.normalize("NFC", relative).casefold()
        if identity in seen:
            raise _error("verifier_manifest_file_duplicate")
        seen.add(identity)
        size = _integer(
            entry.get("size"),
            field="verifier_manifest_file_size",
            minimum=1,
        )
        if size > MAX_VERIFIER_ARTIFACT_BYTES:
            raise _error("verifier_manifest_file_size_invalid")
        declared_bundle_bytes += size
        if declared_bundle_bytes > MAX_VERIFIER_BUNDLE_BYTES:
            raise _error("verifier_manifest_bundle_size_invalid")
        mode = _integer(
            entry.get("mode"),
            field="verifier_manifest_file_mode",
        )
        if mode not in {0o440, 0o550}:
            raise _error("verifier_manifest_file_mode_invalid")
        normalized_files.append(
            {
                "path": relative,
                "sha256": _digest(
                    entry.get("sha256"),
                    field="verifier_manifest_file_sha256",
                ),
                "size": size,
                "mode": mode,
            }
        )
    if [item["path"] for item in normalized_files] != sorted(
        item["path"] for item in normalized_files
    ):
        raise _error("verifier_manifest_files_not_sorted")
    raw_directories = manifest.get("directories")
    if (
        not isinstance(raw_directories, list)
        or len(raw_directories) > MAX_VERIFIER_BUNDLE_DIRECTORIES
    ):
        raise _error("verifier_manifest_directory_count_invalid")
    normalized_directories: list[dict[str, Any]] = []
    directory_identities: set[str] = set()
    for raw_entry in raw_directories:
        entry = _mapping(
            raw_entry,
            field="verifier_manifest_directory",
        )
        _strict_fields(
            entry,
            field="verifier_manifest_directory",
            expected={"path", "mode"},
        )
        relative = _relative_bundle_path(entry.get("path"))
        identity = unicodedata.normalize("NFC", relative).casefold()
        if identity in directory_identities or identity in seen:
            raise _error("verifier_manifest_path_duplicate")
        directory_identities.add(identity)
        mode = _integer(
            entry.get("mode"),
            field="verifier_manifest_directory_mode",
        )
        if mode != 0o550:
            raise _error("verifier_manifest_directory_mode_invalid")
        normalized_directories.append(
            {"path": relative, "mode": mode}
        )
    if [item["path"] for item in normalized_directories] != sorted(
        item["path"] for item in normalized_directories
    ):
        raise _error("verifier_manifest_directories_not_sorted")
    implied_directories: set[str] = set()
    for entry in normalized_files:
        parts = Path(entry["path"]).parts
        for length in range(1, len(parts)):
            implied_directories.add(Path(*parts[:length]).as_posix())
    if {
        item["path"] for item in normalized_directories
    } != implied_directories:
        raise _error("verifier_manifest_directory_inventory_invalid")

    bundle_root = Path(binding["verifier_bundle_root"])
    _validate_parent_chain(
        bundle_root,
        expected_owner_uid=INSTALLATION_OWNER_UID,
    )
    try:
        bundle_info = bundle_root.lstat()
    except OSError as exc:
        raise _error("verifier_bundle_root_unreadable") from exc
    if (
        not stat.S_ISDIR(bundle_info.st_mode)
        or bundle_info.st_uid != INSTALLATION_OWNER_UID
        or bundle_info.st_gid != binding["verifier_gid"]
        or stat.S_IMODE(bundle_info.st_mode) != root_mode
    ):
        raise _error("verifier_bundle_root_unsafe")
    _reject_acl_or_xattrs(bundle_root, field="verifier_bundle_root")

    expected_paths = {item["path"] for item in normalized_files}
    observed_paths, observed_directories = _bounded_verifier_bundle_inventory(
        bundle_root,
        expected_owner_uid=INSTALLATION_OWNER_UID,
        expected_group_gid=binding["verifier_gid"],
    )
    if observed_paths != expected_paths:
        raise _error("verifier_bundle_inventory_mismatch")
    expected_directories = {
        item["path"]: item["mode"] for item in normalized_directories
    }
    if observed_directories != expected_directories:
        raise _error("verifier_bundle_directory_inventory_mismatch")

    for entry in normalized_files:
        content = _read_trusted_file(
            bundle_root / entry["path"],
            field="verifier_bundle_file",
            expected_owner_uid=INSTALLATION_OWNER_UID,
            maximum_bytes=entry["size"],
        )
        info = (bundle_root / entry["path"]).lstat()
        if (
            len(content) != entry["size"]
            or info.st_gid != binding["verifier_gid"]
            or stat.S_IMODE(info.st_mode) != entry["mode"]
            or not hmac.compare_digest(
                sha256_bytes(content),
                entry["sha256"],
            )
        ):
            raise _error("verifier_bundle_file_mismatch")
    if not any(
        str(bundle_root / entry["path"])
        == binding["verifier_entrypoint_path"]
        for entry in normalized_files
    ):
        raise _error("verifier_entrypoint_not_manifested")
    if not any(
        str(bundle_root / entry["path"])
        == binding["verifier_python_path"]
        for entry in normalized_files
    ):
        raise _error("verifier_python_not_manifested")
    public_policy = {
        "schema_version": OPERATOR_POLICY_SCHEMA,
        "instance_slug": normalized_config["instance_slug"],
        "expected_evidence_uid": normalized_config["expected_evidence_uid"],
        "expected_capture_uid": binding["capture_uid"],
        "expected_capture_export_gid": binding["capture_export_gid"],
        "expected_adopted_uid": 0,
        "capture_adoption_binding_schema": (
            adoption_binding.ADOPTION_BINDING_SCHEMA
        ),
        "capture_adoption_required": True,
        "instance_manifest_sha256": binding["instance_manifest_sha256"],
        "verifier_uid": binding["verifier_uid"],
        "verifier_gid": binding["verifier_gid"],
        "verifier_python_sha256": binding["verifier_python_sha256"],
        "verifier_bundle_sha256": binding["verifier_manifest_sha256"],
        "verifier_version": binding["verifier_version"],
        "verifier_timeout_seconds": binding["verifier_timeout_seconds"],
        "verification_execution_policy_sha256": sha256_json(
            VERIFICATION_EXECUTION_POLICY
        ),
        "capture_selection_sha256": selection_digest,
        "claim_strength": CLAIM_STRENGTH,
        "public_reputation_eligible": False,
    }
    return {
        **binding,
        "verifier_bundle_sha256": binding["verifier_manifest_sha256"],
        "verification_policy_sha256": sha256_json(
            {
                "installed_binding": binding,
                "execution_policy": VERIFICATION_EXECUTION_POLICY,
                "capture_selection_sha256": selection_digest,
            }
        ),
        "operator_policy": public_policy,
        "operator_policy_sha256": sha256_json(public_policy),
    }


def read_root_owned_config(path: Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    raw = _read_trusted_file(
        Path(path),
        field="attestor_config",
        expected_owner_uid=0,
        maximum_bytes=MAX_JSON_BYTES,
        private=True,
    )
    return normalize_config(parse_json_bytes(raw, field="attestor_config"))


def assert_verification_identity(
    config: Any, *, process_uid: int | None = None
) -> dict[str, Any]:
    """Require a root verifier distinct from the evidence-producing UID."""

    normalized = normalize_config(config)
    uid = os.geteuid() if process_uid is None else _integer(
        process_uid, field="process_uid"
    )
    if uid != 0 or uid == normalized["expected_evidence_uid"]:
        raise _error("verification_identity_unsupported")
    return normalized


def _safe_directory(path: Path, *, expected_owner_uid: int) -> int:
    _validate_parent_chain(path, expected_owner_uid=expected_owner_uid)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _error("publication_directory_unsafe") from exc
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != expected_owner_uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise _error("publication_directory_unsafe")
    _reject_acl_or_xattrs(path, field="publication_directory")
    return descriptor


def _read_json_state_at(
    directory_fd: int,
    name: str,
    *,
    directory_path: Path,
    expected_owner_uid: int,
    field: str,
) -> dict[str, Any]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    try:
        info = os.fstat(descriptor)
        _reject_acl_or_xattrs(
            directory_path / name,
            field=field,
        )
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_owner_uid
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or not 1 <= info.st_size <= MAX_JSON_BYTES
        ):
            raise _error(f"{field}_unsafe")
        raw = bytearray()
        while len(raw) <= MAX_JSON_BYTES:
            chunk = os.read(
                descriptor, min(64 * 1024, MAX_JSON_BYTES + 1 - len(raw))
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        try:
            named = os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _error(f"{field}_changed_during_read") from exc
        if (
            len(raw) != info.st_size
            or _file_snapshot(info) != _file_snapshot(after)
            or _file_snapshot(after) != _file_snapshot(named)
        ):
            raise _error(f"{field}_changed_during_read")
        return _mapping(parse_json_bytes(bytes(raw), field=field), field=field)
    finally:
        os.close(descriptor)


def _verified_head_for_envelope(
    config: dict[str, Any],
    envelope: dict[str, Any],
    *,
    updated_at_unix: int,
) -> dict[str, Any]:
    payload = envelope["payload"]
    chain = payload["chain"]
    qualification = payload["qualification"]
    updated = _integer(
        updated_at_unix,
        field="verified_head_updated_at_unix",
    )
    if updated < effective_verified_at_unix(payload):
        raise _error("head_update_precedes_verification")
    return normalize_head(
        {
            "schema_version": HEAD_SCHEMA_VERSION,
            "state": "verified",
            "instance_slug": config["instance_slug"],
            "chain_sequence": chain["sequence"],
            "previous_attestation_sha256": chain[
                "previous_attestation_sha256"
            ],
            "run_id": qualification["run_id"],
            "summary_sha256": qualification["summary_sha256"],
            "binding_sha256": qualification["binding_sha256"],
            "expires_at_unix": qualification["expires_at_unix"],
            "attestation_path": _expected_attestation_path(config, envelope),
            "attestation_sha256": sha256_json(envelope),
            "updated_at_unix": updated,
        }
    )


def _read_attestation_archive(
    directory_fd: int,
    *,
    directory_path: Path,
    config: dict[str, Any],
    public_key_bytes: bytes,
    expected_owner_uid: int,
) -> list[dict[str, Any]]:
    """Read and validate the complete bounded, signed local chain."""

    try:
        entries = sorted(os.listdir(directory_fd))
    except OSError as exc:
        raise _error("attestation_archive_unreadable") from exc
    if len(entries) > MAX_ATTESTATION_ARCHIVE_FILES:
        raise _error("attestation_archive_file_count_invalid")

    total_bytes = 0
    envelopes: list[dict[str, Any]] = []
    for name in entries:
        if (
            not name
            or name in {".", ".."}
            or "/" in name
            or not name.endswith(".json")
        ):
            raise _error("attestation_archive_entry_unsafe")
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise _error("attestation_archive_entry_unreadable") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_owner_uid
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or not 1 <= info.st_size <= MAX_JSON_BYTES
        ):
            raise _error("attestation_archive_entry_unsafe")
        total_bytes += info.st_size
        if total_bytes > MAX_ATTESTATION_ARCHIVE_BYTES:
            raise _error("attestation_archive_size_invalid")
        raw_envelope = _read_json_state_at(
            directory_fd,
            name,
            directory_path=directory_path,
            expected_owner_uid=expected_owner_uid,
            field="archived_attestation",
        )
        envelope = _verify_attestation_signature(
            raw_envelope,
            public_key_bytes=public_key_bytes,
            expected_key_id=config["attestor_key_id"],
            expected_public_key_sha256=config["public_key_sha256"],
            expected_instance_slug=config["instance_slug"],
        )
        _assert_payload_schema_activated(envelope["payload"])
        _assert_envelope_matches_config(config, envelope)
        if Path(_expected_attestation_path(config, envelope)).name != name:
            raise _error("attestation_archive_path_not_canonical")
        envelopes.append(envelope)

    envelopes.sort(key=lambda item: item["payload"]["chain"]["sequence"])
    seen_runs: set[str] = set()
    previous: dict[str, Any] | None = None
    for expected_sequence, envelope in enumerate(envelopes, start=1):
        payload = envelope["payload"]
        chain = payload["chain"]
        qualification = payload["qualification"]
        if chain["sequence"] != expected_sequence:
            raise _error("attestation_archive_sequence_invalid")
        run_identity = qualification["run_id"].casefold()
        if run_identity in seen_runs:
            raise _error("attestation_archive_run_reused")
        seen_runs.add(run_identity)
        if previous is None:
            if chain["previous_attestation_sha256"] is not None:
                raise _error("attestation_archive_genesis_invalid")
        else:
            previous_payload = previous["payload"]
            if not hmac.compare_digest(
                chain["previous_attestation_sha256"],
                sha256_json(previous),
            ):
                raise _error("attestation_archive_chain_broken")
            if (
                qualification["qualified_at_unix"]
                <= previous_payload["qualification"]["qualified_at_unix"]
                or effective_verified_at_unix(payload)
                <= effective_verified_at_unix(previous_payload)
            ):
                raise _error("attestation_archive_time_rollback")
        previous = envelope
    return envelopes


def _reconcile_head_with_archive(
    config: dict[str, Any],
    current_head: dict[str, Any],
    *,
    head_was_missing: bool,
    archive: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any] | None, bool]:
    """Return the authoritative latest chain state and whether head needs repair."""

    if not archive:
        if current_head["state"] == "verified":
            raise _error("attestation_archive_missing")
        return current_head, None, False

    latest = archive[-1]
    latest_digest = sha256_json(latest)
    latest_verified_at = effective_verified_at_unix(latest["payload"])
    if head_was_missing:
        return (
            _verified_head_for_envelope(
                config,
                latest,
                updated_at_unix=latest_verified_at,
            ),
            latest,
            True,
        )
    if current_head["state"] != "verified":
        raise _error("attestation_archive_head_mismatch")

    matching_index = None
    for index, envelope in enumerate(archive):
        if hmac.compare_digest(
            sha256_json(envelope),
            current_head["attestation_sha256"],
        ):
            matching_index = index
            break
    if matching_index is None:
        raise _error("attestation_head_not_in_archive")
    _assert_head_attestation_binding(
        current_head,
        archive[matching_index],
    )
    _assert_canonical_attestation_path(
        config,
        archive[matching_index],
        current_head["attestation_path"],
    )
    if matching_index == len(archive) - 1:
        return current_head, latest, False

    repaired_updated_at = max(
        current_head["updated_at_unix"],
        latest_verified_at,
    )
    repaired = _verified_head_for_envelope(
        config,
        latest,
        updated_at_unix=repaired_updated_at,
    )
    if not hmac.compare_digest(
        repaired["attestation_sha256"],
        latest_digest,
    ):
        raise _error("attestation_archive_reconciliation_failed")
    return repaired, latest, True


def _write_once_at(
    directory_fd: int,
    name: str,
    content: bytes,
    *,
    expected_owner_uid: int,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        if os.fstat(descriptor).st_uid != expected_owner_uid:
            raise _error("publication_owner_mismatch")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise _error("publication_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_json_at(
    directory_fd: int,
    name: str,
    value: Any,
    *,
    expected_owner_uid: int,
) -> None:
    temp_name = f".{name}.{secrets.token_hex(16)}.tmp"
    try:
        _write_once_at(
            directory_fd,
            temp_name,
            canonical_json(value) + b"\n",
            expected_owner_uid=expected_owner_uid,
        )
        os.replace(
            temp_name,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    finally:
        try:
            os.unlink(temp_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _publish_immutable_at(
    directory_fd: int,
    name: str,
    content: bytes,
    *,
    expected_owner_uid: int,
) -> bool:
    """Publish an immutable record with an atomic no-replace link."""

    temp_name = f".{name}.{secrets.token_hex(16)}.tmp"
    try:
        _write_once_at(
            directory_fd,
            temp_name,
            content,
            expected_owner_uid=expected_owner_uid,
        )
        try:
            os.link(
                temp_name,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            return False
        finally:
            try:
                os.unlink(temp_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.fsync(directory_fd)
        return True
    finally:
        try:
            os.unlink(temp_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _repair_interrupted_immutable_link(
    directory_fd: int,
    name: str,
    *,
    expected_owner_uid: int,
) -> None:
    """Remove the same-inode temp link left by a link-before-unlink crash."""

    try:
        target = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise _error("existing_attestation_unreadable") from exc
    if target.st_nlink == 1:
        return
    if (
        target.st_nlink != 2
        or not stat.S_ISREG(target.st_mode)
        or target.st_uid != expected_owner_uid
        or stat.S_IMODE(target.st_mode) != 0o600
    ):
        raise _error("interrupted_publication_unsafe")
    prefix = f".{name}."
    candidates: list[str] = []
    try:
        entries = os.listdir(directory_fd)
    except OSError as exc:
        raise _error("interrupted_publication_unreadable") from exc
    for entry in entries:
        if not entry.startswith(prefix) or not entry.endswith(".tmp"):
            continue
        try:
            info = os.stat(entry, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise _error("interrupted_publication_unreadable") from exc
        if (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino):
            candidates.append(entry)
    if len(candidates) != 1:
        raise _error("interrupted_publication_unsafe")
    os.unlink(candidates[0], dir_fd=directory_fd)
    os.fsync(directory_fd)
    repaired = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if (
        (repaired.st_dev, repaired.st_ino) != (target.st_dev, target.st_ino)
        or repaired.st_nlink != 1
    ):
        raise _error("interrupted_publication_repair_failed")


def _repair_interrupted_publications(
    directory_fd: int,
    *,
    expected_owner_uid: int,
) -> None:
    """Repair every bounded link-before-unlink crash artifact under the lock."""

    try:
        entries = os.listdir(directory_fd)
    except OSError as exc:
        raise _error("interrupted_publication_unreadable") from exc
    temporary = [
        name for name in entries if name.startswith(".") and name.endswith(".tmp")
    ]
    if len(temporary) > MAX_INTERRUPTED_PUBLICATION_FILES:
        raise _error("interrupted_publication_count_invalid")
    for name in temporary:
        match = INTERRUPTED_PUBLICATION_RE.fullmatch(name)
        if match is None:
            raise _error("interrupted_publication_unsafe")
        target_name = match.group("target")
        try:
            temporary_info = os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _error("interrupted_publication_unreadable") from exc
        if (
            not stat.S_ISREG(temporary_info.st_mode)
            or temporary_info.st_uid != expected_owner_uid
            or stat.S_IMODE(temporary_info.st_mode) != 0o600
            or temporary_info.st_nlink not in {1, 2}
        ):
            raise _error("interrupted_publication_unsafe")
        try:
            target_info = os.stat(
                target_name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            if temporary_info.st_nlink != 1:
                raise _error("interrupted_publication_unsafe")
        except OSError as exc:
            raise _error("interrupted_publication_unreadable") from exc
        else:
            if (
                temporary_info.st_nlink != 2
                or (temporary_info.st_dev, temporary_info.st_ino)
                != (target_info.st_dev, target_info.st_ino)
            ):
                raise _error("interrupted_publication_unsafe")
        os.unlink(name, dir_fd=directory_fd)
    if temporary:
        os.fsync(directory_fd)


def _repair_head_replacement_temps(
    directory_fd: int,
    head_name: str,
    *,
    expected_owner_uid: int,
) -> None:
    prefix = f".{head_name}."
    try:
        entries = os.listdir(directory_fd)
    except OSError as exc:
        raise _error("head_replacement_temp_unreadable") from exc
    temporary = [
        name
        for name in entries
        if name.startswith(prefix) and name.endswith(".tmp")
    ]
    if len(temporary) > MAX_INTERRUPTED_PUBLICATION_FILES:
        raise _error("head_replacement_temp_count_invalid")
    expected_length = len(prefix) + 32 + len(".tmp")
    for name in temporary:
        token = name[len(prefix) : -len(".tmp")]
        if len(name) != expected_length or not re.fullmatch(r"[0-9a-f]{32}", token):
            raise _error("head_replacement_temp_unsafe")
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise _error("head_replacement_temp_unreadable") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_owner_uid
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise _error("head_replacement_temp_unsafe")
        os.unlink(name, dir_fd=directory_fd)
    if temporary:
        os.fsync(directory_fd)


def _attestation_archive_usage(directory_fd: int) -> tuple[int, int]:
    try:
        entries = os.listdir(directory_fd)
    except OSError as exc:
        raise _error("attestation_archive_unreadable") from exc
    count = 0
    total = 0
    for name in entries:
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise _error("attestation_archive_entry_unreadable") from exc
        if stat.S_ISREG(info.st_mode) and name.endswith(".json"):
            count += 1
            total += info.st_size
    return count, total


def inspect_attestation_chain_tip(
    config: Any,
    *,
    public_key_bytes: bytes,
    publication_owner_uid: int | None = None,
) -> dict[str, Any]:
    """Inspect the signed chain without creating, repairing, or replacing it.

    Recovery code must be able to distinguish a completely published head
    from an archive that merely *could* repair that head.  The ordinary tip
    reader intentionally performs those repairs, so it is not suitable as
    evidence that a pre-existing publication was already complete.

    This inspector requires the publication lock to exist, takes it shared,
    validates every signed archive entry, and reports whether reconciliation
    would require a head write.  It never creates the lock/archive, removes
    interrupted temporary files, repairs hard links, or rewrites the head.
    """

    normalized_config = normalize_config(config)
    owner_uid = os.geteuid() if publication_owner_uid is None else _integer(
        publication_owner_uid,
        field="publication_owner_uid",
    )
    fingerprint = sha256_bytes(public_key_bytes)
    if not hmac.compare_digest(
        fingerprint,
        normalized_config["public_key_sha256"],
    ):
        raise _error("configured_public_key_fingerprint_mismatch")

    head_path = Path(normalized_config["head_path"])
    parent_fd = _safe_directory(
        head_path.parent,
        expected_owner_uid=owner_uid,
    )
    head_name = head_path.name
    lock_name = f".{head_name}.lock"
    lock_flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        lock_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_fd = -1
    attestations_fd = -1
    try:
        try:
            lock_fd = os.open(lock_name, lock_flags, dir_fd=parent_fd)
        except FileNotFoundError as exc:
            raise _error("publication_lock_missing") from exc
        except OSError as exc:
            raise _error("publication_lock_unreadable") from exc
        lock_info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != owner_uid
            or lock_info.st_nlink != 1
            or stat.S_IMODE(lock_info.st_mode) != 0o600
        ):
            raise _error("publication_lock_unsafe")
        fcntl.flock(lock_fd, fcntl.LOCK_SH)
        try:
            named_lock = os.stat(
                lock_name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _error("publication_lock_changed") from exc
        if (named_lock.st_dev, named_lock.st_ino) != (
            lock_info.st_dev,
            lock_info.st_ino,
        ):
            raise _error("publication_lock_changed")

        try:
            parent_entries = os.listdir(parent_fd)
        except OSError as exc:
            raise _error("publication_directory_unreadable") from exc
        head_temp_prefix = f".{head_name}."
        if any(
            name.startswith(head_temp_prefix) and name.endswith(".tmp")
            for name in parent_entries
        ):
            raise _error("attestation_chain_repair_required")

        head_was_missing = False
        observed_head: dict[str, Any] | None
        try:
            observed_head = normalize_head(
                _read_json_state_at(
                    parent_fd,
                    head_name,
                    directory_path=head_path.parent,
                    expected_owner_uid=owner_uid,
                    field="attestation_head",
                )
            )
            current = observed_head
        except FileNotFoundError:
            head_was_missing = True
            observed_head = None
            current = initial_head(
                normalized_config["instance_slug"],
                updated_at_unix=0,
            )

        attestation_dir = head_path.parent / "attestations"
        try:
            archive_info = os.stat(
                "attestations",
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            archive: list[dict[str, Any]] = []
        except OSError as exc:
            raise _error("attestation_archive_unreadable") from exc
        else:
            if not stat.S_ISDIR(archive_info.st_mode):
                raise _error("publication_directory_unsafe")
            attestations_fd = _safe_directory(
                attestation_dir,
                expected_owner_uid=owner_uid,
            )
            opened_archive = os.fstat(attestations_fd)
            if (opened_archive.st_dev, opened_archive.st_ino) != (
                archive_info.st_dev,
                archive_info.st_ino,
            ):
                raise _error("attestation_archive_changed")
            archive = _read_attestation_archive(
                attestations_fd,
                directory_path=attestation_dir,
                config=normalized_config,
                public_key_bytes=public_key_bytes,
                expected_owner_uid=owner_uid,
            )

        authoritative_head, latest, head_needs_repair = (
            _reconcile_head_with_archive(
                normalized_config,
                current,
                head_was_missing=head_was_missing,
                archive=archive,
            )
        )
        if authoritative_head["state"] in {"pending", "invalid"}:
            raise _error("attestation_chain_requires_operator_recovery")
        if latest is None:
            next_sequence = 1
            previous_digest = None
        else:
            next_sequence = latest["payload"]["chain"]["sequence"] + 1
            previous_digest = sha256_json(latest)
        archive_index = []
        for envelope in archive:
            archived_evidence = _verified_evidence_from_payload(
                envelope["payload"],
                expected_evidence_uid=normalized_config[
                    "expected_evidence_uid"
                ],
            )
            archive_index.append(
                {
                    "run_id": archived_evidence["run_id"],
                    "chain_sequence": envelope["payload"]["chain"][
                        "sequence"
                    ],
                    "attestation_sha256": sha256_json(envelope),
                    "verified_evidence_sha256": sha256_json(
                        archived_evidence
                    ),
                }
            )
        return {
            "read_only": True,
            "head_was_missing": head_was_missing,
            "head_needs_repair": head_needs_repair,
            "next_sequence": next_sequence,
            "previous_attestation_sha256": previous_digest,
            "archive_index": archive_index,
            "observed_head": observed_head,
            "current_head": authoritative_head,
            "current_envelope": latest,
        }
    finally:
        if attestations_fd >= 0:
            os.close(attestations_fd)
        if lock_fd >= 0:
            os.close(lock_fd)
        os.close(parent_fd)


def read_attestation_chain_tip(
    config: Any,
    *,
    public_key_bytes: bytes,
    publication_owner_uid: int | None = None,
) -> dict[str, Any]:
    """Return the next signed-chain coordinates after archive reconciliation."""

    normalized_config = normalize_config(config)
    owner_uid = os.geteuid() if publication_owner_uid is None else _integer(
        publication_owner_uid,
        field="publication_owner_uid",
    )
    fingerprint = sha256_bytes(public_key_bytes)
    if not hmac.compare_digest(
        fingerprint,
        normalized_config["public_key_sha256"],
    ):
        raise _error("configured_public_key_fingerprint_mismatch")

    head_path = Path(normalized_config["head_path"])
    parent_fd = _safe_directory(
        head_path.parent,
        expected_owner_uid=owner_uid,
    )
    head_name = head_path.name
    lock_name = f".{head_name}.lock"
    lock_flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        lock_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_fd = -1
    attestations_fd = -1
    try:
        lock_fd = os.open(lock_name, lock_flags, 0o600, dir_fd=parent_fd)
        lock_info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != owner_uid
            or lock_info.st_nlink != 1
            or stat.S_IMODE(lock_info.st_mode) != 0o600
        ):
            raise _error("publication_lock_unsafe")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        _repair_head_replacement_temps(
            parent_fd,
            head_name,
            expected_owner_uid=owner_uid,
        )
        head_was_missing = False
        try:
            current = normalize_head(
                _read_json_state_at(
                    parent_fd,
                    head_name,
                    directory_path=head_path.parent,
                    expected_owner_uid=owner_uid,
                    field="attestation_head",
                )
            )
        except FileNotFoundError:
            head_was_missing = True
            current = initial_head(
                normalized_config["instance_slug"],
                updated_at_unix=0,
            )

        try:
            os.mkdir("attestations", 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
        attestation_dir = head_path.parent / "attestations"
        attestations_fd = _safe_directory(
            attestation_dir,
            expected_owner_uid=owner_uid,
        )
        _repair_interrupted_publications(
            attestations_fd,
            expected_owner_uid=owner_uid,
        )
        if current["state"] == "verified":
            current_path = Path(current["attestation_path"])
            if current_path.parent != attestation_dir:
                raise _error("current_attestation_path_untrusted")
            _repair_interrupted_immutable_link(
                attestations_fd,
                current_path.name,
                expected_owner_uid=owner_uid,
            )
        archive = _read_attestation_archive(
            attestations_fd,
            directory_path=attestation_dir,
            config=normalized_config,
            public_key_bytes=public_key_bytes,
            expected_owner_uid=owner_uid,
        )
        current, latest, head_needs_repair = _reconcile_head_with_archive(
            normalized_config,
            current,
            head_was_missing=head_was_missing,
            archive=archive,
        )
        if current["state"] in {"pending", "invalid"}:
            raise _error("attestation_chain_requires_operator_recovery")
        if head_needs_repair:
            _replace_json_at(
                parent_fd,
                head_name,
                current,
                expected_owner_uid=owner_uid,
            )
        if latest is None:
            return {
                "next_sequence": 1,
                "previous_attestation_sha256": None,
                "current_head": current,
                "current_envelope": None,
            }
        return {
            "next_sequence": latest["payload"]["chain"]["sequence"] + 1,
            "previous_attestation_sha256": sha256_json(latest),
            "current_head": current,
            "current_envelope": latest,
        }
    finally:
        if attestations_fd >= 0:
            os.close(attestations_fd)
        if lock_fd >= 0:
            os.close(lock_fd)
        os.close(parent_fd)


def publish_attestation(
    config: Any,
    envelope: Any,
    *,
    public_key_bytes: bytes,
    updated_at_unix: int,
    publication_owner_uid: int | None = None,
) -> tuple[dict[str, Any], str]:
    """Atomically advance the configured head after immutable publication.

    This low-level primitive accepts explicit bytes for offline tests and a
    future root orchestration layer.  The public command never exposes them.
    """

    normalized_config = normalize_config(config)
    owner_uid = os.geteuid() if publication_owner_uid is None else _integer(
        publication_owner_uid, field="publication_owner_uid"
    )
    fingerprint = sha256_bytes(public_key_bytes)
    if not hmac.compare_digest(
        fingerprint, normalized_config["public_key_sha256"]
    ):
        raise _error("configured_public_key_fingerprint_mismatch")
    proposed = verify_attestation_envelope(
        envelope,
        public_key_bytes=public_key_bytes,
        expected_key_id=normalized_config["attestor_key_id"],
        expected_public_key_sha256=fingerprint,
        expected_instance_slug=normalized_config["instance_slug"],
        now_unix=updated_at_unix,
    )
    _assert_payload_schema_activated(proposed["payload"])
    verification = proposed["payload"]["verification"]
    if (
        verification["expected_evidence_uid"]
        != normalized_config["expected_evidence_uid"]
        or verification["observed_evidence_uid"]
        != normalized_config["expected_evidence_uid"]
    ):
        raise _error("configured_evidence_uid_mismatch")
    head_path = Path(normalized_config["head_path"])
    parent_fd = _safe_directory(head_path.parent, expected_owner_uid=owner_uid)
    head_name = head_path.name
    lock_name = f".{head_name}.lock"
    lock_flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        lock_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_fd = -1
    attestations_fd = -1
    try:
        lock_fd = os.open(lock_name, lock_flags, 0o600, dir_fd=parent_fd)
        lock_info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != owner_uid
            or lock_info.st_nlink != 1
            or stat.S_IMODE(lock_info.st_mode) != 0o600
        ):
            raise _error("publication_lock_unsafe")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        _repair_head_replacement_temps(
            parent_fd,
            head_name,
            expected_owner_uid=owner_uid,
        )

        head_was_missing = False
        try:
            current = normalize_head(
                _read_json_state_at(
                    parent_fd,
                    head_name,
                    directory_path=head_path.parent,
                    expected_owner_uid=owner_uid,
                    field="attestation_head",
                )
            )
        except FileNotFoundError:
            head_was_missing = True
            current = initial_head(
                normalized_config["instance_slug"],
                updated_at_unix=0,
            )

        try:
            os.mkdir("attestations", 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
        attestation_dir = head_path.parent / "attestations"
        attestations_fd = _safe_directory(
            attestation_dir, expected_owner_uid=owner_uid
        )
        _repair_interrupted_publications(
            attestations_fd,
            expected_owner_uid=owner_uid,
        )

        if current["state"] == "verified":
            current_path = Path(current["attestation_path"])
            if current_path.parent != attestation_dir:
                raise _error("current_attestation_path_untrusted")
            _repair_interrupted_immutable_link(
                attestations_fd,
                current_path.name,
                expected_owner_uid=owner_uid,
            )

        archive = _read_attestation_archive(
            attestations_fd,
            directory_path=attestation_dir,
            config=normalized_config,
            public_key_bytes=public_key_bytes,
            expected_owner_uid=owner_uid,
        )
        proposed_run_identity = (
            proposed["payload"]["qualification"]["run_id"].casefold()
        )
        proposed_digest = sha256_json(proposed)
        for archived in archive:
            archived_run_identity = (
                archived["payload"]["qualification"]["run_id"].casefold()
            )
            if (
                archived_run_identity == proposed_run_identity
                and not hmac.compare_digest(
                    sha256_json(archived),
                    proposed_digest,
                )
            ):
                raise _error("same_run_different_attestation_rejected")
        current, current_envelope, head_needs_repair = (
            _reconcile_head_with_archive(
                normalized_config,
                current,
                head_was_missing=head_was_missing,
                archive=archive,
            )
        )
        attestation_path = _expected_attestation_path(
            normalized_config,
            proposed,
        )
        attestation_name = Path(attestation_path).name

        next_head, changed = plan_verified_head_transition(
            normalized_config,
            current,
            proposed,
            public_key_bytes=public_key_bytes,
            attestation_path=attestation_path,
            updated_at_unix=updated_at_unix,
            current_envelope=current_envelope,
        )
        if not changed:
            if head_needs_repair:
                _replace_json_at(
                    parent_fd,
                    head_name,
                    next_head,
                    expected_owner_uid=owner_uid,
                )
                return next_head, "reconciled"
            return next_head, "idempotent"

        encoded = canonical_json(proposed) + b"\n"
        archive_count, archive_bytes = _attestation_archive_usage(
            attestations_fd
        )
        if (
            archive_count + 1 > MAX_ATTESTATION_ARCHIVE_FILES
            or archive_bytes + len(encoded) > MAX_ATTESTATION_ARCHIVE_BYTES
        ):
            raise _error("attestation_archive_capacity_exceeded")
        if not _publish_immutable_at(
            attestations_fd,
            attestation_name,
            encoded,
            expected_owner_uid=owner_uid,
        ):
            _repair_interrupted_immutable_link(
                attestations_fd,
                attestation_name,
                expected_owner_uid=owner_uid,
            )
            existing = normalize_envelope(
                _read_json_state_at(
                    attestations_fd,
                    attestation_name,
                    directory_path=attestation_dir,
                    expected_owner_uid=owner_uid,
                    field="existing_attestation",
                )
            )
            if not hmac.compare_digest(
                canonical_json(existing), canonical_json(proposed)
            ):
                raise _error("attestation_path_collision")
        _replace_json_at(
            parent_fd,
            head_name,
            next_head,
            expected_owner_uid=owner_uid,
        )
        return next_head, "published"
    finally:
        if attestations_fd >= 0:
            os.close(attestations_fd)
        if lock_fd >= 0:
            os.close(lock_fd)
        os.close(parent_fd)


def sign_and_publish_attestation(
    config: Any,
    verified_evidence: Any,
    *,
    public_key_bytes: bytes,
    private_key_loader: Callable[[], bytes],
    updated_at_unix: int,
    publication_owner_uid: int | None = None,
    allow_equivalent_recapture: bool = False,
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    """Sign and publish one run inside a single exclusive transaction.

    The private-key loader is intentionally invoked only after the complete
    signed archive has been reconciled, an existing run has been compared
    against the exact normalized evidence, the proposed chain transition has
    been validated, and archive capacity has been reserved.  The returned
    envelope is the requested run.  On ``idempotent_archived`` the returned
    head remains the authoritative newer head; it never masquerades the older
    envelope as current.  A protected coordinator may explicitly permit an
    equivalent recapture of the same qualified run.  That exception ignores
    only receipt-scoped object/session/time digests from the fresh capture;
    every qualification, creator identity, plan, installed boundary/helper
    policy, and claim field must remain exact.
    It exists solely so a crash after signing but before trust publication can
    be repaired without reopening the private key for unchanged evidence.
    """

    normalized_config = normalize_config(config)
    evidence = normalize_verified_evidence(
        verified_evidence,
        expected_evidence_uid=normalized_config["expected_evidence_uid"],
    )
    owner_uid = os.geteuid() if publication_owner_uid is None else _integer(
        publication_owner_uid,
        field="publication_owner_uid",
    )
    updated = _integer(
        updated_at_unix,
        field="attestation_transaction_updated_at_unix",
    )
    if not callable(private_key_loader):
        raise _error("private_key_loader_invalid")
    if type(allow_equivalent_recapture) is not bool:
        raise _error("allow_equivalent_recapture_invalid")
    fingerprint = public_key_fingerprint(public_key_bytes)
    if not hmac.compare_digest(
        fingerprint,
        normalized_config["public_key_sha256"],
    ):
        raise _error("configured_public_key_fingerprint_mismatch")

    head_path = Path(normalized_config["head_path"])
    parent_fd = _safe_directory(
        head_path.parent,
        expected_owner_uid=owner_uid,
    )
    head_name = head_path.name
    lock_name = f".{head_name}.lock"
    lock_flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        lock_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_fd = -1
    attestations_fd = -1
    try:
        lock_fd = os.open(lock_name, lock_flags, 0o600, dir_fd=parent_fd)
        lock_info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != owner_uid
            or lock_info.st_nlink != 1
            or stat.S_IMODE(lock_info.st_mode) != 0o600
        ):
            raise _error("publication_lock_unsafe")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)

        _repair_head_replacement_temps(
            parent_fd,
            head_name,
            expected_owner_uid=owner_uid,
        )
        head_was_missing = False
        try:
            current = normalize_head(
                _read_json_state_at(
                    parent_fd,
                    head_name,
                    directory_path=head_path.parent,
                    expected_owner_uid=owner_uid,
                    field="attestation_head",
                )
            )
        except FileNotFoundError:
            head_was_missing = True
            current = initial_head(
                normalized_config["instance_slug"],
                updated_at_unix=0,
            )

        try:
            os.mkdir("attestations", 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
        attestation_dir = head_path.parent / "attestations"
        attestations_fd = _safe_directory(
            attestation_dir,
            expected_owner_uid=owner_uid,
        )
        _repair_interrupted_publications(
            attestations_fd,
            expected_owner_uid=owner_uid,
        )
        if current["state"] == "verified":
            current_path = Path(current["attestation_path"])
            if current_path.parent != attestation_dir:
                raise _error("current_attestation_path_untrusted")
            _repair_interrupted_immutable_link(
                attestations_fd,
                current_path.name,
                expected_owner_uid=owner_uid,
            )

        archive = _read_attestation_archive(
            attestations_fd,
            directory_path=attestation_dir,
            config=normalized_config,
            public_key_bytes=public_key_bytes,
            expected_owner_uid=owner_uid,
        )
        current, current_envelope, head_needs_repair = (
            _reconcile_head_with_archive(
                normalized_config,
                current,
                head_was_missing=head_was_missing,
                archive=archive,
            )
        )
        if current["state"] in {"pending", "invalid"}:
            raise _error("attestation_chain_requires_operator_recovery")

        requested_run = evidence["run_id"].casefold()
        matching_envelope: dict[str, Any] | None = None
        matching_recapture = False
        for archived in archive:
            archived_evidence = _verified_evidence_from_payload(
                archived["payload"],
                expected_evidence_uid=normalized_config[
                    "expected_evidence_uid"
                ],
            )
            if archived_evidence["run_id"].casefold() != requested_run:
                continue
            exact_match = hmac.compare_digest(
                canonical_json(archived_evidence),
                canonical_json(evidence),
            )
            equivalent_recapture = (
                allow_equivalent_recapture
                and equivalent_verified_evidence_recapture(
                    archived_evidence,
                    evidence,
                    expected_evidence_uid=normalized_config[
                        "expected_evidence_uid"
                    ],
                )
            )
            if not exact_match and not equivalent_recapture:
                raise _error("same_run_different_attestation_rejected")
            matching_envelope = archived
            matching_recapture = not exact_match
            break

        if matching_envelope is not None:
            if head_needs_repair:
                _replace_json_at(
                    parent_fd,
                    head_name,
                    current,
                    expected_owner_uid=owner_uid,
                )
            matching_sequence = matching_envelope["payload"]["chain"][
                "sequence"
            ]
            if matching_recapture:
                status = (
                    "idempotent_recapture"
                    if matching_sequence == current["chain_sequence"]
                    else "idempotent_recapture_archived"
                )
            else:
                status = (
                    "idempotent"
                    if matching_sequence == current["chain_sequence"]
                    else "idempotent_archived"
                )
            return current, status, matching_envelope

        if current_envelope is None:
            next_sequence = 1
            previous_digest = None
        else:
            next_sequence = (
                current_envelope["payload"]["chain"]["sequence"] + 1
            )
            previous_digest = sha256_json(current_envelope)
        payload = build_attestation_payload(
            normalized_config,
            evidence,
            public_key_bytes=public_key_bytes,
            chain_sequence=next_sequence,
            previous_attestation_sha256=previous_digest,
        )

        # Ed25519 signatures always encode to 86 unpadded URL-safe base64
        # characters.  This strict shell therefore has the exact final size
        # while requiring no access to the private key.
        unsigned_size_shell = normalize_envelope(
            {
                "schema_version": ENVELOPE_SCHEMA_VERSION,
                "payload": payload,
                "signature": {
                    "algorithm": ALGORITHM,
                    "key_id": normalized_config["attestor_key_id"],
                    "value_base64": "A" * 86,
                },
            }
        )
        attestation_path = _expected_attestation_path(
            normalized_config,
            unsigned_size_shell,
        )
        _, preflight_changed = _plan_verified_head_transition(
            current,
            unsigned_size_shell,
            attestation_path=attestation_path,
            updated_at_unix=updated,
            current_envelope=current_envelope,
        )
        if not preflight_changed:
            raise _error("attestation_transaction_preflight_inconsistent")

        predicted_encoded_size = len(
            canonical_json(unsigned_size_shell) + b"\n"
        )
        archive_count, archive_bytes = _attestation_archive_usage(
            attestations_fd
        )
        if (
            archive_count + 1 > MAX_ATTESTATION_ARCHIVE_FILES
            or archive_bytes + predicted_encoded_size
            > MAX_ATTESTATION_ARCHIVE_BYTES
        ):
            raise _error("attestation_archive_capacity_exceeded")

        private_key_bytes = private_key_loader()
        envelope = sign_attestation_payload(
            payload,
            private_key_bytes=private_key_bytes,
            public_key_bytes=public_key_bytes,
        )
        encoded = canonical_json(envelope) + b"\n"
        if len(encoded) != predicted_encoded_size:
            raise _error("attestation_transaction_size_inconsistent")
        next_head, changed = plan_verified_head_transition(
            normalized_config,
            current,
            envelope,
            public_key_bytes=public_key_bytes,
            attestation_path=attestation_path,
            updated_at_unix=updated,
            current_envelope=current_envelope,
        )
        if not changed:
            raise _error("attestation_transaction_transition_inconsistent")

        attestation_name = Path(attestation_path).name
        if not _publish_immutable_at(
            attestations_fd,
            attestation_name,
            encoded,
            expected_owner_uid=owner_uid,
        ):
            _repair_interrupted_immutable_link(
                attestations_fd,
                attestation_name,
                expected_owner_uid=owner_uid,
            )
            existing = normalize_envelope(
                _read_json_state_at(
                    attestations_fd,
                    attestation_name,
                    directory_path=attestation_dir,
                    expected_owner_uid=owner_uid,
                    field="existing_attestation",
                )
            )
            if not hmac.compare_digest(
                canonical_json(existing),
                canonical_json(envelope),
            ):
                raise _error("attestation_path_collision")
        _replace_json_at(
            parent_fd,
            head_name,
            next_head,
            expected_owner_uid=owner_uid,
        )
        return next_head, "published", envelope
    finally:
        if attestations_fd >= 0:
            os.close(attestations_fd)
        if lock_fd >= 0:
            os.close(lock_fd)
        os.close(parent_fd)


def attest_configured(
    config_path: Path = DEFAULT_CONFIG_PATH,
) -> dict[str, Any]:
    """Remain fail-closed until the protected attestor installer qualifies."""

    config = read_root_owned_config(config_path)
    assert_verification_identity(config)
    raise _error("verification_identity_unsupported")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        error = "command_arguments_unsupported"
        print(
            canonical_json({"status": "invalid", "reason": error}).decode(),
            file=sys.stderr,
        )
        return 2
    try:
        result = attest_configured()
    except QualificationAttestorError as exc:
        print(
            canonical_json({"status": "invalid", "reason": exc.code}).decode(),
            file=sys.stderr,
        )
        return 2
    print(canonical_json(result).decode("utf-8"))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
