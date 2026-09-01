#!/usr/bin/env python3
"""Credential-free signed continuity importer.

The ordinary continuity append API intentionally cannot mint owner assertions
or externally verified outcomes.  This module is the narrow admission path for
those dormant record types: it accepts only a canonical Ed25519 envelope,
verifies it with public keys from one exact runtime location, checks the exact
signed continuity head while holding the existing continuity lock, and then
commits a deterministic ledger effect plus an append-only importer record.

Suppression is logical.  The immutable continuity ledger is never rewritten or
truncated; a signed owner suppression creates a durable tombstone in the
importer journal.  Callers that project continuity can use
``effective_entries`` to omit tombstoned entries while retaining an auditable
hash commitment to the suppressed record.

No private-key, signing, network, environment-token, or general continuity
append surface exists here.  Configuration, public keys, journal state, and
transaction state all have exact paths below the existing continuity store.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import john_lomein_continuity as continuity
import john_lomein_continuity_protocol as protocol


IMPORT_RECORD_SCHEMA = "john-lomein.continuity-import-record.v2"
IMPORT_HEAD_SCHEMA = "john-lomein.continuity-import-head.v2"
IMPORT_TRANSACTION_SCHEMA = "john-lomein.continuity-import-transaction.v2"
IMPORT_RESULT_SCHEMA = "john-lomein.continuity-import-result.v2"
IMPORT_STATUS_SCHEMA = "john-lomein.continuity-import-status.v2"
IMPORT_VERIFY_SCHEMA = "john-lomein.continuity-import-verify.v2"
IMPORT_INSPECTION_SCHEMA = "john-lomein.continuity-import-inspection.v2"
PROJECTION_INSPECTION_SCHEMA = (
    "john-lomein.continuity-projection-inspection.v1"
)
IMPORT_ERROR_SCHEMA = "john-lomein.continuity-import-error.v2"

CONFIG_FILENAME = "continuity-import-config.json"
PUBLIC_KEY_DIRECTORY = "continuity-import-public-keys"
JOURNAL_FILENAME = "continuity-import-journal.jsonl"
JOURNAL_HEAD_FILENAME = "continuity-import-head.json"
# Reusing the existing marker name is deliberate.  After an importer crash,
# ordinary continuity readers/writers see an unsupported pending transaction
# and fail closed until this importer proves and recovers the exact projection.
TRANSACTION_FILENAME = continuity.TRANSACTION_FILENAME

MAX_JOURNAL_BYTES = continuity.MAX_LEDGER_BYTES
MAX_JOURNAL_RECORDS = continuity.MAX_ENTRIES
MAX_RECORD_BYTES = protocol.MAX_LEDGER_LINE_BYTES
MAX_TRANSACTION_BYTES = continuity.MAX_TRANSACTION_BYTES
MAX_OUTPUT_BYTES = 16 * 1024
MAX_INSPECTION_RECORDS = 32

_PUBLIC_MESSAGES = {
    "configuration_missing": "signed continuity import is not configured",
    "configuration_invalid": "signed continuity import configuration is invalid",
    "importer_disabled": "signed continuity admission is disabled",
    "key_material_invalid": "signed continuity public-key material is invalid",
    "envelope_invalid": "signed continuity envelope is invalid",
    "expected_head_mismatch": "signed continuity expected head differs",
    "replay_conflict": "signed continuity replay binding conflicts",
    "target_missing": "signed continuity suppression target is missing",
    "target_mismatch": "signed continuity suppression target differs",
    "target_suppressed": "signed continuity target is already suppressed",
    "transaction_pending": "signed continuity recovery is pending",
    "state_invalid": "signed continuity importer state is invalid",
    "state_unsafe": "signed continuity importer filesystem state is unsafe",
    "size_exceeded": "signed continuity importer size limit was exceeded",
    "store_busy": "signed continuity store is busy",
    "store_invalid": "signed continuity store is invalid",
    "io_error": "signed continuity importer storage failed",
}


class ContinuityImporterError(RuntimeError):
    """Fail-closed importer error with bounded input-free public text."""

    def __init__(self, code: str):
        selected = code if code in _PUBLIC_MESSAGES else "state_invalid"
        self.code = selected
        super().__init__(_PUBLIC_MESSAGES[selected])


@dataclass(frozen=True)
class RuntimePaths:
    runtime_home: Path
    store: Path
    config: Path
    public_keys: Path
    journal: Path
    journal_head: Path
    transaction: Path


def _error(code: str) -> ContinuityImporterError:
    return ContinuityImporterError(code)


def public_error(error: BaseException) -> dict[str, Any]:
    code = "state_invalid"
    if type(error) is ContinuityImporterError:
        candidate = vars(error).get("code")
        if type(candidate) is str and candidate in _PUBLIC_MESSAGES:
            code = candidate
    elif type(error) is protocol.ContinuityProtocolError:
        candidate = vars(error).get("code")
        if candidate == "importer_disabled":
            code = "importer_disabled"
        elif candidate in {
            "key_unknown",
            "key_material_invalid",
            "key_fingerprint_mismatch",
        }:
            code = "key_material_invalid"
        else:
            code = "envelope_invalid"
    elif type(error) is continuity.ContinuityError:
        candidate = vars(error).get("code")
        if candidate == "store_busy":
            code = "store_busy"
        elif candidate == "store_unsafe":
            code = "state_unsafe"
        else:
            code = "store_invalid"
    return {
        "schema_version": IMPORT_ERROR_SCHEMA,
        "ok": False,
        "error_code": code,
        "message": _PUBLIC_MESSAGES[code],
    }


def _normalized_absolute(path: str | Path, *, code: str) -> Path:
    selected = Path(os.path.expanduser(str(path)))
    if not selected.is_absolute():
        raise _error(code)
    normalized = Path(os.path.normpath(str(selected)))
    if str(normalized) != str(selected):
        raise _error(code)
    return normalized


def runtime_paths(runtime_home: str | Path) -> RuntimePaths:
    """Return the sole importer layout; callers cannot redirect components."""

    home = _normalized_absolute(runtime_home, code="state_unsafe")
    store = continuity.continuity_root(home)
    return RuntimePaths(
        runtime_home=home,
        store=store,
        config=store / CONFIG_FILENAME,
        public_keys=store / PUBLIC_KEY_DIRECTORY,
        journal=store / JOURNAL_FILENAME,
        journal_head=store / JOURNAL_HEAD_FILENAME,
        transaction=store / TRANSACTION_FILENAME,
    )


def public_key_filename(key_id: str) -> str:
    """Map an opaque protocol key id to a traversal-free exact filename."""

    if type(key_id) is not str or protocol.TOKEN_RE.fullmatch(key_id) is None:
        raise _error("configuration_invalid")
    digest = hashlib.sha256(key_id.encode("ascii")).hexdigest()
    return f"{digest}.ed25519.pub"


def _validate_private_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise _error("configuration_missing") from None
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise _error("state_unsafe")
    try:
        continuity._validate_directory_chain(path)  # noqa: SLF001
    except continuity.ContinuityError:
        raise _error("state_unsafe") from None


def _read_private(path: Path, *, field: str, maximum_bytes: int) -> bytes:
    try:
        return continuity._read_regular(  # noqa: SLF001
            path,
            field=field,
            maximum_bytes=maximum_bytes,
        )
    except continuity.ContinuityError as exc:
        if exc.code == "store_unsafe":
            raise _error("state_unsafe") from None
        raise


def _config_present(paths: RuntimePaths) -> bool:
    try:
        paths.config.lstat()
    except FileNotFoundError:
        return False
    return True


def _load_protocol_material(
    paths: RuntimePaths,
) -> tuple[dict[str, Any], dict[str, bytes], str]:
    if not _config_present(paths):
        raise _error("configuration_missing")
    raw_config = _read_private(
        paths.config,
        field="continuity import config",
        maximum_bytes=protocol.MAX_CONFIG_BYTES,
    )
    try:
        config = protocol.parse_config(raw_config)
    except protocol.ContinuityProtocolError:
        raise _error("configuration_invalid") from None
    _validate_private_directory(paths.public_keys)
    expected_names = {
        public_key_filename(policy["key_id"]): policy["key_id"]
        for policy in config["key_policies"]
    }
    try:
        observed_names = {entry.name for entry in os.scandir(paths.public_keys)}
    except OSError:
        raise _error("state_unsafe") from None
    if observed_names != set(expected_names):
        raise _error("key_material_invalid")
    keys: dict[str, bytes] = {}
    for filename, key_id in expected_names.items():
        raw_key = _read_private(
            paths.public_keys / filename,
            field="continuity import public key",
            maximum_bytes=32,
        )
        if len(raw_key) != 32:
            raise _error("key_material_invalid")
        try:
            fingerprint = protocol.public_key_fingerprint(raw_key)
        except protocol.ContinuityProtocolError:
            raise _error("key_material_invalid") from None
        policy = next(
            item for item in config["key_policies"] if item["key_id"] == key_id
        )
        if not hmac.compare_digest(
            fingerprint,
            policy["public_key_sha256"],
        ):
            raise _error("key_material_invalid")
        keys[key_id] = raw_key
    return config, keys, hashlib.sha256(raw_config).hexdigest()


def _new_import_head(
    *,
    ledger_id: str,
    sequence: int,
    head_record_sha256: str,
    journal_size_bytes: int,
    updated_at: str,
) -> dict[str, Any]:
    base = {
        "schema_version": IMPORT_HEAD_SCHEMA,
        "ledger_id": ledger_id,
        "sequence": sequence,
        "head_record_sha256": head_record_sha256,
        "journal_size_bytes": journal_size_bytes,
        "updated_at": updated_at,
    }
    return {**base, "head_sha256": continuity.sha256_json(base)}


def _validate_import_head(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {
        "schema_version",
        "ledger_id",
        "sequence",
        "head_record_sha256",
        "journal_size_bytes",
        "updated_at",
        "head_sha256",
    }:
        raise _error("state_invalid")
    if value.get("schema_version") != IMPORT_HEAD_SCHEMA:
        raise _error("state_invalid")
    ledger_id = value.get("ledger_id")
    sequence = value.get("sequence")
    size = value.get("journal_size_bytes")
    if (
        type(ledger_id) is not str
        or continuity.LEDGER_ID_RE.fullmatch(ledger_id) is None
        or type(sequence) is not int
        or sequence < 0
        or type(size) is not int
        or not 0 <= size <= MAX_JOURNAL_BYTES
        or type(value.get("head_record_sha256")) is not str
        or continuity.SHA256_RE.fullmatch(value["head_record_sha256"]) is None
        or type(value.get("head_sha256")) is not str
        or continuity.SHA256_RE.fullmatch(value["head_sha256"]) is None
    ):
        raise _error("state_invalid")
    try:
        continuity.parse_utc(value.get("updated_at"), field="import head")
    except continuity.ContinuityError:
        raise _error("state_invalid") from None
    base = dict(value)
    observed = base.pop("head_sha256")
    if not hmac.compare_digest(observed, continuity.sha256_json(base)):
        raise _error("state_invalid")
    if sequence == 0 and value["head_record_sha256"] != continuity.ZERO_HASH:
        raise _error("state_invalid")
    return dict(value)


def _result_for_record(
    *,
    verification: Mapping[str, Any],
    candidate_entry: Mapping[str, Any] | None,
) -> dict[str, Any]:
    effect = verification["effect"]
    if effect["operation"] == "put":
        if candidate_entry is None:
            raise _error("state_invalid")
        return {
            "kind": "put",
            "entry_id": candidate_entry["entry_id"],
            "entry_sha256": candidate_entry["entry_sha256"],
            "entry_sequence": candidate_entry["sequence"],
        }
    suppression = verification["suppression"]
    if candidate_entry is not None or type(suppression) is not dict:
        raise _error("state_invalid")
    return {
        "kind": "suppression_tombstone",
        "target_entry_id": suppression["target_entry_id"],
        "target_entry_sha256": suppression["target_entry_sha256"],
        "reason": suppression["reason"],
    }


def _new_import_record(
    *,
    pre_head: Mapping[str, Any],
    envelope: Mapping[str, Any],
    verification: Mapping[str, Any],
    candidate_entry: Mapping[str, Any] | None,
) -> dict[str, Any]:
    effect = verification["effect"]
    base = {
        "schema_version": IMPORT_RECORD_SCHEMA,
        "sequence": pre_head["sequence"] + 1,
        "previous_record_sha256": pre_head["head_record_sha256"],
        "envelope_sha256": verification["envelope_sha256"],
        "recorded_at": effect["issued_at"],
        "write_id": effect["write_id"],
        "operation": effect["operation"],
        "envelope": dict(envelope),
        "result": _result_for_record(
            verification=verification,
            candidate_entry=candidate_entry,
        ),
    }
    return {**base, "record_sha256": continuity.sha256_json(base)}


def _validate_import_record_structure(
    value: Any,
    *,
    expected_sequence: int,
    expected_previous: str,
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {
        "schema_version",
        "sequence",
        "previous_record_sha256",
        "envelope_sha256",
        "recorded_at",
        "write_id",
        "operation",
        "envelope",
        "result",
        "record_sha256",
    }:
        raise _error("state_invalid")
    if (
        value.get("schema_version") != IMPORT_RECORD_SCHEMA
        or value.get("sequence") != expected_sequence
        or value.get("previous_record_sha256") != expected_previous
        or type(value.get("envelope_sha256")) is not str
        or protocol.HEX_SHA256_RE.fullmatch(value["envelope_sha256"]) is None
        or type(value.get("write_id")) is not str
        or protocol.WRITE_ID_RE.fullmatch(value["write_id"]) is None
        or value.get("operation") not in protocol.OPERATIONS
        or type(value.get("record_sha256")) is not str
        or continuity.SHA256_RE.fullmatch(value["record_sha256"]) is None
    ):
        raise _error("state_invalid")
    try:
        continuity.parse_utc(value.get("recorded_at"), field="import record")
        envelope = protocol.normalize_envelope(value.get("envelope"))
    except (continuity.ContinuityError, protocol.ContinuityProtocolError):
        raise _error("state_invalid") from None
    if envelope != value.get("envelope"):
        raise _error("state_invalid")
    result = value.get("result")
    if type(result) is not dict:
        raise _error("state_invalid")
    if value["operation"] == "put":
        if set(result) != {
            "kind",
            "entry_id",
            "entry_sha256",
            "entry_sequence",
        }:
            raise _error("state_invalid")
        if (
            result.get("kind") != "put"
            or type(result.get("entry_id")) is not str
            or continuity.ENTRY_ID_RE.fullmatch(result["entry_id"]) is None
            or type(result.get("entry_sha256")) is not str
            or continuity.SHA256_RE.fullmatch(result["entry_sha256"]) is None
            or type(result.get("entry_sequence")) is not int
            or result["entry_sequence"] < 1
        ):
            raise _error("state_invalid")
    else:
        if set(result) != {
            "kind",
            "target_entry_id",
            "target_entry_sha256",
            "reason",
        }:
            raise _error("state_invalid")
        if (
            result.get("kind") != "suppression_tombstone"
            or type(result.get("target_entry_id")) is not str
            or continuity.ENTRY_ID_RE.fullmatch(result["target_entry_id"]) is None
            or type(result.get("target_entry_sha256")) is not str
            or continuity.SHA256_RE.fullmatch(
                result["target_entry_sha256"]
            )
            is None
            or result.get("reason") not in protocol.SUPPRESSION_REASONS
        ):
            raise _error("state_invalid")
    base = dict(value)
    observed = base.pop("record_sha256")
    if not hmac.compare_digest(observed, continuity.sha256_json(base)):
        raise _error("state_invalid")
    return dict(value)


def _read_import_head(paths: RuntimePaths) -> tuple[dict[str, Any], bytes]:
    raw = _read_private(
        paths.journal_head,
        field="continuity import head",
        maximum_bytes=4096,
    )
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise _error("state_invalid")
    try:
        parsed = continuity._parse_json(  # noqa: SLF001
            raw,
            field="continuity import head",
        )
    except continuity.ContinuityError:
        raise _error("state_invalid") from None
    head = _validate_import_head(parsed)
    if raw != continuity.canonical_json(head) + b"\n":
        raise _error("state_invalid")
    return head, raw


def _read_journal(paths: RuntimePaths) -> bytes:
    return _read_private(
        paths.journal,
        field="continuity import journal",
        maximum_bytes=MAX_JOURNAL_BYTES,
    )


def _journal_presence(paths: RuntimePaths) -> tuple[bool, bool]:
    present: list[bool] = []
    for path in (paths.journal, paths.journal_head):
        try:
            path.lstat()
        except FileNotFoundError:
            present.append(False)
        else:
            present.append(True)
    return present[0], present[1]


def _ensure_journal_unlocked(
    paths: RuntimePaths,
    *,
    continuity_head: Mapping[str, Any],
) -> None:
    journal_present, head_present = _journal_presence(paths)
    if journal_present and head_present:
        return
    if head_present and not journal_present:
        raise _error("state_invalid")
    if not journal_present:
        try:
            fd = os.open(
                paths.journal,
                continuity._file_flags(  # noqa: SLF001
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL
                ),
                0o600,
            )
        except FileExistsError:
            pass
        except OSError:
            raise _error("io_error") from None
        else:
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        continuity._fsync_directory(paths.store)  # noqa: SLF001
        _initialization_checkpoint("empty_journal_fsynced")
    raw = _read_journal(paths)
    if raw != b"":
        raise _error("state_invalid")
    if not head_present:
        head = _new_import_head(
            ledger_id=continuity_head["ledger_id"],
            sequence=0,
            head_record_sha256=continuity.ZERO_HASH,
            journal_size_bytes=0,
            updated_at=continuity_head["updated_at"],
        )
        continuity._atomic_write(  # noqa: SLF001
            paths.journal_head,
            continuity.canonical_json(head) + b"\n",
        )
        _initialization_checkpoint("empty_import_head_fsynced")


def _initialization_checkpoint(_: str) -> None:
    """No-op seam for first-use durability-boundary crash tests."""


def _verify_record_binding(
    record: Mapping[str, Any],
    *,
    config: Mapping[str, Any],
    public_keys: Mapping[str, bytes],
    entries_by_id: Mapping[str, Mapping[str, Any]],
    ledger_prefix_heads: Mapping[int, Mapping[str, Any]],
) -> dict[str, Any]:
    envelope_raw = protocol.canonical_json(record["envelope"])
    try:
        verification = protocol.verify_for_replay(
            envelope_raw,
            config=config,
            public_keys=dict(public_keys),
            expected_envelope_sha256=record["envelope_sha256"],
        )
    except protocol.ContinuityProtocolError:
        raise _error("state_invalid") from None
    effect = verification["effect"]
    if (
        effect["write_id"] != record["write_id"]
        or effect["operation"] != record["operation"]
        or effect["issued_at"] != record["recorded_at"]
        or not _expected_head_is_ledger_prefix(
            effect["expected_head"],
            ledger_prefix_heads,
        )
    ):
        raise _error("state_invalid")
    result = record["result"]
    if effect["operation"] == "put":
        entry = entries_by_id.get(result["entry_id"])
        write = verification["continuity_write"]
        expected_head = effect["expected_head"]
        if (
            entry is None
            or type(write) is not dict
            or result["entry_id"] != verification["derived_entry_id"]
            or result["entry_sha256"] != entry.get("entry_sha256")
            or result["entry_sequence"] != entry.get("sequence")
            or entry.get("ledger_id") != expected_head["ledger_id"]
            or entry.get("sequence") != expected_head["sequence"] + 1
            or entry.get("previous_entry_sha256")
            != expected_head["head_entry_sha256"]
            or entry.get("recorded_at") != effect["issued_at"]
            or any(
                entry.get(field) != write.get(field)
                for field in (
                    "entry_id",
                    "kind",
                    "subject",
                    "summary",
                    "payload",
                    "source",
                    "scope",
                    "expires_at",
                    "supersedes_entry_id",
                )
            )
        ):
            raise _error("state_invalid")
    else:
        suppression = verification["suppression"]
        target = entries_by_id.get(result["target_entry_id"])
        if (
            type(suppression) is not dict
            or target is None
            or result["target_entry_id"] != suppression["target_entry_id"]
            or result["target_entry_sha256"]
            != suppression["target_entry_sha256"]
            or result["reason"] != suppression["reason"]
            or target.get("entry_sha256") != result["target_entry_sha256"]
            or target.get("scope") != effect["scope"]
            or target.get("sequence", 0) > effect["expected_head"]["sequence"]
        ):
            raise _error("state_invalid")
    return verification


def _expected_head_is_ledger_prefix(
    expected_head: Mapping[str, Any],
    ledger_prefix_heads: Mapping[int, Mapping[str, Any]],
) -> bool:
    sequence = expected_head["sequence"]
    if sequence == 0:
        return (
            expected_head["head_entry_sha256"] == continuity.ZERO_HASH
            and expected_head["ledger_size_bytes"] == 0
        )
    derived = ledger_prefix_heads.get(sequence)
    return derived is not None and _heads_match(expected_head, derived)


def _ledger_prefix_heads(
    entries: Sequence[Mapping[str, Any]],
) -> dict[int, dict[str, Any]]:
    heads: dict[int, dict[str, Any]] = {}
    size = 0
    for entry in entries:
        size += len(continuity.canonical_json(entry) + b"\n")
        heads[int(entry["sequence"])] = continuity._new_head(  # noqa: SLF001
            ledger_id=entry["ledger_id"],
            sequence=entry["sequence"],
            entry_sha256=entry["entry_sha256"],
            ledger_size_bytes=size,
            updated_at=entry["recorded_at"],
        )
    return heads


def _verify_journal_snapshot(
    raw: bytes,
    head: Mapping[str, Any],
    *,
    config: Mapping[str, Any],
    public_keys: Mapping[str, bytes],
    entries: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if len(raw) != head["journal_size_bytes"]:
        raise _error("state_invalid")
    lines = raw.splitlines(keepends=True)
    records: list[dict[str, Any]] = []
    previous = continuity.ZERO_HASH
    previous_time = ""
    envelope_digests: set[str] = set()
    write_ids: set[str] = set()
    suppressed: set[str] = set()
    entries_by_id = {str(entry["entry_id"]): entry for entry in entries}
    prefix_heads = _ledger_prefix_heads(entries)
    for sequence, line in enumerate(lines, 1):
        if (
            not line.endswith(b"\n")
            or line == b"\n"
            or len(line) > MAX_RECORD_BYTES
        ):
            raise _error("state_invalid")
        try:
            parsed = continuity._parse_json(  # noqa: SLF001
                line,
                field="continuity import record",
            )
        except continuity.ContinuityError:
            raise _error("state_invalid") from None
        record = _validate_import_record_structure(
            parsed,
            expected_sequence=sequence,
            expected_previous=previous,
        )
        if line != continuity.canonical_json(record) + b"\n":
            raise _error("state_invalid")
        if (
            record["envelope_sha256"] in envelope_digests
            or record["write_id"] in write_ids
            or (
                record["operation"] == "suppress"
                and record["result"]["target_entry_id"] in suppressed
            )
            or (previous_time and record["recorded_at"] < previous_time)
        ):
            raise _error("state_invalid")
        _verify_record_binding(
            record,
            config=config,
            public_keys=public_keys,
            entries_by_id=entries_by_id,
            ledger_prefix_heads=prefix_heads,
        )
        if record["operation"] == "suppress":
            suppressed.add(record["result"]["target_entry_id"])
        records.append(record)
        envelope_digests.add(record["envelope_sha256"])
        write_ids.add(record["write_id"])
        previous = record["record_sha256"]
        previous_time = record["recorded_at"]
        if len(records) > MAX_JOURNAL_RECORDS:
            raise _error("size_exceeded")
    if (
        len(records) != head["sequence"]
        or previous != head["head_record_sha256"]
        or (records and head["updated_at"] != records[-1]["recorded_at"])
    ):
        raise _error("state_invalid")
    return records


def _read_verified_import_state_unlocked(
    paths: RuntimePaths,
    *,
    config: Mapping[str, Any],
    public_keys: Mapping[str, bytes],
    entries: Sequence[Mapping[str, Any]],
    continuity_head: Mapping[str, Any],
    allow_uninitialized: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None, bytes]:
    journal_present, head_present = _journal_presence(paths)
    if not journal_present and not head_present and allow_uninitialized:
        return [], None, b""
    if not journal_present or not head_present:
        raise _error("state_invalid")
    head, _ = _read_import_head(paths)
    if head["ledger_id"] != continuity_head["ledger_id"]:
        raise _error("state_invalid")
    raw = _read_journal(paths)
    records = _verify_journal_snapshot(
        raw,
        head,
        config=config,
        public_keys=public_keys,
        entries=entries,
    )
    return records, head, raw


def _suppressed_ids(records: Sequence[Mapping[str, Any]]) -> set[str]:
    return {
        str(record["result"]["target_entry_id"])
        for record in records
        if record["operation"] == "suppress"
    }


def effective_entries(
    entries: Sequence[Mapping[str, Any]],
    records: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return projection-safe entries without tombstones or resurrection.

    Supersession edges are computed from the full immutable ledger before
    tombstones are applied.  Otherwise suppressing a newer correction could
    accidentally resurrect the older record that it superseded.
    """

    invisible = _suppressed_ids(records)
    invisible.update(
        str(entry["supersedes_entry_id"])
        for entry in entries
        if entry.get("supersedes_entry_id") is not None
    )
    return [
        dict(entry)
        for entry in entries
        if str(entry.get("entry_id")) not in invisible
    ]


def projection_state(
    runtime_home: str | Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Verify one atomic read snapshot and apply every durable tombstone.

    This is the sole read-path bridge used by continuity capsule generation.
    The immutable ledger, importer journal, signed replay bindings, and any
    recoverable pending transaction are reconciled while holding the same
    exclusive continuity lock.  A removed configuration may never make an
    existing tombstone disappear: stale importer state without its verifier
    configuration fails closed.
    """

    paths = runtime_paths(runtime_home)
    root = continuity._validate_store_root(paths.store)  # noqa: SLF001
    with continuity._store_lock(root, exclusive=True):  # noqa: SLF001
        pending = _read_pending_raw(paths)
        if not _config_present(paths):
            if pending is not None:
                if _transaction_kind(pending) != "ordinary":
                    raise _error("configuration_missing")
                try:
                    continuity._recover_transaction_unlocked(root)  # noqa: SLF001
                except continuity.ContinuityError:
                    raise _error("store_invalid") from None
            if any(_journal_presence(paths)):
                raise _error("configuration_missing")
            entries, head = continuity._verify_store_unlocked(root)  # noqa: SLF001
            return [dict(entry) for entry in entries], dict(head)

        config, public_keys, _ = _load_protocol_material(paths)
        _recover_any_unlocked(
            paths,
            config=config,
            public_keys=public_keys,
        )
        entries, head = continuity._verify_store_unlocked(root)  # noqa: SLF001
        if config["ledger_id"] != head["ledger_id"]:
            raise _error("configuration_invalid")
        records, _, _ = _read_verified_import_state_unlocked(
            paths,
            config=config,
            public_keys=public_keys,
            entries=entries,
            continuity_head=head,
            allow_uninitialized=True,
        )
        return effective_entries(entries, records), dict(head)


def inspect_projection_state(runtime_home: str | Path) -> dict[str, Any]:
    """Verify the runtime-consumed projection without recovery or mutation."""

    paths = runtime_paths(runtime_home)
    root = continuity._validate_store_root(paths.store)  # noqa: SLF001
    with continuity._store_lock(root, exclusive=False):  # noqa: SLF001
        if _read_pending_raw(paths) is not None:
            raise _error("transaction_pending")
        if not _config_present(paths):
            if any(_journal_presence(paths)):
                raise _error("configuration_missing")
            entries, head = continuity._verify_store_unlocked(root)  # noqa: SLF001
            return {
                "schema_version": PROJECTION_INSPECTION_SCHEMA,
                "configured": False,
                "enabled": False,
                "continuity_sequence": head["sequence"],
                "effective_entry_count": len(entries),
                "import_state_initialized": False,
                "import_sequence": 0,
                "suppressed_entry_count": 0,
            }
        config, public_keys, _ = _load_protocol_material(paths)
        entries, head = continuity._verify_store_unlocked(root)  # noqa: SLF001
        if config["ledger_id"] != head["ledger_id"]:
            raise _error("configuration_invalid")
        records, import_head, _ = _read_verified_import_state_unlocked(
            paths,
            config=config,
            public_keys=public_keys,
            entries=entries,
            continuity_head=head,
            allow_uninitialized=True,
        )
        return {
            "schema_version": PROJECTION_INSPECTION_SCHEMA,
            "configured": True,
            "enabled": config["enabled"],
            "continuity_sequence": head["sequence"],
            "effective_entry_count": len(effective_entries(entries, records)),
            "import_state_initialized": import_head is not None,
            "import_sequence": len(records),
            "suppressed_entry_count": len(_suppressed_ids(records)),
        }


def _candidate_entry(
    *,
    verification: Mapping[str, Any],
    pre_head: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    if verification["effect"]["operation"] != "put":
        return None
    write = verification["continuity_write"]
    if type(write) is not dict:
        raise _error("state_invalid")
    try:
        normalized = continuity._normalize_typed_write_request(write)  # noqa: SLF001
    except continuity.ContinuityError:
        raise _error("state_invalid") from None
    if normalized != write or normalized["entry_id"] is None:
        raise _error("state_invalid")
    if len(entries) >= continuity.MAX_ENTRIES:
        raise _error("size_exceeded")
    if any(entry["entry_id"] == normalized["entry_id"] for entry in entries):
        raise _error("replay_conflict")
    recorded_at = verification["effect"]["issued_at"]
    candidate: dict[str, Any] = {
        "schema_version": continuity.ENTRY_SCHEMA,
        "ledger_id": pre_head["ledger_id"],
        "sequence": pre_head["sequence"] + 1,
        "previous_entry_sha256": pre_head["head_entry_sha256"],
        "entry_id": normalized["entry_id"],
        "recorded_at": recorded_at,
        "kind": normalized["kind"],
        "subject": normalized["subject"],
        "summary": normalized["summary"],
        "payload": normalized["payload"],
        "source": normalized["source"],
        "scope": normalized["scope"],
        "expires_at": normalized["expires_at"],
        "supersedes_entry_id": normalized["supersedes_entry_id"],
    }
    by_id = {str(entry["entry_id"]): entry for entry in entries}
    superseded = {
        str(entry["supersedes_entry_id"])
        for entry in entries
        if entry["supersedes_entry_id"] is not None
    }
    try:
        continuity._validate_supersession(  # noqa: SLF001
            candidate,
            by_id=by_id,
            superseded=superseded,
        )
    except continuity.ContinuityError:
        raise _error("state_invalid") from None
    candidate["entry_sha256"] = continuity.sha256_json(candidate)
    line = continuity.canonical_json(candidate) + b"\n"
    if (
        len(line) > continuity.MAX_LINE_BYTES
        or pre_head["ledger_size_bytes"] + len(line)
        > continuity.MAX_LEDGER_BYTES
    ):
        raise _error("size_exceeded")
    return candidate


def _validate_suppression_target(
    *,
    verification: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
    records: Sequence[Mapping[str, Any]],
) -> None:
    if verification["effect"]["operation"] != "suppress":
        return
    suppression = verification["suppression"]
    if type(suppression) is not dict:
        raise _error("state_invalid")
    target = next(
        (
            entry
            for entry in entries
            if entry["entry_id"] == suppression["target_entry_id"]
        ),
        None,
    )
    if target is None:
        raise _error("target_missing")
    if (
        target["entry_sha256"] != suppression["target_entry_sha256"]
        or target["scope"] != verification["effect"]["scope"]
    ):
        raise _error("target_mismatch")
    if suppression["target_entry_id"] in _suppressed_ids(records):
        raise _error("target_suppressed")


def _new_transaction(
    *,
    verification: Mapping[str, Any],
    envelope: Mapping[str, Any],
    pre_continuity_head: Mapping[str, Any],
    candidate_entry: Mapping[str, Any] | None,
    pre_import_head: Mapping[str, Any],
) -> dict[str, Any]:
    candidate_entry_line = (
        None
        if candidate_entry is None
        else (continuity.canonical_json(candidate_entry) + b"\n").decode("ascii")
    )
    if candidate_entry is None:
        post_continuity_head = dict(pre_continuity_head)
    else:
        encoded = candidate_entry_line.encode("ascii")
        post_continuity_head = continuity._new_head(  # noqa: SLF001
            ledger_id=pre_continuity_head["ledger_id"],
            sequence=candidate_entry["sequence"],
            entry_sha256=candidate_entry["entry_sha256"],
            ledger_size_bytes=(
                pre_continuity_head["ledger_size_bytes"] + len(encoded)
            ),
            updated_at=candidate_entry["recorded_at"],
        )
    record = _new_import_record(
        pre_head=pre_import_head,
        envelope=envelope,
        verification=verification,
        candidate_entry=candidate_entry,
    )
    record_line = continuity.canonical_json(record) + b"\n"
    if (
        len(record_line) > MAX_RECORD_BYTES
        or pre_import_head["journal_size_bytes"] + len(record_line)
        > MAX_JOURNAL_BYTES
        or pre_import_head["sequence"] >= MAX_JOURNAL_RECORDS
    ):
        raise _error("size_exceeded")
    post_import_head = _new_import_head(
        ledger_id=pre_import_head["ledger_id"],
        sequence=record["sequence"],
        head_record_sha256=record["record_sha256"],
        journal_size_bytes=(
            pre_import_head["journal_size_bytes"] + len(record_line)
        ),
        updated_at=record["recorded_at"],
    )
    base = {
        "schema_version": IMPORT_TRANSACTION_SCHEMA,
        "envelope_sha256": verification["envelope_sha256"],
        "pre_continuity_head": dict(pre_continuity_head),
        "candidate_entry": (
            None if candidate_entry is None else dict(candidate_entry)
        ),
        "candidate_entry_canonical_line": candidate_entry_line,
        "post_continuity_head": post_continuity_head,
        "pre_import_head": dict(pre_import_head),
        "candidate_record": record,
        "candidate_record_canonical_line": record_line.decode("ascii"),
        "post_import_head": post_import_head,
    }
    return {**base, "transaction_sha256": continuity.sha256_json(base)}


def _parse_transaction_raw(raw: bytes) -> dict[str, Any]:
    if (
        not raw.endswith(b"\n")
        or raw.count(b"\n") != 1
        or len(raw) > MAX_TRANSACTION_BYTES
    ):
        raise _error("state_invalid")
    try:
        value = continuity._parse_json(  # noqa: SLF001
            raw,
            field="continuity import transaction",
        )
    except continuity.ContinuityError:
        raise _error("state_invalid") from None
    if type(value) is not dict:
        raise _error("state_invalid")
    try:
        canonical = continuity.canonical_json(value) + b"\n"
    except continuity.ContinuityError:
        raise _error("state_invalid") from None
    if not hmac.compare_digest(raw, canonical):
        raise _error("state_invalid")
    return value


def _read_pending_raw(paths: RuntimePaths) -> bytes | None:
    try:
        paths.transaction.lstat()
    except FileNotFoundError:
        return None
    return _read_private(
        paths.transaction,
        field="continuity transaction",
        maximum_bytes=MAX_TRANSACTION_BYTES,
    )


def _transaction_kind(raw: bytes) -> str:
    value = _parse_transaction_raw(raw)
    schema = value.get("schema_version")
    if schema == IMPORT_TRANSACTION_SCHEMA:
        return "import"
    if schema == continuity.TRANSACTION_SCHEMA:
        return "ordinary"
    raise _error("state_invalid")


def _validate_transaction(
    value: Any,
    *,
    config: Mapping[str, Any],
    public_keys: Mapping[str, bytes],
    pre_entries: Sequence[Mapping[str, Any]],
    pre_records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {
        "schema_version",
        "envelope_sha256",
        "pre_continuity_head",
        "candidate_entry",
        "candidate_entry_canonical_line",
        "post_continuity_head",
        "pre_import_head",
        "candidate_record",
        "candidate_record_canonical_line",
        "post_import_head",
        "transaction_sha256",
    }:
        raise _error("state_invalid")
    if value.get("schema_version") != IMPORT_TRANSACTION_SCHEMA:
        raise _error("state_invalid")
    base = dict(value)
    observed_transaction_digest = base.pop("transaction_sha256", None)
    if (
        type(observed_transaction_digest) is not str
        or continuity.SHA256_RE.fullmatch(observed_transaction_digest) is None
        or not hmac.compare_digest(
            observed_transaction_digest,
            continuity.sha256_json(base),
        )
    ):
        raise _error("state_invalid")
    pre_continuity_head = continuity._validate_head(  # noqa: SLF001
        value.get("pre_continuity_head")
    )
    post_continuity_head = continuity._validate_head(  # noqa: SLF001
        value.get("post_continuity_head")
    )
    pre_import_head = _validate_import_head(value.get("pre_import_head"))
    post_import_head = _validate_import_head(value.get("post_import_head"))
    record = _validate_import_record_structure(
        value.get("candidate_record"),
        expected_sequence=pre_import_head["sequence"] + 1,
        expected_previous=pre_import_head["head_record_sha256"],
    )
    if record["envelope_sha256"] != value.get("envelope_sha256"):
        raise _error("state_invalid")
    try:
        verification = protocol.verify_for_replay(
            protocol.canonical_json(record["envelope"]),
            config=config,
            public_keys=dict(public_keys),
            expected_envelope_sha256=value.get("envelope_sha256"),
        )
    except protocol.ContinuityProtocolError:
        raise _error("state_invalid") from None
    if (
        not _heads_match(
            verification["expected_head"],
            pre_continuity_head,
        )
        or pre_import_head["ledger_id"] != pre_continuity_head["ledger_id"]
        or pre_import_head["updated_at"] > verification["effect"]["issued_at"]
    ):
        raise _error("state_invalid")
    expected_candidate = _candidate_entry(
        verification=verification,
        pre_head=pre_continuity_head,
        entries=pre_entries,
    )
    _validate_suppression_target(
        verification=verification,
        entries=pre_entries,
        records=pre_records,
    )
    if expected_candidate != value.get("candidate_entry"):
        raise _error("state_invalid")
    expected = _new_transaction(
        verification=verification,
        envelope=record["envelope"],
        pre_continuity_head=pre_continuity_head,
        candidate_entry=expected_candidate,
        pre_import_head=pre_import_head,
    )
    if expected != value:
        raise _error("state_invalid")
    if (
        post_continuity_head != expected["post_continuity_head"]
        or post_import_head != expected["post_import_head"]
    ):
        raise _error("state_invalid")
    return dict(value)


def _append_exact(
    path: Path,
    line: bytes,
    *,
    expected_size: int,
    maximum_bytes: int,
    field: str,
) -> None:
    try:
        fd = os.open(
            path,
            continuity._file_flags(os.O_WRONLY | os.O_APPEND),  # noqa: SLF001
        )
    except OSError:
        raise _error("io_error") from None
    try:
        try:
            info = continuity._validate_open_file(  # noqa: SLF001
                fd,
                path,
                field=field,
                maximum_bytes=maximum_bytes,
            )
        except continuity.ContinuityError:
            raise _error("state_unsafe") from None
        if info.st_size != expected_size:
            raise _error("state_invalid")
        if expected_size + len(line) > maximum_bytes:
            raise _error("size_exceeded")
        continuity._write_all(fd, line)  # noqa: SLF001
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_exact(
    path: Path,
    *,
    expected_raw: bytes,
    maximum_bytes: int,
    field: str,
) -> None:
    try:
        fd = os.open(path, continuity._file_flags(os.O_RDWR))  # noqa: SLF001
    except OSError:
        raise _error("io_error") from None
    try:
        try:
            info = continuity._validate_open_file(  # noqa: SLF001
                fd,
                path,
                field=field,
                maximum_bytes=maximum_bytes,
            )
        except continuity.ContinuityError:
            raise _error("state_unsafe") from None
        if info.st_size != len(expected_raw):
            raise _error("state_invalid")
        os.fsync(fd)
    finally:
        os.close(fd)
    if _read_private(
        path,
        field=field,
        maximum_bytes=maximum_bytes,
    ) != expected_raw:
        raise _error("state_invalid")


def _transaction_checkpoint(_: str) -> None:
    """No-op seam for durability-boundary crash tests."""


def _clear_transaction(paths: RuntimePaths, *, expected_raw: bytes) -> None:
    try:
        continuity._clear_transaction_unlocked(  # noqa: SLF001
            paths.store,
            expected_raw=expected_raw,
        )
    except continuity.ContinuityError:
        raise _error("state_invalid") from None


def _commit_new_transaction_unlocked(
    paths: RuntimePaths,
    *,
    transaction: Mapping[str, Any],
    transaction_raw: bytes,
) -> dict[str, Any]:
    pre_continuity = transaction["pre_continuity_head"]
    post_continuity = transaction["post_continuity_head"]
    entry_line_text = transaction["candidate_entry_canonical_line"]
    if entry_line_text is not None:
        entry_line = entry_line_text.encode("ascii")
        _append_exact(
            paths.store / continuity.LEDGER_FILENAME,
            entry_line,
            expected_size=pre_continuity["ledger_size_bytes"],
            maximum_bytes=continuity.MAX_LEDGER_BYTES,
            field="continuity ledger",
        )
        _transaction_checkpoint("continuity_ledger_fsynced")
        continuity._atomic_write(  # noqa: SLF001
            paths.store / continuity.HEAD_FILENAME,
            continuity.canonical_json(post_continuity) + b"\n",
        )
        _transaction_checkpoint("continuity_head_fsynced")
    pre_import = transaction["pre_import_head"]
    record_line = transaction["candidate_record_canonical_line"].encode("ascii")
    _append_exact(
        paths.journal,
        record_line,
        expected_size=pre_import["journal_size_bytes"],
        maximum_bytes=MAX_JOURNAL_BYTES,
        field="continuity import journal",
    )
    _transaction_checkpoint("import_journal_fsynced")
    continuity._atomic_write(  # noqa: SLF001
        paths.journal_head,
        continuity.canonical_json(transaction["post_import_head"]) + b"\n",
    )
    _transaction_checkpoint("import_head_fsynced")
    _clear_transaction(paths, expected_raw=transaction_raw)
    _transaction_checkpoint("transaction_cleared")
    return dict(transaction["candidate_record"])


def _recover_import_transaction_unlocked(
    paths: RuntimePaths,
    *,
    raw: bytes,
    config: Mapping[str, Any],
    public_keys: Mapping[str, bytes],
) -> dict[str, Any] | None:
    value = _parse_transaction_raw(raw)
    pre_continuity = continuity._validate_head(  # noqa: SLF001
        value.get("pre_continuity_head")
    )
    pre_import = _validate_import_head(value.get("pre_import_head"))
    current_continuity_head, _ = continuity._read_head_unlocked(  # noqa: SLF001
        paths.store
    )
    current_import_head, _ = _read_import_head(paths)
    ledger_raw = continuity._read_ledger_unlocked(paths.store)  # noqa: SLF001
    journal_raw = _read_journal(paths)
    pre_ledger_size = pre_continuity["ledger_size_bytes"]
    pre_journal_size = pre_import["journal_size_bytes"]
    if len(ledger_raw) < pre_ledger_size or len(journal_raw) < pre_journal_size:
        raise _error("state_invalid")
    pre_entries = continuity._verify_ledger_snapshot(  # noqa: SLF001
        ledger_raw[:pre_ledger_size],
        pre_continuity,
    )
    pre_records = _verify_journal_snapshot(
        journal_raw[:pre_journal_size],
        pre_import,
        config=config,
        public_keys=public_keys,
        entries=pre_entries,
    )
    transaction = _validate_transaction(
        value,
        config=config,
        public_keys=public_keys,
        pre_entries=pre_entries,
        pre_records=pre_records,
    )
    post_continuity = transaction["post_continuity_head"]
    post_import = transaction["post_import_head"]
    entry_line_text = transaction["candidate_entry_canonical_line"]
    record_line = transaction["candidate_record_canonical_line"].encode("ascii")

    if entry_line_text is None:
        if (
            current_continuity_head != pre_continuity
            or ledger_raw != ledger_raw[:pre_ledger_size]
        ):
            raise _error("state_invalid")
        continuity_state = "complete"
    else:
        entry_line = entry_line_text.encode("ascii")
        post_ledger = ledger_raw[:pre_ledger_size] + entry_line
        if (
            current_continuity_head == pre_continuity
            and ledger_raw == ledger_raw[:pre_ledger_size]
        ):
            continuity_state = "untouched"
        elif (
            current_continuity_head == pre_continuity
            and ledger_raw == post_ledger
        ):
            continuity_state = "tail"
        elif (
            current_continuity_head == post_continuity
            and ledger_raw == post_ledger
        ):
            continuity_state = "complete"
        else:
            raise _error("state_invalid")

    post_journal = journal_raw[:pre_journal_size] + record_line
    if (
        current_import_head == pre_import
        and journal_raw == journal_raw[:pre_journal_size]
    ):
        journal_state = "untouched"
    elif current_import_head == pre_import and journal_raw == post_journal:
        journal_state = "tail"
    elif current_import_head == post_import and journal_raw == post_journal:
        journal_state = "complete"
    else:
        raise _error("state_invalid")

    if (
        continuity_state == "untouched" and journal_state != "untouched"
    ) or (continuity_state == "tail" and journal_state != "untouched"):
        raise _error("state_invalid")
    if continuity_state == "untouched" and journal_state == "untouched":
        _clear_transaction(paths, expected_raw=raw)
        return None
    if entry_line_text is None and journal_state == "untouched":
        # A suppression intent with no durable journal effect is abandoned.
        _clear_transaction(paths, expected_raw=raw)
        return None
    if continuity_state == "tail":
        _fsync_exact(
            paths.store / continuity.LEDGER_FILENAME,
            expected_raw=ledger_raw,
            maximum_bytes=continuity.MAX_LEDGER_BYTES,
            field="continuity ledger",
        )
        continuity._atomic_write(  # noqa: SLF001
            paths.store / continuity.HEAD_FILENAME,
            continuity.canonical_json(post_continuity) + b"\n",
        )
        continuity_state = "complete"
    if continuity_state != "complete":
        raise _error("state_invalid")
    if journal_state == "untouched":
        _append_exact(
            paths.journal,
            record_line,
            expected_size=pre_journal_size,
            maximum_bytes=MAX_JOURNAL_BYTES,
            field="continuity import journal",
        )
        journal_state = "tail"
    if journal_state == "tail":
        expected_journal = journal_raw[:pre_journal_size] + record_line
        _fsync_exact(
            paths.journal,
            expected_raw=expected_journal,
            maximum_bytes=MAX_JOURNAL_BYTES,
            field="continuity import journal",
        )
        continuity._atomic_write(  # noqa: SLF001
            paths.journal_head,
            continuity.canonical_json(post_import) + b"\n",
        )
    _clear_transaction(paths, expected_raw=raw)
    return dict(transaction["candidate_record"])


def _recover_any_unlocked(
    paths: RuntimePaths,
    *,
    config: Mapping[str, Any],
    public_keys: Mapping[str, bytes],
) -> dict[str, Any] | None:
    raw = _read_pending_raw(paths)
    if raw is None:
        return None
    kind = _transaction_kind(raw)
    if kind == "ordinary":
        try:
            continuity._recover_transaction_unlocked(paths.store)  # noqa: SLF001
        except continuity.ContinuityError:
            raise _error("store_invalid") from None
        return None
    return _recover_import_transaction_unlocked(
        paths,
        raw=raw,
        config=config,
        public_keys=public_keys,
    )


def _heads_match(first: Mapping[str, Any], second: Mapping[str, Any]) -> bool:
    return hmac.compare_digest(
        continuity.canonical_json(dict(first)),
        continuity.canonical_json(dict(second)),
    )


def _public_record_result(
    record: Mapping[str, Any],
    *,
    replayed: bool,
) -> dict[str, Any]:
    result = record["result"]
    projection: dict[str, Any] = {
        "schema_version": IMPORT_RESULT_SCHEMA,
        "ok": True,
        "disposition": "replayed" if replayed else "committed",
        "operation": record["operation"],
        "write_id": record["write_id"],
        "envelope_sha256": record["envelope_sha256"],
        "journal_sequence": record["sequence"],
        "record_sha256": record["record_sha256"],
    }
    if record["operation"] == "put":
        projection["entry_id"] = result["entry_id"]
        projection["entry_sha256"] = result["entry_sha256"]
    else:
        projection["target_entry_id"] = result["target_entry_id"]
        projection["target_entry_sha256"] = result["target_entry_sha256"]
        projection["reason"] = result["reason"]
    return projection


def admit_envelope(
    runtime_home: str | Path,
    raw_envelope: bytes,
    *,
    now: Any = None,
) -> dict[str, Any]:
    """Verify and atomically admit one exact signed envelope."""

    if type(raw_envelope) is not bytes:
        raise _error("envelope_invalid")
    paths = runtime_paths(runtime_home)
    try:
        root = continuity._validate_store_root(paths.store)  # noqa: SLF001
    except continuity.ContinuityError:
        raise
    with continuity._store_lock(root, exclusive=True):  # noqa: SLF001
        config, public_keys, _ = _load_protocol_material(paths)
        _recover_any_unlocked(
            paths,
            config=config,
            public_keys=public_keys,
        )
        entries, continuity_head = continuity._verify_store_unlocked(  # noqa: SLF001
            root
        )
        if config["ledger_id"] != continuity_head["ledger_id"]:
            raise _error("configuration_invalid")
        try:
            envelope = protocol.parse_envelope(raw_envelope)
            envelope_digest = protocol.envelope_sha256(envelope)
        except protocol.ContinuityProtocolError:
            raise
        journal_present, journal_head_present = _journal_presence(paths)
        if journal_present != journal_head_present:
            raise _error("state_invalid")
        if journal_present:
            records, import_head, _ = _read_verified_import_state_unlocked(
                paths,
                config=config,
                public_keys=public_keys,
                entries=entries,
                continuity_head=continuity_head,
            )
            if import_head is None:
                raise _error("state_invalid")
        else:
            records = []
            import_head = None
        existing = next(
            (
                record
                for record in records
                if record["envelope_sha256"] == envelope_digest
            ),
            None,
        )
        if existing is not None:
            try:
                replay = protocol.verify_for_replay(
                    raw_envelope,
                    config=config,
                    public_keys=public_keys,
                    expected_envelope_sha256=existing["envelope_sha256"],
                )
            except protocol.ContinuityProtocolError:
                raise
            if (
                replay["effect"]["write_id"] != existing["write_id"]
                or protocol.canonical_json(envelope)
                != protocol.canonical_json(existing["envelope"])
            ):
                raise _error("replay_conflict")
            return _public_record_result(existing, replayed=True)
        write_id = envelope["effect"]["write_id"]
        if any(record["write_id"] == write_id for record in records):
            raise _error("replay_conflict")
        try:
            verification = protocol.verify_for_new_admission(
                raw_envelope,
                config=config,
                public_keys=public_keys,
                now=now,
            )
        except protocol.ContinuityProtocolError:
            raise
        if not _heads_match(
            verification["expected_head"],
            continuity_head,
        ):
            raise _error("expected_head_mismatch")
        _validate_suppression_target(
            verification=verification,
            entries=entries,
            records=records,
        )
        candidate = _candidate_entry(
            verification=verification,
            pre_head=continuity_head,
            entries=entries,
        )
        if import_head is None:
            # A disabled, stale, malformed, or otherwise denied fresh
            # envelope reaches none of these durable initialization writes.
            _ensure_journal_unlocked(paths, continuity_head=continuity_head)
            records, import_head, _ = _read_verified_import_state_unlocked(
                paths,
                config=config,
                public_keys=public_keys,
                entries=entries,
                continuity_head=continuity_head,
            )
            if records or import_head is None:
                raise _error("state_invalid")
        if (
            import_head["updated_at"] > verification["effect"]["issued_at"]
        ):
            raise _error("state_invalid")
        transaction = _new_transaction(
            verification=verification,
            envelope=envelope,
            pre_continuity_head=continuity_head,
            candidate_entry=candidate,
            pre_import_head=import_head,
        )
        transaction_raw = continuity.canonical_json(transaction) + b"\n"
        if len(transaction_raw) > MAX_TRANSACTION_BYTES:
            raise _error("size_exceeded")
        if _read_pending_raw(paths) is not None:
            raise _error("transaction_pending")
        continuity._atomic_write(paths.transaction, transaction_raw)  # noqa: SLF001
        _transaction_checkpoint("intent_fsynced")
        record = _commit_new_transaction_unlocked(
            paths,
            transaction=transaction,
            transaction_raw=transaction_raw,
        )
        return _public_record_result(record, replayed=False)


def _repair_empty_import_initialization_unlocked(
    paths: RuntimePaths,
) -> bool:
    journal_present, head_present = _journal_presence(paths)
    if head_present and not journal_present:
        raise _error("state_invalid")
    if not journal_present or head_present:
        return False
    if _read_journal(paths) != b"":
        raise _error("state_invalid")
    entries, continuity_head = continuity._verify_store_unlocked(  # noqa: SLF001
        paths.store
    )
    # Reading and verifying entries is intentional even though only the head
    # is needed: repair is permitted solely from a fully valid continuity
    # projection, never from a guessed or partially verified head.
    if len(entries) != continuity_head["sequence"]:
        raise _error("state_invalid")
    _ensure_journal_unlocked(paths, continuity_head=continuity_head)
    return True


def recover_runtime(runtime_home: str | Path) -> dict[str, Any]:
    paths = runtime_paths(runtime_home)
    root = continuity._validate_store_root(paths.store)  # noqa: SLF001
    with continuity._store_lock(root, exclusive=True):  # noqa: SLF001
        config, public_keys, _ = _load_protocol_material(paths)
        raw = _read_pending_raw(paths)
        if raw is None:
            if _repair_empty_import_initialization_unlocked(paths):
                return {
                    "schema_version": IMPORT_RESULT_SCHEMA,
                    "ok": True,
                    "disposition": "repaired_empty_import_state",
                }
            return {
                "schema_version": IMPORT_RESULT_SCHEMA,
                "ok": True,
                "disposition": "no_recovery_needed",
            }
        kind = _transaction_kind(raw)
        if kind == "ordinary":
            try:
                continuity._recover_transaction_unlocked(root)  # noqa: SLF001
            except continuity.ContinuityError:
                raise _error("store_invalid") from None
            _repair_empty_import_initialization_unlocked(paths)
            return {
                "schema_version": IMPORT_RESULT_SCHEMA,
                "ok": True,
                "disposition": "ordinary_transaction_reconciled",
            }
        recovered = _recover_import_transaction_unlocked(
            paths,
            raw=raw,
            config=config,
            public_keys=public_keys,
        )
        if recovered is None:
            return {
                "schema_version": IMPORT_RESULT_SCHEMA,
                "ok": True,
                "disposition": "abandoned_unstarted_intent",
            }
        return _public_record_result(recovered, replayed=True)


def _verified_runtime_state(
    paths: RuntimePaths,
    *,
    allow_uninitialized: bool,
) -> tuple[
    dict[str, Any],
    dict[str, bytes],
    str,
    list[dict[str, Any]],
    dict[str, Any],
    list[dict[str, Any]],
    dict[str, Any] | None,
]:
    root = continuity._validate_store_root(paths.store)  # noqa: SLF001
    with continuity._store_lock(root, exclusive=False):  # noqa: SLF001
        if _read_pending_raw(paths) is not None:
            raise _error("transaction_pending")
        config, keys, config_sha256 = _load_protocol_material(paths)
        entries, continuity_head = continuity._verify_store_unlocked(  # noqa: SLF001
            root
        )
        if config["ledger_id"] != continuity_head["ledger_id"]:
            raise _error("configuration_invalid")
        records, import_head, _ = _read_verified_import_state_unlocked(
            paths,
            config=config,
            public_keys=keys,
            entries=entries,
            continuity_head=continuity_head,
            allow_uninitialized=allow_uninitialized,
        )
        return (
            config,
            keys,
            config_sha256,
            entries,
            continuity_head,
            records,
            import_head,
        )


def status(runtime_home: str | Path) -> dict[str, Any]:
    paths = runtime_paths(runtime_home)
    root = continuity._validate_store_root(paths.store)  # noqa: SLF001
    with continuity._store_lock(root, exclusive=False):  # noqa: SLF001
        pending = _read_pending_raw(paths)
        if not _config_present(paths):
            if pending is not None:
                return {
                    "schema_version": IMPORT_STATUS_SCHEMA,
                    "ok": True,
                    "configured": False,
                    "enabled": False,
                    "recovery_pending": True,
                }
            entries, head = continuity._verify_store_unlocked(root)  # noqa: SLF001
            return {
                "schema_version": IMPORT_STATUS_SCHEMA,
                "ok": True,
                "configured": False,
                "enabled": False,
                "recovery_pending": pending is not None,
                "continuity_sequence": head["sequence"],
                "continuity_head_sha256": head["head_sha256"],
                "import_state_initialized": any(_journal_presence(paths)),
                "import_sequence": 0,
                "effective_entry_count": len(entries),
            }
        if pending is not None:
            config, _, _ = _load_protocol_material(paths)
            return {
                "schema_version": IMPORT_STATUS_SCHEMA,
                "ok": True,
                "configured": True,
                "enabled": config["enabled"],
                "recovery_pending": True,
            }
    (
        config,
        keys,
        _,
        entries,
        head,
        records,
        import_head,
    ) = _verified_runtime_state(paths, allow_uninitialized=True)
    return {
        "schema_version": IMPORT_STATUS_SCHEMA,
        "ok": True,
        "configured": True,
        "enabled": config["enabled"],
        "recovery_pending": False,
        "public_key_count": len(keys),
        "active_key_count": sum(
            policy["state"] == "active" for policy in config["key_policies"]
        ),
        "continuity_sequence": head["sequence"],
        "continuity_head_sha256": head["head_sha256"],
        "import_state_initialized": import_head is not None,
        "import_sequence": len(records),
        "effective_entry_count": len(effective_entries(entries, records)),
        "suppressed_entry_count": len(_suppressed_ids(records)),
    }


def verify_runtime(runtime_home: str | Path) -> dict[str, Any]:
    paths = runtime_paths(runtime_home)
    (
        config,
        keys,
        config_sha256,
        entries,
        head,
        records,
        import_head,
    ) = _verified_runtime_state(paths, allow_uninitialized=True)
    return {
        "schema_version": IMPORT_VERIFY_SCHEMA,
        "ok": True,
        "enabled": config["enabled"],
        "config_sha256": config_sha256,
        "public_key_count": len(keys),
        "continuity_sequence": head["sequence"],
        "continuity_head_sha256": head["head_sha256"],
        "import_state_initialized": import_head is not None,
        "import_sequence": len(records),
        "import_head_sha256": (
            None if import_head is None else import_head["head_sha256"]
        ),
        "effective_entry_count": len(effective_entries(entries, records)),
        "suppressed_entry_count": len(_suppressed_ids(records)),
    }


def inspect_runtime(
    runtime_home: str | Path,
    *,
    limit: int = 20,
) -> dict[str, Any]:
    if type(limit) is not int or not 1 <= limit <= MAX_INSPECTION_RECORDS:
        raise _error("state_invalid")
    paths = runtime_paths(runtime_home)
    (
        config,
        _,
        _,
        entries,
        head,
        records,
        _,
    ) = _verified_runtime_state(paths, allow_uninitialized=True)
    selected = records[-limit:]
    projections: list[dict[str, Any]] = []
    for record in selected:
        result = record["result"]
        item: dict[str, Any] = {
            "sequence": record["sequence"],
            "recorded_at": record["recorded_at"],
            "write_id": record["write_id"],
            "operation": record["operation"],
            "envelope_sha256": record["envelope_sha256"],
            "record_sha256": record["record_sha256"],
            "privacy": record["envelope"]["effect"]["scope"]["privacy"],
        }
        if record["operation"] == "put":
            item["entry_id"] = result["entry_id"]
            item["entry_sha256"] = result["entry_sha256"]
            item["entry_kind"] = record["envelope"]["effect"]["put"]["kind"]
        else:
            item["target_entry_id"] = result["target_entry_id"]
            item["target_entry_sha256"] = result["target_entry_sha256"]
            item["reason"] = result["reason"]
        projections.append(item)
    output = {
        "schema_version": IMPORT_INSPECTION_SCHEMA,
        "ok": True,
        "enabled": config["enabled"],
        "continuity_head_sha256": head["head_sha256"],
        "import_sequence": len(records),
        "effective_entry_count": len(effective_entries(entries, records)),
        "records": projections,
        "redacted": True,
    }
    if len(continuity.canonical_json(output)) > MAX_OUTPUT_BYTES:
        raise _error("size_exceeded")
    return output


def _read_envelope_file(path: str | Path) -> bytes:
    selected = _normalized_absolute(path, code="state_unsafe")
    return _read_private(
        selected,
        field="signed continuity envelope",
        maximum_bytes=protocol.MAX_ENVELOPE_BYTES,
    )


def _write_output(value: Mapping[str, Any]) -> None:
    raw = continuity.canonical_json(dict(value)) + b"\n"
    if len(raw) > MAX_OUTPUT_BYTES:
        raise _error("size_exceeded")
    sys.stdout.buffer.write(raw)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Credential-free signed John Lomein continuity importer"
    )
    parser.add_argument(
        "--runtime-home",
        required=True,
        help="absolute John runtime home; importer paths are derived exactly",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="show bounded importer status")
    commands.add_parser("verify", help="verify continuity and importer state")
    inspect_parser = commands.add_parser(
        "inspect",
        help="inspect redacted importer metadata",
    )
    inspect_parser.add_argument(
        "--limit",
        type=int,
        default=20,
    )
    admit_parser = commands.add_parser(
        "admit",
        help="verify and admit one canonical signed envelope",
    )
    admit_parser.add_argument("--envelope", required=True)
    commands.add_parser(
        "recover",
        help="recover one exact interrupted importer transaction",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "status":
            result = status(args.runtime_home)
        elif args.command == "verify":
            result = verify_runtime(args.runtime_home)
        elif args.command == "inspect":
            result = inspect_runtime(args.runtime_home, limit=args.limit)
        elif args.command == "admit":
            result = admit_envelope(
                args.runtime_home,
                _read_envelope_file(args.envelope),
            )
        elif args.command == "recover":
            result = recover_runtime(args.runtime_home)
        else:
            raise _error("state_invalid")
        _write_output(result)
        return 0
    except (
        ContinuityImporterError,
        protocol.ContinuityProtocolError,
        continuity.ContinuityError,
        OSError,
    ) as exc:
        _write_output(public_error(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
