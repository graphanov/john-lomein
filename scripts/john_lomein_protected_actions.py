#!/usr/bin/env python3
"""Prepare request-only packets for GitHub actions owned by an isolated broker.

This module has no execution path for the protected action. It validates and
persists a narrow, expiring request that a separately isolated broker must
revalidate against live GitHub state before doing anything.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


INPUT_SCHEMA = "john-lomein.protected-action-input.v1"
PACKET_SCHEMA = "john-lomein.protected-action-packet.v1"
VERIFY_SCHEMA = "john-lomein.protected-action-verification.v1"
AUTHORITY = "request_only_no_execution_authority"
ALLOWED_ACTIONS = frozenset(
    {"mark_pr_ready", "resolve_review_thread"}
)
MAX_JSON_BYTES = 256 * 1024
MAX_THREADS = 50
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 3600
MAX_CLOCK_SKEW_SECONDS = 300
MAX_EVIDENCE_AGE_SECONDS = 3600
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$")
REPO_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PACKET_ID_RE = re.compile(r"^jlpa-[0-9a-f]{24}$")
LOGIN_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9-]{0,98}(?:\[bot\])?$"
)
INSTANCE_SLUG_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)
OUTBOX_LOCATOR_PREFIX = Path("state/protected-actions/outbox")


class ProtectedActionError(ValueError):
    """A public-safe packet validation failure."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise ProtectedActionError(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ProtectedActionError(
            f"{field} must be a UTC timestamp"
        ) from exc
    return parsed


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtectedActionError(
                "JSON object contains duplicate fields"
            )
        result[key] = value
    return result


def _reject_nonfinite(_: str) -> None:
    raise ProtectedActionError("JSON contains a non-finite number")


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtectedActionError(f"{field} must be an object")
    return value


def _strict_keys(
    value: dict[str, Any],
    *,
    field: str,
    allowed: set[str],
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ProtectedActionError(f"{field} contains unknown fields")


def _positive_int(
    value: Any,
    *,
    field: str,
    maximum: int = 2**31 - 1,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtectedActionError(f"{field} must be an integer")
    if value <= 0 or value > maximum:
        raise ProtectedActionError(f"{field} is outside the allowed range")
    return value


def _github_url(
    value: Any,
    *,
    field: str,
    repo: str,
    pr_number: int,
    kind: str,
) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ProtectedActionError(f"{field} must be a GitHub URL")
    parsed = urlparse(value)
    expected_path = f"/{repo}/pull/{pr_number}"
    expected_fragment = {
        "pr": None,
        "evidence_comment": re.compile(r"^issuecomment-[1-9][0-9]*$"),
        "review_thread": re.compile(r"^discussion_r[1-9][0-9]*$"),
    }.get(kind)
    if kind not in {"pr", "evidence_comment", "review_thread"}:
        raise ProtectedActionError(f"{field} has an unsupported URL kind")
    if (
        parsed.scheme != "https"
        or parsed.netloc.lower() != "github.com"
        or parsed.path != expected_path
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.params
        or (
            kind == "pr"
            and bool(parsed.fragment)
        )
        or (
            expected_fragment is not None
            and not expected_fragment.fullmatch(parsed.fragment)
        )
    ):
        raise ProtectedActionError(f"{field} must target the bound PR")
    if kind == "pr":
        return f"https://github.com{expected_path}"
    return f"https://github.com{expected_path}#{parsed.fragment}"


def _normalize_input(raw: Any) -> dict[str, Any]:
    data = _mapping(raw, field="protected-action input")
    _strict_keys(
        data,
        field="protected-action input",
        allowed={
            "schema_version",
            "instance_slug",
            "action",
            "observed_at",
            "repo",
            "pr",
            "preconditions",
            "targets",
        },
    )
    if data.get("schema_version") != INPUT_SCHEMA:
        raise ProtectedActionError("protected-action input schema is unsupported")
    instance_slug = str(data.get("instance_slug") or "")
    if not INSTANCE_SLUG_RE.fullmatch(instance_slug):
        raise ProtectedActionError(
            "protected-action instance slug is invalid"
        )
    action = str(data.get("action") or "")
    if action not in ALLOWED_ACTIONS:
        raise ProtectedActionError("protected action is unsupported")
    observed_at = utc_text(
        parse_utc(
            data.get("observed_at"),
            field="protected-action input observed_at",
        )
    )
    repo = str(data.get("repo") or "")
    if not REPO_RE.fullmatch(repo):
        raise ProtectedActionError("protected-action repository is invalid")

    pr = _mapping(data.get("pr"), field="protected-action input pr")
    _strict_keys(
        pr,
        field="protected-action input pr",
        allowed={
            "number",
            "url",
            "base_branch",
            "head_sha",
            "author_login",
            "is_draft",
        },
    )
    number = _positive_int(
        pr.get("number"),
        field="protected-action input pr.number",
    )
    pr_url = _github_url(
        pr.get("url"),
        field="protected-action input pr.url",
        repo=repo,
        pr_number=number,
        kind="pr",
    )
    base_branch = str(pr.get("base_branch") or "")
    if not BRANCH_RE.fullmatch(base_branch):
        raise ProtectedActionError(
            "protected-action input pr.base_branch is invalid"
        )
    head_sha = str(pr.get("head_sha") or "").lower()
    if not OID_RE.fullmatch(head_sha):
        raise ProtectedActionError(
            "protected-action input pr.head_sha is invalid"
        )
    author_login = str(pr.get("author_login") or "")
    if not LOGIN_RE.fullmatch(author_login):
        raise ProtectedActionError(
            "protected-action input pr.author_login is invalid"
        )
    if type(pr.get("is_draft")) is not bool:
        raise ProtectedActionError(
            "protected-action input pr.is_draft must be boolean"
        )

    preconditions = _mapping(
        data.get("preconditions"),
        field="protected-action input preconditions",
    )
    _strict_keys(
        preconditions,
        field="protected-action input preconditions",
        allowed={
            "checks_state",
            "unresolved_thread_count",
            "forbidden_paths_clear",
            "bot_authorship_verified",
            "verification",
            "evidence_comment_url",
        },
    )
    checks_state = str(preconditions.get("checks_state") or "")
    if checks_state not in {"success", "none"}:
        raise ProtectedActionError(
            "protected-action checks must be green or legitimately absent"
        )
    thread_count = preconditions.get("unresolved_thread_count")
    if (
        isinstance(thread_count, bool)
        or not isinstance(thread_count, int)
        or thread_count < 0
        or thread_count > 10_000
    ):
        raise ProtectedActionError(
            "protected-action unresolved thread count is invalid"
        )
    if preconditions.get("forbidden_paths_clear") is not True:
        raise ProtectedActionError(
            "protected-action forbidden-path proof is required"
        )
    if preconditions.get("bot_authorship_verified") is not True:
        raise ProtectedActionError(
            "protected-action bot-authorship proof is required"
        )
    verification = _mapping(
        preconditions.get("verification"),
        field="protected-action input verification",
    )
    _strict_keys(
        verification,
        field="protected-action input verification",
        allowed={"passed", "commands_sha256", "result_sha256"},
    )
    if verification.get("passed") is not True:
        raise ProtectedActionError(
            "protected-action verification must have passed"
        )
    commands_sha256 = str(verification.get("commands_sha256") or "")
    result_sha256 = str(verification.get("result_sha256") or "")
    if not SHA256_RE.fullmatch(commands_sha256):
        raise ProtectedActionError(
            "protected-action verification command digest is invalid"
        )
    if not SHA256_RE.fullmatch(result_sha256):
        raise ProtectedActionError(
            "protected-action verification result digest is invalid"
        )
    evidence_comment_url = _github_url(
        preconditions.get("evidence_comment_url"),
        field="protected-action input evidence_comment_url",
        repo=repo,
        pr_number=number,
        kind="evidence_comment",
    )

    targets = _mapping(
        data.get("targets"),
        field="protected-action input targets",
    )
    _strict_keys(
        targets,
        field="protected-action input targets",
        allowed={"thread_node_ids", "thread_urls"},
    )
    node_ids = targets.get("thread_node_ids")
    thread_urls = targets.get("thread_urls")
    if not isinstance(node_ids, list) or not isinstance(thread_urls, list):
        raise ProtectedActionError(
            "protected-action thread targets must be arrays"
        )
    if len(node_ids) != len(thread_urls) or len(node_ids) > MAX_THREADS:
        raise ProtectedActionError(
            "protected-action thread targets are inconsistent"
        )
    normalized_ids: list[str] = []
    normalized_urls: list[str] = []
    for index, node_id in enumerate(node_ids):
        if not isinstance(node_id, str) or not TOKEN_RE.fullmatch(node_id):
            raise ProtectedActionError(
                f"protected-action thread node id {index} is invalid"
            )
        normalized_ids.append(node_id)
        normalized_urls.append(
            _github_url(
                thread_urls[index],
                field=f"protected-action thread URL {index}",
                repo=repo,
                pr_number=number,
                kind="review_thread",
            )
        )
    if len(set(normalized_ids)) != len(normalized_ids):
        raise ProtectedActionError(
            "protected-action thread node ids must be unique"
        )

    if action == "mark_pr_ready":
        if pr.get("is_draft") is not True:
            raise ProtectedActionError(
                "mark_pr_ready requires a currently draft PR"
            )
        if thread_count != 0:
            raise ProtectedActionError(
                "mark_pr_ready requires zero unresolved threads"
            )
        if normalized_ids:
            raise ProtectedActionError(
                "mark_pr_ready cannot carry review-thread targets"
            )
    else:
        if not normalized_ids:
            raise ProtectedActionError(
                "resolve_review_thread requires exact thread targets"
            )
        if thread_count < len(normalized_ids):
            raise ProtectedActionError(
                "thread targets exceed the observed unresolved count"
            )

    return {
        "schema_version": INPUT_SCHEMA,
        "instance_slug": instance_slug,
        "action": action,
        "observed_at": observed_at,
        "repo": repo,
        "pr": {
            "number": number,
            "url": pr_url,
            "base_branch": base_branch,
            "head_sha": head_sha,
            "author_login": author_login,
            "is_draft": bool(pr["is_draft"]),
        },
        "preconditions": {
            "checks_state": checks_state,
            "unresolved_thread_count": thread_count,
            "forbidden_paths_clear": True,
            "bot_authorship_verified": True,
            "verification": {
                "passed": True,
                "commands_sha256": commands_sha256,
                "result_sha256": result_sha256,
            },
            "evidence_comment_url": evidence_comment_url,
        },
        "targets": {
            "thread_node_ids": normalized_ids,
            "thread_urls": normalized_urls,
        },
    }


def prepare_packet(
    raw: Any,
    *,
    now: datetime | None = None,
    ttl_seconds: int = 900,
) -> dict[str, Any]:
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or ttl_seconds < MIN_TTL_SECONDS
        or ttl_seconds > MAX_TTL_SECONDS
    ):
        raise ProtectedActionError(
            "protected-action packet TTL is outside the allowed range"
        )
    normalized = _normalize_input(raw)
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    observed = parse_utc(
        normalized["observed_at"],
        field="protected-action observed_at",
    )
    if observed > now + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise ProtectedActionError(
            "protected-action evidence timestamp is in the future"
        )
    if observed < now - timedelta(seconds=MAX_EVIDENCE_AGE_SECONDS):
        raise ProtectedActionError(
            "protected-action evidence is stale"
        )
    body = {
        "schema_version": PACKET_SCHEMA,
        "authority": AUTHORITY,
        "requested_by": "john-lomein-maintainer",
        "created_at": utc_text(now),
        "expires_at": utc_text(now + timedelta(seconds=ttl_seconds)),
        "request": normalized,
    }
    digest = sha256_json(body)
    body["packet_id"] = f"jlpa-{digest[:24]}"
    body["request_digest"] = digest
    return body


def verify_packet(
    raw: Any,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    packet = _mapping(raw, field="protected-action packet")
    _strict_keys(
        packet,
        field="protected-action packet",
        allowed={
            "schema_version",
            "authority",
            "requested_by",
            "created_at",
            "expires_at",
            "request",
            "packet_id",
            "request_digest",
        },
    )
    if packet.get("schema_version") != PACKET_SCHEMA:
        raise ProtectedActionError("protected-action packet schema is unsupported")
    if packet.get("authority") != AUTHORITY:
        raise ProtectedActionError("protected-action packet authority is invalid")
    if packet.get("requested_by") != "john-lomein-maintainer":
        raise ProtectedActionError(
            "protected-action packet requester is invalid"
        )
    created = parse_utc(
        packet.get("created_at"),
        field="protected-action packet created_at",
    )
    expires = parse_utc(
        packet.get("expires_at"),
        field="protected-action packet expires_at",
    )
    ttl = int((expires - created).total_seconds())
    if ttl < MIN_TTL_SECONDS or ttl > MAX_TTL_SECONDS:
        raise ProtectedActionError(
            "protected-action packet lifetime is invalid"
        )
    normalized = _normalize_input(packet.get("request"))
    observed = parse_utc(
        normalized["observed_at"],
        field="protected-action observed_at",
    )
    if (
        observed > created + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS)
        or observed
        < created - timedelta(seconds=MAX_EVIDENCE_AGE_SECONDS)
    ):
        raise ProtectedActionError(
            "protected-action evidence is outside the packet freshness window"
        )
    body = {
        "schema_version": PACKET_SCHEMA,
        "authority": AUTHORITY,
        "requested_by": "john-lomein-maintainer",
        "created_at": utc_text(created),
        "expires_at": utc_text(expires),
        "request": normalized,
    }
    digest = sha256_json(body)
    expected_id = f"jlpa-{digest[:24]}"
    if packet.get("request_digest") != digest:
        raise ProtectedActionError(
            "protected-action packet digest does not match"
        )
    if packet.get("packet_id") != expected_id:
        raise ProtectedActionError(
            "protected-action packet id does not match"
        )
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if created > now + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise ProtectedActionError(
            "protected-action packet creation time is in the future"
        )
    if now >= expires:
        raise ProtectedActionError("protected-action packet has expired")
    return {
        **body,
        "packet_id": expected_id,
        "request_digest": digest,
    }


def load_json(path: Path, *, field: str) -> Any:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ProtectedActionError(f"{field} is unreadable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ProtectedActionError(
                f"{field} must be a regular non-symlink file"
            )
        if info.st_size > MAX_JSON_BYTES:
            raise ProtectedActionError(f"{field} exceeds its size limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                fd,
                min(64 * 1024, MAX_JSON_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_JSON_BYTES:
                raise ProtectedActionError(
                    f"{field} exceeds its size limit"
                )
        raw = b"".join(chunks)
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except ProtectedActionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProtectedActionError(f"{field} is invalid JSON") from exc
    finally:
        os.close(fd)


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_directory(path: Path, *, field: str) -> int:
    try:
        fd = os.open(path, _directory_flags())
    except OSError as exc:
        raise ProtectedActionError(f"{field} directory is unsafe") from exc
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        raise ProtectedActionError(f"{field} directory is unsafe")
    return fd


def _ensure_directory_at(
    parent_fd: int,
    name: str,
    *,
    field: str,
) -> int:
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileExistsError:
        pass
    try:
        fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise ProtectedActionError(f"{field} directory is unsafe") from exc
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        raise ProtectedActionError(f"{field} directory is unsafe")
    os.fchmod(fd, 0o700)
    return fd


def _read_json_at(
    directory_fd: int,
    name: str,
    *,
    field: str,
) -> Any:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise ProtectedActionError(f"{field} is unreadable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON_BYTES:
            raise ProtectedActionError(f"{field} is unsafe")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                fd,
                min(64 * 1024, MAX_JSON_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_JSON_BYTES:
                raise ProtectedActionError(
                    f"{field} exceeds its size limit"
                )
        return json.loads(
            b"".join(chunks),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except ProtectedActionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProtectedActionError(f"{field} is invalid JSON") from exc
    finally:
        os.close(fd)


def _write_all(fd: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(fd, raw[offset:])
        if written <= 0:
            raise ProtectedActionError(
                "protected-action packet write made no progress"
            )
        offset += written


def persist_packet(
    runtime_home: Path,
    packet: dict[str, Any],
    *,
    now: datetime | None = None,
) -> Path:
    verified = verify_packet(packet, now=now)
    packet_id = str(verified["packet_id"])
    if not PACKET_ID_RE.fullmatch(packet_id):
        raise ProtectedActionError("protected-action packet id is unsafe")
    raw = canonical_json(verified) + b"\n"
    if len(raw) > MAX_JSON_BYTES:
        raise ProtectedActionError(
            "protected-action packet exceeds its size limit"
        )

    runtime = runtime_home.expanduser()
    runtime.mkdir(parents=True, exist_ok=True)
    runtime_fd = _open_directory(runtime, field="runtime")
    state_fd = root_fd = outbox_fd = -1
    name = f"{packet_id}.json"
    try:
        state_fd = _ensure_directory_at(
            runtime_fd,
            "state",
            field="state",
        )
        root_fd = _ensure_directory_at(
            state_fd,
            "protected-actions",
            field="protected-action",
        )
        outbox_fd = _ensure_directory_at(
            root_fd,
            "outbox",
            field="protected-action outbox",
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(name, flags, 0o600, dir_fd=outbox_fd)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise ProtectedActionError(
                    "protected-action packet could not be persisted"
                ) from exc
            existing = _read_json_at(
                outbox_fd,
                name,
                field="existing protected-action packet",
            )
            if existing != verified:
                raise ProtectedActionError(
                    "protected-action packet id collision"
                )
        else:
            try:
                _write_all(fd, raw)
                os.fsync(fd)
            except BaseException:
                try:
                    os.unlink(name, dir_fd=outbox_fd)
                    os.fsync(outbox_fd)
                finally:
                    raise
            finally:
                os.close(fd)
            os.fsync(outbox_fd)
    finally:
        for fd in (outbox_fd, root_fd, state_fd, runtime_fd):
            if fd >= 0:
                os.close(fd)
    return runtime / OUTBOX_LOCATOR_PREFIX / name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--input", required=True)
    prepare.add_argument("--runtime-home", required=True)
    prepare.add_argument("--ttl-seconds", type=int, default=900)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--packet", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            packet = prepare_packet(
                load_json(
                    Path(args.input),
                    field="protected-action input",
                ),
                ttl_seconds=args.ttl_seconds,
            )
            persist_packet(Path(args.runtime_home), packet)
            print(
                json.dumps(
                    {
                        "ok": True,
                        "packet_id": packet["packet_id"],
                        "request_digest": packet["request_digest"],
                        "action": packet["request"]["action"],
                        "expires_at": packet["expires_at"],
                        "authority": AUTHORITY,
                        "packet_locator": str(
                            OUTBOX_LOCATOR_PREFIX
                            / f"{packet['packet_id']}.json"
                        ),
                    },
                    sort_keys=True,
                )
            )
            return 0
        packet = verify_packet(
            load_json(
                Path(args.packet),
                field="protected-action packet",
            )
        )
        print(
            json.dumps(
                {
                    "schema_version": VERIFY_SCHEMA,
                    "valid": True,
                    "packet_id": packet["packet_id"],
                    "request_digest": packet["request_digest"],
                    "action": packet["request"]["action"],
                    "expires_at": packet["expires_at"],
                    "authority": AUTHORITY,
                },
                sort_keys=True,
            )
        )
        return 0
    except ProtectedActionError as exc:
        print(f"john-lomein protected action blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
