#!/usr/bin/env python3
"""Stage the direct OpenAI persona-qualification adapter outside managed roots.

This command only copies local bytes and writes fixed command descriptors.  It
does not inspect credential values or make a network request.  A staged
directory is fresh and immutable-by-convention: rerunning against an existing
destination fails instead of replacing operator-reviewed artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import unicodedata
from typing import Any

import yaml

from john_lomein_factory_receipts import safe_instance_slug
from john_lomein_manifest_contract import (
    validate_manifest_contract,
    validate_runtime_checkout_separation,
)
from john_lomein_profile_contract import canonical_role_profiles


ROOT = Path(__file__).resolve().parents[1]
ADAPTER_SOURCE = ROOT / "qualification_adapters" / "openai_responses.py"
COMMAND_SCHEMA = "john-lomein.persona-qualification-command.v1"
OUTPUT_SCHEMA = "john-lomein.persona-qualification-openai-adapter-stage.v1"
ADAPTER_NAME = "openai_responses.py"
CANDIDATE_DESCRIPTOR_NAME = "candidate-command.json"
JUDGE_DESCRIPTOR_NAME = "judge-command.json"

MAX_MANIFEST_BYTES = 2_000_000
MAX_ADAPTER_BYTES = 4_000_000
MAX_COMMAND_ARTIFACT_BYTES = 20_000_000
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$")
QUALIFICATION_KEY_ENV_RE = re.compile(
    r"^QUALIFICATION_[A-Z0-9]+(?:_[A-Z0-9]+)*_API_KEY$"
)
FORBIDDEN_CREDENTIAL_MARKERS = (
    "GITHUB",
    "GH_",
    "DISCORD",
    "HERMES",
    "JOHN_LOMEIN",
    "CODEX",
    "SSH",
    "AWS",
    "GOOGLE_APPLICATION_CREDENTIALS",
)
REASONING_EFFORTS = frozenset(
    {"none", "minimal", "low", "medium", "high", "xhigh", "max"}
)

CANDIDATE_ADAPTER_ID = "openai-responses-candidate-v1"
CANDIDATE_ROUTE_ID = "openai-responses-candidate-route-v1"
JUDGE_ADAPTER_ID = "openai-responses-independent-judge-v1"
JUDGE_ROUTE_ID = "openai-responses-independent-judge-route-v1"


class StageError(ValueError):
    """A public-safe staging failure with a stable reason code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class UniqueSafeLoader(yaml.SafeLoader):
    """Safe YAML loader which rejects ambiguous duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueSafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise StageError("instance-manifest-unhashable-key") from exc
        if duplicate:
            raise StageError("instance-manifest-duplicate-key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def retained_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def _path_parts_are_normalized(path: Path) -> bool:
    return all(part not in {".", ".."} for part in path.parts)


def _validate_directory_chain(path: Path, *, code: str) -> None:
    """Reject directory components another local identity can replace."""
    if not path.is_absolute() or not _path_parts_are_normalized(path):
        raise StageError(f"{code}-not-normalized-absolute")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            info = current.lstat()
        except OSError as exc:
            raise StageError(f"{code}-unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise StageError(f"{code}-symlink")
        if not stat.S_ISDIR(info.st_mode):
            raise StageError(f"{code}-not-directory")
        if info.st_uid not in {0, os.geteuid()}:
            raise StageError(f"{code}-wrong-owner")
        if info.st_mode & 0o022:
            # A root-owned sticky directory (normally /tmp) prevents other
            # UIDs from replacing this operator's entry.  Writable non-sticky
            # components remain unsafe and are rejected.
            if info.st_uid != 0 or not info.st_mode & stat.S_ISVTX:
                raise StageError(f"{code}-writable-by-others")


def _open_regular(path: Path, *, code: str, executable: bool = False) -> int:
    _validate_directory_chain(path.parent, code=f"{code}-parent")
    try:
        before = path.lstat()
    except OSError as exc:
        raise StageError(f"{code}-unavailable") from exc
    if stat.S_ISLNK(before.st_mode):
        raise StageError(f"{code}-symlink")
    if not stat.S_ISREG(before.st_mode):
        raise StageError(f"{code}-not-regular")
    if before.st_uid not in {0, os.geteuid()}:
        raise StageError(f"{code}-wrong-owner")
    if before.st_mode & 0o022:
        raise StageError(f"{code}-writable-by-others")
    if executable and not before.st_mode & 0o111:
        raise StageError(f"{code}-not-executable")
    if not hasattr(os, "O_NOFOLLOW"):
        raise StageError("nofollow-unavailable")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise StageError(f"{code}-open-failed") from exc
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise StageError(f"{code}-changed-during-open")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _read_regular(path: Path, *, code: str, maximum: int) -> bytes:
    descriptor = _open_regular(path, code=code)
    try:
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(131_072, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum:
                raise StageError(f"{code}-too-large")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _hash_open_file(
    path: Path,
    *,
    code: str,
    executable: bool = False,
    maximum: int,
) -> tuple[str, bytes]:
    descriptor = _open_regular(path, code=code, executable=executable)
    digest = hashlib.sha256()
    prefix = b""
    size = 0
    try:
        while True:
            chunk = os.read(descriptor, 131_072)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                raise StageError(f"{code}-too-large")
            if len(prefix) < 4:
                prefix += chunk[: 4 - len(prefix)]
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest(), prefix


def _manifest_path(argument: Path) -> Path:
    candidate = argument.expanduser().absolute()
    if not _path_parts_are_normalized(candidate):
        raise StageError("instance-path-not-normalized")
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise StageError("instance-path-unavailable") from exc
    if stat.S_ISLNK(info.st_mode):
        raise StageError("instance-path-symlink")
    if stat.S_ISDIR(info.st_mode):
        _validate_directory_chain(candidate, code="instance-directory")
        primary = candidate / "instance.yaml"
        candidate = primary if primary.exists() else candidate / "bot.yaml"
    return candidate


def _load_manifest(argument: Path) -> tuple[dict[str, Any], Path, Path]:
    raw = _read_regular(
        _manifest_path(argument),
        code="instance-manifest",
        maximum=MAX_MANIFEST_BYTES,
    )
    try:
        manifest = yaml.load(raw.decode("utf-8"), Loader=UniqueSafeLoader) or {}
    except StageError:
        raise
    except (UnicodeError, yaml.YAMLError) as exc:
        raise StageError("instance-manifest-invalid-yaml") from exc
    if type(manifest) is not dict:
        raise StageError("instance-manifest-not-object")
    try:
        validate_manifest_contract(manifest)
        canonical_role_profiles(manifest)
    except (TypeError, ValueError) as exc:
        raise StageError("instance-manifest-contract") from exc

    instance = manifest.get("instance")
    target = manifest.get("target")
    runtime = manifest.get("runtime")
    if type(instance) is not dict or type(target) is not dict or type(runtime) is not dict:
        raise StageError("instance-manifest-path-config")
    try:
        slug = safe_instance_slug(instance.get("slug"))
    except ValueError as exc:
        raise StageError("instance-slug") from exc
    checkout_value = target.get("local_checkout") or target.get("local")
    runtime_value = runtime.get("hermes_home")
    if checkout_value is None:
        checkout_value = f"~/.john-lomein/instances/{slug}/work/repo"
    if runtime_value is None:
        runtime_value = f"~/.john-lomein/instances/{slug}/hermes"
    if type(checkout_value) is not str or type(runtime_value) is not str:
        raise StageError("instance-manifest-path-config")
    try:
        checkout, hermes_home = validate_runtime_checkout_separation(
            Path(checkout_value), Path(runtime_value)
        )
    except (OSError, TypeError, ValueError) as exc:
        raise StageError("instance-runtime-checkout-contract") from exc
    return manifest, checkout.resolve(strict=False), hermes_home.resolve(strict=False)


def _token(value: Any, *, code: str) -> str:
    if type(value) is not str or not TOKEN_RE.fullmatch(value):
        raise StageError(code)
    return value


def _model(
    value: Any,
    *,
    default_reasoning: str | None,
    code: str,
    prefer_model_field: bool = False,
) -> dict[str, str]:
    if type(value) is not dict:
        raise StageError(f"{code}-not-object")
    provider = _token(value.get("provider"), code=f"{code}-provider")
    if provider != "openai":
        if provider == "openai-codex":
            raise StageError("candidate-provider-openai-codex-unsupported")
        raise StageError("candidate-provider-not-openai")
    if prefer_model_field:
        raw_model_name = value.get("model") or value.get("default")
    else:
        raw_model_name = value.get("default") or value.get("model")
    model_name = _token(raw_model_name, code=f"{code}-model")
    effort = _token(
        value.get("reasoning_effort") or default_reasoning or "xhigh",
        code=f"{code}-reasoning-effort",
    )
    if effort not in REASONING_EFFORTS:
        raise StageError(f"{code}-reasoning-effort-unsupported")
    return {"provider": provider, "model": model_name, "reasoning_effort": effort}


def _candidate_models(manifest: dict[str, Any]) -> list[dict[str, str]]:
    raw = manifest.get("model")
    primary = _model(raw, default_reasoning=None, code="primary-model")
    ordered = [primary]
    assert isinstance(raw, dict)
    fallback_raw = raw.get("fallback")
    if fallback_raw not in (None, {}):
        ordered.append(
            _model(
                fallback_raw,
                default_reasoning=primary["reasoning_effort"],
                code="fallback-model",
                prefer_model_field=True,
            )
        )
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in ordered:
        identity = (item["provider"], item["model"], item["reasoning_effort"])
        if identity not in seen:
            seen.add(identity)
            result.append(item)
    return result


def _judge_model(provider: str, model: str, reasoning: str) -> dict[str, str]:
    provider = _token(provider, code="judge-provider")
    if provider != "openai":
        raise StageError("judge-provider-not-openai")
    model = _token(model, code="judge-model")
    reasoning = _token(reasoning, code="judge-reasoning-effort")
    if reasoning not in REASONING_EFFORTS:
        raise StageError("judge-reasoning-effort-unsupported")
    return {"provider": provider, "model": model, "reasoning_effort": reasoning}


def _credential_env(value: str, *, code: str) -> str:
    if len(value) > 128 or not QUALIFICATION_KEY_ENV_RE.fullmatch(value):
        raise StageError(f"{code}-invalid")
    if any(marker in value for marker in FORBIDDEN_CREDENTIAL_MARKERS):
        raise StageError(f"{code}-forbidden")
    return value


def _paths_overlap(left: Path, right: Path) -> bool:
    left = left.resolve(strict=False)
    right = right.resolve(strict=False)
    left_text = unicodedata.normalize("NFC", str(left).rstrip(os.sep)).casefold()
    right_text = unicodedata.normalize("NFC", str(right).rstrip(os.sep)).casefold()
    return (
        left_text == right_text
        or left_text.startswith(right_text + os.sep)
        or right_text.startswith(left_text + os.sep)
    )


def _destination(value: str, *, forbidden_roots: list[Path]) -> Path:
    raw = Path(value)
    if not raw.is_absolute() or not _path_parts_are_normalized(raw):
        raise StageError("destination-not-normalized-absolute")
    destination = raw.absolute()
    if destination.name in {"", ".", ".."}:
        raise StageError("destination-invalid")
    _validate_directory_chain(destination.parent, code="destination-parent")
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise StageError("destination-unavailable") from exc
    else:
        if destination.is_symlink():
            raise StageError("destination-symlink")
        raise StageError("destination-exists")
    if any(_paths_overlap(destination, root) for root in forbidden_roots):
        raise StageError("destination-overlaps-repository-runtime-or-checkout")
    return destination


def _python_binary(value: str, *, forbidden_roots: list[Path]) -> tuple[Path, str]:
    raw = Path(value)
    if not raw.is_absolute() or not _path_parts_are_normalized(raw):
        raise StageError("python-not-normalized-absolute")
    try:
        resolved = raw.resolve(strict=True)
    except OSError as exc:
        raise StageError("python-unavailable") from exc
    if raw.is_symlink() or resolved != raw:
        raise StageError("python-not-resolved-or-symlink")
    if any(_paths_overlap(resolved, root) for root in forbidden_roots):
        raise StageError("python-overlaps-repository-runtime-or-checkout")
    file_sha256, prefix = _hash_open_file(
        resolved,
        code="python",
        executable=True,
        maximum=MAX_COMMAND_ARTIFACT_BYTES,
    )
    if prefix.startswith(b"#!"):
        raise StageError("python-not-regular-binary")
    return resolved, file_sha256


def _write_exclusive(path: Path, payload: bytes) -> None:
    if not hasattr(os, "O_NOFOLLOW"):
        raise StageError("nofollow-unavailable")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise StageError("stage-file-create-failed") from exc
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise StageError("stage-file-short-write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _cleanup_private_stage(path: Path) -> None:
    if not path.exists():
        return
    for name in (ADAPTER_NAME, CANDIDATE_DESCRIPTOR_NAME, JUDGE_DESCRIPTOR_NAME):
        try:
            (path / name).unlink()
        except FileNotFoundError:
            pass
    try:
        path.rmdir()
    except FileNotFoundError:
        pass


def _verify_staged_file(path: Path, expected: bytes, *, code: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise StageError(f"{code}-verification-unavailable") from exc
    if (
        stat.S_IMODE(info.st_mode) != 0o600
        or info.st_uid != os.geteuid()
        or _read_regular(path, code=f"{code}-verification", maximum=len(expected))
        != expected
    ):
        raise StageError(f"{code}-verification-mismatch")


def stage(args: argparse.Namespace) -> dict[str, Any]:
    manifest, checkout, hermes_home = _load_manifest(args.instance)
    candidates = _candidate_models(manifest)
    judge = _judge_model(
        args.judge_provider,
        args.judge_model,
        args.judge_reasoning_effort,
    )
    candidate_identities = {(item["provider"], item["model"]) for item in candidates}
    if (judge["provider"], judge["model"]) in candidate_identities:
        raise StageError("judge-model-not-independent")
    candidate_env = _credential_env(
        args.candidate_api_key_env, code="candidate-api-key-env"
    )
    judge_env = _credential_env(args.judge_api_key_env, code="judge-api-key-env")

    forbidden_roots = [ROOT.resolve(), checkout, hermes_home]
    destination = _destination(args.destination, forbidden_roots=forbidden_roots)
    python, python_sha256 = _python_binary(
        args.python, forbidden_roots=forbidden_roots
    )
    adapter_bytes = _read_regular(
        ADAPTER_SOURCE, code="adapter-source", maximum=MAX_ADAPTER_BYTES
    )
    adapter_sha256 = sha256_bytes(adapter_bytes)

    adapter_path = destination / ADAPTER_NAME
    candidate_path = destination / CANDIDATE_DESCRIPTOR_NAME
    judge_path = destination / JUDGE_DESCRIPTOR_NAME
    candidate_descriptor = {
        "schema_version": COMMAND_SCHEMA,
        "kind": "candidate",
        "id": CANDIDATE_ADAPTER_ID,
        "route_id": CANDIDATE_ROUTE_ID,
        "argv": [
            str(python),
            str(adapter_path),
            "--kind",
            "candidate",
            "--api-key-env",
            candidate_env,
        ],
        "credential_env": [candidate_env],
        "models": candidates,
    }
    judge_descriptor = {
        "schema_version": COMMAND_SCHEMA,
        "kind": "judge",
        "id": JUDGE_ADAPTER_ID,
        "route_id": JUDGE_ROUTE_ID,
        "argv": [
            str(python),
            str(adapter_path),
            "--kind",
            "judge",
            "--api-key-env",
            judge_env,
        ],
        "credential_env": [judge_env],
        "model": judge,
    }
    candidate_bytes = retained_json(candidate_descriptor)
    judge_bytes = retained_json(judge_descriptor)

    parent = destination.parent
    destination_created = False
    try:
        try:
            os.mkdir(destination, 0o700)
        except FileExistsError as exc:
            raise StageError("destination-appeared-during-stage")
        except OSError as exc:
            raise StageError("destination-create-failed") from exc
        destination_created = True
        destination.chmod(0o700)
        _write_exclusive(destination / ADAPTER_NAME, adapter_bytes)
        _write_exclusive(destination / CANDIDATE_DESCRIPTOR_NAME, candidate_bytes)
        _write_exclusive(destination / JUDGE_DESCRIPTOR_NAME, judge_bytes)
        _fsync_directory(destination)
        _fsync_directory(parent)
    except Exception:
        if destination_created:
            _cleanup_private_stage(destination)
        raise

    destination_info = destination.lstat()
    if (
        not stat.S_ISDIR(destination_info.st_mode)
        or destination_info.st_uid != os.geteuid()
        or stat.S_IMODE(destination_info.st_mode) != 0o700
    ):
        raise StageError("destination-verification-mismatch")
    _verify_staged_file(adapter_path, adapter_bytes, code="adapter")
    _verify_staged_file(candidate_path, candidate_bytes, code="candidate-command")
    _verify_staged_file(judge_path, judge_bytes, code="judge-command")

    artifacts = {
        "python": {"path": str(python), "file_sha256": python_sha256},
        "adapter": {"path": str(adapter_path), "file_sha256": adapter_sha256},
        "candidate_command": {
            "path": str(candidate_path),
            "file_sha256": sha256_bytes(candidate_bytes),
            "descriptor_sha256": sha256_json(candidate_descriptor),
        },
        "judge_command": {
            "path": str(judge_path),
            "file_sha256": sha256_bytes(judge_bytes),
            "descriptor_sha256": sha256_json(judge_descriptor),
        },
    }
    return {
        "schema_version": OUTPUT_SCHEMA,
        "status": "staged",
        "destination": str(destination),
        "candidate_models": candidates,
        "judge_model": judge,
        "artifacts": artifacts,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Stage fixed-command descriptors for the direct OpenAI persona-qualification "
            "adapter without reading credentials or using the network"
        )
    )
    parser.add_argument("--instance", type=Path, required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument(
        "--python",
        required=True,
        help="resolved absolute path to a non-symlink executable Python binary",
    )
    parser.add_argument(
        "--candidate-api-key-env",
        default="QUALIFICATION_CANDIDATE_API_KEY",
    )
    parser.add_argument(
        "--judge-api-key-env",
        default="QUALIFICATION_JUDGE_API_KEY",
    )
    parser.add_argument("--judge-provider", required=True)
    parser.add_argument("--judge-model", required=True)
    parser.add_argument("--judge-reasoning-effort", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = stage(args)
    except StageError as exc:
        error = {
            "schema_version": OUTPUT_SCHEMA,
            "status": "error",
            "reason": exc.code,
        }
        sys.stdout.write(canonical_json(error) + "\n")
        return 2
    except OSError:
        error = {
            "schema_version": OUTPUT_SCHEMA,
            "status": "error",
            "reason": "filesystem-operation-failed",
        }
        sys.stdout.write(canonical_json(error) + "\n")
        return 2
    sys.stdout.write(canonical_json(result) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
