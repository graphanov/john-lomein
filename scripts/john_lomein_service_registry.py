#!/usr/bin/env python3
"""Verified launchd ownership and lifecycle for John Lomein instances.

The registry is keyed by the canonical instance-manifest path, so changing an
instance slug does not lose the labels installed by the previous
configuration.  A label may be owned by only one registered instance.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping

SCHEMA_VERSION = "john_lomein_launchd_registry/v1"
SERVICE_KINDS = frozenset({"scheduler", "keepawake", "guide"})
LABEL_RE = re.compile(
    r"^ai\.hermes\.(?:john-lomein|gateway-john-lomein)-[A-Za-z0-9._-]+$"
)
LAUNCHCTL_ENV_RE = re.compile(
    r"^\s*(JOHN_LOMEIN_INSTANCE_HERMES_HOME|HERMES_HOME)"
    r"\s*(?:=>|=)\s*(.*?)\s*$"
)
LAUNCHCTL_PROGRAM_RE = re.compile(r"^\s*program\s*=\s*(.*?)\s*$")
LAUNCHCTL_WORKING_DIR_RE = re.compile(
    r"^\s*working directory\s*=\s*(.*?)\s*$"
)
LAUNCHCTL_ARGUMENTS_RE = re.compile(r"^\s*arguments\s*=\s*\{\s*$")
LAUNCHCTL_NOT_FOUND_MARKERS = (
    "could not find service",
    "could not find specified service",
    "service not found",
    "no such process",
)
LOCK_TIMEOUT_SECONDS = 30.0
BOOTOUT_VERIFY_ATTEMPTS = 101
BOOTOUT_VERIFY_INTERVAL_SECONDS = 0.1


class ServiceRegistryError(RuntimeError):
    pass


def canonical_path(value: str | Path) -> Path:
    return Path(value).expanduser().resolve()


def canonical_manifest_path(value: str | Path) -> Path:
    """Map a setup snapshot back to its stable source registry identity."""

    candidate = canonical_path(value)
    snapshot_raw = os.environ.get(
        "JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT",
        "",
    )
    source_raw = os.environ.get(
        "JOHN_LOMEIN_SETUP_MANIFEST_SOURCE",
        "",
    )
    digest_raw = os.environ.get(
        "JOHN_LOMEIN_SETUP_MANIFEST_SHA256",
        "",
    )
    binding = (snapshot_raw, source_raw, digest_raw)
    if any(binding) and not all(binding):
        raise ServiceRegistryError("setup manifest binding is incomplete")
    if all(binding) and candidate == canonical_path(snapshot_raw):
        return canonical_path(source_raw)
    return candidate


def registry_root() -> Path:
    return canonical_path(
        Path.home() / ".john-lomein" / "service-registry"
    )


def launch_agents_root() -> Path:
    return canonical_path(
        Path.home() / "Library" / "LaunchAgents"
    )


def _lock_path() -> Path:
    return registry_root() / ".lifecycle.lock"


@contextmanager
def lifecycle_lock():
    root = registry_root()
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise ServiceRegistryError(f"launchd registry root unsafe: {root}")
    os.chmod(root, 0o700)
    lock_path = _lock_path()
    inherited_raw = os.environ.get("JOHN_LOMEIN_SERVICE_LOCK_FD")
    if inherited_raw:
        try:
            fd = int(inherited_raw)
            fd_stat = os.fstat(fd)
            path_stat = lock_path.stat()
            if (fd_stat.st_dev, fd_stat.st_ino) != (
                path_stat.st_dev,
                path_stat.st_ino,
            ):
                raise ValueError("lock descriptor points at another file")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception as exc:
            raise ServiceRegistryError(
                "inherited lifecycle lock descriptor is invalid or not locked"
            ) from exc
        yield fd
        return

    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ServiceRegistryError(
                        "timed out waiting for John Lomein service lifecycle lock"
                    )
                time.sleep(0.05)
        yield fd
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def instance_key(manifest: str | Path) -> str:
    canonical = str(canonical_manifest_path(manifest))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def registry_path(manifest: str | Path) -> Path:
    return registry_root() / f"{instance_key(manifest)}.json"


def _validated_label(label: Any) -> str:
    value = str(label or "").strip()
    if not LABEL_RE.fullmatch(value):
        raise ServiceRegistryError(f"unsafe launchd label: {value or '<empty>'}")
    return value


def parse_services(values: list[str]) -> dict[str, str]:
    services: dict[str, str] = {}
    for raw in values:
        if "=" not in raw:
            raise ServiceRegistryError(
                "service must use KIND=LABEL syntax"
            )
        kind, label = raw.split("=", 1)
        kind = kind.strip()
        if kind not in SERVICE_KINDS:
            raise ServiceRegistryError(f"unsafe launchd service kind: {kind}")
        label = _validated_label(label)
        if _service_kind(label) != kind:
            raise ServiceRegistryError(
                f"launchd label does not match service kind: {kind}={label}"
            )
        if kind in services and services[kind] != label:
            raise ServiceRegistryError(
                f"duplicate launchd service kind with conflicting labels: {kind}"
            )
        services[kind] = label
    return services


def _validate_entry(raw: Any, *, path: Path) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ServiceRegistryError(f"launchd registry root invalid: {path}")
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise ServiceRegistryError(f"launchd registry schema invalid: {path}")
    manifest = str(raw.get("manifest") or "")
    runtime_home = str(raw.get("runtime_home") or "")
    labels_raw = raw.get("labels")
    if not manifest or not runtime_home or not isinstance(labels_raw, Mapping):
        raise ServiceRegistryError(f"launchd registry fields invalid: {path}")
    labels: dict[str, str] = {}
    for raw_kind, raw_label in labels_raw.items():
        kind = str(raw_kind)
        if kind not in SERVICE_KINDS:
            raise ServiceRegistryError(
                f"launchd registry contains unsafe kind: {path}"
            )
        labels[kind] = _validated_label(raw_label)
        if _service_kind(labels[kind]) != kind:
            raise ServiceRegistryError(
                f"launchd registry kind/label mismatch: {path}"
            )
    return {
        "schema_version": SCHEMA_VERSION,
        "manifest": str(canonical_path(manifest)),
        "runtime_home": str(canonical_path(runtime_home)),
        "labels": labels,
    }


def read_registry(manifest: str | Path) -> dict[str, Any] | None:
    path = registry_path(manifest)
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ServiceRegistryError(f"launchd registry path unsafe: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ServiceRegistryError(
            f"launchd registry unreadable: {path}: {exc}"
        ) from exc
    entry = _validate_entry(raw, path=path)
    if entry["manifest"] != str(canonical_manifest_path(manifest)):
        raise ServiceRegistryError(f"launchd registry manifest mismatch: {path}")
    return entry


def all_registries() -> list[tuple[Path, dict[str, Any]]]:
    root = registry_root()
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise ServiceRegistryError(f"launchd registry root unsafe: {root}")
    entries: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(root.glob("*.json")):
        if path.is_symlink() or not path.is_file():
            raise ServiceRegistryError(f"launchd registry path unsafe: {path}")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ServiceRegistryError(
                f"launchd registry unreadable: {path}: {exc}"
            ) from exc
        entries.append((path, _validate_entry(raw, path=path)))
    return entries


def label_owners(label: str) -> list[dict[str, Any]]:
    label = _validated_label(label)
    owners: list[dict[str, Any]] = []
    for _, entry in all_registries():
        if label in entry["labels"].values():
            owners.append(entry)
    return owners


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    root = path.parent
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise ServiceRegistryError(f"launchd registry root unsafe: {root}")
    os.chmod(root, 0o700)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(root),
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _write_or_remove_registry(
    manifest: str | Path,
    runtime_home: str | Path,
    labels: Mapping[str, str],
) -> None:
    path = registry_path(manifest)
    if not labels:
        path.unlink(missing_ok=True)
        return
    entry = {
        "schema_version": SCHEMA_VERSION,
        "manifest": str(canonical_manifest_path(manifest)),
        "runtime_home": str(canonical_path(runtime_home)),
        "labels": dict(sorted(labels.items())),
    }
    _atomic_write(path, entry)


def _service_kind(label: str) -> str:
    label = _validated_label(label)
    if label.startswith("ai.hermes.gateway-john-lomein-") and label.endswith(
        "-guide"
    ):
        return "guide"
    if label.endswith("-scheduler"):
        return "scheduler"
    if label.endswith("-keepawake"):
        return "keepawake"
    raise ServiceRegistryError(f"unrecognized John Lomein launchd label: {label}")


def _consistent_observed_runtime(
    label: str,
    observation: Mapping[str, Any],
) -> str:
    runtimes: set[str] = set()
    commands: set[str] = set()
    plist_runtime = observation.get("plist_runtime")
    if plist_runtime is not None:
        if (
            observation.get("plist_label") != label
            or not plist_runtime
            or not observation.get("plist_command")
        ):
            return ""
        runtimes.add(str(canonical_path(plist_runtime)))
        commands.add(str(observation["plist_command"]))
    loaded_runtime = observation.get("loaded_runtime")
    if loaded_runtime is not None:
        if (
            not loaded_runtime
            or not observation.get("loaded_command")
        ):
            return ""
        runtimes.add(str(canonical_path(loaded_runtime)))
        commands.add(str(observation["loaded_command"]))
    if len(runtimes) != 1 or len(commands) != 1:
        return ""
    return next(iter(runtimes))


def _observation_matches_runtime(
    label: str,
    observation: Mapping[str, Any] | None,
    runtime_home: Path,
) -> bool:
    if observation is None:
        return False
    observed = _consistent_observed_runtime(label, observation)
    return bool(observed) and canonical_path(observed) == runtime_home


def _command_identity_uses_model_isolation(
    command_identity: Any,
    runtime_home: Path,
) -> bool:
    try:
        values = json.loads(str(command_identity))
    except (TypeError, ValueError):
        return False
    expected_wrapper = runtime_home / "scripts" / "john_lomein_model_isolation.py"
    return (
        isinstance(values, list)
        and len(values) >= 3
        and isinstance(values[2], str)
        and canonical_path(values[2]) == expected_wrapper
    )


def _observation_uses_model_isolation(
    observation: Mapping[str, Any] | None,
    runtime_home: Path,
) -> bool:
    if observation is None:
        return False
    identities = [
        observation.get(key)
        for key in ("plist_command", "loaded_command")
        if observation.get(key) is not None
    ]
    return bool(identities) and all(
        _command_identity_uses_model_isolation(identity, runtime_home)
        for identity in identities
    )


def _observation_points_at_runtime(
    observation: Mapping[str, Any],
    runtime_home: Path,
) -> bool:
    for key in ("plist_runtime", "loaded_runtime"):
        observed = observation.get(key)
        if observed and canonical_path(observed) == runtime_home:
            return True
    return False


def _product_service_observations(
) -> dict[str, dict[str, Any]]:
    observations: dict[str, dict[str, Any]] = {}
    root = launch_agents_root()
    if root.exists():
        for plist in sorted(root.glob("*.plist")):
            label = plist.stem
            if not LABEL_RE.fullmatch(label):
                continue
            observation = observations.setdefault(
                label,
                {
                    "plist_label": None,
                    "plist_runtime": None,
                    "plist_command": None,
                    "loaded_runtime": None,
                    "loaded_command": None,
                },
            )
            try:
                (
                    observed_label,
                    runtime_home,
                    command_identity,
                ) = _plist_identity(plist)
                observation["plist_label"] = observed_label
                observation["plist_runtime"] = runtime_home
                observation["plist_command"] = command_identity
            except ServiceRegistryError:
                observation["plist_label"] = ""
                observation["plist_runtime"] = ""
                observation["plist_command"] = ""
    for label, loaded in _loaded_product_services().items():
        observation = observations.setdefault(
            label,
            {
                "plist_label": None,
                "plist_runtime": None,
                "plist_command": None,
                "loaded_runtime": None,
                "loaded_command": None,
            },
        )
        observation["loaded_runtime"] = loaded["runtime_home"]
        observation["loaded_command"] = loaded["command_identity"]
    return observations


def _unregistered_product_services(
    observations: Mapping[str, Mapping[str, Any]],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for label, observation in observations.items():
        if label_owners(label):
            continue
        result[label] = _consistent_observed_runtime(label, observation)
    return result


def _record_services_unlocked(
    manifest: str | Path,
    runtime_home: str | Path,
    services: Mapping[str, str],
) -> dict[str, Any]:
    if not services:
        raise ServiceRegistryError("no launchd services supplied for record")
    manifest_path = canonical_manifest_path(manifest)
    runtime_path = canonical_path(runtime_home)
    current_key = instance_key(manifest_path)
    normalized = {
        kind: _validated_label(label)
        for kind, label in services.items()
        if kind in SERVICE_KINDS
    }
    if set(normalized) != set(services):
        raise ServiceRegistryError("unsafe launchd service kind")
    observations = _product_service_observations()
    existing = read_registry(manifest_path)
    existing_labels = dict((existing or {}).get("labels") or {})
    for kind, label in normalized.items():
        for owner in label_owners(label):
            if instance_key(owner["manifest"]) != current_key:
                raise ServiceRegistryError(
                    f"launchd label collision: {kind}={label} is owned by "
                    f"{owner['manifest']}"
                )
        previous = existing_labels.get(kind)
        if previous and previous != label and previous in observations:
            raise ServiceRegistryError(
                f"registered {kind} label changed while the previous service "
                f"still exists: {previous}; stop it before recording {label}"
            )
    permitted_unregistered = set(normalized.values())
    for label, observed_runtime in _unregistered_product_services(
        observations
    ).items():
        if (
            label in permitted_unregistered
            and observed_runtime
            and canonical_path(observed_runtime) == runtime_path
        ):
            continue
        raise ServiceRegistryError(
            "unregistered John Lomein LaunchAgent requires explicit adoption "
            f"or uninstall before installing another instance: {label}"
        )
    for kind, label in normalized.items():
        observation = observations.get(label)
        if (
            not _observation_matches_runtime(
                label,
                observation,
                runtime_path,
            )
            or (
                kind in {"guide", "scheduler"}
                and not _observation_uses_model_isolation(
                    observation,
                    runtime_path,
                )
            )
        ):
            raise ServiceRegistryError(
                f"cannot register {kind}={label}: plist/loaded service identity "
                f"does not consistently match runtime {runtime_path}"
            )
    labels = existing_labels
    if (
        existing
        and canonical_path(existing["runtime_home"]) != runtime_path
        and any(kind not in normalized for kind in labels)
    ):
        raise ServiceRegistryError(
            "runtime home changed while other registered services remain; "
            "run the full service uninstaller before reinstalling"
        )
    labels.update(normalized)
    _write_or_remove_registry(manifest_path, runtime_path, labels)
    return {
        "manifest": str(manifest_path),
        "runtime_home": str(runtime_path),
        "labels": labels,
    }


def record_services(
    manifest: str | Path,
    runtime_home: str | Path,
    services: Mapping[str, str],
) -> dict[str, Any]:
    with lifecycle_lock():
        return _record_services_unlocked(manifest, runtime_home, services)


def _trusted_python_interpreters() -> set[str]:
    candidates: set[Path] = {
        Path("/usr/bin/python3"),
        Path("/opt/homebrew/bin/python3"),
        Path("/usr/local/bin/python3"),
        Path.home() / ".hermes" / "hermes-agent" / "venv" / "bin" / "python",
    }
    hermes = shutil.which("hermes")
    if hermes:
        hermes_dir = Path(hermes).expanduser().parent
        candidates.update({hermes_dir / "python3", hermes_dir / "python"})
        try:
            first_line = Path(hermes).read_text(
                encoding="utf-8",
                errors="strict",
            ).splitlines()[0]
        except (IndexError, OSError, UnicodeError):
            first_line = ""
        if first_line.startswith("#!"):
            shebang = Path(first_line[2:].strip()).expanduser()
            if shebang.name.startswith("python"):
                candidates.add(shebang)
    python3 = shutil.which("python3")
    if python3:
        candidates.add(Path(python3))
    trusted: set[str] = set()
    for candidate in candidates:
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                trusted.add(str(candidate.resolve()))
        except OSError:
            continue
    return trusted


def _service_command_identity(
    label: str,
    runtime_home: str,
    program_arguments: Any,
    working_directory: Any,
) -> str:
    if (
        not runtime_home
        or not isinstance(program_arguments, list)
        or not all(isinstance(value, str) for value in program_arguments)
        or not isinstance(working_directory, str)
        or not working_directory
    ):
        return ""
    try:
        kind = _service_kind(label)
        runtime_path = canonical_path(runtime_home)
        working_path = canonical_path(working_directory)
    except (OSError, ServiceRegistryError):
        return ""
    if kind == "keepawake":
        expected_program = (
            runtime_path / "scripts" / "john-lomein-keepawake.sh"
        )
        if (
            program_arguments != [str(expected_program)]
            or working_path != runtime_path
        ):
            return ""
        return json.dumps(
            [
                kind,
                str(expected_program),
                str(working_path),
            ],
            separators=(",", ":"),
        )
    profile = (
        "john-lomein-guide"
        if kind == "guide"
        else "john-lomein-maintainer"
    )
    if kind in {"guide", "scheduler"} and len(program_arguments) in {13, 14}:
        expected_wrapper = (
            runtime_path / "scripts" / "john_lomein_model_isolation.py"
        )
        outer_executable = canonical_path(program_arguments[0])
        inner_executable = canonical_path(program_arguments[5])
        isolated_python = len(program_arguments) == 14
        expected_inner = [
            "--profile",
            profile,
            "--",
            program_arguments[5],
            *(["-I"] if isolated_python else []),
            "-m",
            "hermes_cli.main",
            "--profile",
            profile,
            "gateway",
            "run",
            "--replace",
        ]
        if (
            str(outer_executable) not in _trusted_python_interpreters()
            or inner_executable != outer_executable
            or canonical_path(program_arguments[1]) != expected_wrapper
            or program_arguments[2:] != expected_inner
            or working_path != runtime_path / "profiles" / profile
        ):
            return ""
        return json.dumps(
            [
                kind,
                str(outer_executable),
                str(expected_wrapper),
                *program_arguments[2:5],
                str(inner_executable),
                *program_arguments[6:],
                str(working_path),
            ],
            separators=(",", ":"),
        )
    # Retain recognition of former unwrapped model commands solely so a
    # pre-boundary service can be discovered and safely uninstalled/adopted
    # during migration. The current installer never writes this form and
    # Doctor rejects it for a required-isolation instance.
    if len(program_arguments) != 8:
        return ""
    executable = canonical_path(program_arguments[0])
    if (
        str(executable) not in _trusted_python_interpreters()
        or program_arguments[1:]
        != [
            "-m",
            "hermes_cli.main",
            "--profile",
            profile,
            "gateway",
            "run",
            "--replace",
        ]
        or working_path != runtime_path / "profiles" / profile
    ):
        return ""
    return json.dumps(
        [
            kind,
            str(executable),
            *program_arguments[1:],
            str(working_path),
        ],
        separators=(",", ":"),
    )


def _runtime_home_from_environment(env: Mapping[str, Any]) -> str:
    values: dict[str, str] = {}
    for name in (
        "JOHN_LOMEIN_INSTANCE_HERMES_HOME",
        "HERMES_HOME",
    ):
        raw = env.get(name)
        if raw:
            values[name] = str(canonical_path(str(raw)))
    if len(set(values.values())) > 1:
        return ""
    return next(iter(values.values()), "")


def _plist_identity(path: Path) -> tuple[str, str, str]:
    if path.is_symlink():
        raise ServiceRegistryError(f"launchd plist is a symlink: {path}")
    if not path.is_file():
        raise ServiceRegistryError(
            f"launchd plist path is not a regular file: {path}"
        )
    try:
        with path.open("rb") as handle:
            data = plistlib.load(handle)
    except Exception as exc:
        raise ServiceRegistryError(
            f"launchd plist unreadable: {path}: {exc}"
        ) from exc
    if not isinstance(data, Mapping):
        raise ServiceRegistryError(f"launchd plist root invalid: {path}")
    label = str(data.get("Label") or "")
    program_arguments = data.get("ProgramArguments")
    working = data.get("WorkingDirectory")
    env = data.get("EnvironmentVariables") if isinstance(data, Mapping) else {}
    runtime_home = ""
    has_runtime_environment = False
    if isinstance(env, Mapping):
        has_runtime_environment = any(
            env.get(name)
            for name in (
                "JOHN_LOMEIN_INSTANCE_HERMES_HOME",
                "HERMES_HOME",
            )
        )
        runtime_home = _runtime_home_from_environment(env)
    if not runtime_home and working and not has_runtime_environment:
        candidate = canonical_path(str(working))
        parts = candidate.parts
        if "profiles" in parts:
            index = parts.index("profiles")
            runtime_home = str(Path(*parts[:index]))
        else:
            runtime_home = str(candidate)
    command_identity = _service_command_identity(
        label,
        runtime_home,
        program_arguments,
        working,
    )
    return label, runtime_home, command_identity


def _plist_runtime_home(path: Path) -> str:
    return _plist_identity(path)[1]


def _launchctl_print(label: str) -> tuple[bool, str]:
    launchctl = shutil.which("launchctl")
    if not launchctl:
        return False, ""
    proc = subprocess.run(
        [launchctl, "print", f"gui/{os.getuid()}/{label}"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    output = (proc.stdout + "\n" + proc.stderr).strip()
    if proc.returncode == 0:
        return True, output
    folded = output.casefold()
    if any(marker in folded for marker in LAUNCHCTL_NOT_FOUND_MARKERS):
        return False, output
    raise ServiceRegistryError(
        f"launchctl could not inspect service {label}: "
        f"{output[:240] or f'exit {proc.returncode}'}"
    )


def _runtime_home_from_launchctl_output(output: str) -> str:
    observed: dict[str, set[str]] = {
        "JOHN_LOMEIN_INSTANCE_HERMES_HOME": set(),
        "HERMES_HOME": set(),
    }
    for line in output.splitlines():
        match = LAUNCHCTL_ENV_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        raw = match.group(2).strip().rstrip(";").strip()
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
            raw = raw[1:-1]
        if raw:
            observed[name].add(str(canonical_path(raw)))
    for name in (
        "JOHN_LOMEIN_INSTANCE_HERMES_HOME",
        "HERMES_HOME",
    ):
        if len(observed[name]) > 1:
            return ""
    values = {
        next(iter(paths))
        for paths in observed.values()
        if paths
    }
    if len(values) != 1:
        return ""
    return next(iter(values))


def _clean_launchctl_value(raw: str) -> str:
    value = raw.strip().rstrip(";").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return value


def _launchctl_command_identity(
    label: str,
    runtime_home: str,
    output: str,
) -> str:
    program = ""
    working_directory = ""
    arguments: list[str] = []
    reading_arguments = False
    for line in output.splitlines():
        if reading_arguments:
            stripped = line.strip()
            if stripped == "}":
                reading_arguments = False
                continue
            if stripped:
                stripped = re.sub(
                    r"^\d+\s*(?:=>|=)\s*",
                    "",
                    stripped,
                )
                arguments.append(_clean_launchctl_value(stripped))
            continue
        match = LAUNCHCTL_PROGRAM_RE.match(line)
        if match:
            program = _clean_launchctl_value(match.group(1))
            continue
        match = LAUNCHCTL_WORKING_DIR_RE.match(line)
        if match:
            working_directory = _clean_launchctl_value(match.group(1))
            continue
        if LAUNCHCTL_ARGUMENTS_RE.match(line):
            reading_arguments = True
    if (
        not program
        or not arguments
        or canonical_path(program) != canonical_path(arguments[0])
    ):
        return ""
    return _service_command_identity(
        label,
        runtime_home,
        arguments,
        working_directory,
    )


def _loaded_product_services() -> dict[str, dict[str, Any]]:
    launchctl = shutil.which("launchctl")
    if not launchctl:
        return {}
    proc = subprocess.run(
        [launchctl, "list"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if proc.returncode != 0:
        raise ServiceRegistryError(
            "launchctl could not enumerate loaded services: "
            f"{(proc.stderr or proc.stdout).strip()[:240]}"
        )
    services: dict[str, dict[str, Any]] = {}
    for line in proc.stdout.splitlines():
        columns = line.split()
        if not columns:
            continue
        label = columns[-1]
        if not LABEL_RE.fullmatch(label):
            continue
        loaded, output = _launchctl_print(label)
        if loaded:
            runtime_home = _runtime_home_from_launchctl_output(output)
            services[label] = {
                "runtime_home": runtime_home,
                "command_identity": _launchctl_command_identity(
                    label,
                    runtime_home,
                    output,
                ),
            }
    return services


def _assert_unregistered_label_belongs_to_runtime(
    label: str,
    runtime_home: Path,
) -> None:
    plist = launch_agents_root() / f"{label}.plist"
    if plist.exists() or plist.is_symlink():
        observed_label, observed, command_identity = _plist_identity(plist)
        if (
            observed_label != label
            or not observed
            or canonical_path(observed) != runtime_home
            or not command_identity
        ):
            raise ServiceRegistryError(
                f"launchd label ownership is ambiguous or belongs to another "
                f"runtime: {label}"
            )
        return
    loaded, output = _launchctl_print(label)
    observed = _runtime_home_from_launchctl_output(output) if loaded else ""
    if loaded and (
        not observed
        or canonical_path(observed) != runtime_home
        or not _launchctl_command_identity(label, observed, output)
    ):
        raise ServiceRegistryError(
            f"loaded launchd label ownership is ambiguous: {label}"
        )


def _preflight_stop_label(label: str, runtime_home: Path) -> None:
    label = _validated_label(label)
    plist = launch_agents_root() / f"{label}.plist"
    plist_command_identity = ""
    if plist.is_symlink():
        raise ServiceRegistryError(f"launchd plist is a symlink: {plist}")
    if plist.exists() and not plist.is_file():
        raise ServiceRegistryError(
            f"launchd plist path is not a regular file: {plist}"
        )
    if plist.exists():
        (
            observed_label,
            observed_runtime,
            command_identity,
        ) = _plist_identity(plist)
        if observed_label != label:
            raise ServiceRegistryError(
                f"launchd plist Label does not match registered label: {plist}"
            )
        if (
            not observed_runtime
            or canonical_path(observed_runtime) != runtime_home
        ):
            raise ServiceRegistryError(
                f"launchd plist runtime does not match registered ownership: "
                f"{plist}"
            )
        if not command_identity:
            raise ServiceRegistryError(
                f"launchd plist command does not match John Lomein service "
                f"contract: {plist}"
            )
        plist_command_identity = command_identity
    loaded, output = _launchctl_print(label)
    if loaded:
        observed_runtime = _runtime_home_from_launchctl_output(output)
        loaded_command_identity = _launchctl_command_identity(
            label,
            observed_runtime,
            output,
        )
        if (
            not observed_runtime
            or canonical_path(observed_runtime) != runtime_home
            or not loaded_command_identity
            or (
                plist_command_identity
                and loaded_command_identity != plist_command_identity
            )
        ):
            raise ServiceRegistryError(
                f"loaded launchd service runtime does not match registered "
                f"ownership: {label}"
            )
    if (
        loaded or plist.exists() or plist.is_symlink()
    ) and not shutil.which("launchctl"):
        raise ServiceRegistryError(
            f"launchctl unavailable while service may still exist: {label}"
        )


def _stop_label(label: str, runtime_home: Path) -> None:
    label = _validated_label(label)
    plist = launch_agents_root() / f"{label}.plist"
    _preflight_stop_label(label, runtime_home)
    launchctl = shutil.which("launchctl")
    loaded, _ = _launchctl_print(label)
    if (loaded or plist.exists() or plist.is_symlink()) and not launchctl:
        raise ServiceRegistryError(
            f"launchctl unavailable while service may still exist: {label}"
        )
    if launchctl:
        subprocess.run(
            [launchctl, "bootout", f"gui/{os.getuid()}/{label}"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        still_loaded = False
        output = ""
        for attempt in range(BOOTOUT_VERIFY_ATTEMPTS):
            still_loaded, output = _launchctl_print(label)
            if not still_loaded:
                break
            if attempt < BOOTOUT_VERIFY_ATTEMPTS - 1:
                time.sleep(BOOTOUT_VERIFY_INTERVAL_SECONDS)
        if still_loaded:
            raise ServiceRegistryError(
                f"launchd service remains loaded after bootout: {label}: "
                f"{output[:240]}"
            )
    if plist.is_symlink():
        raise ServiceRegistryError(f"launchd plist became a symlink: {plist}")
    if plist.exists():
        (
            observed_label,
            observed_runtime,
            command_identity,
        ) = _plist_identity(plist)
        if (
            observed_label != label
            or not observed_runtime
            or canonical_path(observed_runtime) != runtime_home
            or not command_identity
        ):
            raise ServiceRegistryError(
                f"launchd plist ownership changed during removal: {plist}"
            )
        plist.unlink()


def _stop_services_unlocked(
    manifest: str | Path,
    runtime_home: str | Path,
    requested: Mapping[str, str],
) -> dict[str, Any]:
    manifest_path = canonical_manifest_path(manifest)
    runtime_path = canonical_path(runtime_home)
    current_key = instance_key(manifest_path)
    existing = read_registry(manifest_path)
    registered = dict((existing or {}).get("labels") or {})
    registered_runtime = canonical_path(
        (existing or {}).get("runtime_home") or runtime_path
    )
    kinds = set(requested)
    if not kinds:
        raise ServiceRegistryError("no launchd service kinds supplied for stop")
    if not kinds <= SERVICE_KINDS:
        raise ServiceRegistryError("unsafe launchd service kind")

    candidates: dict[str, set[str]] = {kind: set() for kind in kinds}
    for kind in kinds:
        if registered.get(kind):
            candidates[kind].add(_validated_label(registered[kind]))
        if requested.get(kind):
            candidates[kind].add(_validated_label(requested[kind]))
    for label in discover_runtime_labels(runtime_path):
        kind = _service_kind(label)
        if kind in kinds:
            candidates[kind].add(label)

    ownership: dict[str, bool] = {}
    for kind in sorted(candidates):
        for label in sorted(candidates[kind]):
            owners = label_owners(label)
            foreign = [
                owner
                for owner in owners
                if instance_key(owner["manifest"]) != current_key
            ]
            if foreign:
                raise ServiceRegistryError(
                    f"refusing to stop foreign launchd label: {label} is owned "
                    f"by {foreign[0]['manifest']}"
                )
            owned_here = any(
                instance_key(owner["manifest"]) == current_key for owner in owners
            )
            if not owned_here:
                _assert_unregistered_label_belongs_to_runtime(
                    label,
                    runtime_path,
                )
            expected_runtime = (
                registered_runtime if owned_here else runtime_path
            )
            _preflight_stop_label(label, expected_runtime)
            ownership[label] = owned_here

    registry_runtime = (existing or {}).get("runtime_home") or runtime_path
    stopped: list[str] = []
    stopped_registered_kinds: set[str] = set()
    try:
        for kind in sorted(candidates):
            for label in sorted(candidates[kind]):
                expected_runtime = (
                    registered_runtime if ownership.get(label) else runtime_path
                )
                _stop_label(label, expected_runtime)
                stopped.append(label)
                if ownership.get(label) and registered.get(kind) == label:
                    stopped_registered_kinds.add(kind)
    except Exception:
        for kind in stopped_registered_kinds:
            registered.pop(kind, None)
        _write_or_remove_registry(
            manifest_path,
            registry_runtime,
            registered,
        )
        raise

    for kind in kinds:
        registered.pop(kind, None)
    _write_or_remove_registry(manifest_path, registry_runtime, registered)
    return {
        "manifest": str(manifest_path),
        "runtime_home": str(runtime_path),
        "stopped": stopped,
        "remaining_labels": registered,
    }


def stop_services(
    manifest: str | Path,
    runtime_home: str | Path,
    requested: Mapping[str, str],
) -> dict[str, Any]:
    with lifecycle_lock():
        return _stop_services_unlocked(manifest, runtime_home, requested)


def discover_runtime_labels(runtime_home: str | Path) -> set[str]:
    runtime_path = canonical_path(runtime_home)
    observations = _product_service_observations()
    return {
        label
        for label, observation in observations.items()
        if _observation_matches_runtime(label, observation, runtime_path)
    }


def adopt_services(
    manifest: str | Path,
    runtime_home: str | Path,
) -> dict[str, Any]:
    with lifecycle_lock():
        runtime_path = canonical_path(runtime_home)
        manifest_path = canonical_manifest_path(manifest)
        existing = read_registry(manifest_path)
        if (
            existing
            and canonical_path(existing["runtime_home"]) != runtime_path
        ):
            raise ServiceRegistryError(
                "cannot adopt services from a different runtime while this "
                "instance registry is nonempty; uninstall it first"
            )
        observations = _product_service_observations()
        if existing:
            for kind, label in existing["labels"].items():
                if not _observation_matches_runtime(
                    label,
                    observations.get(label),
                    runtime_path,
                ):
                    raise ServiceRegistryError(
                        f"cannot adopt while registered {kind}={label} has "
                        "missing or contradictory service identity"
                    )
        labels: dict[str, str] = {}
        candidates = {
            label
            for label, observation in observations.items()
            if _observation_points_at_runtime(observation, runtime_path)
        }
        for label in sorted(candidates):
            if not _observation_matches_runtime(
                label,
                observations[label],
                runtime_path,
            ):
                raise ServiceRegistryError(
                    f"cannot adopt contradictory plist/loaded identity: {label}"
                )
            kind = _service_kind(label)
            if kind in labels and labels[kind] != label:
                raise ServiceRegistryError(
                    f"multiple unregistered {kind} labels point at {runtime_path}; "
                    "uninstall the obsolete one explicitly"
                )
            labels[kind] = label
        if not labels:
            raise ServiceRegistryError(
                f"no John Lomein LaunchAgents found for {runtime_path}"
            )
        current_key = instance_key(manifest_path)
        for kind, label in labels.items():
            for owner in label_owners(label):
                if instance_key(owner["manifest"]) != current_key:
                    raise ServiceRegistryError(
                        f"cannot adopt foreign label: {kind}={label}"
                    )
        merged = dict((existing or {}).get("labels") or {})
        merged.update(labels)
        _write_or_remove_registry(manifest_path, runtime_path, merged)
        return {
            "manifest": str(manifest_path),
            "runtime_home": str(runtime_path),
            "adopted": labels,
        }


def _registry_status_unlocked(
    manifest: str | Path,
    runtime_home: str | Path,
    expected: Mapping[str, str],
) -> dict[str, Any]:
    manifest_path = canonical_manifest_path(manifest)
    runtime_path = canonical_path(runtime_home)
    entry = read_registry(manifest_path)
    registered = dict((entry or {}).get("labels") or {})
    expected_labels = {
        kind: _validated_label(label) for kind, label in expected.items()
    }
    issues: list[str] = []
    if entry and canonical_path(entry["runtime_home"]) != runtime_path:
        issues.append("registry_runtime_home_stale")
    if registered != expected_labels:
        issues.append("registry_labels_do_not_match_expected")
    observations = _product_service_observations()
    discovered = {
        label
        for label, observation in observations.items()
        if _observation_matches_runtime(label, observation, runtime_path)
    }
    expected_values = set(expected_labels.values())
    missing = sorted(expected_values - discovered)
    if missing:
        issues.append("expected_runtime_services_missing")
    identity_mismatches = sorted(
        label
        for label in set(registered.values()) | expected_values
        if not _observation_matches_runtime(
            label,
            observations.get(label),
            runtime_path,
        )
    )
    if identity_mismatches:
        issues.append("service_identity_mismatch")
    conflicting = sorted(
        label
        for label, observation in observations.items()
        if _observation_points_at_runtime(observation, runtime_path)
        and not _observation_matches_runtime(
            label,
            observation,
            runtime_path,
        )
    )
    if conflicting:
        issues.append("runtime_service_identity_conflict")
    unexpected = sorted(discovered - expected_values)
    if unexpected:
        issues.append("unexpected_runtime_services")
    return {
        "manifest": str(manifest_path),
        "runtime_home": str(runtime_path),
        "registered": registered,
        "expected": expected_labels,
        "discovered": sorted(discovered),
        "missing": missing,
        "identity_mismatches": identity_mismatches,
        "conflicting": conflicting,
        "unexpected": unexpected,
        "issues": issues,
    }


def registry_status(
    manifest: str | Path,
    runtime_home: str | Path,
    expected: Mapping[str, str],
) -> dict[str, Any]:
    with lifecycle_lock():
        return _registry_status_unlocked(manifest, runtime_home, expected)


def run_locked(command: list[str]) -> int:
    if not command:
        raise ServiceRegistryError("run-locked requires a command")
    with lifecycle_lock() as fd:
        os.set_inheritable(fd, True)
        env = dict(os.environ)
        env["JOHN_LOMEIN_SERVICE_LOCK_FD"] = str(fd)
        try:
            proc = subprocess.run(
                command,
                env=env,
                pass_fds=(fd,),
            )
        finally:
            os.set_inheritable(fd, False)
        return int(proc.returncode)


def assert_inherited_lock() -> None:
    if not os.environ.get("JOHN_LOMEIN_SERVICE_LOCK_FD"):
        raise ServiceRegistryError(
            "inherited lifecycle lock descriptor is missing"
        )
    with lifecycle_lock():
        return


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--runtime-home", required=True)
    parser.add_argument(
        "--service",
        action="append",
        default=[],
        metavar="KIND=LABEL",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("stop", "record", "status"):
        _common_arguments(subparsers.add_parser(command))
    adopt_parser = subparsers.add_parser("adopt")
    adopt_parser.add_argument("--manifest", required=True)
    adopt_parser.add_argument("--runtime-home", required=True)
    locked_parser = subparsers.add_parser("run-locked")
    locked_parser.add_argument("locked_command", nargs=argparse.REMAINDER)
    subparsers.add_parser("assert-locked")
    args = parser.parse_args(argv)
    try:
        if args.command == "run-locked":
            command = list(args.locked_command)
            if command[:1] == ["--"]:
                command = command[1:]
            return run_locked(command)
        if args.command == "assert-locked":
            assert_inherited_lock()
            return 0
        if args.command == "adopt":
            result = adopt_services(args.manifest, args.runtime_home)
        else:
            services = parse_services(args.service)
        if args.command == "stop":
            result = stop_services(
                args.manifest,
                args.runtime_home,
                services,
            )
        elif args.command == "record":
            result = record_services(
                args.manifest,
                args.runtime_home,
                services,
            )
        elif args.command == "status":
            result = registry_status(
                args.manifest,
                args.runtime_home,
                services,
            )
    except ServiceRegistryError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
