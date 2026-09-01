#!/usr/bin/env python3
"""Create a mission-candidate John Lomein instance in safe observer mode."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

import yaml


PRODUCT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = PRODUCT_ROOT / "scripts"
TEMPLATE = PRODUCT_ROOT / "templates" / "instance.yaml.example"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from john_lomein_factory_receipts import (  # noqa: E402
    public_metadata_text,
    safe_default_branch,
    safe_github_repo,
    safe_instance_slug,
)
from john_lomein_file_contract import (  # noqa: E402
    StableFileError,
    directory_chain_identity,
)
from john_lomein_manifest_contract import (  # noqa: E402
    validate_manifest_contract,
    validate_runtime_checkout_separation,
)
from john_lomein_orientation import (  # noqa: E402
    OrientationError,
    build_orientation,
    render_human,
)


class InitializerError(RuntimeError):
    """Raised when a fresh instance cannot be created safely."""


def _derived_slug(repo: str) -> str:
    name = repo.split("/", 1)[1].lower()
    slug = re.sub(r"[^a-z0-9._-]+", "-", name).strip("._-")
    try:
        return safe_instance_slug(slug)
    except ValueError as exc:
        raise InitializerError("cannot derive a safe slug from target repo") from exc


def _bounded_text(value: Any, field: str, *, max_length: int) -> str:
    try:
        return public_metadata_text(
            value,
            field,
            max_length=max_length,
        )
    except ValueError as exc:
        raise InitializerError(str(exc)) from exc


def _template_manifest() -> dict[str, Any]:
    try:
        value = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise InitializerError("cannot load the product instance template") from exc
    if not isinstance(value, dict):
        raise InitializerError("product instance template is not a mapping")
    return value


def build_observer_manifest(
    *,
    repo: str,
    mission: str,
    test_cmd: str,
    slug: str | None = None,
    display_name: str | None = None,
    default_branch: str = "main",
    runtime_home: str | None = None,
    local_checkout: str | None = None,
    roadmap_sources: Sequence[str] = (),
) -> dict[str, Any]:
    """Build and validate a credential-free, owner-gated candidate manifest."""

    try:
        safe_repo = safe_github_repo(repo)
        safe_slug = safe_instance_slug(slug) if slug else _derived_slug(safe_repo)
        safe_branch = safe_default_branch(default_branch)
    except ValueError as exc:
        raise InitializerError(str(exc)) from exc
    safe_display = _bounded_text(
        display_name or safe_repo.split("/", 1)[1].replace("-", " ").replace("_", " "),
        "instance.display_name",
        max_length=160,
    )
    safe_mission = _bounded_text(
        mission,
        "mission.statement",
        max_length=1200,
    )
    safe_test_cmd = _bounded_text(
        test_cmd,
        "gates.test_cmd",
        max_length=1000,
    )
    safe_sources = [
        _bounded_text(
            source,
            f"mission.roadmap_sources[{index}]",
            max_length=240,
        )
        for index, source in enumerate(roadmap_sources)
    ]

    runtime_raw=runtime_home or f"~/.john-lomein/instances/{safe_slug}/hermes"
    checkout_raw=local_checkout or f"~/.john-lomein/instances/{safe_slug}/work/repo"
    runtime_path=Path(runtime_raw).expanduser()
    checkout_path=Path(checkout_raw).expanduser()
    try:
        checkout_canonical,runtime_canonical=validate_runtime_checkout_separation(
            checkout_path,
            runtime_path,
        )
    except ValueError as exc:
        raise InitializerError(str(exc)) from exc
    runtime=str(runtime_canonical)
    checkout=str(checkout_canonical)

    manifest = _template_manifest()
    manifest["instance"] = {
        "slug": safe_slug,
        "display_name": safe_display,
    }
    manifest.setdefault("mission", {})
    manifest["mission"].update(
        {
            "owner_authored": False,
            "statement": safe_mission,
        }
    )
    if safe_sources:
        manifest["mission"]["roadmap_sources"] = safe_sources
    manifest["target"] = {
        "repo": safe_repo,
        "default_branch": safe_branch,
        "local_checkout": checkout,
    }
    manifest.setdefault("runtime", {})
    manifest["runtime"].update(
        {
            "hermes_home": runtime,
            "activation": "owner_gated",
            "mutation_enabled": False,
            "discord_enabled": False,
            "guide_gateway_enabled": False,
            "keep_awake_on_ac": False,
        }
    )
    manifest.setdefault("discord", {})
    manifest["discord"].update(
        {
            "enabled": False,
            "guide_gateway_enabled": False,
            "owner_user_ids": [],
            "trusted_collaborator_user_ids": [],
            "allowed_channels": [],
            "free_response_channels": [],
            "untrusted_example_channels": [],
            "no_thread_channels": [],
        }
    )
    manifest.setdefault("release", {})
    manifest["release"]["protected_broker_enabled"] = False
    manifest.setdefault("open_scaffold_portfolio", {})
    manifest["open_scaffold_portfolio"]["enabled"] = False
    manifest.setdefault("authority", {})
    manifest["authority"]["owner_approvers"] = []
    manifest["authority"]["trust_public_key_sha256"] = ""
    manifest.setdefault("gates", {})
    manifest["gates"]["test_cmd"] = safe_test_cmd
    manifest["gates"]["autonomous_safe_labels"] = []
    manifest["secrets"] = {
        "import_env_files": [],
        "env_keys": [],
    }
    manifest.setdefault("workflows", {})
    manifest["workflows"]["omh_home"] = f"{runtime.rstrip('/')}/omh"

    try:
        contract = validate_manifest_contract(manifest)
    except ValueError as exc:
        raise InitializerError(str(exc)) from exc
    flags = contract["flags"]
    required_false = {
        "runtime_mutation_enabled",
        "discord_enabled",
        "guide_gateway_enabled",
        "protected_release_broker_enabled",
        "portfolio_enabled",
    }
    if any(flags[name] for name in required_false):
        raise InitializerError("observer initializer produced an unsafe authority flag")
    if flags["mission_owner_authored"] or contract["mission_complete"]:
        raise InitializerError("observer initializer asserted owner mission provenance")
    if not contract["mission_candidate_complete"]:
        raise InitializerError("observer initializer lost the mission candidate")
    return manifest


def _write_pending_manifest(path: Path, manifest: dict[str, Any]) -> None:
    data = yaml.safe_dump(
        manifest,
        sort_keys=False,
        allow_unicode=True,
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _created_directory_identity(path: Path) -> tuple[int, int]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InitializerError(
            "new instance directory became unavailable"
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise InitializerError("new instance directory identity is unsafe")
    return info.st_dev, info.st_ino


def _assert_creation_identity(
    target: Path,
    *,
    target_identity: tuple[int, int],
    parent_identity: tuple[tuple[int, ...], ...],
) -> None:
    if _created_directory_identity(target) != target_identity:
        raise InitializerError("new instance directory identity changed")
    try:
        observed_parent = directory_chain_identity(target)
    except StableFileError as exc:
        raise InitializerError(
            "instance destination parent became unsafe"
        ) from exc
    if observed_parent != parent_identity:
        raise InitializerError("instance destination parent identity changed")


def create_instance(
    destination: str | Path,
    manifest: dict[str, Any],
    *,
    validator: str | Path = SCRIPT_DIR / "read-instance-env.py",
) -> Path:
    """Create a fresh instance without overwriting any existing path."""

    target = Path(
        os.path.abspath(Path(destination).expanduser())
    )
    if target == Path(target.anchor):
        raise InitializerError("instance destination cannot be a filesystem root")
    try:
        parent_identity = directory_chain_identity(target)
    except StableFileError as exc:
        raise InitializerError(
            "instance destination parent must exist without mutable symlinks"
        ) from exc
    try:
        target.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise InitializerError(
            f"instance destination already exists: {target}"
        ) from exc
    target_identity = _created_directory_identity(target)
    pending = target / ".instance.yaml.pending"
    final = target / "instance.yaml"
    try:
        _assert_creation_identity(
            target,
            target_identity=target_identity,
            parent_identity=parent_identity,
        )
        private = target / "private"
        private.mkdir(mode=0o700)
        _assert_creation_identity(
            target,
            target_identity=target_identity,
            parent_identity=parent_identity,
        )
        _write_pending_manifest(pending, manifest)
        _assert_creation_identity(
            target,
            target_identity=target_identity,
            parent_identity=parent_identity,
        )
        validation = subprocess.run(
            [sys.executable, str(validator), str(pending)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
        _assert_creation_identity(
            target,
            target_identity=target_identity,
            parent_identity=parent_identity,
        )
        if validation.returncode != 0:
            detail = " ".join((validation.stderr or "").split())
            raise InitializerError(
                "generated manifest failed product validation"
                + (f": {detail[:300]}" if detail else "")
            )
        os.replace(pending, final)
        os.chmod(final, 0o600)
        _assert_creation_identity(
            target,
            target_identity=target_identity,
            parent_identity=parent_identity,
        )
        _fsync_directory(target)
        _fsync_directory(target.parent)
    except Exception:
        try:
            _assert_creation_identity(
                target,
                target_identity=target_identity,
                parent_identity=parent_identity,
            )
        except InitializerError:
            pass
        else:
            shutil.rmtree(target, ignore_errors=True)
        raise
    return target


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "create a mission-candidate John Lomein instance in observer mode"
        )
    )
    parser.add_argument("destination")
    parser.add_argument("--repo", required=True)
    parser.add_argument(
        "--mission",
        required=True,
        help=(
            "public-safe mission candidate text; this does not assert owner "
            "authorship"
        ),
    )
    parser.add_argument("--test-cmd", required=True)
    parser.add_argument("--slug")
    parser.add_argument("--display-name")
    parser.add_argument("--default-branch", default="main")
    parser.add_argument("--runtime-home")
    parser.add_argument("--local-checkout")
    parser.add_argument(
        "--roadmap-source",
        action="append",
        default=[],
        dest="roadmap_sources",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="run the existing transactional setup after initialization",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit one machine-readable report; cannot be combined with --install",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.json and args.install:
        print(
            "john-lomein init failed: --json cannot be combined with --install",
            file=sys.stderr,
        )
        return 2
    try:
        manifest = build_observer_manifest(
            repo=args.repo,
            mission=args.mission,
            test_cmd=args.test_cmd,
            slug=args.slug,
            display_name=args.display_name,
            default_branch=args.default_branch,
            runtime_home=args.runtime_home,
            local_checkout=args.local_checkout,
            roadmap_sources=args.roadmap_sources,
        )
        instance = create_instance(args.destination, manifest)
    except (InitializerError, OSError) as exc:
        print(f"john-lomein init failed: {exc}", file=sys.stderr)
        return 2
    try:
        orientation = build_orientation(instance)
    except OrientationError as exc:
        print(
            f"john-lomein init orientation failed: {exc.code}",
            file=sys.stderr,
        )
        return 2
    except Exception:
        print(
            "john-lomein init orientation failed: orientation_internal_error",
            file=sys.stderr,
        )
        return 2

    report = {
        "schema_version": "john_lomein_observer_initializer/v1",
        "status": "initialized",
        "instance": str(instance),
        "manifest": str(instance / "instance.yaml"),
        "posture": {
            "activation": "owner_gated",
            "mutation_enabled": False,
            "discord_enabled": False,
            "guide_gateway_enabled": False,
        },
        "optional_privileged_components": "not_installed",
        "orientation": orientation,
    }
    if args.json:
        print(json.dumps(report, sort_keys=True))
    elif args.install:
        print(f"initialized observer instance: {instance}")
        print("installing the validated observer appliance")
    else:
        print(render_human(orientation))

    if not args.install:
        if not args.json:
            print(f"next: {PRODUCT_ROOT / 'setup.sh'} {instance}")
        return 0
    setup = subprocess.run(
        [str(PRODUCT_ROOT / "setup.sh"), str(instance)],
        stdin=None,
        stdout=None,
        stderr=None,
        check=False,
    )
    return int(setup.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
