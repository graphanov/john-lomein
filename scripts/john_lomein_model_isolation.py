#!/usr/bin/env python3
"""OS-enforced filesystem boundary for every John Lomein model process.

The deterministic scheduler and learning steward remain ordinary trusted
runtime processes.  Hermes chats, the public Guide gateway, and coding-model
executors enter this wrapper before any model-controlled tool can run.  The
sandbox is inherited by descendants, so a terminal tool cannot recover the
private Mnemosyne or raw learning state by launching another process.

Supported enforcement backends:

* macOS: ``sandbox-exec`` (Seatbelt);
* Linux: unprivileged ``bwrap`` (bubblewrap).

There is deliberately no "best effort" execution path when the manifest says
``learning.model_memory_isolation: required``.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

# Product modules execute from a sealed runtime tree; never create import cache
# files there before the sandbox is entered.
sys.dont_write_bytecode = True

from john_lomein_gateway_lock_contract import (
    GatewayLockContractError,
    gateway_lock_root,
    validate_gateway_lock_root,
)
from john_lomein_profile_contract import CANONICAL_ROLE_PROFILES


MODE_REQUIRED = "required"
MODE_DISABLED = "disabled"
SUPPORTED_MODES = frozenset({MODE_REQUIRED, MODE_DISABLED})
CONTROLLED_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
MAX_ALIAS_SCAN_ENTRIES = 500_000
CONTINUITY_PLUGIN = "john-lomein-continuity"
RELEASE_APPROVAL_PLUGIN = "john-lomein-release-approval"
GUIDE_LIFECYCLE_PLUGIN = "john-lomein-guide-lifecycle"
OPENAI_CODEX_PROVIDER = "openai-codex"
PROVIDER_BROKER_SCRIPT = "john_lomein_provider_broker.py"
PROVIDER_BOOTSTRAP_SCRIPT = "john_lomein_provider_bootstrap.py"
PROVIDER_SOCKET_NAME = "broker.sock"
HONCHO_SOCKET_NAME = "honcho.sock"
PROVIDER_SESSION_RE = re.compile(r"^[0-9a-f]{24}$")
PROFILE_ROLE_BY_NAME = {
    profile: role for role, profile in CANONICAL_ROLE_PROFILES.items()
}
HERMES_RUNTIME_CODE_ROOTS = (
    ".git", "acp_adapter", "agent", "batch_runner", "cli", "cron", "gateway",
    "hermes_bootstrap", "hermes_cli", "hermes_constants", "hermes_logging",
    "hermes_state", "hermes_state_common", "hermes_state_portability",
    "hermes_state_schema", "hermes_state_search", "hermes_time",
    "mcp_serve", "model_tools", "plugins", "providers",
    "registration_lifecycle", "run_agent", "tools",
    "toolset_distributions", "toolsets", "trajectory_compressor",
    "tui_gateway", "utils",
)
# Hermes keeps gateway/session databases and atomic JSON siblings directly in a
# selected profile root.  When that exact root is made writable, these product
# and credential surfaces must remain immutable inside the model namespace.
PROFILE_PROTECTED_LEAVES = (
    ".anthropic_oauth.json",
    ".env",
    ".no-bundled-skills",
    "SOUL.md",
    "auth.json",
    "config.yaml",
    "distribution.yaml",
    "honcho.json",
    "credentials.json",
    "google_oauth_pending.json",
    "google_token.json",
    "mcp.json",
    "profile.yaml",
    "shell-hooks-allowlist.json",
    "shell-hooks-allowlist.json.lock",
    "webhook_subscriptions.json",
)
PROFILE_PROTECTED_DIRECTORIES = (
    "auth",
    "bin",
    "credentials",
    "hooks",
    "mcp-tokens",
    "memories",
    "plugins",
    "scripts",
    "skills",
    "skins",
)
PROFILE_PROTECTED_NESTED_LEAVES = (
    ("cache", "bws_cache.json"),
)


class IsolationError(RuntimeError):
    """Raised when a required model boundary cannot be proven."""


def _uses_openai_codex(env: Mapping[str, str]) -> bool:
    return OPENAI_CODEX_PROVIDER in {
        str(env.get("BOT_MODEL_PROVIDER") or "").strip(),
        str(env.get("BOT_FALLBACK_PROVIDER") or "").strip(),
    }


def _provider_broker_root() -> Path:
    """Return a short, deterministic per-UID root outside long instance paths."""

    try:
        temporary = Path("/tmp").resolve(strict=True)
    except OSError as exc:
        raise IsolationError("model_isolation_provider_tmp_unavailable") from exc
    return temporary / f"jl-pb-{os.geteuid()}"


def provider_broker_socket_path() -> Path:
    """Return a fresh portable AF_UNIX path for one controller/model pair."""

    path = (
        _provider_broker_root()
        / secrets.token_hex(12)
        / PROVIDER_SOCKET_NAME
    )
    if len(os.fsencode(path)) > 100:
        raise IsolationError("model_isolation_provider_socket_path_too_long")
    return path


def honcho_broker_socket_path(provider_socket: Path) -> Path:
    """Return the second fixed sibling socket for one model process."""

    provider = _validate_provider_socket_path(provider_socket)
    path = provider.with_name(HONCHO_SOCKET_NAME)
    if len(os.fsencode(path)) > 100:
        raise IsolationError("model_isolation_honcho_socket_path_too_long")
    return path


def _validate_provider_socket_path(path: Path) -> Path:
    candidate = Path(os.path.abspath(path.expanduser()))
    if (
        candidate.name != PROVIDER_SOCKET_NAME
        or candidate.parent.parent != _provider_broker_root()
        or not PROVIDER_SESSION_RE.fullmatch(candidate.parent.name)
        or len(os.fsencode(candidate)) > 100
    ):
        raise IsolationError("model_isolation_provider_socket_outside_runtime")
    return candidate


def _validate_honcho_socket_path(path: Path, provider_socket: Path) -> Path:
    candidate = Path(os.path.abspath(path.expanduser()))
    expected = honcho_broker_socket_path(provider_socket)
    if candidate != expected:
        raise IsolationError("model_isolation_honcho_socket_outside_runtime")
    return candidate


def _absolute_no_symlink(path: Path, *, label: str, must_exist: bool = True) -> Path:
    raw = Path(os.path.abspath(path.expanduser()))
    current = Path(raw.anchor)
    for component in raw.parts[1:]:
        current /= component
        if current.is_symlink():
            link = current.lstat()
            parent = current.parent.stat()
            immutable_platform_alias = (
                link.st_uid == 0
                and parent.st_uid == 0
                and not (parent.st_mode & 0o022)
            )
            if not immutable_platform_alias:
                raise IsolationError(f"{label}_symlink_component:{current}")
    if must_exist and not raw.exists():
        raise IsolationError(f"{label}_missing:{raw}")
    return raw


def _runtime_home(env: Mapping[str, str]) -> Path:
    raw = str(env.get("BOT_HERMES_HOME") or env.get("HERMES_HOME") or "").strip()
    if not raw or "\x00" in raw:
        raise IsolationError("model_isolation_missing_runtime_home")
    home = _absolute_no_symlink(Path(raw), label="model_isolation_runtime")
    if not home.is_dir():
        raise IsolationError(f"model_isolation_runtime_not_directory:{home}")
    return home


def _mode(env: Mapping[str, str]) -> str:
    mode = str(env.get("BOT_MODEL_MEMORY_ISOLATION") or MODE_REQUIRED).strip()
    if mode not in SUPPORTED_MODES:
        raise IsolationError(f"model_isolation_invalid_mode:{mode}")
    return mode


def private_root(env: Mapping[str, str]) -> Path:
    home = _runtime_home(env)
    expected = home / "private" / "learning-steward"
    configured = Path(
        str(env.get("BOT_STEWARD_PRIVATE_ROOT") or expected)
    ).expanduser()
    if Path(os.path.abspath(configured)) != expected:
        raise IsolationError("model_isolation_private_root_not_canonical")
    root = _absolute_no_symlink(expected, label="model_isolation_private")
    if not root.is_dir():
        raise IsolationError("model_isolation_private_root_not_directory")
    return root


def projection_root(env: Mapping[str, str]) -> Path:
    home = _runtime_home(env)
    expected = home / "state" / "learning"
    configured = Path(
        str(env.get("BOT_STEWARD_PROJECTION_ROOT") or expected)
    ).expanduser()
    if Path(os.path.abspath(configured)) != expected:
        raise IsolationError("model_isolation_projection_root_not_canonical")
    root = _absolute_no_symlink(expected, label="model_isolation_projection")
    if not root.is_dir():
        raise IsolationError("model_isolation_projection_root_not_directory")
    return root


def _scheme_string(value: Path | str) -> str:
    text = str(value)
    if "\x00" in text or "\n" in text or "\r" in text:
        raise IsolationError("model_isolation_unsafe_policy_path")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _policy_path(path: Path) -> Path:
    """Use the kernel-facing canonical spelling for immutable platform aliases."""

    return path.resolve(strict=False)


def _policy_spellings(path: Path) -> list[Path]:
    """Cover both a profile binding and the kernel-facing target it names."""

    raw = Path(os.path.abspath(path.expanduser()))
    canonical = _policy_path(raw)
    return list(dict.fromkeys((raw, canonical)))


def _profile_roots(home: Path) -> list[Path]:
    profiles = home / "profiles"
    if not profiles.exists():
        return []
    profiles = _absolute_no_symlink(profiles, label="model_isolation_profiles")
    roots: list[Path] = []
    for child in sorted(profiles.iterdir(), key=lambda item: item.name):
        if child.is_symlink():
            raise IsolationError(f"model_isolation_profile_symlink:{child}")
        if child.is_dir():
            roots.append(child)
    return roots


def _active_profile_root(
    env: Mapping[str, str],
    profile: str | None,
) -> Path | None:
    """Resolve one canonical profile as the only profile-scoped write grant."""

    if profile is None:
        return None
    name = str(profile).strip()
    if name not in PROFILE_ROLE_BY_NAME:
        raise IsolationError(f"model_isolation_unknown_active_profile:{name}")
    home = _runtime_home(env)
    root = _absolute_no_symlink(
        home / "profiles" / name,
        label="model_isolation_active_profile",
    )
    if not root.is_dir():
        raise IsolationError(
            f"model_isolation_active_profile_not_directory:{root}"
        )
    expected_managed = home / "managed-policy" / name
    configured_managed = str(env.get("HERMES_MANAGED_DIR") or "").strip()
    if not configured_managed:
        raise IsolationError("model_isolation_active_profile_policy_missing")
    observed_managed = Path(
        os.path.abspath(Path(configured_managed).expanduser())
    )
    if observed_managed != expected_managed:
        raise IsolationError(
            "model_isolation_active_profile_policy_mismatch"
        )
    _absolute_no_symlink(
        expected_managed,
        label="model_isolation_active_profile_policy",
    )
    return root


def _profile_protected_paths(profile: Path) -> list[tuple[str, Path]]:
    """Return fixed control paths, including absent names that must stay sealed."""

    protected: list[tuple[str, Path]] = [
        ("leaf", profile / name) for name in PROFILE_PROTECTED_LEAVES
    ]
    protected.extend(
        ("directory", profile / name)
        for name in PROFILE_PROTECTED_DIRECTORIES
    )
    protected.extend(
        ("leaf", profile.joinpath(*parts))
        for parts in PROFILE_PROTECTED_NESTED_LEAVES
    )
    return protected


def _auth_authority_home(
    env: Mapping[str, str],
    *,
    required: bool = False,
) -> Path | None:
    """Resolve the trusted host auth store without accepting path overrides."""

    real_home_raw = str(env.get("HERMES_REAL_HOME") or "").strip()
    configured_raw = str(
        env.get("JOHN_LOMEIN_AUTH_AUTHORITY_HOME") or ""
    ).strip()
    if not real_home_raw:
        if required or configured_raw:
            raise IsolationError("model_isolation_auth_authority_real_home_missing")
        return None
    if "\x00" in real_home_raw or "\x00" in configured_raw:
        raise IsolationError("model_isolation_auth_authority_path_invalid")
    real_home = Path(os.path.abspath(Path(real_home_raw).expanduser()))
    expected = real_home / ".hermes"
    observed = Path(
        os.path.abspath(
            Path(configured_raw).expanduser() if configured_raw else expected
        )
    )
    if observed != expected:
        raise IsolationError("model_isolation_auth_authority_path_mismatch")
    if not observed.exists():
        if required:
            raise IsolationError("model_isolation_auth_authority_missing")
        return None
    authority = _absolute_no_symlink(
        observed,
        label="model_isolation_auth_authority",
    )
    if not authority.is_dir():
        raise IsolationError("model_isolation_auth_authority_not_directory")
    auth_file = authority / "auth.json"
    if auth_file.exists() or auth_file.is_symlink():
        _validate_protected_leaf(
            auth_file,
            label="auth_authority",
        )
    elif required:
        raise IsolationError("model_isolation_auth_authority_store_missing")
    return authority


def _hidden_credential_paths(
    env: Mapping[str, str],
    *,
    active_profile: Path | None,
) -> list[Path]:
    """Credential stores a model must never read through another home."""

    home = _runtime_home(env)
    # Provider resolution is controller-brokered. Model processes have no
    # reason to read any runtime, profile, host, or CLI credential store.
    candidates: list[Path] = [home / "auth.json"]
    authority = _auth_authority_home(
        env,
        required=_uses_openai_codex(env),
    )
    if authority is not None:
        candidates.append(authority / "auth.json")
    candidates.extend(
        root / "auth.json"
        for root in _profile_roots(home)
    )
    candidates.extend(root / "home" / ".config" / "gh" for root in _profile_roots(home))
    real_home = Path(str(env.get("HERMES_REAL_HOME") or Path.home())).expanduser().resolve()
    for relative in (".ssh", ".gnupg", ".git-credentials", ".netrc", ".gitcookies", ".npmrc", ".pypirc", ".config/gh", ".config/git", ".config/hub", ".config/gcloud", ".aws", ".azure", ".kube", ".docker", ".codex", "Library/Keychains", "Library/Application Support/GitHub CLI"):
        candidates.append(real_home / relative)
    return list(
        dict.fromkeys(
            path
            for path in candidates
            if path.exists() or path.is_symlink()
        )
    )


def _release_bundle_control_root(env: Mapping[str, str]) -> Path:
    root = _runtime_home(env) / "private" / "release-bundles"
    if root.is_symlink() or not root.is_dir():
        raise IsolationError("release_bundle_controller_root_unsafe")
    _validate_protected_tree(root, label="release_bundles")
    return root


def _hidden_control_roots(env: Mapping[str, str]) -> list[Path]:
    home = _runtime_home(env)
    roots: list[Path] = [_release_bundle_control_root(env)]
    candidates = (
        (home / "private" / "owner-overrides", "owner-overrides"),
        (home / "private" / "review-receipts", "review-receipts"),
        (home / "private" / "honcho-deletion-tombstones", "honcho-deletion-tombstones"),
        (home / "private" / "honcho-backups", "honcho-backups"),
        (home / "state" / "honcho", "honcho-state"),
        (home / "services" / "public-honcho", "public-honcho-service"),
        (home / "logs" / "public-honcho", "public-honcho-logs"),
    )
    for root, label in candidates:
        if not root.exists() and not root.is_symlink():
            continue
        checked = _absolute_no_symlink(root, label=f"{label}_control_root")
        if not checked.is_dir():
            raise IsolationError(f"{label}_control_root_not_directory")
        roots.append(checked)
    return roots


def _shared_gateway_lock_root(env: Mapping[str, str]) -> Path | None:
    """Validate the one machine-wide Hermes token-lock write grant."""

    configured = str(env.get("HERMES_GATEWAY_LOCK_DIR") or "").strip()
    if not configured:
        return None
    real_home_raw = str(env.get("HERMES_REAL_HOME") or "").strip()
    if not real_home_raw:
        raise IsolationError("model_isolation_gateway_lock_home_missing")
    real_home = Path(os.path.abspath(Path(real_home_raw).expanduser()))
    expected = gateway_lock_root(real_home)
    observed = Path(os.path.abspath(Path(configured).expanduser()))
    if observed != expected:
        raise IsolationError("model_isolation_gateway_lock_path_mismatch")
    try:
        validated = validate_gateway_lock_root(real_home)
    except GatewayLockContractError as exc:
        raise IsolationError(
            f"model_isolation_gateway_lock_unsafe:{exc}"
        ) from exc
    if validated != expected:
        raise IsolationError("model_isolation_gateway_lock_path_mismatch")
    return _absolute_no_symlink(
        expected,
        label="model_isolation_gateway_lock",
    )


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _validate_private_tree(root: Path) -> None:
    """Reject redirects/hardlinks that could alias protected bytes elsewhere."""

    uid = os.geteuid()
    seen = 0
    for directory, names, files in os.walk(root, followlinks=False):
        current = Path(directory)
        info = current.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != uid
            or info.st_mode & 0o077
        ):
            raise IsolationError(f"model_isolation_private_directory_unsafe:{current}")
        for name in [*names, *files]:
            seen += 1
            if seen > MAX_ALIAS_SCAN_ENTRIES:
                raise IsolationError("model_isolation_private_tree_too_large")
            path = current / name
            entry = path.lstat()
            if stat.S_ISLNK(entry.st_mode):
                raise IsolationError(f"model_isolation_private_symlink:{path}")
            if stat.S_ISDIR(entry.st_mode):
                continue
            if (
                not stat.S_ISREG(entry.st_mode)
                or entry.st_uid != uid
                or entry.st_nlink != 1
                or entry.st_mode & 0o077
            ):
                raise IsolationError(f"model_isolation_private_file_unsafe:{path}")


def _validate_protected_tree(root: Path, *, label: str) -> None:
    """Reject inode aliases or mutable metadata on model-read deployment code."""

    if root.is_symlink() or not root.is_dir():
        raise IsolationError(f"model_isolation_{label}_root_unsafe:{root}")
    uid = os.geteuid()
    seen = 0
    for directory, names, files in os.walk(root, followlinks=False):
        current = Path(directory)
        info = current.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != uid
            or info.st_mode & 0o022
        ):
            raise IsolationError(
                f"model_isolation_{label}_directory_unsafe:{current}"
            )
        for name in [*names, *files]:
            seen += 1
            if seen > MAX_ALIAS_SCAN_ENTRIES:
                raise IsolationError(f"model_isolation_{label}_tree_too_large")
            path = current / name
            entry = path.lstat()
            if stat.S_ISLNK(entry.st_mode):
                raise IsolationError(
                    f"model_isolation_{label}_symlink:{path}"
                )
            if stat.S_ISDIR(entry.st_mode):
                continue
            if (
                not stat.S_ISREG(entry.st_mode)
                or entry.st_uid != uid
                or entry.st_nlink != 1
                or entry.st_mode & 0o022
            ):
                raise IsolationError(
                    f"model_isolation_{label}_file_unsafe:{path}"
                )


def _validate_profile_plugin_bindings(
    root: Path,
    *,
    home: Path,
    label: str,
) -> None:
    """Validate the exact product plugin aliases installed in a profile.

    Deployed profiles bind their executable hooks to the single protected
    runtime copy.  Arbitrary aliases remain forbidden: only the role's named
    product hooks may be links, each must resolve to its exact runtime plugin
    directory, and those targets are validated as protected trees separately.
    """

    runtime_plugins = home / "plugins"
    if runtime_plugins.is_symlink() or not runtime_plugins.is_dir():
        raise IsolationError(
            f"model_isolation_runtime_plugins_root_unsafe:{runtime_plugins}"
        )
    runtime_info = runtime_plugins.lstat()
    if (
        not stat.S_ISDIR(runtime_info.st_mode)
        or runtime_info.st_uid != os.geteuid()
        or runtime_info.st_mode & 0o022
    ):
        raise IsolationError(
            f"model_isolation_runtime_plugins_directory_unsafe:"
            f"{runtime_plugins}"
        )
    for plugin_name in (
        CONTINUITY_PLUGIN,
        RELEASE_APPROVAL_PLUGIN,
        GUIDE_LIFECYCLE_PLUGIN,
    ):
        _validate_protected_tree(
            runtime_plugins / plugin_name,
            label=f"runtime_plugin_{plugin_name.replace('-', '_')}",
        )

    if root.is_symlink() or not root.is_dir():
        raise IsolationError(f"model_isolation_{label}_root_unsafe:{root}")
    info = root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o022
    ):
        raise IsolationError(
            f"model_isolation_{label}_directory_unsafe:{root}"
        )
    role = PROFILE_ROLE_BY_NAME.get(root.parent.name)
    if role is None:
        raise IsolationError(
            f"model_isolation_{label}_unknown_profile:{root.parent}"
        )
    expected_names = {CONTINUITY_PLUGIN}
    if role == "guide":
        expected_names.update(
            {RELEASE_APPROVAL_PLUGIN, GUIDE_LIFECYCLE_PLUGIN}
        )
    observed = {entry.name: entry for entry in root.iterdir()}
    if set(observed) != expected_names:
        raise IsolationError(
            f"model_isolation_{label}_bindings_incomplete:{root}"
        )
    for plugin_name in sorted(expected_names):
        plugin = observed[plugin_name]
        link = plugin.lstat()
        if (
            not stat.S_ISLNK(link.st_mode)
            or link.st_uid != os.geteuid()
            or link.st_nlink != 1
        ):
            raise IsolationError(
                f"model_isolation_{label}_binding_unsafe:{plugin}"
            )
        expected = runtime_plugins / plugin_name
        try:
            observed_target = os.readlink(plugin)
        except OSError:
            raise IsolationError(
                f"model_isolation_{label}_binding_unsafe:{plugin}"
            )
        if observed_target != str(expected):
            raise IsolationError(
                f"model_isolation_{label}_binding_unsafe:{plugin}"
            )


def _validate_profile_scripts_binding(
    profile: Path,
    *,
    home: Path,
    label: str,
) -> None:
    """Validate the exact protected mirror Hermes uses for profile cron."""

    binding = profile / "scripts"
    runtime = home / "scripts"
    _validate_protected_tree(binding, label=label)

    def entries(root: Path) -> dict[Path, tuple[str, int]]:
        result: dict[Path, tuple[str, int]] = {}
        for directory, names, files in os.walk(root, followlinks=False):
            current = Path(directory)
            names[:] = [
                name
                for name in names
                if name not in {"__pycache__", ".DS_Store"}
            ]
            relative_directory = current.relative_to(root)
            if relative_directory != Path("."):
                result[relative_directory] = (
                    "directory",
                    stat.S_IMODE(current.lstat().st_mode),
                )
            for name in files:
                if name in {".DS_Store"}:
                    continue
                path = current / name
                result[path.relative_to(root)] = (
                    "file",
                    stat.S_IMODE(path.lstat().st_mode),
                )
        return result

    expected = entries(runtime)
    observed = entries(binding)
    if observed != expected:
        raise IsolationError(
            f"model_isolation_{label}_mirror_metadata_mismatch:{binding}"
        )
    for relative, (kind, _mode) in expected.items():
        if kind != "file":
            continue
        source = runtime / relative
        mirrored = binding / relative
        if source.read_bytes() != mirrored.read_bytes():
            raise IsolationError(
                f"model_isolation_{label}_mirror_content_mismatch:{mirrored}"
            )


def _validate_protected_leaf(path: Path, *, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise IsolationError(f"model_isolation_{label}_missing_or_redirected:{path}")
    info = path.lstat()
    if (
        info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o022
    ):
        raise IsolationError(f"model_isolation_{label}_file_unsafe:{path}")


def _validate_protected_deployment(home: Path) -> None:
    """Prove writable aliases cannot mutate model policy through another path."""

    for label, root in (
        ("scripts", home / "scripts"),
        ("managed_policy", home / "managed-policy"),
        ("continuity", home / "state" / "continuity"),
    ):
        _validate_protected_tree(root, label=label)
    _validate_protected_leaf(
        home / "instance.yaml",
        label="instance_manifest",
    )
    for label, path in (
        ("runtime_auth", home / "auth.json"),
        ("runtime_config", home / "config.yaml"),
        ("runtime_env", home / ".env"),
    ):
        if path.exists() or path.is_symlink():
            _validate_protected_leaf(path, label=label)
    for index, profile in enumerate(_profile_roots(home)):
        for kind, path in _profile_protected_paths(profile):
            if path.name in {"plugins", "scripts"}:
                continue
            if not (path.exists() or path.is_symlink()):
                continue
            label = (
                f"profile_{index}_"
                + "_".join(path.relative_to(profile).parts).replace(".", "_")
            )
            if kind == "directory":
                _validate_protected_tree(path, label=label)
            else:
                _validate_protected_leaf(path, label=label)
        _validate_profile_plugin_bindings(
            profile / "plugins",
            home=home,
            label=f"profile_{index}_plugins",
        )
        _validate_profile_scripts_binding(
            profile,
            home=home,
            label=f"profile_{index}_scripts",
        )
    # The runtime plugin root intentionally contains the deterministic
    # Mnemosyne dependency symlink. Validate only product-owned regular plugin
    # trees that may execute in a model process.
    for index, plugin in enumerate((home / "plugins" / "omh",)):
        if plugin.exists() or plugin.is_symlink():
            _validate_protected_tree(plugin, label=f"runtime_plugin_{index}")


def _validate_no_private_aliases(roots: Sequence[Path], private: Path) -> None:
    """Reject pre-existing symlinks from model-writable trees into private state."""

    seen = 0
    visited: set[Path] = set()
    for root in roots:
        if root in visited or not root.exists():
            continue
        visited.add(root)
        for directory, names, files in os.walk(root, followlinks=False):
            current = Path(directory)
            for name in [*names, *files]:
                seen += 1
                if seen > MAX_ALIAS_SCAN_ENTRIES:
                    raise IsolationError("model_isolation_alias_scan_too_large")
                path = current / name
                if not path.is_symlink():
                    continue
                try:
                    target = path.resolve(strict=False)
                except (OSError, RuntimeError):
                    raise IsolationError(
                        f"model_isolation_unresolvable_symlink:{path}"
                    )
                if _is_within(target, private.resolve(strict=False)):
                    raise IsolationError(
                        f"model_isolation_private_alias:{path}"
                    )


def _hermes_runtime_read_roots(
    command: Sequence[str],
    env: Mapping[str, str],
) -> list[Path]:
    if not command or not Path(str(command[0])).name.startswith("python"):
        return []
    real_raw = str(env.get("HERMES_REAL_HOME") or "").strip()
    if not real_raw:
        raise IsolationError("model_isolation_real_home_invalid")
    real_home = Path(real_raw).expanduser().resolve(strict=True)
    interpreter = Path(os.path.abspath(str(command[0])))
    venv_root = interpreter.parent.parent
    if not _is_within(venv_root.resolve(strict=True), real_home):
        return []
    engine_root = venv_root.parent
    if venv_root.name != "venv" or engine_root.name != "hermes-agent":
        raise IsolationError("model_isolation_hermes_venv_unsafe")

    def checked(path: Path, label: str) -> Path:
        raw_path = Path(os.path.abspath(path.expanduser()))
        info = raw_path.stat()
        if raw_path.is_symlink() or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
            raise IsolationError(f"{label}_unsafe")
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise IsolationError(f"{label}_invalid")
        return raw_path

    allowed = [checked(venv_root, "model_isolation_hermes_venv")]
    target_root = interpreter.resolve(strict=True).parent.parent
    if _is_within(target_root, real_home):
        runtime_base = engine_root / ".hermes-runtime" / "python"
        checked_runtime = checked(runtime_base, "model_isolation_python_runtime")
        if not _is_within(target_root, checked_runtime.resolve(strict=True)):
            raise IsolationError("model_isolation_python_runtime_outside_engine")
        allowed.append(checked_runtime)
    for name in HERMES_RUNTIME_CODE_ROOTS:
        candidate = engine_root / name
        if not candidate.exists():
            candidate = candidate.with_suffix(".py")
        if candidate.exists():
            allowed.append(checked(candidate, f"model_isolation_hermes_code_{name}"))
    return list(dict.fromkeys(allowed))


def _guide_gateway_network_allowed(
    env: Mapping[str, str],
    active_profile: Path | None,
    profile: str | None,
    command: Sequence[str],
) -> bool:
    guide_profile = CANONICAL_ROLE_PROFILES["guide"]
    canonical_suffix = [
        "-I",
        "-m",
        "hermes_cli.main",
        "gateway",
        "run",
        "--replace",
    ]
    venv_raw = str(env.get("VIRTUAL_ENV") or "").strip()
    interpreter = Path(os.path.abspath(str(command[0]))) if command else None
    if (
        profile != guide_profile
        or active_profile is None
        or len(command) != len(canonical_suffix) + 1
        or list(command[1:]) != canonical_suffix
        or interpreter is None
        or re.fullmatch(r"python(?:3(?:\.\d+)?)?", interpreter.name) is None
        or not venv_raw
        or interpreter.parent
        != Path(os.path.abspath(Path(venv_raw).expanduser())) / "bin"
    ):
        return False
    # VIRTUAL_ENV is model-process input, not authority. Network may only be
    # granted when the interpreter itself resolves inside the validated Hermes
    # engine/runtime projection.
    if not _hermes_runtime_read_roots(command, env):
        return False

    def checked_policy(path: Path, label: str) -> object:
        try:
            info = path.lstat()
        except OSError:
            raise IsolationError(f"model_isolation_guide_{label}_missing") from None
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_mode & 0o022
        ):
            raise IsolationError(f"model_isolation_guide_{label}_unsafe")
        return yaml.safe_load(path.read_text(encoding="utf-8"))

    try:
        import yaml
        from john_lomein_memory_contract import (
            agent_memory_boundary_errors,
            agent_memory_managed_policy_errors,
            managed_policy_directory,
        )

        config = checked_policy(active_profile / "config.yaml", "config")
        managed = checked_policy(
            managed_policy_directory(_runtime_home(env), guide_profile)
            / "config.yaml",
            "managed_policy",
        )
        errors = [
            *agent_memory_boundary_errors(config, "guide"),
            *agent_memory_managed_policy_errors(managed, "guide"),
        ]
    except IsolationError:
        raise
    except Exception:
        raise IsolationError("model_isolation_guide_tool_contract_invalid") from None
    if errors:
        raise IsolationError("model_isolation_guide_tool_contract_invalid")
    return True


def darwin_policy(
    env: Mapping[str, str],
    *,
    allow_projection: bool = True,
    profile: str | None = None,
    provider_socket: Path | None = None,
    honcho_socket: Path | None = None,
    runtime_read_roots: Sequence[Path] = (),
    allow_gateway_network: bool = False,
) -> str:
    """Build a Seatbelt policy with private reads and policy writes denied."""

    home = _runtime_home(env)
    protected = private_root(env)
    projection = projection_root(env)
    active_profile = _active_profile_root(env, profile)
    writable = _model_writable_roots(
        env,
        active_profile=active_profile,
    )
    if allow_gateway_network:
        writable = [home, *writable]
    lines = [
        "(version 1)",
        "(allow default)",
        # Model tools may not connect to Honcho, PostgreSQL, loopback services,
        # or the public network. The controller's per-process Unix broker is
        # the sole provider transport reopened below.
        "(deny network*)",
        # The controller broker contains the real provider credential. Deny
        # process enumeration/task-port access to ancestors and sibling roles,
        # while retaining the self-inspection Python and Hermes need.
        "(deny process-info*)",
        "(allow process-info* (target self))",
        "(deny mach-task-name)",
        "(allow mach-task-name (target self))",
        # Same UID is not a write boundary. Make the model namespace read-only
        # by default, then reopen only the explicit work/state/session roots.
        "(deny file-write*)",
        "(allow file-write*",
        '  (literal "/dev/null")',
        '  (literal "/dev/tty")',
        '  (literal "/dev/dtracehelper")',
        *(
            f"  ({matcher} {_scheme_string(_policy_path(path))})"
            for path in writable
            for matcher in ("literal", "subpath")
        ),
        ")",
        (
            "(deny file-read* file-write* "
            f"(subpath {_scheme_string(_policy_path(protected))}))"
        ),
        # A stale pre-boundary path must not become an alias around the new
        # private root during an upgrade.
        (
            "(deny file-read* file-write* "
            f"(subpath {_scheme_string(_policy_path(home / 'mnemosyne'))}))"
        ),
        # Hardlinks retain an inode even when opened through a writable path.
        # Symlinks remain usable for normal build/package workflows because
        # Seatbelt resolves their target against the protected canonical path.
        "(deny file-link)",
        (
            "(deny file-write* "
            f"(subpath {_scheme_string(_policy_path(projection))}))"
        ),
    ]
    if allow_gateway_network:
        lines.append("(allow network-outbound)")
        lines.append("(allow network-bind)")
    if provider_socket is not None:
        socket_path = _validate_provider_socket_path(provider_socket)
        lines.append(
            "(allow network-outbound "
            f"(literal {_scheme_string(_policy_path(socket_path))}))"
        )
    if honcho_socket is not None:
        if provider_socket is None:
            raise IsolationError("model_isolation_honcho_provider_socket_missing")
        socket_path = _validate_honcho_socket_path(
            honcho_socket,
            provider_socket,
        )
        lines.append(
            "(allow network-outbound "
            f"(literal {_scheme_string(_policy_path(socket_path))}))"
        )
    lines.extend([
        '(deny process-exec (literal "/usr/bin/security"))',
        '(deny mach-lookup (global-name "com.apple.securityd"))',
        '(deny mach-lookup (global-name "com.apple.securityd.xpc"))',
    ])
    real_home_raw = str(env.get("HERMES_REAL_HOME") or "").strip()
    if not real_home_raw:
        raise IsolationError("model_isolation_real_home_invalid")
    real_home = Path(real_home_raw).expanduser().resolve()
    for spelling in _policy_spellings(real_home):
        lines.append(f"(deny file-read* (subpath {_scheme_string(spelling)}))")
        lines.append(
            f"(allow file-read-metadata (literal {_scheme_string(spelling)}))"
        )
    readable_roots = list(dict.fromkeys([home, *runtime_read_roots, *writable]))
    local = str(env.get("BOT_LOCAL") or "").strip()
    if local:
        readable_roots.append(Path(local).expanduser().resolve())
    metadata_ancestors: list[Path] = []
    for root in [*writable, *readable_roots]:
        canonical = root.resolve(strict=False)
        if not _is_within(canonical, real_home) or canonical == real_home:
            continue
        metadata_ancestors.append(canonical)
        parent = canonical.parent
        while parent != real_home and parent.parent != parent:
            metadata_ancestors.append(parent)
            parent = parent.parent
    for parent in dict.fromkeys(metadata_ancestors):
        for spelling in _policy_spellings(parent):
            lines.append(
                f"(allow file-read-metadata (literal {_scheme_string(spelling)}))"
            )
    for root in readable_roots:
        matchers = ("literal", "subpath") if root.is_dir() else ("literal",)
        for spelling in _policy_spellings(root):
            for matcher in matchers:
                lines.append(
                    f"(allow file-read* ({matcher} {_scheme_string(spelling)}))"
                )
    lines.append(f"(deny file-read* file-write* (subpath {_scheme_string(_policy_path(protected))}))")
    for root in _hidden_control_roots(env):
        lines.append(
            "(deny file-read* file-write* "
            f"(subpath {_scheme_string(_policy_path(root))}))"
        )
    if not allow_projection:
        lines.append(
            "(deny file-read* file-write* "
            f"(subpath {_scheme_string(_policy_path(projection))}))"
        )
    for path in (
        home / "scripts",
        home / "managed-policy",
        home / "plugins",
        home / "state" / "continuity",
    ):
        lines.append(
            f"(deny file-write* (subpath {_scheme_string(_policy_path(path))}))"
        )
    for path in (
        home / "instance.yaml",
        home / "auth.json",
        home / "config.yaml",
        home / ".env",
    ):
        lines.append(
            f"(deny file-write* (literal {_scheme_string(_policy_path(path))}))"
        )
    for root in _profile_roots(home):
        for kind, path in _profile_protected_paths(root):
            matcher = "subpath" if kind == "directory" else "literal"
            for spelling in _policy_spellings(path):
                lines.append(
                    "(deny file-write* "
                    f"({matcher} {_scheme_string(spelling)}))"
                )
    for path in _hidden_credential_paths(
        env,
        active_profile=active_profile,
    ):
        matcher = "subpath" if path.is_dir() else "literal"
        for spelling in _policy_spellings(path):
            lines.append(
                "(deny file-read* file-write* "
                f"({matcher} {_scheme_string(spelling)}))"
            )
    return "\n".join(lines) + "\n"


def _real_directory(path: Path, *, label: str) -> Path:
    checked = _absolute_no_symlink(path, label=label)
    info = checked.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise IsolationError(f"{label}_not_directory:{checked}")
    return checked


def _model_tmp_root(env: Mapping[str, str]) -> Path:
    temporary = Path("/tmp").resolve(strict=True)
    info = temporary.stat()
    if info.st_uid != 0 or not stat.S_ISDIR(info.st_mode) or not stat.S_IMODE(info.st_mode) & stat.S_ISVTX:
        raise IsolationError("model_isolation_tmp_unsafe")
    tag = hashlib.sha256(str(_runtime_home(env)).encode()).hexdigest()[:10]
    root = temporary / f"jl-mt-{os.geteuid()}-{tag}"
    root.mkdir(mode=0o700, exist_ok=True)
    root_info = root.lstat()
    if root.is_symlink() or root_info.st_uid != os.geteuid() or stat.S_IMODE(root_info.st_mode) != 0o700:
        raise IsolationError("model_isolation_tmp_root_unsafe")
    return root


def _model_writable_roots(
    env: Mapping[str, str],
    *,
    active_profile: Path | None = None,
) -> list[Path]:
    home = _runtime_home(env)
    candidates = [
        home / "state",
        home / "logs",
        home / "work",
        _model_tmp_root(env),
    ]
    checkout = str(env.get("BOT_LOCAL") or "").strip()
    if checkout:
        candidates.append(Path(checkout).expanduser())
    if active_profile is not None:
        candidates.append(active_profile)
    gateway_locks = _shared_gateway_lock_root(env)
    if gateway_locks is not None:
        candidates.append(gateway_locks)
    roots: list[Path] = []
    seen: set[Path] = set()
    for index, candidate in enumerate(candidates):
        if not candidate.exists():
            continue
        root = _real_directory(
            candidate,
            label=f"model_isolation_writable_{index}",
        )
        if root not in seen:
            roots.append(root)
            seen.add(root)
    return roots


def _model_working_directory(env: Mapping[str, str]) -> Path:
    configured = str(env.get("BOT_LOCAL") or "").strip()
    candidate = Path(configured).expanduser() if configured else _runtime_home(env) / "work"
    root = _real_directory(candidate, label="model_isolation_working_directory")
    info = root.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise IsolationError("model_isolation_working_directory_unsafe")
    return root


def _resolve_command(command: Sequence[str], env: Mapping[str, str]) -> list[str]:
    if not command or not str(command[0]).strip():
        raise IsolationError("model_isolation_missing_command")
    result = [str(item) for item in command]
    executable = result[0]
    if "\x00" in executable:
        raise IsolationError("model_isolation_invalid_executable")
    if "/" not in executable:
        executable = shutil.which(
            executable,
            path=str(env.get("PATH") or CONTROLLED_PATH),
        ) or ""
    if not executable:
        raise IsolationError(f"model_isolation_command_not_found:{result[0]}")
    resolved = Path(executable).expanduser()
    if not resolved.is_absolute() or not resolved.exists() or resolved.is_dir():
        raise IsolationError(f"model_isolation_invalid_executable:{executable}")
    result[0] = str(resolved)
    return result


def _isolate_hermes_python_entrypoint(command: list[str]) -> list[str]:
    """Run the Hermes console script with Python isolated import semantics."""

    executable = Path(command[0])
    if executable.name != "hermes":
        return command
    info = executable.lstat()
    if (
        executable.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid not in {0, os.geteuid()}
        or info.st_nlink != 1
        or info.st_mode & 0o022
    ):
        raise IsolationError("model_isolation_hermes_entrypoint_unsafe")
    try:
        text = executable.read_text(
            encoding="utf-8",
            errors="strict",
        )
        first = text.splitlines()[0]
    except (OSError, UnicodeError, IndexError) as exc:
        raise IsolationError(
            "model_isolation_hermes_entrypoint_unreadable"
        ) from exc
    if not first.startswith("#!"):
        raise IsolationError("model_isolation_hermes_entrypoint_no_shebang")
    interpreter = first[2:].strip()
    if interpreter == "/bin/sh":
        lines = text.splitlines()
        polyglot_exec = (
            "'''exec' \"$(dirname -- \"$(realpath -- \"$0\")\")\"/"
            "'python3' \"$0\" \"$@\""
        )
        if len(lines) < 3 or lines[1] != polyglot_exec or lines[2] != "' '''":
            raise IsolationError(
                "model_isolation_hermes_wrapper_unsupported"
            )
        try:
            candidate = executable.parent / "python3"
            candidate_info = candidate.lstat()
            parent_info = candidate.parent.stat()
            target = candidate.resolve(strict=True)
            target_info = target.stat()
        except OSError as exc:
            raise IsolationError(
                "model_isolation_hermes_entrypoint_unsafe_interpreter"
            ) from exc
        if (
            not (candidate.is_symlink() or stat.S_ISREG(candidate_info.st_mode))
            or candidate_info.st_uid not in {0, os.geteuid()}
            or parent_info.st_uid not in {0, os.geteuid()}
            or parent_info.st_mode & 0o022
            or not stat.S_ISREG(target_info.st_mode)
            or target_info.st_uid not in {0, os.geteuid()}
            or target_info.st_mode & 0o022
            or not os.access(candidate, os.X_OK)
            or not target.name.startswith("python")
        ):
            raise IsolationError(
                "model_isolation_hermes_entrypoint_unsafe_interpreter"
            )
        return [str(candidate), "-I", str(executable), *command[1:]]
    if interpreter in {"/usr/bin/env bash", "/bin/bash"}:
        matches = re.findall(
            r'(?m)^exec "([^"\\\r\n]+)" "\$@"$',
            text,
        )
        if len(matches) != 1:
            raise IsolationError(
                "model_isolation_hermes_wrapper_unsupported"
            )
        target = Path(matches[0])
        if not target.is_absolute() or target.name != "hermes":
            raise IsolationError("model_isolation_hermes_wrapper_unsafe")
        return _isolate_hermes_python_entrypoint(
            [str(target), *command[1:]]
        )
    if (
        not interpreter
        or " " in interpreter
        or "\x00" in interpreter
        or not Path(interpreter).is_absolute()
        or not Path(interpreter).is_file()
        or not os.access(interpreter, os.X_OK)
        or not Path(interpreter).name.startswith("python")
    ):
        raise IsolationError(
            "model_isolation_hermes_entrypoint_unsafe_interpreter"
        )
    return [interpreter, "-I", str(executable), *command[1:]]


def _is_hermes_invocation(command: Sequence[str]) -> bool:
    if not command:
        return False
    if Path(str(command[0])).name == "hermes":
        return True
    return any(
        str(command[index]) == "-m"
        and index + 1 < len(command)
        and str(command[index + 1]) == "hermes_cli.main"
        for index in range(1, len(command))
    )


def _provider_bootstrap_command(
    command: list[str],
    *,
    bootstrap: Path,
) -> list[str]:
    """Run the Hermes entrypoint only after installing the UDS transport."""

    if len(command) >= 3 and command[1] == "-I" and Path(command[2]).name == "hermes":
        return [
            command[0],
            "-I",
            str(bootstrap),
            command[2],
            "--",
            *command[3:],
        ]
    for index in range(1, len(command) - 1):
        if command[index : index + 2] == ["-m", "hermes_cli.main"]:
            prefix = [item for item in command[1:index] if item != "-I"]
            if prefix:
                raise IsolationError("model_isolation_hermes_module_flags_unsupported")
            return [
                command[0],
                "-I",
                str(bootstrap),
                "--module",
                "hermes_cli.main",
                "--",
                *command[index + 2 :],
            ]
    raise IsolationError("model_isolation_provider_bootstrap_not_hermes")


def backend_name(
    *,
    system: str | None = None,
    which: object = shutil.which,
) -> str:
    """Return the available enforcement backend or raise."""

    current = system or platform.system()
    lookup = which
    if not callable(lookup):
        raise IsolationError("model_isolation_invalid_backend_lookup")
    if current == "Darwin":
        if lookup("sandbox-exec", path=CONTROLLED_PATH):
            return "seatbelt"
        raise IsolationError("model_isolation_seatbelt_unavailable")
    if current == "Linux":
        if lookup("bwrap", path=CONTROLLED_PATH):
            return "bubblewrap"
        raise IsolationError("model_isolation_bubblewrap_unavailable")
    raise IsolationError(f"model_isolation_unsupported_platform:{current}")


def isolated_command(
    env: Mapping[str, str],
    command: Sequence[str],
    *,
    system: str | None = None,
    which: object = shutil.which,
    allow_projection: bool = True,
    profile: str | None = None,
    provider_socket: Path | None = None,
    honcho_socket: Path | None = None,
) -> list[str]:
    """Return an OS-sandboxed command for a model-facing process."""

    resolved = _resolve_command(command, env)
    hermes_invocation = _is_hermes_invocation(resolved)
    active_profile = _active_profile_root(env, profile)
    gateway_invocation = list(resolved)
    if active_profile is not None and Path(resolved[0]).name == "hermes":
        resolved = _isolate_hermes_python_entrypoint(resolved)
    if _mode(env) == MODE_DISABLED:
        return resolved
    home = _runtime_home(env)
    brokered_provider = bool(
        active_profile is not None
        and hermes_invocation
        and _uses_openai_codex(env)
    )
    if brokered_provider:
        bootstrap = home / "scripts" / PROVIDER_BOOTSTRAP_SCRIPT
        if bootstrap.is_symlink() or not bootstrap.is_file():
            raise IsolationError("model_isolation_provider_bootstrap_missing")
        resolved = _provider_bootstrap_command(resolved, bootstrap=bootstrap)
        if provider_socket is None:
            provider_socket = provider_broker_socket_path()
        if honcho_socket is None:
            honcho_socket = honcho_broker_socket_path(provider_socket)
        else:
            _validate_honcho_socket_path(honcho_socket, provider_socket)
    runtime_read_roots = _hermes_runtime_read_roots(resolved, env)
    allow_gateway_network = _guide_gateway_network_allowed(
        env,
        active_profile,
        profile,
        gateway_invocation,
    )
    protected = private_root(env)
    _validate_private_tree(protected)
    _validate_protected_deployment(home)
    current = system or platform.system()
    if allow_gateway_network and current != "Darwin":
        raise IsolationError("model_isolation_guide_gateway_network_unsupported")
    if current == "Darwin":
        # Seatbelt is path based, so reject aliases from every tree the model
        # can write before entering the policy. Bubblewrap masks the protected
        # inode tree inside a mount namespace and does not need this expensive
        # monorepo scan.
        alias_roots = _model_writable_roots(
            env,
            active_profile=active_profile,
        )
        _validate_no_private_aliases(alias_roots, protected)
    backend = backend_name(system=current, which=which)
    lookup = which
    if backend == "seatbelt":
        sandbox = lookup("sandbox-exec", path=CONTROLLED_PATH)
        if not sandbox:
            raise IsolationError("model_isolation_seatbelt_unavailable")
        sandboxed = [
            str(sandbox),
            "-p",
            darwin_policy(
                env,
                allow_projection=allow_projection,
                profile=profile,
                provider_socket=provider_socket,
                honcho_socket=honcho_socket,
                runtime_read_roots=runtime_read_roots,
                allow_gateway_network=allow_gateway_network,
            ),
            *resolved,
        ]
        if brokered_provider:
            assert provider_socket is not None and profile is not None
            broker = home / "scripts" / PROVIDER_BROKER_SCRIPT
            if broker.is_symlink() or not broker.is_file():
                raise IsolationError("model_isolation_provider_broker_missing")
            return [
                sys.executable,
                "-I",
                str(broker),
                "--socket",
                str(provider_socket),
                "--profile",
                profile,
                "--honcho-socket",
                str(honcho_socket),
                "--",
                *sandboxed,
            ]
        return sandboxed

    bwrap = lookup("bwrap", path=CONTROLLED_PATH)
    if not bwrap:
        raise IsolationError("model_isolation_bubblewrap_unavailable")
    private = protected
    projection = projection_root(env)
    args = [
        str(bwrap),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--ro-bind",
        "/",
        "/",
        "--dev-bind",
        "/dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
    ]
    real_home_raw = str(env.get("HERMES_REAL_HOME") or "").strip()
    if not real_home_raw:
        raise IsolationError("model_isolation_real_home_invalid")
    real_home = Path(real_home_raw).expanduser().resolve()
    args.extend(("--tmpfs", str(real_home), "--ro-bind", str(home), str(home)))
    for root in runtime_read_roots:
        args.extend(("--ro-bind", str(root), str(root)))
    local = str(env.get("BOT_LOCAL") or "").strip()
    if local:
        local_path = Path(local).expanduser().resolve()
        args.extend(("--ro-bind", str(local_path), str(local_path)))
    if Path("/usr/bin/security").exists():
        args.extend(("--ro-bind", "/dev/null", "/usr/bin/security"))
    if provider_socket is not None:
        socket_path = _validate_provider_socket_path(provider_socket)
        # The controller creates this private session directory before bwrap
        # starts. Expose it read-only after the namespace-local /tmp mount.
        args.extend(("--ro-bind", str(socket_path.parent), str(socket_path.parent)))
    for root in _model_writable_roots(
        env,
        active_profile=active_profile,
    ):
        args.extend(("--bind", str(root), str(root)))
    # A profile root must be writable for Hermes' atomic runtime state. Apply
    # narrower read-only mounts afterwards so config, credentials, executable
    # hooks, persona and product skills cannot be replaced through that parent.
    if active_profile is not None:
        for _kind, path in _profile_protected_paths(active_profile):
            if path.exists() or path.is_symlink():
                args.extend(("--ro-bind", str(path), str(path)))
    # The active profile needs its access-token-only projection. Conceal the
    # refresh authority, runtime-root fallback and every inactive profile's
    # projection so a model cannot aggregate credentials across identities.
    for path in _hidden_credential_paths(
        env,
        active_profile=active_profile,
    ):
        if path.is_dir():
            args.extend(("--tmpfs", str(path)))
        else:
            args.extend(("--ro-bind", "/dev/null", str(path)))
    # Nested mounts are applied after their writable parent.  The continuity
    # projection is model-readable but steward-owned, while the private mount
    # is replaced by an empty namespace-local filesystem.
    if allow_projection:
        args.extend(("--ro-bind", str(projection), str(projection)))
    else:
        args.extend(("--tmpfs", str(projection)))
    for root in _hidden_control_roots(env):
        args.extend(("--tmpfs", str(root)))
    for child in sorted(private.iterdir()):
        if child.is_dir():
            args.extend(("--tmpfs", str(child)))
        else:
            args.extend(("--ro-bind", "/dev/null", str(child)))
    legacy = home / "mnemosyne"
    if legacy.exists():
        legacy = _real_directory(legacy, label="model_isolation_legacy_memory")
        args.extend(("--tmpfs", str(legacy)))
    args.extend(("--", *resolved))
    if brokered_provider:
        assert provider_socket is not None and profile is not None
        broker = home / "scripts" / PROVIDER_BROKER_SCRIPT
        if broker.is_symlink() or not broker.is_file():
            raise IsolationError("model_isolation_provider_broker_missing")
        return [
            sys.executable,
            "-I",
            str(broker),
            "--socket",
            str(provider_socket),
            "--profile",
            profile,
            "--honcho-socket",
            str(honcho_socket),
            "--",
            *args,
        ]
    return args


def isolated_environment(
    env: Mapping[str, str],
    *,
    profile: str | None = None,
) -> dict[str, str]:
    """Scrub direct index pointers and mark an inherited model sandbox."""

    out = {str(key): str(value) for key, value in env.items()}
    blocked_prefixes = (
        "GH_", "GITHUB_", "AWS_", "AZURE_", "GOOGLE_", "SSH_", "NPM_",
        "DOCKER_", "KUBECONFIG", "GIT_CONFIG_", "CURL_", "XDG_",
        "OPENAI_", "ANTHROPIC_", "CODEX_", "HERMES_CODEX_", "HONCHO_", "REDIS_", "PG",
    )
    for key in list(out):
        if key.startswith(blocked_prefixes) or key in {
            "ALL_PROXY", "DATABASE_URL", "GIT_ASKPASS", "GIT_SSH",
            "GIT_SSH_COMMAND", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
            "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
        }:
            out.pop(key, None)
    out.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"})
    out.pop("MNEMOSYNE_DATA_DIR", None)
    out.pop("JOHN_LOMEIN_STEWARD_PRIVATE_ROOT", None)
    out.pop("BOT_STEWARD_PRIVATE_ROOT", None)
    out.pop("BOT_STEWARD_PROJECTION_ROOT", None)
    out["JOHN_LOMEIN_MODEL_ISOLATED"] = "1"
    out["PYTHONDONTWRITEBYTECODE"] = "1"
    active_profile = _active_profile_root(env, profile)
    if active_profile is not None:
        # Hermes freezes several home-derived paths at import time. Pin the
        # selected profile before Python starts instead of relying on its later
        # command-line profile switch.
        out["HERMES_HOME"] = str(active_profile)
        out["HERMES_HONCHO_HOST"] = "hermes"
    if _mode(env) == MODE_REQUIRED:
        out["TMPDIR"] = str(_model_tmp_root(env))
    return out


def _run_isolation_canary(
    env: Mapping[str, str],
    *,
    python: str | None = None,
    runner: object = subprocess.run,
) -> tuple[bool, str]:
    """Prove protected reads/writes fail and projection reads still work."""

    if _mode(env) == MODE_DISABLED:
        return False, "model_isolation_disabled"
    home = _runtime_home(env)
    private = private_root(env)
    projection = projection_root(env)
    nonce = secrets.token_hex(12)
    sentinel = private / f".model-isolation-canary-{nonce}"
    projection_sentinel = projection / f".model-isolation-canary-{nonce}"
    release_sentinel = home / "private" / "release-bundles" / f".model-isolation-canary-{nonce}"
    writable_sentinel = home / "work" / f".model-isolation-canary-{nonce}"
    real_home = Path(str(env.get("HERMES_REAL_HOME") or "")).expanduser().resolve()
    outside_sentinel = real_home / f".model-isolation-canary-outside-{nonce}"
    protected_script = home / "scripts" / "john_lomein_model_isolation.py"
    if protected_script.is_symlink() or not protected_script.is_file():
        return False, "model_isolation_canary_protected_script_missing"
    try:
        sentinel.write_text("private\n", encoding="utf-8")
        projection_sentinel.write_text("projection\n", encoding="utf-8")
        release_sentinel.write_text("release\n", encoding="utf-8")
        outside_sentinel.write_text("host-secret\n", encoding="utf-8")
        os.chmod(sentinel, 0o600)
        os.chmod(projection_sentinel, 0o600)
        os.chmod(release_sentinel, 0o600)
        executable = python or sys.executable
        child_code = (
            "from pathlib import Path;"
            f"Path({str(sentinel)!r}).read_bytes()"
        )
        probe = (
            "from pathlib import Path\n"
            "import subprocess,sys\n"
            f"private=Path({str(sentinel)!r})\n"
            f"projection=Path({str(projection_sentinel)!r})\n"
            f"release=Path({str(release_sentinel)!r})\n"
            f"protected=Path({str(protected_script)!r})\n"
            f"writable=Path({str(writable_sentinel)!r})\n"
            f"outside=Path({str(outside_sentinel)!r})\n"
            "def denied_read(path):\n"
            "  try: path.read_bytes(); return False\n"
            "  except (OSError,PermissionError): return True\n"
            "def denied_write(path):\n"
            "  try: path.write_bytes(path.read_bytes()); return False\n"
            "  except (OSError,PermissionError): return True\n"
            "def denied_create(path):\n"
            "  try: path.write_text('escaped'); return False\n"
            "  except (OSError,PermissionError): return True\n"
            "child=subprocess.run([sys.executable,'-c',"
            f"{child_code!r}],"
            "capture_output=True)\n"
            "checks={'private':denied_read(private),'protected_write':denied_write(protected),'projection_read':projection.read_text().strip()=='projection','release_read':denied_read(release),'release_write':denied_write(release),'projection_write':denied_write(projection),'outside_write':denied_create(outside),'outside_read':denied_read(outside),'descendant':child.returncode!=0}\n"
            "ok=all(checks.values())\n"
            "if not ok: print(checks)\n"
            "if ok:\n"
            " writable.write_text('allowed')\n"
            "raise SystemExit(0 if ok else 9)\n"
        )
        command = isolated_command(
            env,
            [executable, "-c", probe],
            allow_projection=True,
        )
        result = runner(
            command,
            env=isolated_environment(env),
            capture_output=True,
            text=True,
            timeout=20,
            cwd=str(_model_working_directory(env)),
        )
    except Exception as exc:
        return False, f"model_isolation_canary_error:{type(exc).__name__}:{exc}"
    finally:
        sentinel.unlink(missing_ok=True)
        projection_sentinel.unlink(missing_ok=True)
        release_sentinel.unlink(missing_ok=True)
        writable_sentinel.unlink(missing_ok=True)
        outside_sentinel.unlink(missing_ok=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[:240]
        return False, f"model_isolation_canary_failed:{result.returncode}:{detail}"
    try:
        backend = backend_name()
    except IsolationError as exc:
        return False, str(exc)
    return True, backend


def run_isolation_canary(
    env: Mapping[str, str],
    *,
    python: str | None = None,
    runner: object = subprocess.run,
) -> tuple[bool, str]:
    """Run the fail-closed proof without leaking setup exceptions to callers."""

    try:
        return _run_isolation_canary(env, python=python, runner=runner)
    except Exception as exc:
        return False, f"model_isolation_canary_error:{type(exc).__name__}:{exc}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one John Lomein model process inside the required OS boundary"
    )
    parser.add_argument(
        "--profile",
        required=True,
        help="exact canonical profile receiving the sole profile-scoped write grant",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("model isolation wrapper requires a command after --")
    env = dict(os.environ)
    try:
        if _uses_openai_codex(env):
            from john_lomein_auth_projection import scrub_model_credentials

            home = _runtime_home(env)
            _auth_authority_home(env, required=True)
            scrub_model_credentials(
                home,
                profiles=[
                    home / "profiles" / profile
                    for profile in CANONICAL_ROLE_PROFILES.values()
                ],
                provider=OPENAI_CODEX_PROVIDER,
            )
        is_public_guide = args.profile == "john-lomein-guide"
        wrapped = isolated_command(
            env,
            command,
            allow_projection=not is_public_guide,
            profile=args.profile,
        )
        child_env = isolated_environment(env, profile=args.profile)
        working_directory = _model_working_directory(env)
        os.chdir(working_directory)
    except Exception as exc:
        print(f"john-lomein model isolation refused execution: {exc}", file=sys.stderr)
        return 78
    os.execvpe(wrapped[0], wrapped, child_env)
    return 70


if __name__ == "__main__":
    raise SystemExit(main())
