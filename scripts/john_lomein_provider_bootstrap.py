#!/usr/bin/env python3
"""Install the model-side half of the sealed provider broker boundary."""

from __future__ import annotations

import argparse
import os
import runpy
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any


BROKER_API_KEY = "john-lomein-provider-broker"
BROKER_BASE_URL = "http://localhost"
OPENAI_CODEX_PROVIDER = "openai-codex"
BROKER_SOCKET_NAME = "broker.sock"
HONCHO_SOCKET_NAME = "honcho.sock"
_WORKSPACE_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


class ProviderBootstrapError(RuntimeError):
    """The sandbox did not receive an exact sealed broker endpoint."""


def _capability(name: str) -> str:
    capability = str(os.environ.get(name) or "")
    if (
        not 16 <= len(capability) <= 128
        or not capability.isascii()
        or any(
            char
            not in (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789-_"
            )
            for char in capability
        )
    ):
        raise ProviderBootstrapError("provider_bootstrap_capability_invalid")
    return capability


def _broker_values() -> tuple[str, str, str, str, str]:
    raw_path = str(os.environ.get("JOHN_LOMEIN_PROVIDER_BROKER_SOCKET") or "")
    honcho_raw_path = str(
        os.environ.get("JOHN_LOMEIN_HONCHO_BROKER_SOCKET") or ""
    )
    workspace = str(
        os.environ.get("JOHN_LOMEIN_HONCHO_BROKER_WORKSPACE") or ""
    )
    controller_homes = [
        str(os.environ.get(name) or "")
        for name in ("BOT_HERMES_HOME", "JOHN_LOMEIN_INSTANCE_HERMES_HOME")
        if str(os.environ.get(name) or "")
    ]
    if len(set(controller_homes)) > 1:
        raise ProviderBootstrapError("provider_bootstrap_runtime_mismatch")
    home_raw = controller_homes[0] if controller_homes else ""
    if not raw_path or not honcho_raw_path or not workspace or not home_raw:
        raise ProviderBootstrapError("provider_bootstrap_binding_missing")
    capability = _capability("JOHN_LOMEIN_PROVIDER_BROKER_CAPABILITY")
    honcho_capability = _capability("JOHN_LOMEIN_HONCHO_BROKER_CAPABILITY")
    if (
        capability == honcho_capability
        or not 1 <= len(workspace) <= 128
        or any(char not in _WORKSPACE_CHARS for char in workspace)
    ):
        raise ProviderBootstrapError("provider_bootstrap_honcho_binding_invalid")
    path = Path(os.path.abspath(Path(raw_path).expanduser()))
    honcho_path = Path(os.path.abspath(Path(honcho_raw_path).expanduser()))
    try:
        expected_root = Path("/tmp").resolve(strict=True) / f"jl-pb-{os.geteuid()}"
    except OSError:
        raise ProviderBootstrapError("provider_bootstrap_tmp_unavailable") from None
    if (
        path.name != BROKER_SOCKET_NAME
        or path.parent.parent != expected_root
        or len(path.parent.name) != 24
        or any(char not in "0123456789abcdef" for char in path.parent.name)
        or len(os.fsencode(path)) > 100
        or path.is_symlink()
    ):
        raise ProviderBootstrapError("provider_bootstrap_socket_path_invalid")
    if (
        honcho_path != path.with_name(HONCHO_SOCKET_NAME)
        or len(os.fsencode(honcho_path)) > 100
        or honcho_path.is_symlink()
    ):
        raise ProviderBootstrapError("provider_bootstrap_honcho_socket_path_invalid")
    try:
        info = path.lstat()
        honcho_info = honcho_path.lstat()
    except OSError:
        raise ProviderBootstrapError("provider_bootstrap_socket_missing") from None
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise ProviderBootstrapError("provider_bootstrap_socket_unsafe")
    if (
        not stat.S_ISSOCK(honcho_info.st_mode)
        or honcho_info.st_uid != os.geteuid()
        or stat.S_IMODE(honcho_info.st_mode) & 0o077
    ):
        raise ProviderBootstrapError("provider_bootstrap_honcho_socket_unsafe")
    return (
        str(path),
        capability,
        str(honcho_path),
        honcho_capability,
        workspace,
    )


def _install_honcho_boundary(
    httpx: Any,
    *,
    socket_path: str,
    capability: str,
    workspace: str,
) -> None:
    """Patch the SDK constructor before Hermes initializes memory plugins."""

    import honcho

    honcho_class = honcho.Honcho
    original_init = honcho_class.__init__
    if getattr(original_init, "__john_lomein_honcho_broker__", False):
        raise ProviderBootstrapError("provider_bootstrap_honcho_already_installed")

    def brokered_init(self: Any, *args: Any, **kwargs: Any) -> None:
        if args:
            raise ProviderBootstrapError(
                "provider_bootstrap_honcho_positional_config_denied"
            )
        requested_workspace = str(kwargs.get("workspace_id") or workspace)
        if requested_workspace != workspace:
            raise ProviderBootstrapError(
                "provider_bootstrap_honcho_workspace_denied"
            )
        timeout = httpx.Timeout(120.0, connect=10.0)
        safe = dict(kwargs)
        safe.update(
            {
                "api_key": capability,
                "base_url": BROKER_BASE_URL,
                "environment": "local",
                "workspace_id": workspace,
                "http_client": httpx.Client(
                    transport=httpx.HTTPTransport(uds=socket_path),
                    timeout=timeout,
                ),
            }
        )
        original_init(self, **safe)
        # The Honcho SDK lazily builds a second client for ``.aio`` and does
        # not inherit the custom sync client. Seal that path to the same UDS.
        self._http_config = {
            "base_url": BROKER_BASE_URL,
            "api_key": capability,
            "timeout": 120.0,
            "http_client": httpx.AsyncClient(
                transport=httpx.AsyncHTTPTransport(uds=socket_path),
                timeout=timeout,
            ),
        }

    brokered_init.__wrapped__ = original_init
    brokered_init.__john_lomein_honcho_broker__ = True
    honcho_class.__init__ = brokered_init


def _install_gateway_runtime_boundary() -> None:
    if os.environ.get("JOHN_LOMEIN_GATEWAY_PROCESS") != "1":
        return
    root = Path(os.environ.get("TMPDIR") or "")
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ProviderBootstrapError("provider_bootstrap_tmp_invalid")
    import gateway.shutdown_watchdog as watchdog
    def short_tick_path(home=None, pid=None):
        return root / f"gt-{pid or os.getpid()}.sock"
    watchdog.get_loop_tick_socket_path = short_tick_path


def install_broker_boundary() -> None:
    """Patch Hermes' provider chokepoints before runtime imports."""

    (
        socket_path,
        capability,
        honcho_socket_path,
        honcho_capability,
        honcho_workspace,
    ) = _broker_values()
    # Advertise only the per-process capability so Hermes' early provider
    # preflight succeeds without probing denied credential files. Runtime client
    # creation below still forces the UDS transport and broker origin.
    os.environ["OPENAI_API_KEY"] = capability
    os.environ["OPENAI_BASE_URL"] = BROKER_BASE_URL
    _install_gateway_runtime_boundary()
    import httpx

    _install_honcho_boundary(
        httpx,
        socket_path=honcho_socket_path,
        capability=honcho_capability,
        workspace=honcho_workspace,
    )

    import hermes_cli.runtime_provider as runtime_provider

    original_resolve = runtime_provider.resolve_runtime_provider

    def resolve_runtime_provider(*, requested=None, **kwargs):
        selected = runtime_provider.resolve_requested_provider(requested)
        if selected != OPENAI_CODEX_PROVIDER:
            raise ProviderBootstrapError(
                f"provider_bootstrap_unbrokered_provider:{selected}"
            )
        return {
            "provider": OPENAI_CODEX_PROVIDER,
            "api_mode": "codex_responses",
            "base_url": BROKER_BASE_URL,
            "api_key": capability,
            "source": BROKER_API_KEY,
            "requested_provider": selected,
        }

    resolve_runtime_provider.__wrapped__ = original_resolve
    runtime_provider.resolve_runtime_provider = resolve_runtime_provider

    import agent.agent_runtime_helpers as runtime_helpers

    original_create = runtime_helpers.create_openai_client

    def create_openai_client(agent: Any, client_kwargs: dict, **kwargs):
        if str(getattr(agent, "provider", "")).strip() != OPENAI_CODEX_PROVIDER:
            raise ProviderBootstrapError("provider_bootstrap_client_not_brokered")
        safe = dict(client_kwargs)
        safe.update(
            {
                "api_key": capability,
                "base_url": BROKER_BASE_URL,
                "http_client": httpx.Client(
                    transport=httpx.HTTPTransport(uds=socket_path),
                    timeout=httpx.Timeout(180.0, connect=10.0),
                ),
            }
        )
        return original_create(agent, safe, **kwargs)

    create_openai_client.__wrapped__ = original_create
    runtime_helpers.create_openai_client = create_openai_client

    # Hermes builds side-task clients (compression, title generation, and
    # similar calls) through a separate auxiliary chokepoint. Route those over
    # the same UDS and replace every auth-store lookup with the local
    # capability, so an auxiliary call cannot reopen credential reads.
    import agent.auxiliary_client as auxiliary_client

    def broker_http_client_kwargs(_base_url=None, *, async_mode=False):
        if async_mode:
            return {
                "http_client": httpx.AsyncClient(
                    transport=httpx.AsyncHTTPTransport(uds=socket_path),
                    timeout=httpx.Timeout(180.0, connect=10.0),
                )
            }
        return {
            "http_client": httpx.Client(
                transport=httpx.HTTPTransport(uds=socket_path),
                timeout=httpx.Timeout(180.0, connect=10.0),
            )
        }

    auxiliary_client._openai_http_client_kwargs = broker_http_client_kwargs
    auxiliary_client._read_codex_access_token = lambda: capability
    auxiliary_client._select_pool_entry = lambda _provider: (False, None)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--module")
    parser.add_argument("entrypoint", nargs="?")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    items = list(sys.argv[1:] if argv is None else argv)
    module: str | None = None
    entrypoint: str | None = None
    if items[:1] == ["--module"]:
        if len(items) < 2:
            raise ProviderBootstrapError("provider_bootstrap_entrypoint_missing")
        module = items[1]
        remainder = items[2:]
    elif items:
        entrypoint = items[0]
        remainder = items[1:]
    else:
        raise ProviderBootstrapError("provider_bootstrap_entrypoint_missing")
    if remainder[:1] == ["--"]:
        remainder = remainder[1:]
    if any(
        remainder[index : index + 2] == ["gateway", "run"]
        for index in range(len(remainder) - 1)
    ):
        os.environ["JOHN_LOMEIN_GATEWAY_PROCESS"] = "1"
    install_broker_boundary()
    if module:
        sys.argv = [module, *remainder]
        runpy.run_module(module, run_name="__main__", alter_sys=True)
    elif entrypoint:
        sys.argv = [entrypoint, *remainder]
        runpy.run_path(entrypoint, run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
