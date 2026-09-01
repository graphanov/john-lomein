#!/usr/bin/env python3
from __future__ import annotations

import importlib
import os
import socket
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import john_lomein_provider_bootstrap as bootstrap  # noqa: E402
from john_lomein_model_isolation import (  # noqa: E402
    honcho_broker_socket_path,
    provider_broker_socket_path,
)


class FakeTransport:
    def __init__(self, *, uds: str):
        self.uds = uds


class FakeClient:
    def __init__(self, *, transport=None, timeout=None):
        self.transport = transport
        self.timeout = timeout


class FakeTimeout:
    def __init__(self, value: float, *, connect: float):
        self.value = value
        self.connect = connect


class ProviderBootstrapTest(unittest.TestCase):
    def test_honcho_constructor_is_patched_before_plugin_import_and_forces_uds(self):
        provider_path = provider_broker_socket_path()
        honcho_path = honcho_broker_socket_path(provider_path)
        provider_path.parent.parent.mkdir(mode=0o700, exist_ok=True)
        os.chmod(provider_path.parent.parent, 0o700)
        provider_path.parent.mkdir(mode=0o700)
        listeners = []
        for path in (provider_path, honcho_path):
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            os.chmod(path, 0o600)
            listener.listen(1)
            listeners.append(listener)

        fake_httpx = types.ModuleType("httpx")
        fake_httpx.Client = FakeClient
        fake_httpx.AsyncClient = FakeClient
        fake_httpx.HTTPTransport = FakeTransport
        fake_httpx.AsyncHTTPTransport = FakeTransport
        fake_httpx.Timeout = FakeTimeout

        class FakeHoncho:
            def __init__(self, **kwargs):
                self.constructor_kwargs = kwargs
                self._http_config = {"must": "be-replaced"}

        fake_honcho = types.ModuleType("honcho")
        fake_honcho.Honcho = FakeHoncho

        runtime_provider = types.ModuleType("hermes_cli.runtime_provider")
        runtime_provider.resolve_requested_provider = lambda requested: requested
        runtime_provider.resolve_runtime_provider = lambda **_kwargs: {}
        hermes_cli = types.ModuleType("hermes_cli")
        hermes_cli.runtime_provider = runtime_provider

        runtime_helpers = types.ModuleType("agent.agent_runtime_helpers")
        runtime_helpers.create_openai_client = (
            lambda _agent, kwargs, **_extra: kwargs
        )
        auxiliary = types.ModuleType("agent.auxiliary_client")
        agent = types.ModuleType("agent")
        agent.agent_runtime_helpers = runtime_helpers
        agent.auxiliary_client = auxiliary

        modules = {
            "httpx": fake_httpx,
            "honcho": fake_honcho,
            "hermes_cli": hermes_cli,
            "hermes_cli.runtime_provider": runtime_provider,
            "agent": agent,
            "agent.agent_runtime_helpers": runtime_helpers,
            "agent.auxiliary_client": auxiliary,
        }
        environment = {
            "BOT_HERMES_HOME": "/controller/runtime",
            "JOHN_LOMEIN_PROVIDER_BROKER_SOCKET": str(provider_path),
            "JOHN_LOMEIN_PROVIDER_BROKER_CAPABILITY": "provider-ephemeral-capability",
            "JOHN_LOMEIN_HONCHO_BROKER_SOCKET": str(honcho_path),
            "JOHN_LOMEIN_HONCHO_BROKER_CAPABILITY": "honcho-ephemeral-capability",
            "JOHN_LOMEIN_HONCHO_BROKER_WORKSPACE": "selected-workspace",
        }
        try:
            with mock.patch.dict(sys.modules, modules, clear=False), mock.patch.dict(
                os.environ,
                environment,
                clear=True,
            ):
                importlib.reload(bootstrap)
                self.assertNotIn("plugins.memory.honcho.client", sys.modules)
                bootstrap.install_broker_boundary()
                self.assertNotIn("plugins.memory.honcho.client", sys.modules)

                client = fake_honcho.Honcho(
                    api_key="real-key-must-not-leave",
                    base_url="https://attacker.invalid",
                    workspace_id="selected-workspace",
                )
                kwargs = client.constructor_kwargs
                self.assertEqual(kwargs["api_key"], "honcho-ephemeral-capability")
                self.assertEqual(kwargs["base_url"], "http://localhost")
                self.assertEqual(kwargs["workspace_id"], "selected-workspace")
                self.assertEqual(
                    kwargs["http_client"].transport.uds,
                    str(honcho_path),
                )
                self.assertNotIn("real-key-must-not-leave", repr(kwargs))
                self.assertEqual(
                    client._http_config["http_client"].transport.uds,
                    str(honcho_path),
                )
                with self.assertRaisesRegex(
                    bootstrap.ProviderBootstrapError,
                    "workspace_denied",
                ):
                    fake_honcho.Honcho(workspace_id="other-workspace")
        finally:
            for listener in listeners:
                listener.close()
            provider_path.unlink(missing_ok=True)
            honcho_path.unlink(missing_ok=True)
            provider_path.parent.rmdir()
            try:
                provider_path.parent.parent.rmdir()
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
