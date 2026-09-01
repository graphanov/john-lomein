#!/usr/bin/env python3
"""Root-managed entrypoint for the isolated protected release broker."""

from __future__ import annotations

import os
import sys
from pathlib import Path


# This file is the LaunchDaemon entrypoint.  Scrub ambient credential, proxy,
# TLS, and OpenSSL controls before importing the package: release_broker's
# package initializer imports cryptography-backed modules.
_SENSITIVE = {
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "GH_CONFIG_DIR",
    "GIT_ASKPASS",
    "GIT_SSH_COMMAND",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "SSLKEYLOGFILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "OPENSSL_CONF",
    "OPENSSL_MODULES",
    "OPENSSL_ENGINES",
    "AWS_PROFILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "KUBECONFIG",
    "DOCKER_CONFIG",
    "NETRC",
}
for _key in tuple(os.environ):
    if _key in _SENSITIVE or _key.upper().endswith(
        ("_API_KEY", "_PASSWORD", "_PRIVATE_KEY", "_SECRET", "_TOKEN")
    ):
        os.environ.pop(_key, None)


if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release_broker.john_lomein_release_broker_daemon import main


if __name__ == "__main__":
    raise SystemExit(main())
