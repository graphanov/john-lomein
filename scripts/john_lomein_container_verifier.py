#!/usr/bin/env python3
"""Credential-free container backend for verifier-owned repository tests."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any


CONTRACT_LABEL = "org.john-lomein.verifier-contract"
CONTRACT_VALUE = "tracked-head-archive-v1"
LOCK_LABEL = "org.john-lomein.lock-sha256"
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DOCKER_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
MAX_CAPTURE_BYTES = 2 * 1024 * 1024


def _docker_host() -> str:
    configured = os.environ.get("DOCKER_HOST", "").strip()
    if configured:
        if not configured.startswith("unix://"):
            return ""
        socket = Path(configured.removeprefix("unix://")).expanduser()
        return configured if socket.exists() else ""
    for socket in (Path.home() / ".docker" / "run" / "docker.sock", Path("/var/run/docker.sock")):
        if socket.exists():
            return f"unix://{socket}"
    return ""


def _runtime_env(process_env: dict[str, str]) -> dict[str, str]:
    out = {
        key: value
        for key, value in process_env.items()
        if key in {"HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE"}
    }
    out["PATH"] = DOCKER_PATH
    host = _docker_host()
    if host:
        out["DOCKER_HOST"] = host
    return out


def _inspect_image(
    docker: str,
    image: str,
    *,
    lock_sha256: str,
    runtime_env: dict[str, str],
) -> tuple[bool, str, dict[str, Any]]:
    try:
        proc = subprocess.run(
            [docker, "image", "inspect", image],
            capture_output=True,
            text=True,
            env=runtime_env,
            timeout=30,
        )
    except Exception as exc:
        return False, f"container_image_inspect_error:{type(exc).__name__}", {}
    if proc.returncode != 0:
        return False, "container_image_unavailable", {}
    try:
        data = json.loads(proc.stdout or "[]")
        inspected = data[0] if isinstance(data, list) and data else {}
        labels = ((inspected.get("Config") or {}).get("Labels") or {})
        digests = inspected.get("RepoDigests") or []
    except Exception:
        return False, "container_image_inspect_invalid_json", {}
    if image not in digests:
        return False, "container_image_digest_mismatch", {}
    if labels.get(CONTRACT_LABEL) != CONTRACT_VALUE:
        return False, "container_image_contract_mismatch", {}
    if labels.get(LOCK_LABEL) != lock_sha256:
        return False, "container_image_lock_mismatch", {}
    return True, "ok", {
        "image": image,
        "image_id": str(inspected.get("Id") or ""),
        "contract": CONTRACT_VALUE,
    }


def _run_bounded_process(
    command: list[str],
    *,
    env: dict[str, str],
    timeout: int,
    max_bytes: int = MAX_CAPTURE_BYTES,
) -> tuple[int, str, str, bool]:
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    buffers = [bytearray(), bytearray()]
    totals = [0, 0]

    def drain(stream, index: int) -> None:
        assert stream is not None
        while chunk := stream.read(64 * 1024):
            totals[index] += len(chunk)
            buffers[index].extend(chunk)
            overflow = len(buffers[index]) - max_bytes
            if overflow > 0:
                del buffers[index][:overflow]

    threads = [
        threading.Thread(target=drain, args=(proc.stdout, 0), daemon=True),
        threading.Thread(target=drain, args=(proc.stderr, 1), daemon=True),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        returncode = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        returncode = proc.wait(timeout=30)
    for thread in threads:
        thread.join(timeout=30)
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            stream.close()

    def render(index: int) -> str:
        text = bytes(buffers[index]).decode("utf-8", errors="replace")
        prefix = "[output_truncated]\n" if totals[index] > max_bytes else ""
        return (prefix + text).strip()

    return returncode, render(0), render(1), timed_out


def _force_remove_container(docker: str, name: str, *, env: dict[str, str]) -> bool:
    for _attempt in range(3):
        subprocess.run(
            [docker, "rm", "-f", name],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
            check=False,
        )
        probe = subprocess.run(
            [docker, "container", "inspect", name],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
            check=False,
        )
        if probe.returncode != 0:
            return True
    return False


def run_container_verifier(
    cmd: str,
    *,
    process_env: dict[str, str],
    archive: Path,
    image: str,
    lock_sha256: str,
    timeout: int = 900,
) -> tuple[int, str, str, bool, dict[str, Any]]:
    """Run tests from a tracked-HEAD archive in a loopback-private container."""
    base_meta: dict[str, Any] = {
        "backend": "docker",
        "image": image,
        "network": "none",
        "source": "tracked_head_archive",
        "rootfs_read_only": True,
        "cap_drop_all": True,
        "no_new_privileges": True,
        "non_root": True,
        "lock_sha256": lock_sha256,
    }
    if not IMAGE_RE.fullmatch(image):
        return 997, "", "container_image_not_immutable", False, base_meta
    if not SHA256_RE.fullmatch(lock_sha256):
        return 997, "", "container_lock_digest_invalid", False, base_meta
    try:
        archive_stat = archive.lstat()
    except OSError:
        return 997, "", "container_archive_missing", False, base_meta
    if archive.is_symlink() or not archive.is_file():
        return 997, "", "container_archive_not_regular_file", False, base_meta
    if any(char in str(archive) for char in ("\n", "\r", ",")):
        return 997, "", "container_archive_path_unsafe", False, base_meta

    docker = shutil.which("docker", path=DOCKER_PATH)
    runtime_env = _runtime_env(process_env)
    if docker is None or "DOCKER_HOST" not in runtime_env:
        return 997, "", "container_runtime_unavailable", False, base_meta
    image_ok, image_reason, image_meta = _inspect_image(
        docker,
        image,
        lock_sha256=lock_sha256,
        runtime_env=runtime_env,
    )
    base_meta.update(image_meta)
    if not image_ok:
        return 997, "", image_reason, False, base_meta

    container_name = f"john-lomein-verifier-{uuid.uuid4().hex}"
    script = (
        "set -euo pipefail; "
        "mkdir -p /tmp/home /work; "
        "tar -xf /source.tar -C /work; "
        "rm -rf /work/node_modules; "
        "cp -a /opt/john-lomein/node_modules /work/node_modules; "
        "cd /work; "
        "exec /bin/bash -lc \"$JOHN_LOMEIN_TEST_CMD\""
    )
    command = [
        docker,
        "run",
        "--rm",
        "--pull",
        "never",
        "--name",
        container_name,
        "--restart",
        "no",
        "--label",
        "org.john-lomein.verifier=true",
        "--network",
        "none",
        "--ipc",
        "none",
        "--read-only",
        "--log-driver",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "2048",
        "--memory",
        "6g",
        "--cpus",
        "4",
        "--user",
        "65534:65534",
        "--tmpfs",
        "/work:rw,exec,nosuid,nodev,size=3g,mode=1777",
        "--tmpfs",
        "/tmp:rw,exec,nosuid,nodev,size=1g,mode=1777",
        "--mount",
        f"type=bind,source={archive},target=/source.tar,readonly",
        "--env",
        f"JOHN_LOMEIN_TEST_CMD={cmd}",
        "--env",
        "HOME=/tmp/home",
        "--env",
        "CI=1",
        "--env",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "--env",
        "GIT_CONFIG_NOSYSTEM=1",
        "--env",
        "GIT_TERMINAL_PROMPT=0",
        "--env",
        "NPM_CONFIG_USERCONFIG=/dev/null",
        "--env",
        "npm_config_cache=/tmp/npm-cache",
        "--entrypoint",
        "/usr/bin/timeout",
        image,
        "--kill-after=5s",
        f"{max(1, int(timeout))}s",
        "/bin/bash",
        "-lc",
        script,
    ]
    try:
        returncode, stdout, stderr, timed_out = _run_bounded_process(
            command,
            env=runtime_env,
            timeout=timeout + 15,
        )
        if timed_out:
            if not _force_remove_container(docker, container_name, env=runtime_env):
                return 998, stdout, "container_cleanup_failed", False, base_meta
            return 124, stdout, (stderr + "\ncontainer_verifier_timeout").strip(), True, base_meta
        return returncode, stdout, stderr, True, base_meta
    except Exception as exc:
        return 999, "", f"container_verifier_error:{type(exc).__name__}", True, base_meta
