#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, module_name: str):
    scripts = ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    spec = importlib.util.spec_from_file_location(module_name, scripts / name)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def make_polyglot_hermes(tmp_path: Path) -> tuple[Path, Path]:
    bin_dir = tmp_path / "venv" / "bin"
    bin_dir.mkdir(parents=True)
    hermes = bin_dir / "hermes"
    hermes.write_text(
        "#!/bin/sh\n"
        "'''exec' \"$(dirname -- \"$(realpath -- \"$0\")\")\"/'python3' \"$0\" \"$@\"\n"
        "' '''\n",
        encoding="utf-8",
    )
    hermes.chmod(0o755)
    runtime = tmp_path / "runtime" / "python3.11"
    runtime.parent.mkdir()
    runtime.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    runtime.chmod(0o755)
    python = bin_dir / "python3"
    python.symlink_to(runtime)
    return hermes, python


def test_doctor_resolves_python_next_to_polyglot_hermes_launcher(tmp_path: Path) -> None:
    doctor = load_script("doctor-instance.py", "doctor_runtime_python_test")
    hermes, python = make_polyglot_hermes(tmp_path)

    with mock.patch.object(doctor.shutil, "which", return_value=str(hermes)):
        resolved = doctor.resolve_hermes_python({}, tmp_path)

    assert resolved == str(python)
    assert os.path.basename(resolved).startswith("python")


def test_worker_resolves_python_next_to_polyglot_hermes_launcher(tmp_path: Path) -> None:
    worker = load_script("john-lomein-worker.py", "worker_runtime_python_test")
    hermes, python = make_polyglot_hermes(tmp_path)

    with mock.patch.object(worker, "shutil_which", return_value=str(hermes)):
        resolved = worker.resolve_hermes_python({})

    assert resolved == str(python)


def test_forge_resolves_python_next_to_polyglot_hermes_launcher(tmp_path: Path) -> None:
    forge = load_script(
        "john-lomein-forge-orchestrator.py",
        "forge_runtime_python_test",
    )
    hermes, python = make_polyglot_hermes(tmp_path)

    with mock.patch.object(forge, "which", return_value=str(hermes)):
        resolved = forge.hermes_python({})

    assert resolved == str(python)


def test_service_registry_does_not_trust_shell_from_polyglot_launcher(
    tmp_path: Path,
) -> None:
    registry = load_script(
        "john_lomein_service_registry.py",
        "service_registry_runtime_python_test",
    )
    hermes, python = make_polyglot_hermes(tmp_path)

    def fake_which(name: str):
        if name == "hermes":
            return str(hermes)
        if name == "python3":
            return None
        return None

    with mock.patch.object(registry.shutil, "which", side_effect=fake_which):
        trusted = registry._trusted_python_interpreters()

    assert str(python.resolve()) in trusted
    assert str(Path("/bin/sh").resolve()) not in trusted


def test_model_isolation_executes_polyglot_hermes_with_its_python(
    tmp_path: Path,
) -> None:
    isolation = load_script(
        "john_lomein_model_isolation.py",
        "model_isolation_runtime_python_test",
    )
    hermes, python = make_polyglot_hermes(tmp_path)

    command = isolation._isolate_hermes_python_entrypoint(
        [str(hermes), "chat", "-q", "hello"]
    )

    assert command == [
        str(python),
        "-I",
        str(hermes),
        "chat",
        "-q",
        "hello",
    ]


def test_shell_launchers_use_the_python_next_to_hermes() -> None:
    launchers = (
        "install-guide-gateway.sh",
        "install-runtime-supervisor.sh",
        "uninstall-runtime-supervisor.sh",
        "john-lomein-learning-trigger.sh",
    )
    for name in launchers:
        text = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        assert 'head -1 "$HERMES_BIN"' not in text
        assert 'dirname "$HERMES_BIN"' in text


def test_deploy_generator_uses_the_python_next_to_hermes() -> None:
    text = (ROOT / "scripts" / "deploy-instance.sh").read_text(encoding="utf-8")
    assert "hermes_dir=Path(hermes_bin).expanduser().parent" in text
    assert "candidate.name.startswith('python')" in text
