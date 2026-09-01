#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "privacy-scan.py"


def test_privacy_scan_rejects_concrete_instance_names_case_insensitively(tmp_path: Path) -> None:
    marker = "lazy" + "glm"
    (tmp_path / "fixture.txt").write_text(marker, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCANNER), str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "concrete_instance_name" in result.stdout


def test_privacy_scan_accepts_generic_fixture(tmp_path: Path) -> None:
    (tmp_path / "fixture.txt").write_text("sample-instance", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCANNER), str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
