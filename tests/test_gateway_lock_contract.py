#!/usr/bin/env python3
from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from john_lomein_gateway_lock_contract import (  # noqa: E402
    GatewayLockContractError,
    gateway_lock_root,
    prepare_gateway_lock_root,
    validate_gateway_lock_root,
)


class GatewayLockContractTest(unittest.TestCase):
    def fixture_home(self, base: Path) -> Path:
        home = base / "real-home"
        home.mkdir(mode=0o700)
        return home

    def test_derives_only_the_exact_default_path_from_explicit_real_home(self):
        home = Path("/opt/john-fixture")
        self.assertEqual(
            gateway_lock_root(home),
            Path("/opt/john-fixture/.local/state/hermes/gateway-locks"),
        )
        for unsafe in (
            "opt/john-fixture",
            "/",
            "/opt/john-fixture/../other",
            "/opt/john-fixture\x00suffix",
        ):
            with self.subTest(unsafe=repr(unsafe)):
                with self.assertRaises(GatewayLockContractError):
                    gateway_lock_root(unsafe)

    def test_prepare_creates_private_tree_and_normalizes_without_reading_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.fixture_home(Path(tmp).resolve())
            expected = gateway_lock_root(home)
            expected.mkdir(parents=True)
            lock = expected / "token-digest.lock"
            payload = b"opaque lock payload must remain byte-identical\n"
            lock.write_bytes(payload)
            os.chmod(lock, 0o000)
            for directory in (
                home / ".local",
                home / ".local" / "state",
                home / ".local" / "state" / "hermes",
                expected,
            ):
                os.chmod(directory, 0o755)

            self.assertEqual(prepare_gateway_lock_root(home), expected)
            self.assertEqual(lock.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
            for directory in (
                home / ".local",
                home / ".local" / "state",
                home / ".local" / "state" / "hermes",
            ):
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(expected.stat().st_mode), 0o700)
            self.assertEqual(validate_gateway_lock_root(home), expected)

    def test_prepare_creates_missing_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.fixture_home(Path(tmp).resolve())
            root = prepare_gateway_lock_root(home)
            self.assertTrue(root.is_dir())
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(validate_gateway_lock_root(home), root)

    def test_validation_is_read_only_and_fails_closed_on_modes_or_missing_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.fixture_home(Path(tmp).resolve())
            with self.assertRaisesRegex(
                GatewayLockContractError,
                "gateway_lock_root_missing",
            ):
                validate_gateway_lock_root(home)

            root = prepare_gateway_lock_root(home)
            lock = root / "token.lock"
            lock.write_text("preserve me", encoding="utf-8")
            os.chmod(lock, 0o644)
            with self.assertRaisesRegex(
                GatewayLockContractError,
                "gateway_lock_entry_mode_unsafe",
            ):
                validate_gateway_lock_root(home)
            self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o644)
            self.assertEqual(lock.read_text(encoding="utf-8"), "preserve me")

            os.chmod(lock, 0o600)
            os.chmod(root, 0o755)
            with self.assertRaisesRegex(
                GatewayLockContractError,
                "gateway_lock_directory_unsafe",
            ):
                validate_gateway_lock_root(home)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)

    def test_rejects_symlink_home_or_controlled_component_without_following_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            home = self.fixture_home(base)
            alias = base / "home-alias"
            alias.symlink_to(home, target_is_directory=True)
            with self.assertRaisesRegex(
                GatewayLockContractError,
                "gateway_lock_home_ancestry_unsafe",
            ):
                prepare_gateway_lock_root(alias)

            target = base / "outside"
            target.mkdir(mode=0o755)
            marker = target / "marker"
            marker.write_text("untouched", encoding="utf-8")
            (home / ".local").symlink_to(target, target_is_directory=True)
            with self.assertRaises(GatewayLockContractError):
                prepare_gateway_lock_root(home)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
            self.assertEqual(marker.read_text(encoding="utf-8"), "untouched")

    def test_rejects_symlink_entry_without_touching_target_or_removing_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            home = self.fixture_home(base)
            root = prepare_gateway_lock_root(home)
            target = base / "outside.lock"
            target.write_text("outside", encoding="utf-8")
            os.chmod(target, 0o644)
            link = root / "token.lock"
            link.symlink_to(target)

            with self.assertRaisesRegex(
                GatewayLockContractError,
                "gateway_lock_entry_unsafe_type",
            ):
                prepare_gateway_lock_root(home)
            self.assertTrue(link.is_symlink())
            self.assertEqual(target.read_text(encoding="utf-8"), "outside")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    def test_rejects_hardlinked_entry_without_chmod_or_deletion(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            home = self.fixture_home(base)
            root = prepare_gateway_lock_root(home)
            outside = base / "outside.lock"
            outside.write_text("same inode", encoding="utf-8")
            os.chmod(outside, 0o644)
            lock = root / "token.lock"
            os.link(outside, lock)

            with self.assertRaisesRegex(
                GatewayLockContractError,
                "gateway_lock_entry_hardlinked",
            ):
                prepare_gateway_lock_root(home)
            self.assertTrue(outside.exists())
            self.assertTrue(lock.exists())
            self.assertEqual(outside.read_text(encoding="utf-8"), "same inode")
            self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o644)

    def test_rejects_fifo_and_nested_directory_without_deleting_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.fixture_home(Path(tmp).resolve())
            root = prepare_gateway_lock_root(home)
            fifo = root / "token.fifo"
            os.mkfifo(fifo, 0o600)
            with self.assertRaisesRegex(
                GatewayLockContractError,
                "gateway_lock_entry_unsafe_type",
            ):
                prepare_gateway_lock_root(home)
            self.assertTrue(stat.S_ISFIFO(fifo.lstat().st_mode))

            fifo.unlink()
            nested = root / "nested"
            nested.mkdir()
            marker = nested / "marker"
            marker.write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(
                GatewayLockContractError,
                "gateway_lock_entry_unsafe_type",
            ):
                validate_gateway_lock_root(home)
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    def test_rejects_non_owner_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.fixture_home(Path(tmp).resolve())
            other_uid = os.geteuid() + 1
            with self.assertRaisesRegex(
                GatewayLockContractError,
                "gateway_lock_home_unsafe",
            ):
                prepare_gateway_lock_root(
                    home,
                    expected_owner_uid=other_uid,
                )


if __name__ == "__main__":
    unittest.main()
