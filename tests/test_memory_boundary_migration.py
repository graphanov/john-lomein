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

from john_lomein_memory_boundary_migration import (  # noqa: E402
    MARKER_NAME,
    MARKER_TEXT,
    MemoryBoundaryError,
    reconcile_memory_boundary,
)


class MemoryBoundaryMigrationTest(unittest.TestCase):
    def roots(self, temporary: str) -> tuple[Path, Path, Path]:
        home = Path(temporary) / "runtime"
        private = home / "private" / "learning-steward"
        projection = home / "state" / "learning"
        home.mkdir(mode=0o700)
        return home, private, projection

    def reconcile(self, temporary: str) -> dict:
        home, private, projection = self.roots(temporary)
        return reconcile_memory_boundary(home, private, projection)

    def test_initial_migration_preserves_memory_and_projects_only_brief(self):
        with tempfile.TemporaryDirectory() as temporary:
            home, private, projection = self.roots(temporary)
            legacy_memory = home / "mnemosyne" / "data"
            legacy_memory.mkdir(parents=True)
            (legacy_memory / "mnemosyne.db").write_bytes(b"memory")
            legacy_learning = home / "state" / "learning"
            legacy_learning.mkdir(parents=True)
            (legacy_learning / "private-observations.jsonl").write_text(
                "private\n",
                encoding="utf-8",
            )
            (legacy_learning / "current-operating-brief.md").write_text(
                "public-safe brief\n",
                encoding="utf-8",
            )

            report = reconcile_memory_boundary(home, private, projection)

            self.assertTrue(report["initial_memory_migrated"])
            self.assertTrue(report["initial_learning_migrated"])
            self.assertFalse(report["late_legacy_quarantined"])
            self.assertFalse((home / "mnemosyne").exists())
            self.assertEqual(
                (private / "mnemosyne" / "data" / "mnemosyne.db").read_bytes(),
                b"memory",
            )
            self.assertEqual(
                (private / "learning" / "private-observations.jsonl").read_text(
                    encoding="utf-8"
                ),
                "private\n",
            )
            self.assertEqual(
                (projection / "current-operating-brief.md").read_text(
                    encoding="utf-8"
                ),
                "public-safe brief\n",
            )
            marker = private / MARKER_NAME
            self.assertEqual(marker.read_text(encoding="utf-8"), MARKER_TEXT)
            self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
            self.assertEqual(
                stat.S_IMODE((private / "mnemosyne").stat().st_mode),
                0o700,
            )
            self.assertEqual(
                stat.S_IMODE(
                    (
                        private / "mnemosyne" / "data" / "mnemosyne.db"
                    ).stat().st_mode
                ),
                0o600,
            )

    def test_late_legacy_tree_is_preserved_in_sealed_quarantine(self):
        with tempfile.TemporaryDirectory() as temporary:
            home, private, projection = self.roots(temporary)
            reconcile_memory_boundary(home, private, projection)
            canonical = private / "mnemosyne" / "data"
            canonical.mkdir(parents=True)
            (canonical / "mnemosyne.db").write_bytes(b"canonical")
            legacy = home / "mnemosyne" / "data"
            legacy.mkdir(parents=True)
            (legacy / "mnemosyne.db").write_bytes(b"late residue")

            report = reconcile_memory_boundary(home, private, projection)

            self.assertTrue(report["late_legacy_quarantined"])
            self.assertFalse((home / "mnemosyne").exists())
            self.assertEqual(
                (canonical / "mnemosyne.db").read_bytes(),
                b"canonical",
            )
            destination = Path(report["quarantine_path"])
            self.assertTrue(destination.is_dir())
            self.assertEqual(
                (destination / "data" / "mnemosyne.db").read_bytes(),
                b"late residue",
            )
            self.assertEqual(
                stat.S_IMODE(destination.stat().st_mode),
                0o700,
            )
            self.assertEqual(
                stat.S_IMODE(
                    (destination / "data" / "mnemosyne.db").stat().st_mode
                ),
                0o600,
            )

            second = reconcile_memory_boundary(home, private, projection)
            self.assertFalse(second["late_legacy_quarantined"])
            self.assertEqual(
                sorted(
                    path
                    for path in destination.parent.iterdir()
                    if path.is_dir()
                ),
                [destination],
            )

    def test_existing_private_and_pre_marker_legacy_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            home, private, projection = self.roots(temporary)
            (home / "mnemosyne").mkdir()
            (home / "mnemosyne" / "legacy.db").write_bytes(b"legacy")
            (private / "mnemosyne").mkdir(parents=True)
            (private / "mnemosyne" / "private.db").write_bytes(b"private")

            with self.assertRaisesRegex(
                MemoryBoundaryError,
                "both legacy and private Mnemosyne",
            ):
                reconcile_memory_boundary(home, private, projection)
            self.assertTrue((home / "mnemosyne" / "legacy.db").exists())
            self.assertTrue(
                (private / "mnemosyne" / "private.db").exists()
            )

    def test_late_legacy_symlink_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            home, private, projection = self.roots(temporary)
            reconcile_memory_boundary(home, private, projection)
            outside = Path(temporary) / "outside"
            outside.mkdir()
            (outside / "keep").write_text("untouched", encoding="utf-8")
            (home / "mnemosyne").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(
                MemoryBoundaryError,
                "unsafe late legacy Mnemosyne root",
            ):
                reconcile_memory_boundary(home, private, projection)
            self.assertTrue((home / "mnemosyne").is_symlink())
            self.assertEqual(
                (outside / "keep").read_text(encoding="utf-8"),
                "untouched",
            )

    def test_marker_tampering_and_noncanonical_roots_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            home, private, projection = self.roots(temporary)
            reconcile_memory_boundary(home, private, projection)
            marker = private / MARKER_NAME
            marker.write_text("forged\n", encoding="utf-8")
            os.chmod(marker, 0o600)
            with self.assertRaisesRegex(
                MemoryBoundaryError,
                "invalid model-memory boundary marker",
            ):
                reconcile_memory_boundary(home, private, projection)

            with self.assertRaisesRegex(
                MemoryBoundaryError,
                "non-canonical private steward root",
            ):
                reconcile_memory_boundary(
                    home,
                    home / "private" / "wrong",
                    projection,
                )


if __name__ == "__main__":
    unittest.main()
