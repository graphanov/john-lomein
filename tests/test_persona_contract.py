#!/usr/bin/env python3
from __future__ import annotations

import json
import hashlib
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import john_lomein_file_contract as file_contract  # noqa: E402
from john_lomein_persona_contract import load_persona_core  # noqa: E402


PERSONA = ROOT / "persona" / "JOHN_LOMEIN.md"
SCENARIOS = ROOT / "evals" / "persona" / "scenarios.json"
LONGITUDINAL_SCENARIOS = (
    ROOT / "evals" / "persona" / "longitudinal-scenarios.json"
)


class PersonaContractTest(unittest.TestCase):
    def test_stable_file_trusts_only_root_owned_system_symlink_ancestors(self):
        def metadata(*, uid: int, mode: int):
            return mock.Mock(st_uid=uid, st_mode=mode)

        trusted_link = metadata(uid=0, mode=stat.S_IFLNK | 0o777)
        trusted_parent = metadata(uid=0, mode=stat.S_IFDIR | 0o755)
        directory_target = metadata(uid=501, mode=stat.S_IFDIR | 0o700)
        self.assertTrue(
            file_contract._trusted_system_directory_symlink(
                trusted_link,
                trusted_parent,
                directory_target,
            )
        )

        unsafe_cases = {
            "user-owned link": (
                metadata(uid=501, mode=stat.S_IFLNK | 0o777),
                trusted_parent,
                directory_target,
            ),
            "user-owned parent": (
                trusted_link,
                metadata(uid=501, mode=stat.S_IFDIR | 0o755),
                directory_target,
            ),
            "group-writable parent": (
                trusted_link,
                metadata(uid=0, mode=stat.S_IFDIR | 0o775),
                directory_target,
            ),
            "world-writable parent": (
                trusted_link,
                metadata(uid=0, mode=stat.S_IFDIR | 0o757),
                directory_target,
            ),
            "non-directory target": (
                trusted_link,
                trusted_parent,
                metadata(uid=0, mode=stat.S_IFREG | 0o644),
            ),
        }
        for name, inputs in unsafe_cases.items():
            with self.subTest(name=name):
                self.assertFalse(
                    file_contract._trusted_system_directory_symlink(*inputs)
                )

    def test_stable_file_descriptor_failures_are_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "persona.md"
            path.write_text(
                "<!-- john-lomein.persona.v1 -->\noriginal",
                encoding="utf-8",
            )
            os.chmod(path, 0o644)
            real_fstat = file_contract.os.fstat
            real_close = file_contract.os.close

            def read_source() -> bytes:
                return file_contract.read_stable_regular(
                    path,
                    maximum_bytes=4_500,
                    owner_only=False,
                )

            with mock.patch.object(
                file_contract.os,
                "fstat",
                side_effect=OSError("initial fstat failed"),
            ):
                with self.assertRaises(file_contract.StableFileError) as caught:
                    read_source()
                self.assertEqual(caught.exception.code, "unreadable")

            fstat_calls = 0

            def failing_final_fstat(descriptor: int):
                nonlocal fstat_calls
                fstat_calls += 1
                if fstat_calls == 2:
                    raise OSError("final fstat failed")
                return real_fstat(descriptor)

            with mock.patch.object(
                file_contract.os,
                "fstat",
                side_effect=failing_final_fstat,
            ):
                with self.assertRaises(file_contract.StableFileError) as caught:
                    read_source()
                self.assertEqual(caught.exception.code, "unreadable")

            with mock.patch.object(
                file_contract.os,
                "read",
                side_effect=OSError("read failed"),
            ):
                with self.assertRaises(file_contract.StableFileError) as caught:
                    read_source()
                self.assertEqual(caught.exception.code, "unreadable")

            def failing_close(descriptor: int) -> None:
                real_close(descriptor)
                raise OSError("close failed")

            with mock.patch.object(
                file_contract.os,
                "close",
                side_effect=failing_close,
            ):
                with self.assertRaises(file_contract.StableFileError) as caught:
                    read_source()
                self.assertEqual(caught.exception.code, "unreadable")

    def test_stable_file_close_failure_does_not_mask_contract_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "persona.md"
            path.write_text(
                "<!-- john-lomein.persona.v1 -->\noriginal",
                encoding="utf-8",
            )
            os.chmod(path, 0o644)
            real_close = file_contract.os.close

            def failing_close(descriptor: int) -> None:
                real_close(descriptor)
                raise OSError("close failed")

            with (
                mock.patch.object(
                    file_contract,
                    "_metadata_matches",
                    return_value=False,
                ),
                mock.patch.object(
                    file_contract.os,
                    "close",
                    side_effect=failing_close,
                ),
            ):
                with self.assertRaises(file_contract.StableFileError) as caught:
                    file_contract.read_stable_regular(
                        path,
                        maximum_bytes=4_500,
                        owner_only=False,
                    )
                self.assertEqual(caught.exception.code, "ambiguous")

    def test_shared_persona_loader_returns_exact_canonical_binding(self):
        text, version, digest = load_persona_core(PERSONA)
        self.assertEqual(text, PERSONA.read_text(encoding="utf-8").strip())
        self.assertEqual(version, "john-lomein.persona.v1")
        self.assertEqual(
            digest,
            hashlib.sha256(text.encode("utf-8")).hexdigest(),
        )

    def test_shared_persona_loader_rejects_ambiguous_and_unsafe_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.md"
            duplicate.write_text(
                "<!-- john-lomein.persona.v1 -->\n"
                "<!-- john-lomein.persona.v2 -->\n",
                encoding="utf-8",
            )
            oversized = root / "oversized.md"
            oversized.write_text(
                "<!-- john-lomein.persona.v1 -->\n" + "x" * 4_501,
                encoding="utf-8",
            )
            linked = root / "linked.md"
            linked.symlink_to(duplicate)
            hardlink = root / "hardlink.md"
            os.link(duplicate, hardlink)
            writable = root / "writable.md"
            writable.write_text(
                "<!-- john-lomein.persona.v1 -->\nvalid persona",
                encoding="utf-8",
            )
            os.chmod(writable, 0o666)
            for path in (duplicate, oversized, linked, hardlink, writable):
                with self.subTest(path=path.name):
                    with self.assertRaises(ValueError):
                        load_persona_core(path)

    def test_shared_persona_loader_rejects_in_place_and_name_replacement_races(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / "persona.md"
            original = "<!-- john-lomein.persona.v1 -->\noriginal"
            replacement = "<!-- john-lomein.persona.v1 -->\ntampered"
            self.assertEqual(len(original), len(replacement))

            for race in ("in_place", "name_replacement"):
                with self.subTest(race=race):
                    path.write_text(original, encoding="utf-8")
                    os.chmod(path, 0o644)
                    real_read = file_contract.os.read
                    raced = False

                    def racing_read(descriptor: int, size: int) -> bytes:
                        nonlocal raced
                        if not raced:
                            raced = True
                            if race == "in_place":
                                path.write_text(
                                    replacement,
                                    encoding="utf-8",
                                )
                                os.chmod(path, 0o644)
                            else:
                                candidate = root / "replacement.md"
                                candidate.write_text(
                                    replacement,
                                    encoding="utf-8",
                                )
                                os.chmod(candidate, 0o644)
                                candidate.replace(path)
                        return real_read(descriptor, size)

                    with mock.patch.object(
                        file_contract.os,
                        "read",
                        side_effect=racing_read,
                    ):
                        with self.assertRaises(ValueError):
                            load_persona_core(path)

    def test_shared_persona_loader_never_blocks_on_fifo_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "persona.md"
            path.write_text(
                "<!-- john-lomein.persona.v1 -->\noriginal",
                encoding="utf-8",
            )
            os.chmod(path, 0o644)
            real_open = file_contract.os.open
            replaced = False

            def racing_open(selected, flags, *args, **kwargs):
                nonlocal replaced
                if Path(selected) == path and not replaced:
                    replaced = True
                    path.unlink()
                    os.mkfifo(path, 0o600)
                self.assertTrue(
                    flags & getattr(os, "O_NONBLOCK", 0),
                )
                return real_open(selected, flags, *args, **kwargs)

            with mock.patch.object(
                file_contract.os,
                "open",
                side_effect=racing_open,
            ):
                with self.assertRaises(ValueError):
                    load_persona_core(path)

    def test_canonical_persona_is_compact_versioned_and_non_deceptive(self):
        text = PERSONA.read_text(encoding="utf-8")
        self.assertIn("<!-- john-lomein.persona.v1 -->", text)
        self.assertLessEqual(len(text.strip()), 4500)
        self.assertLessEqual(len(text.split()), 500)
        self.assertIn("fictional AI software maintainer", text)
        self.assertIn("Truth outranks agreement", text)
        self.assertIn("Never use a fake accent", text)
        self.assertIn("Do not use jealousy, guilt, exclusivity", text)
        self.assertIn("Personality changes how you explain", text)

    def test_all_roles_compose_one_identity(self):
        souls = sorted((ROOT / "profiles").glob("john-lomein-*/SOUL.md"))
        self.assertEqual(len(souls), 5)
        for path in souls:
            text = path.read_text(encoding="utf-8")
            self.assertEqual(text.count("{{JOHN_LOMEIN_PERSONA_CORE}}"), 1, path)
            self.assertIn("The role changes your attention and authority, not your identity.", text, path)

    def test_golden_scenarios_cover_independence_channels_and_boundaries(self):
        data = json.loads(SCENARIOS.read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], "john-lomein.persona-evals.v1")
        self.assertEqual(data["persona_version"], "john-lomein.persona.v1")
        scenarios = data["scenarios"]
        ids = [item["id"] for item in scenarios]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(scenarios), 10)
        surfaces = {item["surface"] for item in scenarios}
        self.assertTrue({"github", "owner_chat", "discord_public", "discord_casual", "companion_chat"} <= surfaces)
        traits = {trait for item in scenarios for trait in item["traits"]}
        self.assertTrue(
            {
                "non_sycophancy",
                "hard_refusal",
                "continuity",
                "ai_disclosure",
                "relationship_boundary",
            }
            <= traits
        )
        for item in scenarios:
            self.assertIn(item["role"], {"maintainer", "forge", "guide", "overwatch", "learning_steward"})
            self.assertTrue(item["authority_state"].strip(), item["id"])
            self.assertIsInstance(item["evidence"], list, item["id"])
            self.assertTrue(item["permitted_action"].strip(), item["id"])
            self.assertTrue(item["prompt"].strip(), item["id"])
            self.assertTrue(item["expected"], item["id"])
            self.assertTrue(item["forbidden"], item["id"])

    def test_longitudinal_scenarios_separate_pressure_from_evidence(self):
        data = json.loads(
            LONGITUDINAL_SCENARIOS.read_text(encoding="utf-8")
        )
        self.assertEqual(
            data["schema_version"],
            "john-lomein.persona-evals.v1",
        )
        self.assertEqual(data["persona_version"], "john-lomein.persona.v1")
        scenarios = {item["id"]: item for item in data["scenarios"]}
        required = {
            "pressure-without-evidence",
            "counterevidence-changes-verdict",
            "superseded-preference",
            "role-migration-private-boundary",
            "fallback-handoff-under-pressure",
        }
        self.assertTrue(required <= set(scenarios))
        self.assertIn(
            "pressure_independence",
            scenarios["pressure-without-evidence"]["traits"],
        )
        self.assertIn(
            "evidence_responsiveness",
            scenarios["counterevidence-changes-verdict"]["traits"],
        )
        self.assertIn(
            "memory_supersession",
            scenarios["superseded-preference"]["traits"],
        )
        self.assertIn(
            "memory_isolation",
            scenarios["role-migration-private-boundary"]["traits"],
        )
        self.assertIn(
            "dialogue_conditioned_persistence",
            scenarios["fallback-handoff-under-pressure"]["traits"],
        )
        self.assertEqual(len(scenarios), len(data["scenarios"]))
        for item in scenarios.values():
            self.assertTrue(item["authority_state"].strip(), item["id"])
            self.assertTrue(item["evidence"], item["id"])
            self.assertTrue(item["permitted_action"].strip(), item["id"])
            self.assertTrue(item["prompt"].strip(), item["id"])
            self.assertTrue(item["expected"], item["id"])
            self.assertTrue(item["forbidden"], item["id"])


if __name__ == "__main__":
    unittest.main()
