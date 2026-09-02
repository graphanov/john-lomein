from __future__ import annotations

import copy
import inspect
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _fingerprint(seed: str) -> str:
    return "sha256:" + seed * 64


def _bound_candidates(pilot, *, participant: bool = False) -> dict[str, list[object]]:
    keys = pilot.DELETION_CANDIDATE_KEYS if participant else pilot.RETENTION_CANDIDATE_KEYS
    required = {
        "message_identities",
        "embedding_identities",
        "queue_identities",
        "sequence_high_waters",
    }
    assert required <= set(keys)
    candidates: dict[str, list[object]] = {key: [] for key in keys}
    candidates.update(
        {
            "message_ids": [7],
            "message_public_ids": ["message-old"],
            "message_identities": [
                {
                    "id": 7,
                    "public_id": "message-old",
                    "fingerprint": _fingerprint("a"),
                }
            ],
            "embedding_ids": [8],
            "embedding_identities": [
                {
                    "id": 8,
                    "message_id": "message-old",
                    "fingerprint": _fingerprint("b"),
                }
            ],
            "queue_ids": [9],
            "queue_identities": [
                {
                    "id": 9,
                    "work_unit_key": "unit-old",
                    "fingerprint": _fingerprint("c"),
                }
            ],
            "work_unit_keys": ["unit-old"],
            "sequence_high_waters": [
                {
                    "table": "message_embeddings",
                    "column": "id",
                    "sequence": "public.message_embeddings_id_seq",
                    "high_water": 80,
                },
                {
                    "table": "messages",
                    "column": "id",
                    "sequence": "public.messages_id_seq",
                    "high_water": 70,
                },
                {
                    "table": "queue",
                    "column": "id",
                    "sequence": "public.queue_id_seq",
                    "high_water": 90,
                },
            ],
        }
    )
    if participant:
        candidates.update(
            {
                "peer_ids": ["peer-row"],
                "session_ids": ["session-row"],
                "session_names": ["session-old"],
                "session_peer_link_keys": ["session-old\u001fparticipant"],
            }
        )
    return candidates


def _retention_plan(pilot, candidates: dict[str, list[object]]) -> dict[str, object]:
    values = {
        "workspace": "public-pilot-memory",
        "cutoff": "2026-08-02T12:00:00Z",
        "retention_days": 30,
        "generated_at": "2026-09-01T12:00:00.000001Z",
        "database_oid": 44,
        "schema_fingerprint": _fingerprint("d").removeprefix("sha256:"),
        "message_count": len(candidates["message_ids"]),
        "embedding_count": len(candidates["embedding_ids"]),
        "document_count": len(candidates["document_ids"]),
        "queue_count": len(candidates["queue_ids"]),
    }
    return pilot.make_retention_plan(values, candidate_sets=candidates)


def _participant_plan(pilot, candidates: dict[str, list[object]]) -> dict[str, object]:
    return pilot.make_participant_deletion_plan(
        database_oid=44,
        workspace="public-pilot-memory",
        peer="participant",
        generated_at="2026-09-01T12:00:00.000001Z",
        schema_fingerprint=_fingerprint("d"),
        allowed_service_peers=(),
        candidate_sets=candidates,
    )


def test_candidate_and_apply_sql_bind_bigint_rows_and_restore_sequence_floors():
    import john_lomein_honcho_pilot as pilot

    for name in ("honcho-retention-candidates.sql", "honcho-participant-candidates.sql"):
        sql = (SCRIPTS / name).read_text(encoding="utf-8")
        for key in (
            "message_identities",
            "embedding_identities",
            "queue_identities",
            "sequence_high_waters",
        ):
            assert f"'{key}'" in sql
        assert "sha256(convert_to(to_jsonb(" in sql
        assert "pg_get_serial_sequence" in sql
        assert "pg_sequence_last_value" in sql

    for sql in (pilot.retention_apply_sql(), pilot.participant_deletion_apply_sql()):
        for relation in ("message", "embedding", "queue"):
            assert f"jl_{relation}_identities" in sql
        assert "sha256(convert_to(to_jsonb(" in sql
        assert "pg_get_serial_sequence" in sql
        assert "pg_sequence_last_value" in sql
        assert "setval(" in sql
        # An ID-only DELETE is not a safe replay predicate.
        assert "USING jl_message_identities" in sql
        assert "USING jl_embedding_identities" in sql
        assert "USING jl_queue_identities" in sql


def test_tombstone_residue_rejects_reused_bigint_with_different_identity(monkeypatch):
    import john_lomein_honcho_pilot as pilot

    candidates = _bound_candidates(pilot, participant=True)
    replacement = copy.deepcopy(candidates)
    replacement["message_public_ids"] = ["message-unrelated"]
    replacement["message_identities"] = [
        {
            "id": 7,
            "public_id": "message-unrelated",
            "fingerprint": _fingerprint("f"),
        }
    ]

    def fake_psql_json(_database, sql, *, variables=None):
        assert "message_identities" in sql
        assert variables is not None and "message_identities" in variables
        return {
            "message_ids": replacement["message_ids"],
            "message_public_ids": replacement["message_public_ids"],
            "message_identities": replacement["message_identities"],
            "embedding_ids": [],
            "embedding_identities": [],
            "queue_ids": [],
            "queue_identities": [],
            "document_ids": [],
            "collection_ids": [],
            "active_queue_session_ids": [],
            "peer_ids": [],
            "session_ids": [],
            "session_names": [],
            "session_peer_link_keys": [],
        }

    monkeypatch.setattr(pilot, "psql_json", fake_psql_json)
    with pytest.raises(ValueError, match="identity collision"):
        pilot.exact_tombstone_residue(
            "public_database",
            workspace="public-pilot-memory",
            exact_ids=candidates,
        )


@pytest.mark.parametrize("participant", [False, True])
def test_deletion_backup_is_newer_than_and_bound_to_exact_signed_plan(participant):
    import john_lomein_honcho_pilot as pilot

    candidates = _bound_candidates(pilot, participant=participant)
    plan = (
        _participant_plan(pilot, candidates)
        if participant
        else _retention_plan(pilot, candidates)
    )
    coverage = pilot.deletion_backup_coverage(
        plan=plan,
        candidate_sets=candidates,
    )
    metadata = {
        "verified": True,
        "database": "public_database",
        "created_at": "2026-09-01T12:00:00.000002Z",
        "deletion_coverage": coverage,
    }
    kwargs = {
        "plan": plan,
        "candidate_sets": candidates,
        "now": datetime(2026, 9, 1, 12, 1, tzinfo=timezone.utc),
    }
    assert pilot.deletion_backup_covers_plan(metadata, **kwargs)

    stale = copy.deepcopy(metadata)
    stale["created_at"] = str(plan["generated_at"])
    assert not pilot.deletion_backup_covers_plan(stale, **kwargs)

    wrong_plan = copy.deepcopy(metadata)
    wrong_plan["deletion_coverage"]["plan_digest"] = "0" * 64
    assert not pilot.deletion_backup_covers_plan(wrong_plan, **kwargs)

    incomplete = copy.deepcopy(metadata)
    incomplete["deletion_coverage"]["id_set_digests"].pop("message_ids")
    assert not pilot.deletion_backup_covers_plan(incomplete, **kwargs)

    wrong_candidates = copy.deepcopy(candidates)
    wrong_candidates["message_ids"] = [7, 10]
    assert not pilot.deletion_backup_covers_plan(
        metadata, **(kwargs | {"candidate_sets": wrong_candidates})
    )


def test_manual_and_automated_deletion_paths_share_exact_plan_backup_gate():
    import john_lomein_honcho_pilot as pilot

    for apply in (pilot._apply_retention, pilot._apply_participant_deletion):
        source = inspect.getsource(apply)
        assert "verified_deletion_backup_for_plan(" in source
        assert "verified_backup_metadata(" not in source

    cycle = inspect.getsource(pilot.run_public_retention_cycle)
    assert cycle.index("plan = make_retention_plan(") < cycle.index("create_backup(")
    assert "deletion_plan=plan" in cycle
    assert "candidate_sets=candidates" in cycle
