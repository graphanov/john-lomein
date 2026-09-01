# Dedicated public Honcho operations

Status: prepared, inactive until the owner-enabled Guide deployment provisions the service. Doctor remains read-only. No command in this product patches, adopts, bootouts, bootstraps, or restarts personal Hermes Honcho services.

## Service boundary

Public John memory is a dedicated service per configured instance:

- one dedicated PostgreSQL database whose name is derived from `instance.slug`;
- one dedicated Redis instance on a distinct loopback port, using its database 0;
- one distinct loopback Honcho API port (port 8000 is rejected);
- one clean, detached, commit-pinned checkout of `plastic-labs/honcho` at `9379c634ed240d0225b63443606e5304a4e261c5` under the instance runtime;
- one product-owned LaunchAgent, `ai.john-lomein.<slug>.public-honcho`.

Redis, API, and deriver are children of that supervisor. They do not have independent LaunchAgents. The personal checkout under `~/.hermes/honcho-local`, the personal database `honcho_local`, API port 8000, Redis 6379/0, and all personal LaunchAgents are invalid public-service targets.

The example manifest derives collision-resistant ports, database name, service root, and label from `instance.slug`. Explicit overrides remain fail-closed and must still be dedicated.

## Provisioning

Owner-enabled deployment runs:

```bash
python3 scripts/john_lomein_public_honcho_service.py \
  public-service-install --manifest /absolute/path/to/instance.yaml
```

Provisioning creates only product-owned runtime paths, clones the approved remote into a new checkout, detaches the exact commit, runs `uv sync --frozen`, creates the dedicated PostgreSQL database when absent, applies the pinned Alembic migrations, writes a private Honcho environment and Redis configuration, and installs the product supervisor plist.

Provisioning fails without local PostgreSQL database-creation and migration privileges. It never falls back to `honcho_local`, a shared database, the personal checkout, or personal Redis. An existing checkout must already have the approved remote, exact HEAD, and an empty tracked/untracked status; provisioning does not clean, reset, or repurpose it.

## Startup reconciliation

Before API or deriver children start, the supervisor:

1. verifies the approved remote, exact pinned commit, clean checkout, runtime database/cache configuration, and non-personal API/Redis ports;
2. inventories every workspace-bearing Honcho table and rejects any workspace other than the configured public workspace;
3. rejects malformed tombstones and every `pending` tombstone;
4. queries every exact ID in each `applied` tombstone; restored residue causes `deletion_replay_required`, while applied-clean tombstones are allowed;
5. flushes only the dedicated Redis database;
6. runs the 30-day retention transaction and writes a fresh identity-bound receipt;
7. starts the API and deriver as its children.

Guide startup runs the same database/check-out/tombstone checks and requires `state/honcho/retention-latest.json` to be valid, identity-bound, and no more than five minutes old. Missing, malformed, stale, or mismatched evidence blocks Guide.

## Retention promise

The supervisor runs retention before the first API/deriver start and every 300 seconds thereafter. The public active-store promise is:

- raw Honcho messages: 30 days plus at most 5 minutes;
- message embeddings and recursively derived active documents rooted in those messages: the same bound;
- direct, payload-only legacy, and sibling queue rows sharing affected work-unit keys: the same bound;
- matching `active_queue_sessions`: the same bound.

PostgreSQL supplies the clock and exact cutoff. Planning records exact message, public-message, embedding, document, queue, work-unit, and active-queue-session IDs. Unknown raw-message references or malformed lineage fail closed. Every mutable table with `workspace_name` uses the exact configured workspace predicate; `active_queue_sessions`, whose supported schema has no workspace column, is selected by exact ID through a workspace-bound queue predicate.

Retention physically deletes active documents instead of retaining their content behind a soft-delete marker. SQL takes a workspace advisory lock, requires database quiescence, checks exact pre-counts, deletes dependencies first, and checks exact postconditions before commit.

## Public-only recovery backups

A destructive retention or participant-deletion transaction requires a verified private custom-format PostgreSQL backup. Database isolation is checked before backup creation, so the archive contains only the configured public service database and cannot contain or restore personal Hermes workspaces.

Public backup archives and manifests live under the instance-private runtime, mode 0600. The supervisor expires them automatically no later than 30 days after creation. Tombstones remain durable for at least the lifetime of every backup that might contain their exact IDs.

The dedicated Redis cache is configured without RDB snapshots or append-only persistence. It is rebuildable from the public database and is synchronously flushed for deletion, replay, and startup sanitization.

This promise does not cover Discord-held messages, Hermes session files, logs, telemetry exports, or another external store. Those require separate inventory and deletion policies.

## Participant deletion and tombstones

Only v2 exact-ID plans are executable. V1 tombstones and plans are rejected rather than upgraded implicitly.

```bash
python3 scripts/john_lomein_honcho_pilot.py deletion-request-plan \
  --database "$PUBLIC_HONCHO_DATABASE" \
  --workspace "$PUBLIC_HONCHO_WORKSPACE" \
  --peer "$PARTICIPANT_PEER" \
  --manifest "$INSTANCE_ROOT/instance.yaml" \
  --output "$PRIVATE_STATE/deletion-plan.json"
```

The plan covers the participant peer, exact sessions and session links, all exact session messages, embeddings, recursively dependent documents, observing/observed collections, every sibling queue row, and exact active queue rows. A session containing another non-service participant blocks the request.

Application requires the plan digest, current schema/database identity, pinned server identity, exact manifest digest, verified public-only backup, and a fresh product-child quiescence receipt. The private tombstone embeds the complete exact ID sets plus that evidence.

Crash ordering is deliberate:

1. atomically create and fsync `pending` with all exact IDs;
2. apply the exact-ID SQL transaction;
3. verify every exact database ID is absent;
4. synchronously `FLUSHDB` only on the dedicated Redis instance and verify `DBSIZE=0`;
5. atomically replace the tombstone with `applied`.

A crash during SQL, after commit, during cache flush, or before the applied-tombstone fsync leaves the durable state `pending`. Cache failure can never produce `applied`.

## Restore and replay

Mechanical restore verification is not permission to serve. After an older backup is restored into the dedicated service database, startup checks the exact IDs embedded in every applied tombstone. Any residue blocks API, deriver, and Guide until explicit replay succeeds:

```bash
python3 scripts/john_lomein_honcho_pilot.py tombstone-replay \
  --database "$PUBLIC_HONCHO_DATABASE" \
  --manifest "$INSTANCE_ROOT/instance.yaml" \
  --tombstone "$PRIVATE_TOMBSTONE" \
  --confirm-tombstone-digest "$TOMBSTONE_DIGEST" \
  --backup "$RESTORED_FROM_BACKUP" \
  --quiescence-receipt "$PRIVATE_STATE/quiescence.json"
```

Replay is idempotent and deletes only recorded IDs. It never recomputes by participant name, session membership, payload contents, cutoff, or work-unit key. New post-request messages and queues therefore survive, including rows for the same participant or rows that reuse an old work-unit key. A clean applied tombstone passes future startup after the dedicated cache is sanitized.

## Failure behavior and Doctor

If startup reconciliation, a five-minute retention cycle, API/deriver monitoring, database verification, or cache verification fails, the supervisor terminates its public children, writes the manual-clear pause receipt, stops the public Guide, records a private paused status, and stays resident without restarting children. The optional watchdog consumes that supervisor state and can boot out only the product-owned supervisor label while reasserting the Guide pause.

Doctor checks, without mutation:

- exact dedicated manifest settings and profile bindings;
- product supervisor plist arguments (no direct API/deriver execution);
- pinned clean checkout and exact runtime DB/cache targets;
- single-workspace PostgreSQL inventory;
- fresh five-minute retention receipt;
- tombstone structure and exact-ID residue;
- private state, backup, and tombstone directories;
- Guide lifecycle discovery and exact public workspace binding.

Resumption is an explicit operator action after the root cause is fixed, any pending/resurrected tombstone is replayed, retention succeeds, and the pause receipt is manually cleared.
