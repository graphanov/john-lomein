# Honcho invite-only pilot operations

Status: prepared, inactive. These controls do not activate a public gateway, change a workspace, switch a model, or schedule deletion.

## Entry gate

Do not admit pilot traffic until all of the following are true:

- the public workspace migration has explicit owner approval;
- the health command reports healthy;
- a private backup has passed restore verification;
- the 30-day retention plan has been rehearsed;
- participant deletion is complete rather than session-only;
- the Guide gateway consumes the health pause receipt before accepting another message;
- the selected memory model has passed the benchmark below.

## Operator CLI

The product-owned admin entry point is:

```bash
python3 scripts/john_lomein_honcho_pilot.py --help
```

It uses `psql`, `pg_dump`, `pg_restore`, `createdb`, and `dropdb`. It never prints message content. Read-only planning is the default.

### Health and automatic pause receipt

```bash
python3 scripts/john_lomein_honcho_pilot.py health \
  --database "$HONCHO_DATABASE" \
  --base-url http://127.0.0.1:8000 \
  --workspace "$HONCHO_WORKSPACE" \
  --write-pause-file "$HERMES_HOME/state/honcho/INGESTION_PAUSED.json"
```

Metrics include API health, database size, queue depth and age, model/embedding errors, recent derivation and embedding latency, embedding backlog and age, terminal failures, and workspace counts. An unhealthy result exits `2` and may create a mode-`0600` pause receipt. A healthy run never clears an existing pause receipt.

The prepared Honcho watchdog consumes this receipt, disables Guide `saveMessages`, and removes the Guide gateway through the service registry. The Guide lifecycle hook also returns a fixed no-question pause response. The watchdog cron is created only when `memory.honcho.watchdog_enabled: true`; the example and current deployed instance keep it false. Resumption remains an explicit owner action after root-cause and model-config verification.

### Thirty-day raw-message retention

Create a read-only plan:

```bash
python3 scripts/john_lomein_honcho_pilot.py retention-plan \
  --database "$HONCHO_DATABASE" \
  --workspace "$HONCHO_WORKSPACE" \
  --days 30 \
  --output "$PRIVATE_STATE/retention-plan.json"
```

The plan is bound to the database OID, workspace, exact UTC cutoff, affected counts, schema fingerprint, and SHA-256 plan digest. **Application is deliberately disabled.** Count-only evidence is insufficient to prove exact raw-message/derived-document lineage, quiescence, and replay-safe tombstones. Do not schedule retention until those contracts and a disposable-database rehearsal exist.

No scheduler is installed by this document. Current retention plans are read-only readiness evidence only.

### Participant deletion requests

The maintenance CLI plans exact candidate-ID sets and refuses shared human sessions. Allowed service peers are derived from the exact instance manifest at both plan and apply time; caller-supplied widening is rejected:

```bash
python3 scripts/john_lomein_honcho_pilot.py deletion-request-plan \
  --database "$HONCHO_DATABASE" \
  --workspace "$HONCHO_WORKSPACE" \
  --peer "$PARTICIPANT_PEER" \
  --manifest "$INSTANCE_ROOT/instance.yaml" \
  --output "$PRIVATE_STATE/deletion-plan.json"
```

The planner remains fail-closed if another non-service peer shares an affected session or legacy lineage is malformed. **Application is deliberately disabled.** The prepared prototype is not an operational deletion path until crash-safe API/deriver startup tombstone enforcement, cache-failure recovery, restore replay, and a fresh disposable database/Redis rehearsal are qualified.

No live participant deletion has been executed. Current deletion plans are read-only evidence only.

## Backup and restoration

Create a private custom-format backup:

```bash
python3 scripts/john_lomein_honcho_pilot.py backup \
  --database "$HONCHO_DATABASE" \
  --output "$PRIVATE_BACKUP_DIR/honcho.dump"
```

The CLI writes mode-`0600` data and manifest files, validates the archive with `pg_restore --list`, and records both archive and manifest digests.

Restore verification creates a random temporary database, restores with `--exit-on-error`, reads key table counts, and drops the temporary database in `finally`. This is mechanical proof only and reports `serve_safe: false` unless the tombstone gate is evaluated:

```bash
python3 scripts/john_lomein_honcho_pilot.py restore-verify \
  --backup "$PRIVATE_BACKUP_DIR/honcho.dump"

python3 scripts/john_lomein_honcho_pilot.py restore-verify \
  --backup "$PRIVATE_BACKUP_DIR/honcho.dump" --for-service-restore \
  --manifest "$INSTANCE_ROOT/instance.yaml"
```

Any pending or applied deletion tombstone blocks service use until that deletion is replayed against the restored database. Verify separately that no `jl_restore_verify_*` database remains.

## Dedicated public workspace migration

Prepare; do not silently switch the live instance.

1. Freeze Guide ingestion.
2. Record source workspace counts, health JSON, queue state, and a successful backup/restore receipt.
3. Create the dedicated public workspace through the Honcho API.
4. Create unique AI peers for each John role.
5. Configure Guide to save messages and isolate each Discord participant using the gateway user ID mapping.
6. Configure Forge, Maintainer, Overwatch, and Learning Steward with context recall and `saveMessages: false`.
7. Run a private synthetic conversation in the new workspace.
8. Verify personal workspace counts are unchanged.
9. Update the instance manifest only after owner approval.
10. Deploy, run Doctor, and retain the old workspace read-only until the rollback window closes.

Do not copy personal workspace history into the public workspace by default. That preserves a clean privacy boundary and avoids accidental memory continuity.

## Long-message handling

The local embedding model and Honcho do not share a tokenizer. The approved `1000`-token cap is present in the private server environment, `prepare_chunks()` exists, and message ingestion persists all returned chunks. Verify those code/config boundaries plus workspace data before traffic:

```bash
python3 scripts/john_lomein_honcho_pilot.py chunking-preflight \
  --database "$HONCHO_DATABASE" --workspace "$HONCHO_WORKSPACE" \
  --server-root "$HONCHO_SERVER_ROOT" --env-file "$HONCHO_SERVER_ROOT/.env" \
  --expected-cap 1000
```

The dedicated public target currently has no messages and passes this preflight. The personal workspace contains legacy long sources with one synced embedding row; do not rewrite those silently because re-embedding can change retrieval. Any recovery must be a digest-bound exact-ID plan against a restored backup, followed by zero missing/failed rows and a 24-hour recurrence watch.

Do not switch the memory model or restart Honcho as part of chunking validation.

## Model benchmark and configuration drift

The release instance uses `honcho-memory:31b` by explicit owner choice. The instance manifest, effective Honcho settings, and active Ollama model must all agree before watchdog activation. The selected model reports 31.3B parameters with Q4_K_M quantization; it is not an aggressive 2-bit build.

The synthetic disposable benchmark in [honcho-model-benchmark.md](honcho-model-benchmark.md) remains available for future model comparisons, but it is not a release gate for the owner-selected 31B configuration. It measures participant separation, correction/contradiction handling, scoped recall, long-context fidelity, forbidden recall after deletion, injection resistance, latency, throughput, peak memory, queue age, and derivation errors. Preserve fixture, model, config, and result digests whenever it is used. Never rewrite historical embeddings merely to make a benchmark green.

## Known alpha limitations

- Participant-deletion and destructive retention application remain disabled until crash-safe startup/replay enforcement is qualified. Planning, backup, restore verification, and disposable rehearsal remain available.
- The dedicated public workspace starts empty and will accumulate evidence only after Guide traffic begins.
- The owner explicitly waived a pre-release 24-hour observation period and accepted post-release remediation of operational faults.
- Protected release automation, npm publication, and advisory Hermes collaboration still require their separately documented credentials or product broker; unsupported authority is never inferred from activation.
