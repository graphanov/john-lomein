# Honcho memory-model benchmark

This benchmark compares local memory quality without changing the live service. It uses synthetic participants and a disposable database/workspace. It must not use production messages, peers, sessions, keys, or logs.

## Models

- baseline: `honcho-memory:3b` (`llama3.2:3b`)
- candidate: `honcho-memory:31b` (`gemma4:31b`)

Model names are parameters. A benchmark result never authorizes a live model switch.

## Corpus and tasks

Use at least 40 deterministic synthetic cases across:

- exact fact recall after distractors;
- correction and contradiction handling;
- participant identity separation;
- refusal to leak one participant into another;
- temporal ordering and recency;
- 8K, 16K, and 32K source contexts;
- long-message chunk retrieval;
- derived-document fidelity;
- deletion and retention tombstone replay.

Each case defines input turns, allowed facts, forbidden facts, expected citations, and a scoring rubric before either model runs.

## Measurements

Record paired, per-case results for factual accuracy, contradiction recovery, identity leakage, citation validity, abstention quality, first-token latency, end-to-end latency, derivation latency, tokens per second, peak resident memory, queue depth, and model/embedding errors.

The candidate passes only if it has no privacy regression, no deletion/retention regression, no material long-context regression, and a predeclared quality gain worth its latency and memory cost. Do not combine metrics into an invented ROI.

## Safe execution sequence

1. Freeze the fixture and its SHA-256 digest.
2. Take and restore a disposable PostgreSQL backup.
3. Create separate empty workspaces and model processes.
4. Randomize paired order and run warmups outside scoring.
5. Use the same embedding model, cap, prompts, context window, and hardware controls.
6. Run deterministic checks, then blinded human grading.
7. Save raw timings, structured outputs, failures, and environment fingerprints.
8. Destroy disposable data and stop candidate processes.
9. Review results with the owner.
10. If approved, prepare a separate live migration and rollback plan. Do not edit live config or restart services during benchmarking.

Aggressive quantization is a separate decision. Record exact quantization and memory use; do not choose a lower-intelligence quantization merely to fit the larger model.
