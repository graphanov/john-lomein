---
name: john-lomein-learning-steward
description: Instance-local John Lomein learning steward: post-flight observation ingestion, deterministic bounded Mnemosyne index projection, and quarantined self-improvement candidates.
---

# john-lomein-learning-steward

Use this inside the `john-lomein-learning-steward` profile or when repairing the deterministic learning lane for a john-lomein instance.

## Mission

Keep John’s understanding of a target repo fresh without letting operational roles rewrite their own identity. The steward ingests structured observations from maintainer/forge/guide/overwatch runs, periodically reconciles source-of-truth state, invokes the deterministic steward script to refresh a bounded Mnemosyne index, and creates quarantined candidate skill/workflow improvements when repeated evidence justifies them.

## Boundary

- Dynamic state remains canonical in repo/GitHub/Kanban/runtime state files.
- Generated operating briefs are derived and non-canonical.
- Raw observations, candidates, reviews, promotions, and reports resolve beneath the model-hidden `$HERMES_HOME/private/learning-steward/learning/`. Only the bounded operating brief is projected to `$HERMES_HOME/state/learning/` for private roles. Traversal, absolute escapes, aliases, and symlink escapes fail closed.
- The Hermes profile uses local Honcho context with `saveMessages: false`; built-in/model-facing memory, session-search, and Mnemosyne tools remain disabled. Only the deployed deterministic `john-lomein-learning-steward.py` path may import the runtime-level Mnemosyne dependency.
- Mnemosyne stores a compact private semantic index of bounded counts and pattern fingerprints. Raw source names, repo excerpts, worker summaries, dynamic state, untrusted labels, and local paths remain in bounded artifacts rather than durable prompt context.
- Memory and journey-card writes accept only the exact configured private maintainer, forge, overwatch, and learning-steward role/profile allowlist. Guide, its configured alias, and the canonical public Guide profile are always excluded.
- Operational models emit observations only; the deterministic steward process performs index writes.
- Skill/workflow self-improvement is a candidate artifact requiring review before patching.

## Commands

```bash
python3 "$HERMES_HOME/scripts/john-lomein-learning-steward.py" observe \
  --role maintainer --event post_flight --status ok --summary "..."

python3 "$HERMES_HOME/scripts/john-lomein-learning-steward.py" reconcile --mode scheduled --json
python3 "$HERMES_HOME/scripts/john-lomein-learning-steward.py" smoke --json
```

Product-level targets:

```bash
make learning-smoke INSTANCE=/path/to/instance
make tick-learning INSTANCE=/path/to/instance
```

## Learning cadence

1. Post-flight: worker supervisor appends a structured observation after maintainer/forge/release work and invokes the steward in `post-flight` mode.
2. Scheduled: `john-lomein-<slug>-learning-steward` cron runs a deterministic reconciliation against configured source bundles and current repo/GitHub/runtime state.
3. On-demand: `make learning-smoke` proves deterministic index write/recall and generated brief output without enabling an agent provider.

## Candidate improvement rule

- One observation updates memory/briefing only.
- Repeated matching failure/blocker patterns create steward-private candidate improvement artifacts; use `review-candidates` rather than addressing their filesystem path from a model role.
- Candidate artifacts include suggested product skill/doc targets and proposal starters, but they are not applied patches.
- `backfill-worker-logs` can ingest recent real maintainer/forge worker logs as structured observations when older workers failed to emit them directly.

## Review / approval workflow

```bash
python3 "$HERMES_HOME/scripts/john-lomein-learning-steward.py" backfill-worker-logs --json
python3 "$HERMES_HOME/scripts/john-lomein-learning-steward.py" review-candidates --json
python3 "$HERMES_HOME/scripts/john-lomein-learning-steward.py" prepare-promotion \
  --candidate <id> \
  --target skills/john-lomein-forge/SKILL.md \
  --proposal-text "Reviewed, exact text to append."
python3 "$HERMES_HOME/scripts/john-lomein-learning-steward.py" apply-promotion \
  --request <id> \
  --approval "APPROVE JOHN-LOMEIN LEARNING PROMOTION <id> DIGEST <digest>: append to <target>"
```

`prepare-promotion` binds the candidate hash, proposal hash, target, and target baseline into the request digest. `apply-promotion` refuses to write product source unless the exact phrase and a fresh owner-tier `JOHN_LOMEIN_TRUST_ASSERTION` bind the request ID, request digest, target, target baseline, and approval hash. Until external gateway-owned code can mint that assertion, application remains fail-closed. The steward may prepare review artifacts, but it cannot silently patch product skills/docs.

## Verification

A healthy instance should prove:

- learning steward profile exists;
- learning script/trigger are deployed;
- scheduled learning cron exists;
- generated operating brief exists and says non-canonical;
- the deterministic script can upsert/get/recall the compact semantic index in configured private Mnemosyne banks;
- candidate improvement artifacts are quarantined, not applied.
