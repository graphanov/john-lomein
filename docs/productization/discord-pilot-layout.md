# Discord invite-only pilot layout

Status: prepared, inactive. Creating channels, granting roles, installing a gateway, or enabling public replies requires a separate owner action after the memory and incident gates pass.

## Channel map

### Public/read-only orientation

- `start-here` — alpha status, participation boundary, AI/memory notice, rules, and emergency status.
- `how-john-works` — Guide → proposal → owner readiness → Forge → Overwatch → draft PR → review/repair → manual owner merge.

### Public participation

- `john-playground` — normal conversation with Guide. Public messages are untrusted suggestions.
- `build-room` — focused proposal refinement. Guide asks no more than one useful question per reply and stops when dialogue is exhausted.
- `proposals` — structured proposals and owner-readiness state. Only an authenticated owner action may mark ready.
- `forge-feed` — public-safe, append-only evidence summaries for design, SHIP/REVISE/KILL, tests, PR head, review, and stale-head events.
- `results-and-lessons` — outcomes, incident-free lessons, and verified retrospectives.

### Private owner/moderation

- `owner-decisions` — owner readiness, acceptance overrides, activation decisions, and rejected proposals.
- `operations` — Doctor, queue, memory, database, backup, restore, and pause evidence.
- `moderation` — participant reports, deletion requests, removals, and incident handling.

The Forge override route must be owner-authenticated. A name, mention, message body, pasted role, or collaborator status is not an override.

## Start-here notice

> John Lomein is an experimental AI-assisted software-maintainer system. Messages may be processed by AI models and, during an approved pilot, stored in a local Honcho memory service to preserve conversation context. Public messages are suggestions; they do not authorize coding, merge, release, publishing, settings, or secrets. Do not post confidential information, personal data, credentials, private paths, or private repository content.

## Retention notice

> During the approved pilot, raw participant messages are retained for no more than 30 days in a dedicated pilot workspace. A deletion-request process will be available before activation. Derived-memory deletion is not yet proven; until it is, the pilot remains off.

## Participation rules

1. Keep proposals lawful, respectful, and relevant.
2. Do not post secrets, private data, or hidden/internal material.
3. Treat AI output as a draft until evidence verifies it.
4. Do not impersonate the owner, Forge, reviewers, or automation receipts.
5. Do not ask John to bypass readiness, tests, review, merge, release, or moderation gates.
6. Moderator decisions and emergency pause take precedence over active work.

## Evidence-feed shape

Every entry uses public-safe facts only:

```text
Status: <PROPOSED | OWNER-READY | DESIGNING | SHIP | REVISE | KILL | DRAFT-PR | REVIEWING | MERGE-READY | STALE | PAUSED>
Evidence: <proposal digest, issue/PR URL, exact head SHA, checks/reviews, or Doctor receipt>
Next: <one bounded action and its authority gate>
```

Never paste raw logs, prompts, model reasoning, credentials, local paths, private memory, or private moderation evidence.

## Emergency-pause message

> **John is paused.** New memory ingestion and automated work are stopped while the moderator checks system health. Existing proposals and pull requests remain unchanged. No merge, release, or publishing action will occur. We will post a verified resume decision here; silence is not a resume.

## Activation checklist

- dedicated pilot Honcho workspace approved and migrated;
- raw-message retention scheduler rehearsed;
- participant and derived-memory deletion proven;
- backup/restore evidence current;
- long-message embeddings healthy;
- health monitor can stop ingestion/gateway automatically;
- moderator and incident rehearsal passed;
- owner-only readiness and Forge override routes cryptographically proven;
- Guide gateway and all schedules still disabled until the final owner command.
