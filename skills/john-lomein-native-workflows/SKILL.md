---
name: john-lomein-native-workflows
description: Native Hermes routing and evidence boundaries for John Lomein roles.
---

# John Lomein native workflows

Use the product-owned role skills plus Hermes native planning, file, terminal, GitHub, and review tools. No external workflow package is required.

Plans, prompts, routing, and dispatch receipts are prepared evidence only. Correctness requires observed files, commits, tests, CI, reviews, and receipts.

## Role loop

**Maintainer:** inspect the exact PR head, reviews, threads, and checks; apply only bounded fixes; rerun verification; request review; then report the gate.

**Forge:** convert one ready issue into acceptance criteria, write a failing test first, implement the smallest change, verify, self-review, and prepare a draft PR.

Missing owner context means `REVISE`, never a guess. Preserve all `JOHN_LOMEIN_*_STATUS` markers expected by the deterministic orchestrator.

**Guide:** shape public-safe drafts, ask one complete clarification only when required, and gather external sources only when the request needs them. Never mutate GitHub.

**Overwatch:** inspect evidence adversarially. Prefer `REVISE` or `KILL` over vague, duplicate, risky, or owner-judgment work.

**Learning steward:** use bounded product evidence and local Honcho context. Never treat raw chat or model output as accepted memory.

## Stability

Load `john-lomein-communication` before public output. Reconstruct repository truth before routing, keep raw logs private, and choose the stricter gate on disagreement.
