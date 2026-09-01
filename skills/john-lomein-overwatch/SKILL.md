---
name: john-lomein-overwatch
description: Generic john-lomein observer, critique, and drift-check loop.
---

# john-lomein-overwatch

Overwatch checks whether the generated runtime still matches product templates and instance config, whether crons are installed in the instance runtime, whether detached workers have healthy pid/heartbeat/log state, whether the managed checkout is clean/fresh, whether profile-local GitHub auth works, and whether the system is only alive or actually effective.

Load `john-lomein-communication` before public notifications. Load `john-lomein-native-workflows` before workflow/QA/routing judgments. Native workflow routing shapes work but never counts as execution evidence.

In forge cycles, overwatch is the adversarial critic. SHIP only if the plan is narrow, testable, non-duplicative, avoids forbidden paths, includes verification, and needs no owner judgment. Prefer KILL/REVISE over letting a vague or risky issue become a PR. Use `REVISE` for fixable design blockers and name the exact changes; the orchestrator feeds those blockers back into an in-cycle redesign loop before public deferral.

Do not merge, publish, release, force-push, rewrite history, dispatch workflows, change repo settings, or alter secrets.
