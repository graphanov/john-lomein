# Changelog

All notable changes to John Lomein are documented here.

## 0.1.0 — 2026-09-01

First public alpha of the macOS-first John Lomein appliance.

### Added

- Native Hermes profiles for Guide, Forge, Maintainer, Overwatch, and Learning Steward.
- Deterministic Guide dialogue and proposal enforcement after model generation.
- Owner-authenticated readiness and acceptance-constraint overrides; public messages remain suggestion data.
- Exact-head test, Maintainer, Overwatch, Codex, and configured-human review quorum.
- Private, digest-bound review receipts and release-bundle v6 evidence.
- Credential-hidden model sandboxes with read-only release evidence and controller-owned private state.
- Dedicated Honcho public-workspace configuration, 30-day retention planning, backup/restore checks, participant-deletion planning, chunking preflight, health monitoring, and automatic Guide pause.
- Disabled-by-default advisory Hermes collaboration policy.
- Owner-gated deployment, scheduler, Discord Guide, protected-release, and publication controls.

### Changed

- Generated runtime and Guide configuration writes are private, atomic, and fail closed on unsafe path ownership, modes, symlinks, or hard links.
- Review-only profile qualification is now an explicit host- and product-version-specific manifest decision.
- Honcho watchdog embedding-backlog signals are scoped to the selected workspace while shared queue health remains system-wide.
- Release bundles and packet validation now preserve policy and quorum digests end to end.

### Security

- Model processes do not inherit GitHub, SSH, npm, cloud, Docker, or controller credentials.
- GitHub association labels and owner-looking public text cannot grant authority.
- Owner-override digests and nonces are consumed once under a durable controller lock.
- Release bundles, review receipts, owner overrides, and deletion tombstones are controller artifacts rather than model authority.

### Migration

- Redeploy each instance from its source manifest; do not hand-edit generated runtime files.
- Configure a dedicated public Honcho workspace, expected memory model, and watchdog before enabling the Guide gateway.
- Set `runtime.review_only_profiles_qualified: true` only after qualifying the review-only model boundary for the exact host and product version.
- Old review receipts and release bundles do not satisfy the v6 policy/quorum contract and must be regenerated.

### Known limitations

- Participant-deletion and retention application remain disabled pending crash-safe startup/replay qualification; planning and verification remain available.
- Protected release automation requires separately installed root-owned broker and owner-gateway credentials.
- The npm onboarding package is designed but not implemented or published in this release.
- Hermes Peer/Bot Chat collaboration remains advisory and disabled until a least-privilege product broker is available.
- This alpha is macOS-first. Ubuntu CI verifies portable product logic, but other production hosts are unqualified.
