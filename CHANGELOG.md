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

- Public verification now uses portable Git, Python, and OpenSSL resolution,
  isolated runner temporary roots, and clean-repository enforcement on both CI
  platforms.
- The privacy scan rejects prohibited concrete instance names without regard
  to case, and legacy instance-specific fixtures were replaced with generic
  public-safe examples.
- `pyproject.toml` is explicitly a non-packageable `uv` environment at product
  version 0.1.0; this release does not claim a Python wheel or sdist.
- Generated runtime and Guide configuration writes are private, atomic, and fail closed on unsafe path ownership, modes, symlinks, or hard links.
- Guide and maintainer Hermes gateway LaunchAgents now both enter through the model-isolation controller; deployment, Doctor, and the service registry fail closed on missing broker assets or unwrapped current services.
- Review-only profile qualification is now an explicit host- and product-version-specific manifest decision.
- Honcho watchdog embedding-backlog signals are scoped to the selected workspace while shared queue health remains system-wide.
- Release bundles and packet validation now preserve policy and quorum digests end to end.

### Security

- Model processes do not inherit GitHub, SSH, npm, cloud, Docker, or controller credentials.
- Model processes cannot read runtime/profile/Codex auth stores or connect directly to PostgreSQL, Honcho, loopback services, or arbitrary Internet hosts.
- OpenAI Codex calls cross a controller-owned, fixed-origin Unix provider broker; access and refresh tokens remain outside the model namespace.
- Local Honcho calls cross a separate per-process Unix broker bound to one protected profile workspace; direct Honcho/PostgreSQL/Redis access remains denied, and only Guide's existing `saveMessages` policy can enable message writes.
- macOS blocks ancestor process inspection/task ports, while Linux uses a private network/PID namespace and a read-only bind of one broker session directory.
- GitHub association labels and owner-looking public text cannot grant authority.
- Owner-override digests and nonces are consumed once under a durable controller lock.
- Release bundles, review receipts, owner overrides, and deletion tombstones are controller artifacts rather than model authority.

### Migration

- Redeploy each instance from its source manifest; do not hand-edit generated runtime files.
- Redeployment scrubs historical OpenAI Codex access-token projections from every runtime/profile `auth.json`; rollback to a pre-broker build requires keeping public gateways and model workers stopped until the old projection boundary is replaced.
- Configure a dedicated public Honcho workspace, expected memory model, and watchdog before enabling the Guide gateway.
- Set `runtime.review_only_profiles_qualified: true` only after qualifying the review-only model boundary for the exact host and product version.
- Old review receipts and release bundles do not satisfy the v6 policy/quorum contract and must be regenerated.

### Rollback

- Before rollback, disable the Guide gateway, schedulers, repository mutation,
  and every optional protected broker in the instance manifest, then reconcile
  the instance so no release authority remains active.
- Version 0.1.0 is the first public alpha, so there is no earlier public state
  schema to downgrade to. Restore the exact pre-0.1.0 internal checkout,
  instance manifest, and private runtime/state backup as one matched set, or
  redeploy 0.1.0 in dormant observer posture from a fresh runtime root.
- Do not copy v6 receipts, release bundles, qualification evidence, or generated
  runtime files into an older checkout. Regenerate evidence after the selected
  source and manifest are restored.
- Run `make status INSTANCE=/path/to/instance` and then
  `make doctor INSTANCE=/path/to/instance`; keep gateways, mutation, and
  protected release disabled until both the restored source identity and
  runtime boundary are requalified.

### Known limitations

- Participant-deletion and retention application remain disabled pending crash-safe startup/replay qualification; planning and verification remain available.
- Protected release automation requires separately installed root-owned broker and owner-gateway credentials.
- The npm onboarding package is designed but not implemented or published in this release.
- Hermes Peer/Bot Chat collaboration remains advisory and disabled until a least-privilege product broker is available.
- This alpha is macOS-first. Ubuntu CI verifies portable product logic, but other production hosts are unqualified.
