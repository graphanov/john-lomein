# john-lomein operations runbook

This is the product-level operating contract for a deployed john-lomein instance. It exists because a runtime can look alive while the work queue is dead.

## Model/steward filesystem boundary

Every learning-enabled manifest must contain:

```yaml
learning:
  enabled: true
  model_memory_isolation: required
```

macOS requires `/usr/bin/sandbox-exec`. Linux requires `bubblewrap` with
`bwrap` on the controlled system path. Unsupported platforms and Linux hosts
without bubblewrap may be inspected, but required model lanes fail closed and
Doctor reports the appliance unhealthy.

The shipped service transaction (`setup.sh`, supervisor installer, and Guide
installer) targets macOS `launchd`. Linux has a production boundary backend,
not a turnkey product-owned systemd installer. On Linux, operator-owned units
must preserve the deployed environment and place
`$HERMES_HOME/scripts/john_lomein_model_isolation.py --profile <profile> --`
in front of every direct model-facing Hermes gateway/command. Worker and Forge
already wrap their model children. Do not report a Linux appliance as fully
supervised until those units, ownership, restart behavior, and Doctor output
have been audited.

Deployment performs a one-time migration from the former model-readable
`mnemosyne/` and `state/learning/` roots. It rejects symlinks, hardlinks,
foreign ownership, and group/other-writable source state instead of copying
ambiguous continuity. Raw observations, candidates, reports, and Mnemosyne data
move beneath `$HERMES_HOME/private/learning-steward`; only a bounded
private-role operating brief is projected into `state/learning`.

`make doctor` launches a real sandboxed canary proving that private reads,
descendant reads, and deployment-policy writes fail. Guide and coding-executor
scopes additionally prove no private-role projection is mounted. Environment
omission by itself is not evidence of isolation.

`make uninstall-supervisor` stops services but deliberately preserves the
private continuity root. Remove it only as an explicit continuity-destruction
operation after any required backup.

## What "fixed" means

Do not call an instance fixed just because profiles, crons, or LaunchAgents exist.

The one-command setup owns a fail-closed LaunchAgent lifecycle. It records labels per canonical instance manifest, binds each job to the expected runtime, John profile/command, and working directory, verifies `launchctl print` no longer sees a service before deleting its plist, and rolls back partially installed scheduler/keepawake/Guide jobs when a fatal setup or doctor check fails. Use `make uninstall-supervisor INSTANCE=...` rather than deleting plists by hand so recorded labels from an earlier slug are reconciled too.

For a one-time migration from services installed before the registry existed, keep the old runtime path long enough for setup to discover matching plists or still-loaded jobs. If both the slug and runtime path already changed, first run the uninstaller with the old manifest. As an explicit recovery step, the old labels can be adopted before uninstalling. Adoption refuses to combine labels from a different runtime with a nonempty instance registry:

```bash
uv run --frozen python scripts/john_lomein_service_registry.py adopt \
  --manifest /path/to/old/instance.yaml \
  --runtime-home /path/to/old/hermes
```

A fixed instance must satisfy all three layers:

1. **Alive** — runtime exists, profiles load, crons are installed, GitHub auth works, checkout is clean/fresh, tests/smokes run.
2. **Visible** — warnings, failed ticks, queue blockers, and state changes route to the configured bot notification channel. `deliver: local` alone is not visibility.
3. **Effective or explicitly gated** — every open PR/issue lane is either moved, verified clean, or blocked by a named owner gate with evidence.

The separately privileged draft-promotion/outdated-thread broker is not part of normal instance setup or the user LaunchAgent transaction. Neither are the Discord release-owner gateway or merge-only release broker. Install them only through the root/operator procedures in `docs/productization/protected-action-broker.md` and `docs/productization/protected-release-broker.md`. Doctor reports their root-owned public trust/config surfaces independently; an enabled manifest with a missing signer, sudo boundary, authenticated socket, or pinned receipt material is visible and remains fail-closed.

If a maintainer tick says "no safe mutation" while a PR has green CI and unresolved current review threads, the tick is defective unless it has inspected the thread and produced the next legal action. It must reproduce the finding, then either fix/push and post top-level PR evidence, or post proof that the finding is fixed/false-positive and prepare an exact `resolve_review_thread` owner/protected-broker gate packet. The current runtime must not claim it resolved the thread.

## Silent-stuck failure mode

Symptoms:

- Open PRs remain blocked for hours.
- Issues with readiness labels do not move.
- Discord bot notification channel is quiet.
- Local cron list looks active, so the runtime appears healthy.

Known root causes:

- Cron/profile HOME drift selects system Python instead of the Hermes venv, causing `ModuleNotFoundError: hermes_cli`.
- Cron jobs use `deliver: local`, so successful or failed no-agent scripts do not automatically appear in Discord.
- Notification script only echoes locally instead of sending through the guide profile.
- Maintainer prompt/skill allows a diagnostic-only report even when safe GitHub maintenance action exists.
- Maintainer prompt/skill asks for latest-head Codex evidence but only checks formal reviews, missing normal Codex issue comments that already say `Didn't find any major issues` for the current head; this can spam duplicate `@codex review` comments.
- Overwatch checks install health but not PR queue health.
- Long maintainer ticks run synchronously inside a no-agent cron and hit the scheduler cap (`Script timed out after 120s`).
- Forge reports `open_prs/open_issues/ready_issues` but never turns ready issues into designed, critiqued, draft PRs.
- Forge defers `REVISE` issues forever unless a human edits the issue, even though the design loop could retry with the previous critique as context.

## Product guards

The product now has these guards:

- `john-lomein-queue-health.py`
  - Inspects live open PRs.
  - Counts current unresolved review threads.
  - Reports blocked PRs, failing/pending checks, and blocking merge states.
  - Adds stable `factory_loops` and `factory_receipts` projections to JSON and human-readable output. These fields are additive: `action_board` ownership and `notification` priority/fingerprint semantics remain unchanged.
  - Projects sanitized roadmap candidates from the latest portfolio receipt without making extra GitHub calls.
  - Treats a legacy forge `summary.json` that says `COMPLETE` as unverified when it lacks a passed `john-lomein-verifier` receipt; it cannot clear a current blocked cycle by itself.
  - Distinguishes `deferred_ready_issues` from `retry_due_issues` so a ready issue is not hidden forever behind a stale forge deferral.
  - Distinguishes unresolved dependency edges from `satisfied_dependency_issues`: when a follow-up issue says `Depends on #N` but a recent merged PR visibly references #N, the dependency is treated as landed and the follow-up issue may proceed while the stale predecessor issue remains visible for cleanup.
  - Exits non-zero when a queue blocker requires maintainer/owner attention.
- `john-lomein-overwatch-scan.py`
  - Includes queue health in overwatch, not just runtime installation state.
- `john-lomein-overwatch-trigger.sh`
  - Posts warning/failure alerts through `john-lomein-overwatch-post.sh` only when the alert fingerprint changes, preventing Discord spam while still surfacing stuck states.
- `john-lomein-overwatch-post.sh`
  - Sends through the guide profile to `discord:<bot_notifications_channel>` when Discord is enabled.
  - Supports `JOHN_LOMEIN_NOTIFY_DRY_RUN=1` for doctor checks.
- `john-lomein-maintainer-prompt.txt` and `john-lomein-maintainer` skill
  - Explicitly require blocked-PR review-thread inspection and safe action before standing down.
  - Keep autonomous fixes, scoped pushes, top-level evidence comments, and deduplicated Codex review triggers, while routing inline review replies, thread resolution, and draft promotion into exact protected-action gate packets.
  - Treat normal Codex issue comments with `Reviewed commit: <current head>` as valid clean evidence and forbid duplicate review requests for the same head.
  - Load the communication and native-workflow contracts so public comments stay predictable and routes do not overclaim execution.
- `john-lomein-gh-guard.py` + `$HERMES_HOME/scripts/bin/gh`
  - Wrap maintainer worker `gh` calls.
  - Classify GitHub writes by effect and lane, permit only the bounded autonomous grammar, and journal successful effects with typed receipts.
  - Permit maintainer top-level PR/issue comments and configured safe-label changes, while rejecting draft promotion, inline review replies, review-thread resolution, close/reopen, merge, workflow, release, settings, secrets, and generic API mutations as protected-broker actions.
  - Skip duplicate requests when the current PR head already has a clean Codex artifact or a newer review trigger is already pending.
- `john-lomein-maintainer-trigger.sh`
  - Uses queue-health JSON before spawning the heavyweight maintainer worker.
  - No longer spawns maintainer worker just because open issues exist.
  - No longer spawns maintainer worker for clean owner-gated PRs.
  - No longer spawns maintainer worker while Codex review is already pending.
  - Does wake the maintainer for abandoned dirty checkouts so partial previous worker progress can be verified, committed/pushed, or reported as an exact recovery blocker.
- `john-lomein-forge-trigger.sh`
  - Uses queue-health JSON before spawning the heavyweight forge worker.
  - Stays silent while open PR capacity is full or the PR queue has maintainer blockers/failures/drafts/missing latest-head Codex work.
  - Sources only its deployed sibling instance environment.
  - Runs scheduled issue classification before queue health, but classification never grants a readiness label. Acceptance criteria produce a visible candidate requiring a signed route or trusted GitHub label.
- `john-lomein-worker.py`
  - Detaches long maintainer/forge/release work from no-agent cron so scheduler timeouts do not kill real work.
  - Writes pid/state/heartbeat JSON under `state/workers/` and logs under `logs/workers/`.
  - Warns via overwatch when a child stalls, but does not force-kill complex agent work.
  - Prepends `$HERMES_HOME/scripts/bin` to worker PATH so the GitHub CLI guard is active inside maintainer profile terminal commands.
  - Verifies worker pidfiles by process command identity, replaces fresh lane state instead of merging stale run residue, and prevents concurrent maintainer/forge workers on the shared checkout.
- `john-lomein-forge-orchestrator.py`
  - Selects one uncovered ready issue within configured PR capacity.
  - Treats a still-open dependency issue as satisfied when a merged PR visibly references that dependency issue, so phased chains keep moving even if a predecessor/umbrella issue was left open after the predecessor PR landed.
  - Runs design -> overwatch critique -> implementation in fresh synchronous profile calls.
  - Opens/updates a draft PR and triggers `@codex review` only after critique passes.
  - For an explicit `john-lomein.forge-owner-scope.v1` packet, gives Codex only edit/test authority over the exact listed paths and removes GitHub/SSH publication credentials from the child. A locked deterministic parent transaction validates the owned worktree, base, origin, exact dirty/staged tree, forbidden paths, commit, non-force exact-OID push, and same-repo draft-PR readback before verification. Its atomic `parent-publication.json` checkpoint is reusable for an explicit retry; it never grants merge/publish/release authority.
  - Automatically retries `REVISE` deferrals after the configured backoff, including the previous rejected design/critique tail in the next design prompt; `KILL` deferrals still require an issue update or explicit state-file removal.
  - Mirrors `REVISE`/`KILL` deferrals back to the GitHub issue with a visible marker comment, so `forge-ready` issues are not silently skipped because of hidden local JSON state.
  - Blocks Codex review for newly created forge PRs until the PR body includes `Closes #N` or an explicit explanation for keeping issue `#N` open.
  - Writes an atomic `john-lomein.factory-receipt.v1` receipt for each forge cycle and records the executor report separately from the `john-lomein-verifier` verdict.
  - Marks local implementation verification passed only after an open draft PR exists on the exact expected branch, the issue-link contract is satisfied, the deterministically registered implementation worktree is clean and on that branch, PR and local heads match, changed files exist, `git diff --check` passes, the configured test command exists and passes, and the Codex review handoff is recorded.
  - Revalidates worktree registration/common-Git-dir ownership immediately before and after tests, requires branch/head stability, and binds production completion to live verifier-command provenance.
  - Runs repository-owned tests with a scrubbed environment. The default macOS backend denies network and parent-process inspection, hides user/shared-temp state except exact verifier paths, and limits writes. An explicit Docker backend instead exports the captured commit OID as a size-bounded tracked archive, rejects replace/graft/export-attribute/index-flag/gitlink/tracked-`node_modules` ambiguity, attests the lock blob against an immutable labeled image, and runs with network-none, a read-only root, private tmpfs, non-root UID, no capabilities, no-new-privileges, bounded output, and an internal timeout. This preserves container-private loopback without exposing host localhost, ignored worktree residue, common Git metadata, or credentials. Verifier Git probes remain separately sandboxed and completion fails closed when the configured isolation is unavailable.
  - Treats executor `COMPLETE` and a zero process exit as observations, not done authority. Missing or contradictory evidence becomes a repair-due receipt and blocks the Codex handoff.
- `john-lomein-omh-implementation.py`
  - Converts Codex process-launch failures and implementation-prompt/final-artifact read failures into durable `BLOCKED` executor results with one canonical status marker and no traceback.
  - Reads final output once with strict UTF-8, preserves child stdout/stderr unchanged, rejects stale preexisting executor artifacts without overwriting them, and does not let a stdout `COMPLETE` marker override unreadable or invalid final evidence.
- `john_lomein_factory_receipts.py`
  - Owns the `john-lomein.factory-receipt.v1` schema, public-safe summaries, verifier-owned completion checks, mission-signal classification, and stable factory-loop projection.
  - Writes JSON through a same-directory temporary file plus atomic replace and removes private absolute paths and secret-shaped values from public fields.
- `john-lomein-osc-portfolio-steward.py`
  - Persists its latest sanitized roadmap candidates and current lifecycle classification to `state/factory/portfolio-receipt.json`, including mission context and the next owner/automation action; queue-health includes that classification so pending/partial portfolio work prevents clean idle.
  - Writes `mutation_pending` before the first apply-side mutation, checkpoints issue/branch/PR progress atomically, and leaves a `repair_due` receipt with safe partial identifiers when a later step fails.
  - Keeps dry-run candidates visible to queue-health without granting merge, publish, release, or workflow-dispatch authority.
- `john-lomein-release-bundler.py`
  - Groups clean PR candidates into a durable owner-gated release bundle.
  - Signals the bundle to Discord without merging, publishing, or dispatching workflows.
  - Computes and binds the exact expected squash-merge tree for the approved PR.
  - Records package publish readiness (`package.json`, the workflow contract and digest, npm latest, and whether the repo version is already published) as information only; the current bundle and broker contract always say **DO NOT publish**.
- `john-lomein-release-executor.py`
  - Dry-runs and re-verifies an exact bundle, including live PR heads, bases, file sets, CI, mergeability, unresolved review threads, and latest-head Codex/human review.
  - Produces broker-ready evidence, including the expected merge tree, but direct `--merge` and `--publish` fail closed before runtime authority is loaded.
  - Leaves one exact squash merge to the separately isolated protected release broker. Post-merge mutation, branch deletion, GitHub Release, workflow dispatch, and live package publication remain unavailable.
- `john-lomein-release-approve.py`
  - Handles only an exact generated approval from the current regular Discord turn.
  - Treats Hermes actor metadata as non-authoritative, stages the exact bundle into the owner-gateway spool, requests one independent Discord re-fetch/signature, prepares one packet, and submits it once.
  - Never reads the Discord token, owner signing key, GitHub App key, or broker receipt key.
- `doctor-instance.py`
  - Verifies queue-health deployment.
  - Runs queue-health.
  - Dry-runs notification routing.
  - Loads each deployed profile's regular, non-symlink `config.yaml` and fails if built-in memory/user-profile injection, a non-Honcho provider, a profile-local Mnemosyne plugin, or the model-facing `memory`/`session_search` toolsets are present.
  - Loads each profile's private `honcho.json` and verifies exact workspace, AI/user peers, gateway identity separation, observation policy, and role-specific message-saving policy.
  - Loads each role's exact `managed-policy/<profile>/config.yaml`, resolves
    Hermes' effective config through the exact profile and managed scope, and
    fails on missing/ambiguous output, policy drift, any profile MCP server, or
    a model platform without `no_mcp`.
  - Treats the runtime-level Mnemosyne link only as the deterministic
    learning-index dependency; it is never accepted as a profile agent
    provider or a source of per-turn synchronization.
  - Runs the OS-boundary canary and fails if the model can read raw steward
    state, delegate the read to a descendant, rewrite deployed policy, or use a
    pre-existing model-writable alias. Configuration and environment omission
    alone are not accepted as filesystem evidence.

## Required checks after any repair

```bash
make deploy INSTANCE=/path/to/instance
make smoke-all INSTANCE=/path/to/instance
make install-supervisor INSTANCE=/path/to/instance
make install-guide-gateway INSTANCE=/path/to/instance
make doctor INSTANCE=/path/to/instance
make queue-health INSTANCE=/path/to/instance
make worker-status INSTANCE=/path/to/instance
make release-health INSTANCE=/path/to/instance
make release-dry-run INSTANCE=/path/to/instance
```

Then run the live queue/overwatch checks:

```bash
eval "$(uv run --frozen --project /path/to/john-lomein-product python /path/to/john-lomein-product/scripts/read-instance-env.py /path/to/instance)"
. "$BOT_HERMES_HOME/scripts/john-lomein-instance.env"
. "$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"
HERMES_HOME="$BOT_HERMES_HOME" "$HERMES_PYTHON" "$BOT_HERMES_HOME/scripts/john-lomein-queue-health.py"
HERMES_HOME="$BOT_HERMES_HOME" bash "$BOT_HERMES_HOME/scripts/john-lomein-overwatch-trigger.sh"
```

For a local proving-target check of the roadmap-maintainer factory contract, run the deterministic simulation from product source:

```bash
python3 scripts/john-lomein-factory-simulate.py \
  --instance /path/to/instance \
  --repo /path/to/repository \
  --scenario roadmap-maintainer \
  --dry-run \
  --json
```

The simulation reads only public-safe manifest and repository facts. Git facts are collected with a credential-free environment and, on macOS, a read-only/no-network sandbox that denies repository-configured child processes; without that sandbox the dirty-state probe is conservative rather than executing `git status`. It does not call GitHub, mutate the instance or repository, merge, publish, release, or dispatch workflows. Omit `--output-dir` for a write-free run; when supplied, it must be outside both inputs and receives only atomic, flat JSON evidence artifacts. Synthetic structural checks use a simulation-only contract authority and remain blocked by the production live-provenance requirement.

If Discord routing changed, run one explicit notification smoke:

```bash
HERMES_HOME="$BOT_HERMES_HOME" "$BOT_HERMES_HOME/scripts/john-lomein-overwatch-post.sh" REPAIR_SMOKE "john-lomein notification route smoke"
```

## Reading queue-health output

Healthy, but owner-pending:

```text
john-lomein queue health: ... clean_candidates=[22,25] drafts=[26] ready_issues=[13,14,19] deferred_ready_issues=[15] retry_due_issues=[13,14] blockers=0 failures=0 details=ok
```

This means the runtime is not stuck at PR-review level. It may still be owner-gated for merge, need forge implementation capacity for ready issues, or have retryable `REVISE` candidates that the next forge tick will reconsider.

`factory_loops` is a compact projection of those same classifications: `owner_gate`, `automation_blocker`, `codex_pending`, `triage`, `repair_due`, `in_progress`, `forge`, `roadmap_candidates`, `ignored_noise`, and `clean_idle`. An in-progress receipt prevents a false clean-idle state, and an unreadable/unknown receipt is fail-visible as an automation blocker. An `owner_action` or `codex_pending` receipt whose verifier is not passed is projected as `repair_due`, so a classification/verdict mismatch cannot become owner-ready. Persisted issue receipts are reconciled against current open issue, PR branch/head, and Codex state before projection so historical receipts cannot strand the live queue. `factory_receipts` contains the reconciled public-safe forge receipt summary per event. Neither field raises or suppresses notifications independently of `action_board`.

Actionable/stuck:

```text
john-lomein queue health: ... blockers=1 details=PR#22 blocked_by_current_review_threads ...
```

This must be visible in Discord and the maintainer must not report "no safe mutation" until it has verified/fixed/resolved the blocker.

## Current product boundary

The product can:

- keep open PRs moving through CI/review/Codex loops until they are latest-head clean or exactly blocked;
- avoid duplicate Codex-review spam by recognizing current-head clean normal issue comments and guarding `gh pr comment @codex review` calls;
- recover from partial worker progress through dirty-checkout maintainer wakeups and stale-pid/cross-lane supervisor guards;
- prepare readiness evidence for bot-created draft PRs after local verification, green checks, zero review threads, and forbidden-path checks; draft promotion itself remains protected-broker gated;
- turn uncovered ready issues into designed, critiqued, draft PRs when PR capacity is available;
- maintain atomic, public-safe factory receipts whose executor report and verifier verdict remain separate;
- refuse false-green completion when a legacy summary or executor report lacks verifier-owned evidence;
- expose factory-loop state and persisted roadmap candidates without changing owner-action, Codex-pending, ignored-noise, or notification semantics;
- carry an owner-authored mission card with explicit signal provenance so authenticated mission signals can route bounded roadmap work while public suggestions remain triage data;
- retry `REVISE` forge deferrals with previous critique context instead of silently parking ready issues forever;
- trigger Codex review after draft PR creation and after a separately brokered draft promotion;
- prepare an exact one-PR release bundle, bind the expected squash-merge tree, and signal the owner gate;
- dry-run that bundle by re-verifying the live PR head/base, target branch, file set, checks, reviews, threads, and potential merge tree;
- when the separately installed owner gateway and release broker are explicitly enabled, authenticate one fresh exact regular Discord approval and apply one squash merge with signed readback receipts;
- keep worker state durable with pidfiles, logs, heartbeat, stall warnings, and no forced wall-clock kill.

The local roadmap-maintainer simulation exercises the factory contract against read-only proving-target facts. It never performs a real merge, publish, release, workflow dispatch, or other public mutation, and synthetic evidence never grants live authority.

Merge remains a protected gate, but its first narrowly implemented path now exists: one PR, exact owner-approved v5 bundle, squash only, expected merge tree pinned, no branch deletion, no publish. The runtime cannot self-sign approval or merge directly; the external Discord signer and release broker must both be installed, enabled, and independently healthy.

Publish, GitHub Release creation, workflow dispatch, branch-protection changes, force-push, and secret changes remain unavailable. Direct release-executor `--merge` and `--publish` stay deliberately blocked with `merge_requires_protected_broker` and `publish_requires_protected_broker`; package/version/workflow readiness may be reported, but it is not mutation authority.

The future publish lane must use a distinct protected broker, an immutable dispatch ref, and an immutable digest-verified package artifact built without registry authority. Repository tests and lifecycle scripts must never run in the OIDC-enabled publish job.

The current exact approval is posted, without a bot mention or reply wrapper, as
a new regular Discord message in a channel whose ID is configured in all three
Hermes sets: `allowed_channels`, `free_response_channels`, and
`no_thread_channels`:

```text
APPROVE JOHN-LOMEIN BUNDLE <bundle-id> DIGEST <bundle-digest>: squash-merge the listed PR with the protected release broker; DO NOT publish. Post-merge repository verification and any publication require separate gates.
```

Edited messages, replies, slash interactions, webhooks, bot messages, unauthorized actors/channels, stale messages, and copied phrases fail closed. Full installation, identity, Discord permission, failure-recovery, and private-canary procedures are in `docs/productization/protected-release-broker.md`.
