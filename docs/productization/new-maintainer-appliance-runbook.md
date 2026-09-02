# New john-lomein maintainer appliance runbook

Use this to instantiate john-lomein for a fresh repository.

## 1. Create and install a safe observer instance

The normal path is mission-first and starts with all mutation, Discord, Guide,
portfolio, and protected-broker authority disabled:

```bash
./setup.sh --init /path/to/john-lomein-<slug> \
  --repo owner/repo \
  --mission "Maintain this repository toward its documented user value." \
  --test-cmd "uv run --frozen pytest -q"
```

This creates a mode-restricted instance from the product template, validates it
through the same strict manifest and path contracts as deployment, then hands it
to the existing transactional setup. The supplied mission text begins as an
unconfirmed candidate; initialization does not claim that product- or
model-drafted text is owner-authored. Initialization refuses to overwrite an
existing path and never writes credentials or literal secrets. A failed runtime
installation leaves the validated observer manifest in place for diagnosis and
retry.
The final handoff is John's offline mission orientation: one
`Verdict / Evidence / Next` briefing that explains who John is, which mission
and repository he is bound to, what the observer can do, and what remains
deliberately gated.

For a migrated instance, requested active authority does not bypass this
mission-first boundary. If `owner_authored`, `statement`, `roadmap_sources`, or
`owner_signal_policy` is missing, the effective scheduler, mutation, Discord,
portfolio, and protected-release gates are forced off. Setup fails Doctor and
removes product-managed scheduler/gateway services. An owner must complete the
public-safe mission card before reactivation; migration never fabricates that
owner decision.

### Confirm a proposed mission without activating John

The locally implemented mission workflow uses a reviewable, digest-bound
proposal. Preparing a proposal does not change the source manifest:

```bash
uv run --frozen --offline python scripts/john-lomein-mission.py propose \
  /path/to/instance \
  --statement "Maintain the repository toward its documented user value." \
  --roadmap-source "ROADMAP.md" \
  --owner-signal-policy "Authenticated owner signals set mission priorities." \
  --output /path/to/instance/private/mission-candidate.json
```

Review the normalized statement, every roadmap source, the owner-signal policy,
the full candidate digest, and the stated dormant post-confirmation posture.
Until the owner adopts those exact canonical proposal bytes, the artifact is
unconfirmed and `mission.owner_authored` remains false.

Confirmation accepts only the exact full-digest adoption phrase:

```bash
uv run --frozen --offline python scripts/john-lomein-mission.py confirm \
  /path/to/instance \
  --proposal /path/to/instance/private/mission-candidate.json \
  --owner-confirmation \
  "I AM THE OWNER AND I ADOPT JOHN LOMEIN MISSION <full-candidate-sha256>"
```

This phrase is a deliberate owner declaration, not cryptographic authentication
and not an activation approval. Confirmation atomically writes the adopted
mission and forces desired configuration to dormant observer posture:

- `runtime.activation: owner_gated`;
- mutation, Discord, Guide, protected release, and every configured portfolio alias disabled;
- `runtime.keep_awake_on_ac: false`;
- cron and legacy Discord delivery set to `local`.

Confirmation never runs setup or deploy, invokes Hermes, starts a scheduler or
gateway, or otherwise reconciles live state. Run `make status` at any point for
the same offline, read-only projection. After confirmation, reconcile the safe
observer separately:

```bash
./setup.sh /path/to/instance
make status INSTANCE=/path/to/instance
make doctor INSTANCE=/path/to/instance
```

Only after that observer reconciliation and evidence review should the owner
make a separate decision to request active capabilities. The local workflow
passed local verification: 1,842 tests plus 2,062 subtests, Python
compilation, privacy scan, shell syntax, and diff checks. Live adoption,
reconciliation, and any later reactivation remain separate evidence.

Confirmation writes one canonical YAML representation after an exact semantic
allowlist check. It preserves configuration values outside the mission and
dormant-reset fields, but normalizes formatting and does not preserve YAML
comments or aliases. Keep explanatory policy in versioned product/runbook
documentation rather than relying on comments inside the operator manifest.
The operator-visible adoption is declarative: the desired manifest carries
`mission.owner_authored: true`, but this local workflow does not issue a signed
identity or adoption receipt. Lifecycle-lock files may also be created or
updated; no runtime or service state changes.

Use `--slug`, `--display-name`, `--default-branch`, `--runtime-home`,
`--local-checkout`, or repeated `--roadmap-source` options only when the derived
defaults are not correct.

`setup.sh` requires a mode-0600 owner-controlled manifest. It keeps a
mode-0700 instance directory as-is and safely tightens a legacy mode-0755
owner-controlled directory to 0700 through an identity-bound directory
descriptor before staging any manifest bytes.

## 2. Advanced manual creation

```bash
mkdir -p /path/to/john-lomein-<slug>/private
cp /path/to/john-lomein-product/templates/instance.yaml.example /path/to/john-lomein-<slug>/instance.yaml
chmod 700 /path/to/john-lomein-<slug> /path/to/john-lomein-<slug>/private
chmod 600 /path/to/john-lomein-<slug>/instance.yaml
```

Edit `instance.yaml`:

- `instance.slug` — filesystem-safe slug.
- `mission.statement` — proposed, public-safe repository purpose until exact digest adoption.
- `mission.roadmap_sources` — proposed public-safe repository files or issue classes the roadmap/portfolio lane may inspect.
- `mission.owner_signal_policy` — proposed provenance rules for owner/collaborator signals versus public suggestion data, including the one-question ambiguity gate.
- `mission.owner_authored` — keep false for drafts and templates; only the confirmation workflow may adopt the exact reviewed proposal.
- `mission.personality` — template compatibility text only; confirmation removes it, and the product-controlled persona remains authoritative.
- `target.repo` — `owner/repo`.
- `target.local_checkout` — managed checkout under the instance runtime/work dir.
- `runtime.hermes_home` — standalone Hermes runtime root.
- `runtime.mutation_enabled` — start false for new repos; enable only after doctor/smoke/read-only tick.
- `runtime.discord_enabled` / `runtime.guide_gateway_enabled` — enable only after a per-instance Discord bot token/channel access smoke.
- `gates.test_cmd` — the real full verification command; deployment must write it into the runtime script env as `BOT_TEST_CMD` so detached workers/release executor run more than `git diff --check`.
- `gates.forbidden_paths` — secrets, release workflows, version bumps, protected release evidence.
- `parallel_lanes` — max open total/forge PRs.
- `release.protected_broker_enabled` — keep false until the separately installed owner gateway and release broker pass their disabled-install and private-repository canaries.
- remaining `release` fields — bundle threshold, squash merge method, and informational publish workflow/tag metadata. The current protected release contract cannot publish.

Do not put literal secrets in the manifest. Put them in `private/local.env` and list only the variable names under `secrets.env_keys`.

## 3. Deploy and verify read-only health

```bash
make -C /path/to/john-lomein-product deploy INSTANCE=/path/to/john-lomein-<slug>
make -C /path/to/john-lomein-product smoke-all INSTANCE=/path/to/john-lomein-<slug>
make -C /path/to/john-lomein-product install-supervisor INSTANCE=/path/to/john-lomein-<slug>
make -C /path/to/john-lomein-product install-guide-gateway INSTANCE=/path/to/john-lomein-<slug>
make -C /path/to/john-lomein-product status INSTANCE=/path/to/john-lomein-<slug>
make -C /path/to/john-lomein-product doctor INSTANCE=/path/to/john-lomein-<slug>
```

Prefer `./setup.sh /path/to/john-lomein-<slug>` for normal installation. It validates first, stops and verifies both current and previously registered LaunchAgent labels, deploys/smokes, installs only required services, and rolls back partial service installation on fatal failure. The private service registry is keyed by the canonical instance-manifest path, so keep the instance folder stable; run the uninstaller before relocating or retiring it.

Deployment requires Hermes 0.20.3 or newer. It renders all five profiles first, then stages and installs distributions from those rendered SOULs. Unresolved templates are rejected.
The installer owns only rendered `SOUL.md` and `distribution.yaml`; profile config and user/runtime data remain in place across redeploys, then the instance-specific runtime config is reconciled after installation. Use `hermes profile list` or
`hermes profile info <profile>` against the instance Hermes home to inspect the
installed product version and distribution identity.

`status` is read-only and offline. It can prove an exact deployed manifest,
persona binding, and continuity ledger, but it does not call GitHub, Hermes, a
model, launchd, or a protected broker. An active capability therefore appears
as configured rather than live-proven until Doctor supplies the operational
evidence. A missing optional component is a gate, not an observer failure.

When upgrading a pre-registry installation, setup automatically discovers old plists and still-loaded jobs only when their runtime, John command/profile, and working directory agree. If both the slug and runtime path were changed first, restore/use the old manifest long enough to run `make uninstall-supervisor`; the product refuses to guess ownership among unrelated unregistered LaunchAgents, contradictory live/plist identities, or two runtime homes during adoption.

If `doctor` reports drift, patch the product source or instance manifest, then redeploy. Do not hand-edit generated runtime files.

## 4. Enable mutation after proof

Mission confirmation is not this step. It deliberately leaves the requested
configuration dormant. Enabling any active capability is a later, separate
owner action followed by deployment and live verification.

Before setting `runtime.mutation_enabled: true`, confirm:

- profile-local `gh auth status` works;
- managed checkout is clean and fresh;
- test command works locally;
- forbidden paths are correct;
- queue-health can inspect PRs/issues;
- no other automation lane is mutating the same repo/branches.

Then deploy again and run:

```bash
make -C /path/to/john-lomein-product deploy INSTANCE=/path/to/john-lomein-<slug>
make -C /path/to/john-lomein-product smoke-all INSTANCE=/path/to/john-lomein-<slug>
make -C /path/to/john-lomein-product install-supervisor INSTANCE=/path/to/john-lomein-<slug>
make -C /path/to/john-lomein-product install-guide-gateway INSTANCE=/path/to/john-lomein-<slug>
make -C /path/to/john-lomein-product doctor INSTANCE=/path/to/john-lomein-<slug>
make -C /path/to/john-lomein-product queue-health INSTANCE=/path/to/john-lomein-<slug>
make -C /path/to/john-lomein-product worker-status INSTANCE=/path/to/john-lomein-<slug>
make -C /path/to/john-lomein-product release-health INSTANCE=/path/to/john-lomein-<slug>
```

## 5. Operational behavior

- Watchdog cron posts state changes only.
- Maintainer cron first runs queue-health JSON and detaches a maintainer worker only when a PR/workspace needs action: draft-readiness or review-thread gate preparation, failing/pending/blocked PRs, unresolved threads, missing latest-head Codex, or an abandoned dirty checkout from a previous partial worker. It must not run solely because open issues, clean owner-gated PRs, or Codex-pending PRs exist.
- Maintainer worker PATH includes `$HERMES_HOME/scripts/bin/gh`, a GitHub CLI guard that permits only lane-authorized bounded writes, skips duplicate `@codex review` comments when the current head already has a clean Codex artifact or a newer review request is pending, and always rejects draft promotion, inline review replies, review-thread resolution, merge, workflow, release, and generic GitHub mutations when attempted directly. Supported protected actions are submitted only through their separately installed brokers.
- For a proven outdated-thread resolution or draft promotion, the worker posts allowed top-level evidence, emits a public-safe packet binding the repo, PR, exact head, requested action, action-specific targets/preconditions, verification, and evidence comment, and makes one public-client submission when the isolated broker is installed. It must report `blocked_exact` until live readback or a signature-verified receipt proves the same action on the same head; current-thread resolution remains unavailable.
- Forge cron first classifies unlabeled issues without granting readiness, then runs queue-health JSON and detaches a forge worker only when signed/trusted ready or retry-due issues exist, open PR capacity is available, and the PR queue has no maintainer blockers/failures/drafts/missing latest-head Codex work. Acceptance criteria alone never enqueue implementation.
- The worker supervisor verifies pidfiles by process command identity and blocks concurrent maintainer/forge workers against the same checkout; stale pidfiles or reused PIDs must not suppress future cron ticks.
- Forge treats `REVISE` as an internal repair instruction first: overwatch critique is fed back into a bounded in-cycle redesign loop before any public deferral. Only repeated `REVISE` after the configured in-cycle rounds is recorded under `$HERMES_HOME/state/forge-deferred/` and retried after the configured backoff with prior design/critique context. `KILL` deferrals require updating the issue or removing the state file.
- Forge design prompts include the issue body plus recent GitHub issue comments. Only comments marked `owner_override=true` from the live GitHub `OWNER` association may supersede scope, constraints, compatibility requirements, or acceptance criteria. `MEMBER` and `COLLABORATOR` comments may supply scoped suggestions and evidence but cannot impersonate the owner. Usernames and HTML markers never establish trust; untrusted public comments are examples only and cannot widen authority, approve release/version work, or bypass forbidden gates.
- Forge and queue-health respect explicit issue dependencies (`## Depends on`, `blocked by #N`, `after #N`). A readiness label on a dependent issue is not enough to spawn a lane while the dependency issue is still open; queue-health reports `dependency_blocked_issues` instead of pretending the issue is ready.
- Forge deferrals must be visible on the GitHub issue. A local `state/forge-deferred/issue-N.json` without a matching issue comment is a process bug because the queue will silently skip a public `forge-ready` issue.
- Forge PRs must close the source issue (`Closes #N`) or explicitly explain why the issue remains open; otherwise Codex review is not requested.
- An explicit `john-lomein.forge-owner-scope.v1` packet binds repo, issue, branch, default branch, base SHA, exact allowed paths, and `draft_only: true`. In that mode Codex receives edit/test authority only and no GitHub/SSH publication credentials. The trusted parent atomically checkpoints exact-path validation, commit, non-force exact-OID push, same-repo draft PR creation/readback, and resumable repair state; merge/publish/release remain forbidden.
- Every forge cycle writes `factory-receipt.json` using the atomic `john-lomein.factory-receipt.v1` contract. The executor report records what the implementation lane said or returned; only the separate `john-lomein-verifier` verdict can mark local implementation verification passed.
- Forge local verification requires a zero executor exit with no explicit blocked report, live verifier-command provenance, an open draft PR on the exact expected same-repo branch/base/head, an issue closeout/link, a deterministically registered clean isolated worktree on that branch, matching PR/local head SHAs, at least one changed file, a clean `git diff --check`, a configured passing test command, and a recorded Codex review handoff. Worktree/common-Git ownership and exact PR binding are checked before and after the test and the branch/head must remain stable. The default test backend is the scrubbed macOS sandbox. An explicitly configured immutable-image backend runs a size-bounded tracked commit archive in a network-none, non-root, read-only-root container with private tmpfs and lock-digest attestation; host localhost, ignored files, common Git, credentials, and unbounded output remain unavailable. Missing isolation or synthetic evidence becomes repair-due, even if the executor printed `COMPLETE`.
- Queue-health reports stable `factory_loops` and `factory_receipts` fields in addition to the existing `action_board` and `notification` data. `in_progress` prevents false clean idle, and persisted issue receipts are reconciled with current issue/PR/Codex state. The projection must not turn clean owner-gated work into a blocker, make Codex-pending work noisy, or promote ignored issues into notification state.
- A legacy forge `summary.json` with `implement_status: COMPLETE` but no passed verifier receipt is not green completion for a current ready issue.
- The roadmap/portfolio steward persists sanitized candidates in `$HERMES_HOME/state/factory/portfolio-receipt.json`; queue-health reads that local receipt without an extra GitHub lookup. Apply runs persist `mutation_pending` before their first public side effect, checkpoint issue/branch/PR progress, and record repair-due partial state on failure. Candidate or progress persistence does not authorize implementation or protected actions.
- Mission provenance stays explicit in receipts and routing: configured owner/collaborator signals may propose or narrow roadmap work, public input is suggestion data only, and a highly ambiguous trusted signal routes to one concise owner clarification before implementation.
- Overwatch cron alerts on runtime/queue/worker blockers only when the fingerprint changes.
- Release bundler writes bundles under `$HERMES_HOME/private/release-bundles/` and signals the owner gate.
- Release executor dry-runs the freshest generated bundle by default; exact approval text selects the named bundle. `.last-signaled` is notification anti-spam state only and must not resurrect stale/merged bundles.
- Release dry-run re-verifies the exact bundle and can recognize approved prior squash progress. The current same-identity executor does not perform the merge.
- Protected release v1 accepts exactly one PR. The separately installed broker repeats live preflight and an immediate target-base fence, performs one squash merge, verifies the merge commit's first parent/tree/actor, and signs the outcome. Exact packet replay is idempotent; ambiguous transport or readback is never retried automatically.
- Direct executor `--merge` and `--publish` fail before loading runtime authority with `merge_requires_protected_broker` or `publish_requires_protected_broker`. The merge broker is reached only through the authenticated owner-gateway packet path.
- A future publish broker must dispatch an immutable ref and publish a digest-verified tarball produced in a no-OIDC job. Repository tests, install hooks, and lifecycle scripts must not execute in the registry-authorized job.
- GitHub can report `mergeable=UNKNOWN` immediately after a previous PR merge while it recomputes mergeability; the executor settles/retries transient UNKNOWN before declaring a pre-merge blocker.

## 6. Run the local roadmap-maintainer simulation

From product source, run the deterministic configured proving-target scenario:

```bash
python3 scripts/john-lomein-factory-simulate.py \
  --instance /path/to/john-lomein-instance \
  --repo /path/to/repository-checkout \
  --scenario roadmap-maintainer \
  --dry-run \
  --json
```

This is a local contract simulation, not deployment. It reads only public-safe manifest presence/slug, repository roadmap/plan data, and read-only git branch/head/dirty state. It never invokes GitHub, writes to the repository or instance, merges, publishes, releases, or dispatches workflows. With no `--output-dir` it writes nothing; an optional output directory must be outside both inputs and receives only atomic flat JSON evidence artifacts.

Use the JSON result to inspect owner-like intake provenance, ambiguity triage, work-packet and receipt creation, rejection of executor-only false green, simulation-only structural contract exercise, factory-loop projection, protected-action blocking, and roadmap feedback. The real path remains held in triage when ambiguity exists; the synthetic branch grants no authority, stays blocked by production completion's live-provenance requirement, and remains `repair_due` in the production queue projection. This simulation does not replace the normal focused tests, full verification suite, doctor, smoke, or deployment checks.

## 7. Owner gates

When a bundle is ready, john-lomein reports its ID, digest, path, and exact
`owner_approval_text`. Post that exact text, without a bot mention or reply
wrapper, as a new regular message in a Discord channel whose ID appears in
`allowed_channels`, `free_response_channels`, and `no_thread_channels`; do not
reconstruct it from a documentation template. The Guide-only deterministic hook
passes the current channel/message locator to the separately installed signer.
The signer re-fetches the message, authenticates the configured
owner/application/bot/guild/channel/type/content/freshness, and mints a
short-lived assertion for that exact bundle. Hermes actor metadata is ignored.

The separately installed release broker may then apply one exact squash merge and return a signature-verified receipt. This path remains fail-closed until all of the following are true:

- `runtime.mutation_enabled: true`;
- `release.protected_broker_enabled: true`;
- the owner-gateway fixed-wrapper authorization is effective;
- the broker's authenticated socket and pinned public configuration are present;
- the private-repository canary has been accepted by the operator.

The merge receipt proves only the protected merge/readback result. Automatic post-merge repository testing is not yet part of that receipt; keep credential-free release verification as a separate artifact. Publishing, GitHub Release creation, workflow dispatch, branch deletion, force-push, settings, and secrets remain unavailable.

## 8. Uninstall

```bash
make -C /path/to/john-lomein-product uninstall-supervisor INSTANCE=/path/to/john-lomein-<slug>
```

Then pause/remove instance crons from the instance runtime if retiring the bot. The uninstaller also removes the manifest-owned dedicated public-Honcho supervisor, including registered or discoverable labels from an earlier slug, but never personal `ai.hermes.honcho.*` services. Do not delete runtime folders before checking active LaunchAgents, gateway processes, and logs.
