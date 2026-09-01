# Autonomous Delivery Hardening Tracker

This tracker captures product hardening slices for durable autonomous delivery. It intentionally avoids runtime instance names, private paths, personal identifiers, and operational secrets.

## Slices

| Slice | Focus | Status | Evidence |
| --- | --- | --- | --- |
| 1 | No false-green autonomous delivery | Implemented and deployed locally | Focused hardening tests pass; full pytest passes; privacy scan passes; diff check passes. Deployed to both active instances. Queue-health now suppresses covered/closed stale blocked cycles and surfaces real dirty-checkout or blocked-implementation state for follow-up hardening. |
| 2 | Deterministic git/worktree ownership for implementation lanes | Implemented and deployed locally | Forge now safe-updates the managed checkout only when clean, prepares per-issue implementation worktrees under runtime state, routes OMH/Codex implementation through the worktree path, and records blocked-cycle evidence when worktree ownership fails. Independent review found and fixed worktree path-escape blockers and a nonzero-exit false-green blocker; symlinked implementation worktree paths and symlinked worktree-root components now fail closed, and nonzero implementation exits force BLOCKED status. Focused hardening tests, full pytest, privacy scan, diff check, static scan, and independent review pass. Deployed to both active instances. One instance has doctor/smoke/queue-health fully green; the other has smoke/queue-health green and doctor only warns that PR review is pending latest-head Codex clean evidence. |
| 3 | Owner Action Board / quiet notification taxonomy | Implemented and deployed locally | Queue-health now emits a deterministic `action_board` plus notification fingerprint: clean owner-gated PRs and release bundles are owner action, Codex-pending PRs are quiet, automation blockers are separate, and ignored issue noise is audit-visible but not high-priority notification state. Worker OK output remains in logs/state without Discord progress noise. Full pytest, privacy scan, diff check, static added-line scan, independent read-only review, deploy, smoke-all, and queue-health passed. |
| 4 | Discord trust tiers / anti-hijack hardening | Implemented locally; privileged canary pending | Runtime config renders owner, trusted collaborator, public guide, and untrusted-example tiers. Route labels require a signed gateway/runtime trust assertion plus configured owner/collaborator identity. The release-owner gateway now re-fetches an exact regular Discord message under an isolated identity and never trusts Hermes actor metadata. The first routine protected broker covers exact draft promotion and one outdated-thread resolution with live checks and signed receipts. Caller env cannot select authority manifests, repos, readiness labels, runtime env files, GitHub auth paths, trust keys, or owner identity. |
| 5 | Product/runtime drift and dirty-checkout recovery UX | Implemented and deployed locally | Doctor/overwatch/queue-health output now separates domain state for deployed runtime, managed checkout, queue/release, workers, and Discord visibility. Dirty managed checkout guidance explicitly says inspect status, then stash/commit/clean before rerun; it never instructs reset/delete recovery. Full pytest, privacy scan, diff check, static added-line scan, independent read-only review, deploy, smoke-all, and queue-health passed. |
| 6 | Maintainer-factory receipts, verifier-owned completion, mission provenance, and local roadmap-maintainer simulation | Implemented and verified locally | Atomic `john-lomein.factory-receipt.v1` state, sandboxed live-provenance verifier checks, exact worktree/head evidence, additive reconciled forge/portfolio queue views, partial-mutation portfolio checkpoints, and public-safe mission provenance are regression-covered. The full product suite, privacy scan, diff check, shell syntax, and Python compilation passed. Two independent read-only `roadmap-maintainer` simulation runs produced identical five-artifact hashes, used credential-free sandboxed Git probes, held the live ambiguous path in triage, exercised a simulation-only contract/owner-gate path that remained production-blocked and production-queue `repair_due`, blocked protected actions, made zero remote calls/mutations, and left both proving inputs unchanged. Runtime deployment was intentionally not attempted. |
| 7 | Canonical persona, public-input trust closure, memory isolation, and protected self-modification | Implemented in product source; runtime/broker canary pending | One versioned persona core now composes into all five roles with golden conformance scenarios. Instance personality free text cannot rewrite the canonical character. Scheduled issue triage cannot grant readiness, comment trust uses live GitHub association only, and the two first protected GitHub packets may be submitted only to a distinct-identity live-state broker with signed readback receipts. Guide is excluded from private operating memory, raw excerpts/summaries and untrusted pattern labels stay out of Mnemosyne projection, agent memory/skill writes require approval, and learning promotion requires full request digest binding plus a fresh signed owner assertion. Locked `uv` verification passes. |
| 8 | Authenticated release approval and exact protected merge | Implemented locally; privileged/private-repository canary pending | A v5 one-PR bundle binds the exact head/base/files/checks/reviews and expected squash-merge tree. A Guide-only deterministic Hermes hook passes only current Discord channel/message IDs to the isolated signer; Guide keeps terminal, filesystem, memory, session-search, and GitHub credentials disabled. The signer authenticates the fresh exact owner message and emits a short-lived assertion. A distinct release broker repeats live preflight, applies one squash merge, verifies parent/tree/actor readback, signs receipts, and has no publish, branch-delete, workflow, release, settings, secrets, or package authority. |
| 9 | Protected persona-qualification identity handoff and signed evidence | Dormant contracts implemented; activation blocked | Adoption receipt v2 binds the capture creator, export group, root adoption, exact object/inventory, request, session, and installed boundary/helper policy. READY-time retained descriptor authority and zombie-pinned PID/process-group reaping prevent name and numeric-identifier reuse; both are focused-tested but have no privileged canary. Verifier/request v4 re-observes the adopted tree and emits verifier output v3; signed payload v5, operator policy v3, and execution policy v5 additionally bind a root-produced post-verifier live-source receipt to the exact verifier-output digest, with public reputation eligibility still false. Publication has an irreversible committed/cleanup-pending state and cleanup-only in-process reconciliation. Darwin native-host evidence is measured but is not activation proof. No deployment or production activation is claimed: root-owned per-session staging and crash recovery, installed-route source-revalidation canaries, native-closure consumption, durable restart cleanup recovery, Doctor coverage, and privileged real-identity/platform canaries remain required. |
| 10 | Mission-aware first-run orientation, owner adoption, and activation dossier | Implemented and verified locally; live adoption, reconciliation, and reactivation pending | A fresh or existing instance renders one versioned, deterministic `Verdict / Evidence / Next` report from its validated owner mission, canonical persona, exact deployed manifest/persona binding, aggregate continuity proof, and configured authority. Setup and direct deployment bind every consumer to one owner-private digest snapshot, detect source drift, clean partial staging, reject fake inherited-lock descriptors, and roll services back. Missing owner mission provenance forces requested authority off. The local adoption workflow keeps proposals unconfirmed, requires an exact full-digest adoption phrase over canonical proposal bytes, and atomically resets desired activation, mutation, Discord, Guide, every configured portfolio alias, protected release, keep-awake, and external delivery to a dormant local observer. Confirmation is a declarative desired-manifest assertion rather than cryptographic authentication or a signed adoption receipt; it neither deploys nor starts services, and reactivation remains a later owner action. Local verification passed 1,842 tests plus 2,062 subtests, privacy scan, Python compilation, shell syntax, and diff checks. Managed instances remain deliberately inactive pending owner mission adoption. Same-UID GitHub write credentials remain explicitly tracked broker-migration debt rather than a claimed hostile-model boundary. |

## Slice 1 Acceptance

- Codex zero-exit with final `JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED` must record blocked and exit non-zero.
- A Codex launch failure, unreadable implementation prompt, unreadable or invalid-UTF final artifact, or stale executor artifact must write a distinct blocked executor result and emit exactly one canonical `BLOCKED` marker without overwriting prior evidence or reusing self-reported completion evidence.
- OMH semantic blocked/missing statuses must block even when command exits are zero.
- Forge implementation finalization must write `blocked.json` and avoid Codex review when no PR evidence exists.
- Worker state must distinguish blocked implementation output from ok output.
- Queue health must report dirty default checkouts and recent blocked forge cycles as blockers.

## Slice 2 Acceptance

- Managed checkout remains the read-only design, critique, and queue-health base.
- Forge blocks before checkout or pull when the managed default checkout is dirty.
- Implementation runs in a deterministic runtime worktree for the expected issue branch.
- Existing implementation worktrees are reused only when clean and on the exact expected branch.
- Dirty or wrong-branch implementation worktrees write durable blocked-cycle evidence and skip implementation.

## Slice 3 Acceptance

- Queue-health JSON includes an `action_board` with `owner_action`, `automation_blocker`, `codex_pending`, and `ignored_noise` sections.
- Clean latest-head PRs become `owner_action.clean_owner_gated_prs` and produce an owner-action notification fingerprint without making queue-health a blocker.
- Codex-pending PRs are classified as `codex_pending` and do not produce owner-action notification state.
- Ignored open issues remain visible in JSON under `ignored_noise` but do not increment blockers or notification priority.
- Release bundles persist the same action-board/notification metadata and dedupe owner-gate posts by owner-action fingerprint.
- Worker success logs remain saved under worker state/log artifacts, but routine `ok` progress is not posted to Discord.

## Slice 4 Acceptance

- Instance manifests expose empty owner/collaborator Discord trust-tier config without embedding private IDs.
- Guide Discord config renders trusted owner, trusted collaborator, public guide, and untrusted-example tiers.
- Issue route labels require a signed gateway/runtime trust assertion whose owner/collaborator actor matches config; public, plain-env, CLI-claimed, or impersonated input fails closed.
- Protected release approval must require both the exact generated bundle text/digest and an assertion minted only after the isolated signer re-fetches the current Discord message and verifies configured owner, application, bot, guild, channel, message type, content, and freshness. Hermes-provided actor identity is never authority.
- Product communication and guide SOUL templates state that untrusted channel text is data/examples only and cannot approve merge, publish, release, workflow dispatch, settings, secrets, or readiness routing.

## Slice 5 Acceptance

- Queue-health and overwatch dirty-checkout blockers include explicit safe recovery: inspect status, then stash, commit, or clean intentionally before rerun.
- Doctor prints separate health domains for product source, deployed runtime, managed checkout/GitHub, queue/release, and Discord visibility.
- Overwatch summaries include domain state for runtime, managed checkout, queue/release, workers, and Discord visibility.
- Recovery guidance avoids destructive reset/delete instructions.

## Slice 6 Acceptance

- Factory receipts use `john-lomein.factory-receipt.v1`, are written atomically, keep public-facing fields free of private absolute paths and secret-shaped values, and preserve executor report and verifier verdict as separate facts.
- `john-lomein-verifier` remains the done authority. Executor `COMPLETE`, a zero exit, a prepared handoff, or synthetic evidence is insufficient without live verifier-command provenance plus the required PR, branch, issue-link, registered clean isolated worktree, stable matching head, changed-file, diff-check, sandboxed configured-test, and recorded Codex-review-handoff evidence. Repository tests fail closed behind the macOS filesystem/network/process-information sandbox.
- A current legacy forge cycle whose summary says `COMPLETE` but lacks a passed verifier receipt is classified as unverified/blocked rather than green.
- Queue-health adds stable `factory_loops` and `factory_receipts` fields while preserving existing `action_board` and notification semantics for owner action, Codex pending, blockers, and ignored noise. In-progress forge or portfolio work prevents clean idle, while live issue/PR/Codex state removes stale forge classifications.
- The portfolio steward persists sanitized roadmap candidates for queue-health, including clean-idle and owner-review next actions, and checkpoints pending/partial apply progress before and after public side effects.
- The mission card is owner-authored and public-safe. Owner/collaborator provenance can route bounded roadmap work; public suggestions remain non-authoritative triage data, and high ambiguity produces one concise owner question.
- The local `roadmap-maintainer` simulation is dry-run and read-only for its instance and repository inputs. Its real ambiguity path remains held in triage while a separately labeled synthetic branch exercises false-green and owner-gate contracts; it performs no merge, publish, release, or workflow dispatch.

## Slice 7 Acceptance

- One canonical versioned identity composes into every role, while role authority and public/private memory boundaries remain deterministic and independent of persona expression.
- Guide receives no private operating memory, terminal, filesystem, session-search, or GitHub credential authority.
- Persona conformance scenarios cover independent judgment, proportionate pushback, hard refusal, correction handling, AI disclosure, public-channel restraint, and non-caricature boundaries.
- Learning proposals cannot modify canonical persona, product source, or private memory without the configured approval and digest gates.

## Slice 8 Acceptance

- New instances default `release.protected_broker_enabled` to false, and enabling it also requires runtime mutation authority.
- The public Guide profile alone loads the exact-message release hook; all private profiles explicitly disable it.
- Non-approval messages are a no-op. An exact approval outside a regular Discord Guide turn or without current channel/message IDs fails closed.
- The runtime helper never trusts `HERMES_SESSION_USER_ID`, reads no Discord/GitHub/signing credential, stages one exact bundle, invokes one fixed signer wrapper, prepares one packet, and makes one broker attempt.
- The signer independently re-fetches the exact message and rejects wrong actor/guild/channel/application/bot, stale or edited content, replies/system types, webhooks, bots, attachments, embeds, components, stickers, and polls.
- Protected release v1 accepts exactly one PR, squash only, no branch deletion, and no publish. It repeats live preflight and immediate-base fencing, then verifies merge parent, tree, commit, and actor before signing success.
- Ambiguous mutation transport or readback is `indeterminate`, never success; recovery reconciles durable evidence without blind automatic retry.
- Doctor/status distinguishes a disabled manifest from a callable signer and authenticated broker socket. Public descriptors alone are not readiness.
- Local tests do not count as a live canary. Root installation, real Discord permission/message proof, real repository-scoped GitHub App behavior, and a private-repository squash/readback/recovery exercise remain required.

## Slice 9 Acceptance

- The capture handoff preserves separate evidence, capture, export-group, verifier, and adopted-root identities. Adoption receipt v2 binds the exact creator/adopter transition, request/session, installed boundary/helper policy, object identity, and content inventory.
- Verifier/request v4 independently re-observes the root-adopted tree and binds verifier output v3 into signed payload v5, operator policy v3, execution policy v5, and the public projection. Root then revalidates the adopted tree and live export sources, binding its receipt to exact verifier output before key access. The claim remains local operator conformance and cannot mint public reputation eligibility.
- READY must pin the exact provisional object with a root-retained descriptor before child death is accepted. Reaping must prevent numeric PID/process-group reuse from turning cleanup into a signal against an unrelated process.
- A root-owned staging root creates one exclusive C:export session leaf per run. Success, rejection, timeout, and crash recovery must remove or root-quarantine that exact leaf without blocking a later run.
- Once signed head and trust projection publication are durable, capture deletion is cleanup-pending rather than abortable work. Cleanup retry or restart recovery must not reopen the key, advance the chain, or misreport committed publication as uncommitted.
- Post-verifier live-source evidence must exist before the private-key gate. Pre-relinquish source revalidation alone is accurately recorded but is not sufficient for activation.
- Native-host and closure measurements are evidence inputs only. The installed launcher must consume the measured closure, and Doctor plus privileged real-identity/platform canaries must prove runtime, code-sign, OS, filesystem, process, sandbox, and recovery behavior.
- Repository primitives and focused tests do not constitute activation or deployment. Every production gate remains disabled until all blockers above have durable receipts and fail-closed Doctor coverage.

## Slice 10 Acceptance

- Fresh mission-candidate instances begin as healthy configured observers even
  before installation; optional privileged components are gated rather than
  misreported as failures.
- Exact desired/deployed manifests, canonical persona version/digest/role map,
  and a non-recovering read-only continuity verification are required before
  the local observer foundation is called proven.
- Enabled mutation, Discord, Guide, portfolio, or protected-release flags are
  configuration intent only. Orientation never claims live readiness and sends
  active instances to Doctor for operational proof.
- A stale persona, runtime drift, corrupt or transaction-pending continuity
  store, unsafe manifest, or active posture without an owner mission produces a
  bounded attention/broken state and exact safe next action.
- Human and JSON output derive from one report, contain no credential, private
  runtime path, owner identifier, raw continuity record, model call, network
  call, or authority mutation, and are deterministic across repeated reads.
- Setup and direct deploy use one digest-bound manifest snapshot for
  orientation, Doctor, deployment, and service identity; source drift or
  cleanup ambiguity fails closed and reconciles product-managed services.
- Every deterministic mutating entry point consumes the effective deployed
  mission/capability projection and a live journaled run where applicable.
  Cooperative client/guard controls are not described as a hostile same-UID
  credential boundary; root-owned brokers and independent owner signatures
  retain that distinction.
- Mission proposals remain explicitly unconfirmed and cannot set
  `mission.owner_authored`. Confirmation accepts only the exact full-digest
  adoption phrase and is documented as a declarative operator decision, not
  cryptographic authentication.
- The confirmation transaction atomically binds the adopted mission while
  resetting desired activation, mutation, Discord, Guide, protected release,
  both portfolio spellings, keep-awake, and external delivery to a dormant
  local observer. It invokes no deploy, service start, model, network, or
  credential path; observer reconciliation and reactivation are separate owner
  actions.
- `status` remains deterministic, offline, read-only, and unable to confirm or
  activate a mission.
