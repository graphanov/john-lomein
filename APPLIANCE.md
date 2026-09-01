# john-lomein appliance contract

john-lomein is a reusable non-human Hermes appliance. A concrete repository is an instance of the appliance, not a new bot family.

## Invariants

1. Generic profile names are used inside each isolated runtime.
2. The instance slug isolates filesystem paths, state, crons, and external labels.
3. Product source contains only templates, scripts, SOULs, and skills.
4. Instance source contains only manifest/config and local notes.
5. Runtime state is generated and disposable.
6. GitHub, CI, issues, PRs, and the managed checkout are live truth for repo state.
7. Doctor distinguishes installed/healthy from actually moving repo work.
8. Queue health is part of runtime health: blocked PRs, failing/pending checks, current unresolved review threads, stale Codex reviews, clean release candidates, and ready issues must be classified.
9. Long work runs as detached durable workers, not inside the no-agent cron process.
10. Public guide exposure and mutation lanes stay owner-gated unless explicitly enabled.
11. Public comments and Discord replies use the product communication contract: compact, evidence-shaped, no mascotry, no hidden runtime leakage.
12. Native Hermes workflow routing is the default. Legacy OMH projection is explicit opt-in compatibility only; routes and prepared handoffs are never execution evidence.
13. Meaningful forge/factory cycles use atomic `john-lomein.factory-receipt.v1` receipts whose public projection omits private absolute paths and secret-shaped values.
14. Executor reports are observations. Only the separate `john-lomein-verifier` verdict owns local completion, and a legacy `COMPLETE` summary without that verdict is not green.
15. `factory_loops` and `factory_receipts` are additive queue-health views; they do not redefine `action_board` ownership or notification priority/fingerprints.
16. The owner-authored mission card carries public-safe purpose, roadmap sources, and signal-provenance policy. The product-controlled persona preset cannot be rewritten by instance free text. Public suggestions remain data, never authority.
17. Model-controlled runtimes may hold only the public protected-action submission client and pinned receipt-verification material. Broker code, GitHub App credentials, signing keys, policy configuration, and broker state remain under a distinct OS identity outside every runtime directory.
18. Release-owner identity comes only from an isolated signer re-fetching the exact current Discord message. Hermes actor metadata, copied approval text, public descriptors, and model claims are never owner authority.
19. Protected release v1 is one PR, squash only, no branch deletion, and no publish. A signed merge receipt proves only the exact broker result it contains; it must not be presented as proof of package publication or a separate repository-test run.
20. Every operational Hermes profile uses the configured local Honcho provider while Hermes built-in memory, session search, Mnemosyne-as-provider, and model-facing memory tools remain disabled. The Guide separates gateway users and maps configured owner IDs to the owner peer; autonomous workers use context recall with `saveMessages: false`. The runtime-level Mnemosyne link remains reserved for the deterministic learning-steward indexer.
21. Every learning-enabled model process enters an inherited OS filesystem sandbox before Hermes or Codex starts. The private steward/Mnemosyne root is unreadable, deployment policy and persona files are not writable, link-based aliases are rejected, and the public Guide plus coding executor cannot read the private-role continuity projection.
22. A mission proposal remains unconfirmed until the owner adopts its exact full digest. Adoption is a declarative provenance event, not cryptographic person authentication, and it atomically returns desired configuration to a dormant observer: owner-gated activation, no mutation or public gateway, no protected release or portfolio lane, keep-awake disabled, and local delivery. Adoption itself never deploys, starts services, or grants reactivation.
23. Local Honcho is an explicit prerequisite, not silently provisioned infrastructure. Deploy probes the configured loopback `/health` endpoint before any runtime mutation, and Doctor probes it again.

## Role model

| Role | Profile name | Authority |
|---|---|---|
| Maintainer | `john-lomein-maintainer` | review, triage, scoped branch fixes/top-level evidence, latest-head Codex loop, and protected-action/release request packets; no draft promotion, thread resolution, merge, or publish |
| Forge | `john-lomein-forge` | ready issue -> design -> critique -> draft PR; never merge/publish/release |
| Guide | `john-lomein-guide` | public/interactively safe guide; local Honcho uses gateway identity separation; built-in memory/session search, terminal, filesystem, and GitHub credentials disabled; may invoke only the deterministic exact-message release-approval bridge |
| Overwatch | `john-lomein-overwatch` | observer, critique, worker-stall sentinel; no merge/publish/release |
| Learning Steward | `john-lomein-learning-steward` | deterministic bounded semantic-index projection and gated learning proposals; local Honcho context is read-only (`saveMessages: false`); no direct product self-modification |

The deterministic roadmap/portfolio steward is a runtime lane rather than a new authority-bearing profile. It may persist sanitized roadmap candidates and prepare owner review, but cannot merge, publish, release, or dispatch workflows.

Every deployed profile config sets `memory_enabled: false`, `user_profile_enabled: false`, provider `honcho`, zero built-in memory nudge/flush intervals, and a global disable for the model-facing `memory` and `session_search` toolsets. A private exact `honcho.json` controls provider lifecycle: Guide gateway users are separated, while worker profiles use `saveMessages: false`. Per-profile MCP servers remain empty, every active model platform carries `no_mcp`, and role-specific managed policy pins the effective plugin/tool boundary. Profile-local Mnemosyne assets remain forbidden.
Product-owned `MEMORY.md` and
`USER.md` files remain deterministic declarative artifacts only; Hermes does not
inject them through its memory/user-profile subsystem or expose memory-tool
mutation. The model sandbox makes their deployed doctrine paths read-only to
terminal-capable model descendants. The deterministic learning-steward script
may import the runtime-level Mnemosyne dependency to update its bounded private
index without activating provider lifecycle, prompt recall, or per-turn sync.

Learning-enabled instances set
`learning.model_memory_isolation: required`. Raw observations, candidate
proposals, reports, and Mnemosyne data live beneath
`$HERMES_HOME/private/learning-steward`; only the bounded operating brief is
projected to `$HERMES_HOME/state/learning`. Private roles may read that
projection. Guide and coding-executor sandboxes mask it as well.

macOS uses the inherited Seatbelt boundary supplied by `sandbox-exec`. Linux
uses an unprivileged bubblewrap mount/user/PID namespace with the host
filesystem read-only, explicit runtime work mounts, and the private steward
mount replaced by an empty namespace-local filesystem. Missing `sandbox-exec`
or `bwrap`, an unsafe private-tree mode, a hardlink, or a symlink from a
model-writable root into private state fails the model launch. Doctor executes a
real read/write/descendant canary; environment omission alone is not accepted.

This boundary separates trusted deterministic runtime code from model-controlled
execution, not from the machine owner or root. The scheduler and deterministic
steward intentionally run outside it. An operator, root process, or a defect in
unsandboxed deterministic product code can still access the private root.
Supervisor uninstall preserves continuity state. A stronger multi-tenant host
should additionally use a dedicated service account/container; this appliance
does not claim protection from a malicious host administrator.

## Factory completion contract

A forge implementation is locally verified only when the verifier records all of the following:

- an open draft PR on the exact expected issue branch;
- the issue-link contract (`Closes #N` or an explicit keep-open explanation);
- an isolated, clean implementation worktree on the expected branch;
- matching local and PR head SHAs;
- at least one changed file in the implementation worktree;
- passing `git diff --check` and the configured test command;
- a recorded Codex review handoff.

The executor's marker and process exit remain in `executor_report`; they do not overwrite `verifier.verdict`. The verifier revalidates deterministic Git worktree/common-dir ownership before and after testing, requires the branch/head to remain stable, and runs repository-owned tests in a macOS sandbox with a scrubbed environment, network and parent-process inspection denied, user/temp state hidden, and writes limited to the worktree plus verifier home. The gate fails closed if that sandbox is unavailable. Production completion also requires live verifier provenance; synthetic contract evidence can never satisfy it. Missing evidence produces a repair-due/blocked receipt. Once the local verifier passes and the review handoff is recorded, the queue classification is still `codex_pending`, not owner-approved merge authority.

## Mission and roadmap provenance

Each instance may define a public-safe mission card in its manifest. Established owner/collaborator provenance can route a bounded mission-fit signal into the roadmap/portfolio lane; a public signal is always non-authoritative triage data. High ambiguity yields one concise owner question and holds implementation. The John persona and expression preset are product-controlled; mission text cannot change identity, verification, trust, memory, relationship, or protected-action gates.

The locally implemented mission workflow distinguishes an unconfirmed proposal
from an adopted mission. Proposal creation validates and binds public-safe text
without setting `owner_authored`. Confirmation requires this exact phrase for
the full proposal digest:

```text
I AM THE OWNER AND I ADOPT JOHN LOMEIN MISSION <full-candidate-sha256>
```

No short digest, case-folded spelling, generic `yes`, or partial match counts.
This is an operator declaration reflected by `mission.owner_authored` in the
desired manifest, not a signature, independent proof of owner identity, or a
durable signed adoption receipt.

Confirmation changes no runtime or service state. Its persistent writes are the
desired manifest plus lifecycle-lock bookkeeping. The desired authority request
is forced to a dormant observer, including `runtime.keep_awake_on_ac: false` and
local delivery. It does not deploy, invoke Hermes, start a scheduler or gateway,
or claim live reconciliation. The owner reconciles the observer separately and
may consider reactivation only as another explicit decision after status,
Doctor, and repository evidence. Local verification passed 1,842 tests plus
2,062 subtests, Python compilation, privacy scan,
shell syntax, and diff checks. Live adoption and reconciliation remain separate
evidence.

The portfolio steward persists sanitized candidate summaries to runtime factory state. Before an apply run's first public mutation it records `mutation_pending`, checkpoints issue/branch/PR progress after each side effect, and records `repair_due` with safe identifiers if a later step fails. Queue-health projects both candidate data and the current portfolio lifecycle classification, so pending/partial work cannot appear clean-idle, without an additional GitHub call or a notification-semantics change.

## Local proving-target simulation

The product-local simulator accepts an instance root, repository checkout, and the generic `roadmap-maintainer` scenario in `--dry-run --json` mode. It reads only safe manifest/repository/git facts, uses credential-free sandboxed Git probes on macOS, writes nothing unless an external output directory is supplied, and never invokes GitHub or performs merge, publish, release, or workflow dispatch. A real ambiguity remains held in the live-path triage state; a separately labeled simulation-contract authority exercises structural checks and owner-gate behavior. Its synthetic evidence remains `blocked` under the production completion predicate and `repair_due` in the production queue projection because it lacks live verifier provenance. The resulting artifacts are contract-exercise evidence, not live implementation, mutation, or deployment evidence.

## Protected release contract

The normal runtime may bundle and dry-run a release but cannot merge directly. When explicitly enabled, the Guide-only Hermes hook recognizes only the exact generated approval in the current regular Discord turn. It forwards the channel/message locator—not a claimed actor—to a separately installed signer. The signer re-fetches and authenticates the message, and a distinct release broker may then perform one exact squash merge after live revalidation.

The broker's signed receipt is merge evidence. Publishing, GitHub Release creation, workflow dispatch, branch deletion, settings, secrets, and package-registry authority remain unavailable. Automatic post-merge repository testing is a separate credential-free gate and must not be implied by a merge-only receipt.

## Verification bar

A new instance is not ready until all of these pass:

```bash
make deploy INSTANCE=/path/to/instance
make smoke-all INSTANCE=/path/to/instance
make install-supervisor INSTANCE=/path/to/instance
make install-guide-gateway INSTANCE=/path/to/instance
make status INSTANCE=/path/to/instance
make doctor INSTANCE=/path/to/instance
make verify
```

Status must give a deterministic, offline `Verdict / Evidence / Next`
orientation without invoking a model or network, opening configured credential
files/authentication stores, reading credential environment variables, or
performing mutation. `configured` is manifest intent; only exact local
manifest/persona/continuity evidence may be called `proven`. Optional authority
absent from a coherent observer is `gated`, not broken. Requested authority
without a complete owner-authored mission is projected off; setup must fail
Doctor and remove product-managed scheduler/gateway services rather than
preserve an active legacy posture. Status never replaces Doctor for live
effectiveness, never confirms a proposal, and remains read-only before and
after mission adoption.

Doctor must show `failures=0 warnings=0`, except explicitly owner-gated pending activation that doctor classifies as OK rather than a warning.
