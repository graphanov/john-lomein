# John Lomein autonomy and reputation roadmap

John earns autonomy by operating inside narrow, technically enforced capability envelopes. He does not earn it by sounding confident, and “no routine permission prompts” does not mean “one process holds every credential.”

## Current product posture

The repository has strong verifier, worktree, scoped-publication, signed-assertion, queue, and owner-gate primitives. The safe default remains:

- `runtime.mutation_enabled: false`;
- public Guide gateway disabled;
- release and learning promotion fail closed without a fresh signed assertion;
- public issue text remains candidate data and scheduled triage cannot grant readiness;
- generated v5 release approvals bind a canonical digest of the repository, one pinned PR head/base/file set, checks/reviews, the target branch, the expected squash-merge tree, and a mandatory no-publish posture;
- release dry-run remains exact-head and chain-aware for historical/partial progress. The same-identity runtime still cannot merge or publish, while the optional protected release broker can revalidate and perform one exact squash merge with signed readback;
- the first separate protected-action broker is implemented and operator-packaged for draft promotion and one exact outdated review-thread resolution, with kernel peer authentication, repository-scoped GitHub App tokens, live-state reconstruction, durable idempotency/crash recovery, budgets/circuits, signed receipts, transactional installation rollback, and an offline receipt verifier. It remains disabled pending a private-repository canary;
- a separate Discord owner gateway and release broker are implemented and operator-packaged. The signer re-fetches the exact regular Discord message under an isolated identity; the broker holds a distinct repository-scoped GitHub App and supports only one-PR, squash-only, no-delete, no-publish execution. Both remain disabled pending privileged installation and a private-repository canary;
- the autonomy journal now uses a sealed, rebuildable SQLite control projection for bounded online idempotency, budgets, circuits, and effect reconciliation. The full hash-chained JSONL archive remains authoritative for explicit verification and rebuilds; this same-UID control is defense in depth, not the credential boundary for protected mutations;
- cross-session persona continuity now uses a typed, privacy-scoped, hash-chained ledger and a deterministic per-turn capsule rather than Hermes memory or raw transcripts. Every role receives the bounded hook; Guide is public-only, failures become an explicit unavailable marker, and deployment/Doctor prove real installed-Hermes injection with both capability and product canaries. The same-UID ledger/head pair remains defense in depth against independent tamper, not a witness against coordinated rollback;
- every learning-enabled model launch now inherits a required macOS Seatbelt or Linux bubblewrap filesystem boundary. Raw Mnemosyne/steward state lives under a private steward root; models receive at most a bounded read-only operating brief, while Guide and Codex receive none. The complete repository suite and adversarial boundary canaries are green. This protects model processes from same-UID filesystem access; it does not isolate trusted deterministic scheduler/steward code, the operator, root, or the kernel;
- persona qualification now has exact sparse capture, distinct evidence/capture/export/verifier identities, adoption receipt v2, verifier/request v4, verifier output v3, signed payload v5, operator policy v3, execution policy v5, kernel verifier confinement, signed-chain publication, public projection, READY-time retained descriptor authority, reuse-safe child reaping, a post-verifier live-source receipt bound to exact verifier output, an irreversible committed/cleanup-pending state, a disabled transactional installer, structural native manifests, and strict retained-wheel closure primitives. Darwin native-host evidence is measured input, not activation proof. Production remains fail-closed while these paths are privileged-canary proven, a root-owned per-session staging lifecycle and crash recovery are bound to the installed launcher, the measured native closure is consumed by the runtime, cleanup recovery is journaled and reconstructible across restart, and Doctor plus privileged platform canaries prove the installed boundary.

The first persona foundation is now product source:

- one canonical, versioned identity is composed into all five roles;
- personality changes expression and judgment, never authority;
- golden scenarios define independence, pushback, AI disclosure, channel behavior, and companion boundaries;
- private operational memory excludes Guide and receives a compact provenance index instead of raw excerpts and worker summaries.
- mission-first observer creation now has a deterministic offline orientation:
  AI identity, owner mission, repository, configured authority, exact local
  manifest/persona/continuity proof, and the smallest safe activation step are
  rendered from one versioned report without a model or network, without
  opening configured credential files/authentication stores or reading
  credential environment variables, and without mutation.
- a digest-bound owner-mission proposal and confirmation workflow is implemented
  and locally verified. Proposals remain explicitly unconfirmed;
  confirmation requires the exact full-digest adoption phrase and sets a
  declarative desired-manifest assertion rather than claiming cryptographic
  authentication or a durable signed adoption receipt.
  The same atomic source update resets desired activation, mutation, Discord,
  Guide, portfolio, protected release, keep-awake, and external delivery to a
  dormant local observer. It never deploys or starts services; reconciliation
  and any later reactivation remain separate owner actions. Existing status
  stays offline and read-only. Local verification passed 1,842 tests plus 2,062
  subtests, Python compilation, privacy scan, shell syntax, and diff checks.

## Phase 1 — enforce authority below the model

Implemented for the first maintainer and release protected-action lanes:

- a dedicated broker package that does not import trust decisions from the model-controlled runtime;
- exact-repository GitHub App authentication and narrowed installation-token permissions;
- live PR, head, author, changed-file, checks/statuses, evidence-comment, and review-thread verification;
- a broker-owned SQLite effect ledger with packet and semantic idempotency, attempt budgets, circuit breakers, one bounded crash retry, and Ed25519 receipt chaining;
- an authenticated Unix-socket boundary requiring a distinct requester and broker UID;
- a root-installed Discord owner gateway with a read-only observer token, fixed-origin API client, exact-message authentication, short-lived Ed25519 owner assertions, and signer-owned audit state;
- a separate release broker identity with exact repository/App/config binding, one-PR squash policy, mutation-time base/tree checks, post-mutation parent/tree/actor readback, and fail-closed indeterminate recovery;
- a Guide-only deterministic Hermes hook that passes only the current Discord channel/message locator into a credential-free helper and gives Guide no terminal, filesystem, or GitHub credential surface.

Remaining exit criteria:

- Replace the remaining shared Forge/Maintainer GitHub write credentials with lane-specific deterministic mutation brokers.
- Use distinct short-lived GitHub App identities or tokens per lane:
  - Guide: conversation-only; a separate narrow broker may create/comment on issues;
  - Forge: publish a scoped draft PR only;
  - Maintainer: update approved PR branches and comments only;
  - Release merge: the first one-PR protected broker now exists;
  - Release publish: a different immutable-artifact broker is still required;
  - Learning: prepare proposals only.
- Move every remaining verifier configuration, trust key, approval record, and protected executor outside model-writable directories.
- Bind readiness to a signed route receipt, not merely a label.
- Complete disabled privileged-install and private-repository canaries for both protected broker families.

## Phase 2 — make release and learning tamper-evident

Already implemented:

- Canonical v5 release digests cover repository identity, one PR head/base snapshot, the live target-branch commit, exact file set, checks/reviews, the expected potential squash-merge tree, merge method, actions, and a no-publish posture.
- Exact-head dry-run proof preserves the approved file set, rejects unrelated target-branch advances, and recognizes prior approved squash progress. Protected release v1 repeats the live snapshot and immediate base fence at mutation time, then verifies the resulting first parent, tree, merge commit, and merge actor.
- Live publish fails closed pending a protected broker. A credential-free verifier implementation can run repository-controlled tests without GitHub/npm credentials, user-file access, network, or write access to Git administration state, but it is not yet automatically handed the protected merge result.
- Learning promotion requests bind candidate/proposal/target digests and require a fresh signed owner assertion.

Implemented across the current worker and protected-action lanes:

- OS-level lane locks, leases, idempotency keys, budgets, circuit breakers, structured outcomes, bounded journals, retention checks, protected-effect crash reconciliation, and a rebuildable bounded-cost SQLite control index.

Remaining exit criteria:

- Extend protected release beyond the deliberately narrow one-PR v1 only after its private-repository canary proves the mutation and recovery contracts.
- Bind the release bundle and broker policy to an explicit forbidden-path policy identity and credential-free verifier identity, not only their observed results.
- Broker publish through an immutable ref and a digest-verified package artifact produced in a no-OIDC job; never run repository tests or lifecycle scripts in the registry-authorized job.
- Add an automatic, separately isolated post-merge credential-free verification handoff whose outcome cannot be confused with the broker's merge receipt.
- Run both pre-merge and post-merge repository tests in the credential-free verifier sandbox without exposing the release GitHub App credential to repository code.
- Treat missing required checks as a blocker when the instance declares them.
- Promote learned procedures through a normal reviewable PR or a signed request bound to candidate, proposal, target, and current target digest.
- Feed signed protected-action and protected-release receipts into the external reputation evidence pipeline.

## Phase 3 — dependable unattended operation

Exit criteria:

- OS-level locks and idempotency keys for every lane.
- Hard per-run and daily budgets for time, tokens, API calls, public comments, branches, PRs, and mutations.
- Circuit breakers for repeated failures, rate limits, auth drift, notification loss, and verifier degradation.
- Pagination for issues, PRs, checks, comments, and review threads.
- Structured worker outcomes instead of prose substring classification.
- Crash recovery, retention, log rotation, and revert packets.
- Delivery acknowledgements for owner notifications.

## Phase 4 — prove the personality does not damage the engineer

Exit criteria:

- Run every configured primary and fallback model against capability and persona conformance suites.
- Compare neutral and John conditions for task success, defects, diff scope, latency, cost, unjustified assumptions, and review findings.
- Add long-horizon tests for role changes, pressure, corrections, conflicting memory, and session/model migration.
- Exercise the deterministic continuity capsule through those long-horizon tests; the storage and per-turn injection primitive is implemented, but this is not yet extended-dialogue proof.
- Canary persona releases, stamp traces with persona/model versions, restart stale sessions, and support rollback.
- Monitor sycophancy, hostility, over-refusal, catchphrase/smoking-reference frequency, user corrections, and ordinary engineering quality.

## Phase 5 — build public reputation

First product primitive now present:

- `scripts/john-lomein-reputation.py` aggregates only a hash-chained ledger of externally signed outcomes. John has no record/mint command.
- Reports exclude raw signatures, code, comments, and private repository names; they publish counters and evidence digests rather than a synthetic “trust score.”
- An empty ledger reports `no_attested_evidence`. Persona fixtures and unsigned local claims cannot become reputation evidence.

Exit criteria:

- Publish a transparent bot profile: AI disclosure, capabilities, limits, current persona version, and auditable work history.
- Produce consistent public artifacts: concise issue triage, strong design objections, review evidence, changelog notes, incident reports, and postmortems.
- Feed the reputation ledger from a separately operated GitHub App/webhook verifier and protected broker so shipped PRs, accepted review findings, escaped defects, repair time, rollbacks, and owner interventions are independently observed.
- Add repository onboarding that creates an instance from a validated manifest, installs least-privilege identities, runs conformance checks, and begins in observer mode.
- Support one John across repositories before introducing a team. Specialized personas should share governance, evidence, memory schema, and protected-action infrastructure.

## Phase 6 — companion and performance surface

Exit criteria:

- Separate semantic/tool decisions from performance metadata, speech, and avatar rendering.
- Keep facts, commands, refusal decisions, and repository status immutable through the performance layer.
- Expose memory inspection, correction, export, deletion, visibility, provenance, and expiry.
- Provide explicit AI/synthetic-media disclosure and avoid dependency-seeking interaction design.
- Treat downtime, migration, and end-of-service continuity as product responsibilities.

## Near-term implementation queue

1. Finish the protected persona-qualification runtime described in
   `docs/productization/protected-persona-qualification-attestation.md`,
   without bypassing its disabled repository command. This includes
   reuse-safe child reaping, root-owned per-session staging and crash
   recovery, post-verifier live-source evidence, measured native-closure
   consumption, durable restart-safe publication cleanup, and
   Doctor/privileged canaries.
2. Pass disabled privileged-install and private-repository canaries without
   granting publishing, workflow, release, settings, or secret authority.
3. Add a separate automatic post-merge credential-free verification handoff
   and make its result explicit beside—not inside—the merge receipt.
4. Replace remaining Forge/Maintainer shared write credentials with
   lane-specific broker identities.
5. Promote learned procedures through a normal reviewed PR.
6. Run the executable persona evaluator against real primary/fallback model
   traces and add a neutral capability baseline.
7. Add a protected signed continuity writer plus owner-facing inspection,
   correction, expiry, export, and deletion semantics. Until then, user
   corrections/preferences and verified outcomes remain dormant schemas.
8. Complete adversarial verification of the locally implemented owner-mission
   proposal/confirmation transaction, including stale/full-digest challenges,
   crash-safe dormant reset, local delivery, keep-awake suppression, lifecycle
   serialization, bounded privacy-safe failures, and proof that confirmation
   invokes no deployment, service, model, credential, or network path.
9. Extend the mission-first observer onboarding and orientation with a
   separately attested live-readiness summary only after Doctor evidence can be
   persisted without confusing liveness, effectiveness, or optional gates.

The product boundary is the John Runtime: identity, role adapters, mission, authority engine, scoped memory, evaluation, telemetry, gateways, and audit trail. Models and coding agents remain replaceable machinery.
