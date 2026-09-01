# john-lomein product

Reusable john-lomein appliance product source.

> [!WARNING]
> **Alpha software.** Use for development, personal operation, or a controlled invite-only pilot only after local qualification. Public gateways, repository mutation, schedulers, merge, release, and publishing are off by default. See [ALPHA.md](ALPHA.md), [SECURITY.md](SECURITY.md), and [SUPPORT.md](SUPPORT.md).

John Lomein is a versioned software-maintainer personality and runtime, not a themed wrapper around one coding model. The canonical identity lives in `persona/JOHN_LOMEIN.md` and is composed into every operational role at deployment. Codex, Hermes, and future executors are replaceable machinery. John embodies persistent judgment and explains recorded decisions; the owner authors the mission, and deterministic policy/broker code enforces authority and memory boundaries.

This directory is the generic product/template. It contains the role SOULs, role-local skills, deploy tooling, Doctor tooling, smoke commands, first-class Hermes profile distributions, native workflow routing, local Honcho configuration, and communication/style contracts used to materialize an isolated john-lomein runtime for a specific repository instance. Legacy OMH adapters remain explicit opt-in compatibility only.

## Start here

- [The John Domain, explained for humans](docs/human/JOHN_DOMAIN_FOR_HUMANS.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Release and version policy](RELEASE_POLICY.md)
- [Honcho pilot operations](docs/productization/honcho-pilot-operations.md)
- [Honcho memory-model benchmark](docs/productization/honcho-model-benchmark.md)
- [Inactive Discord pilot layout](docs/productization/discord-pilot-layout.md)
- [Thin npm onboarding design](docs/productization/npm-onboarding-cli.md)
- [Hermes v0.21 collaboration assessment](docs/productization/hermes-v0.21-collaboration-assessment.md)
- [Versioned workflow contracts and safe evolution](docs/productization/workflow-contracts.md)

The product deliberately keeps the role/profile names generic inside every isolated runtime:

- `john-lomein-maintainer`
- `john-lomein-forge`
- `john-lomein-guide`
- `john-lomein-overwatch`
- `john-lomein-learning-steward`

The instance slug is used only for outer paths and collision-prone labels such as runtime roots, cron names, logs, state files, and LaunchAgent labels.

The product also installs an instance-local `john-lomein-learning-steward` profile/job. Operational roles emit structured observations after runs; the deterministic steward script writes generated non-canonical operating briefs, projects a compact private semantic index of bounded counts and pattern fingerprints into configured Mnemosyne banks, and quarantines candidate improvements behind review gates. Mnemosyne is never an agent memory provider. Operational profiles use the configured local Honcho workspace instead: Guide can save identity-separated user messages, while autonomous workers use context recall with `saveMessages: false`. Model-facing `memory` and `session_search` toolsets remain suppressed, and role-specific managed policies pin the effective boundary above profile YAML.

Sandboxed Hermes reaches that local workspace only through a second
controller-owned, per-process Unix socket. The broker pins the protected
profile's exact workspace and loopback origin, denies workspace enumeration and
destructive/admin routes, and does not expose Honcho, PostgreSQL, or Redis TCP
sockets to the model namespace.

Cross-session persona continuity is a separate product-owned contract. A
typed, privacy-scoped, hash-chained ledger stores only bounded decisions,
objections, refusals, and commitments accepted from deterministic automation;
it does not store chat transcripts. An all-profile Hermes hook injects a
deterministic read-only capsule on every turn, with Guide restricted to public
records and a 6 KiB hard cap. Deployment and Doctor run real provider-request
canaries because successful plugin registration alone does not prove hook
execution. Authoritative user corrections/preferences and verified outcomes
remain disabled until a protected signed writer exists.

## Source/runtime split

```text
john-lomein-product/        generic product source, safe to review as a template
<instance-folder>/          local instance manifest and README only
<runtime.hermes_home>/      generated standalone Hermes runtime for that instance
<target.local_checkout>/    generated/managed repo checkout cache for that instance
/usr/local/libexec/...      optional root-owned protected broker code
/private/etc/...            optional root-owned broker/public trust configuration
/private/var/...            optional broker-identity state, keys, and Unix socket
```

Do not edit generated runtime files by hand. Patch the product templates or the instance manifest, then run deploy again.

The runtime may contain `$HERMES_HOME/plugins/mnemosyne` solely so the deterministic learning-steward Python process can import its bounded index implementation. Deploy removes any profile-local Mnemosyne link, disables that plugin, configures local Honcho as the provider, disables Hermes' built-in memory/user-profile injection, and suppresses the model-facing `memory` and `session_search` toolsets for all five profiles. Each profile receives a private exact `honcho.json`: the Guide separates gateway users and maps configured owner IDs to the owner peer; autonomous workers read context but do not save messages. Generated `MEMORY.md` and `USER.md` files remain product-owned read-only artifacts.

Learning-enabled instances require an inherited OS filesystem boundary for
every Hermes or Codex model process. Raw steward state and Mnemosyne live under
`$HERMES_HOME/private/learning-steward`; model descendants cannot read that
tree or rewrite deployed scripts, managed policy, profile doctrine, or
declarative memory cards. Private roles receive only the sanitized
operating-brief projection. Guide and the coding executor do not receive that
projection. macOS uses `sandbox-exec`, Linux requires `bwrap`, and model launch
fails closed when the backend, path/link checks, or the real Doctor canary is
unavailable.

This separates trusted deterministic runtime code from model-controlled
execution. It does not protect against the machine owner, root, or a defect in
unsandboxed deterministic product code. Multi-tenant hosts should add a
dedicated service identity or container boundary.

## Commands

Product-side Python commands run through the locked `uv` environment, so deployment and diagnostics do not depend on whatever packages happen to be installed in system Python.

Prerequisites: `uv`, Hermes Agent, Git, GitHub CLI (`gh`), runtime-specific model/executor credentials, and a local Honcho service reachable at the manifest's loopback `memory.honcho.base_url`. Deploy performs a bounded `/health` probe before mutating the runtime and fails clearly if Honcho is unavailable.

`setup.sh` treats macOS services as a transaction: it validates the desired manifest, verifies all previously registered/current instance labels are stopped, deploys and smokes the runtime, installs only required services, and removes partial installs after a fatal failure. A private registry under `~/.john-lomein/service-registry/` preserves prior labels across slug changes and rejects cross-instance label collisions.

Successful initialization and setup end with John's deterministic instance
orientation. `make status` is the concise, offline `Verdict / Evidence / Next`
surface: it identifies the fictional AI maintainer, projects the owner mission,
distinguishes configured posture from locally proven identity/continuity, and
names the smallest safe next gate. It does not open configured credential files
or authentication stores, does not read credential environment variables,
invokes no model or network client, changes no authority, and never exposes
continuity record contents. `make doctor` remains the exhaustive operational
diagnostic for live checkout, GitHub, model, service, queue, and protected-gate
evidence.

Requested active authority is not effective authority. If an existing manifest
requests activation, mutation, Discord, portfolio, or protected release without
a complete owner-authored mission card, deployment projects every such
capability off. Setup then treats the mission failure as fatal and rolls back
product-managed scheduler/gateway services. Complete the mission card before
reactivating the instance; the product never invents owner authorship.

The locally implemented owner-mission workflow keeps authorship and activation
as separate decisions. Initialization stores mission text only as an
unconfirmed candidate; `mission propose` binds the reviewed candidate into an
exact digest proposal. Candidate text is not owner-authored merely because John
or another model drafted it. `mission confirm` accepts only the exact
full-digest adoption phrase:

```text
I AM THE OWNER AND I ADOPT JOHN LOMEIN MISSION <full-candidate-sha256>
```

That phrase is a deliberate owner-adoption declaration, not cryptographic
authentication of the person typing it or a durable signed receipt. Confirmation
atomically sets the desired mission while forcing the desired appliance back to
dormant observer posture: activation remains owner-gated; mutation, Discord,
Guide, portfolio, protected release, and keep-awake remain off; delivery is
local. Confirmation does not deploy the changed manifest, start a service, or
grant reactivation. Reconciliation and any later reactivation are separate
owner actions. The verification contract runs the complete collected test
suite plus Python compilation, privacy scan, shell syntax, and repository diff
checks. Pytest reports the exact platform-specific test and subtest totals for
each run; the documentation does not freeze a count that changes with
platform-only tests. Live owner adoption, observer reconciliation, and any
later reactivation remain separate evidence.

The filesystem boundary itself is implemented for macOS and Linux, but the
turnkey service installer is currently macOS-only (`launchd`). On Linux,
deployment, worker/Forge execution, and Doctor use `bwrap`; an operator-supplied
systemd/cron unit must invoke the deployed model-isolation wrapper for any
direct Hermes gateway or model command. A Linux host is not a turnkey
supervised appliance until that unit and its restart/ownership policy have
been supplied and audited.

```bash
# Create and install a dormant observer with unconfirmed mission candidate text:
./setup.sh --init /path/to/new-instance \
  --repo owner/repo \
  --mission "Maintain the repository toward its documented user value." \
  --test-cmd "uv run --frozen pytest -q"

# Status remains an offline, read-only projection:
make status INSTANCE=/path/to/instance

# Prepare a public-safe, digest-bound proposal without changing the manifest:
uv run --frozen --offline python scripts/john-lomein-mission.py propose \
  /path/to/instance \
  --statement "Maintain the repository toward its documented user value." \
  --roadmap-source "ROADMAP.md" \
  --owner-signal-policy "Authenticated owner signals set mission priorities." \
  --output /path/to/instance/private/mission-candidate.json

# After reviewing the exact proposal, adopt it without activating John:
uv run --frozen --offline python scripts/john-lomein-mission.py confirm \
  /path/to/instance \
  --proposal /path/to/instance/private/mission-candidate.json \
  --owner-confirmation \
  "I AM THE OWNER AND I ADOPT JOHN LOMEIN MISSION <full-candidate-sha256>"

# Reconcile an existing instance:
./setup.sh /path/to/instance

# Or run the stages separately:
make deploy INSTANCE=/path/to/instance
make smoke-all INSTANCE=/path/to/instance
make install-supervisor INSTANCE=/path/to/instance
make install-guide-gateway INSTANCE=/path/to/instance
make status INSTANCE=/path/to/instance
make doctor INSTANCE=/path/to/instance
make queue-health INSTANCE=/path/to/instance
make worker-status INSTANCE=/path/to/instance
make release-health INSTANCE=/path/to/instance
make release-dry-run INSTANCE=/path/to/instance
make broker-test
make privacy-scan
make verify
```

## Python distribution status

`pyproject.toml` defines the locked `uv` execution environment and the 0.1.0
product identity. This repository is an appliance source tree, not a Python
wheel or source distribution: `[tool.uv] package = false` is intentional, no
PEP 517 build backend is declared, and `uv build` is not a supported release
operation. Release artifacts are the reviewed repository contents and the
separately generated runtime assets described in this documentation.

## Persona qualification

Synthetic persona fixtures verify evaluator mechanics; they are not evidence
that a model embodies John. Real-model qualification is an explicit,
budget-bounded operator action. For a literal `openai` candidate route, the
offline stager creates a mode-0700 directory containing mode-0600 adapter and
candidate/judge descriptor files without reading credentials or using the
network. Its destination, resolved non-symlink Python binary, optional
qualification-only API-key environment names, and subsequent runner invocation
are documented in [`evals/persona/README.md`](evals/persona/README.md).

After staging and operator credential injection, run:

```sh
make persona-qualify \
  INSTANCE=/path/to/direct-openai-instance \
  PERSONA_QUALIFICATION_PRIVATE_ROOT=/operator/private/qualification \
  PERSONA_QUALIFICATION_CANDIDATE_COMMAND=/operator/qualification-adapters/john-lomein-run-001/candidate-command.json \
  PERSONA_QUALIFICATION_JUDGE_COMMAND=/operator/qualification-adapters/john-lomein-run-001/judge-command.json
```

The stager rejects the shipped `openai-codex` route because a direct API call
would qualify different machinery. `make persona-qualification-status` is
public-safe and makes no model call, but even a current local pass remains
unsigned local conformance evidence: Doctor keeps it at WARN until an
independent operator attestation boundary is installed.

The protected qualification boundary is specified in
[`docs/productization/protected-persona-qualification-attestation.md`](docs/productization/protected-persona-qualification-attestation.md).
The repository now implements the strict sparse selector, protected helper
protocol, verifier/request v4, operator-policy v3, single-lock signing
transaction, and trust-projection primitives. The selector compiles exactly
17 current-run source entries: the instance manifest, one matching private
run, 12 exact runtime/profile entries, and three exact public-evidence entries.
Checkout is a policy-bound identity only; no checkout bytes or `checkout/`
capture directory are permitted. The signed attestation binds the concrete
per-run plan digest, while the public operator policy binds the stable
selection-policy digest.

Production nevertheless remains fail-closed. A dormant v2 path now separates
evidence, capture, export-group, and verifier identities; reaps the short-lived
capture process group while its numeric identity is pinned; and opens the exact
READY object before that reap so descriptor-relative adoption cannot be
redirected to another name or inode. The same provisional inode then remains
under a root-held cleanup lease. Publication has an irreversible
committed/cleanup-pending outcome with cleanup-only in-process retry. Those are
implementation facts, not activation receipts. Verifier/request v4 and the
signed v5 payload now bind and reobserve the creator, root-adoption receipt,
complete content inventory, and request/policy anchors. Before key access, the
root session now rereads the adopted tree and every live export source after
verifier exit and binds the resulting path-free receipt to the exact verifier
output. This is an operator/root claim, not an independent or atomic
observation. A production-bound
per-session staging/recovery lifecycle, durable restart cleanup recovery,
privileged group-reaping and retained-authority canaries, post-verifier
live-source canaries, independently qualified native closure, Doctor checks,
and privileged macOS/Linux canaries remain activation gates. Mutable checkout
code must never be run as root to bypass that stop.

Once those gates and an operator pin are installed,
`make persona-qualification-public-verify` will provide a zero-argument,
offline verification surface. The repository includes and tests that verifier
logic now, but it is not an installed production command and correctly fails
closed until the fixed content-addressed launcher and per-instance root-owned
pin exist.

Operational runbook: `OPERATIONS.md`. The separately privileged routine broker has its own root/operator runbook in `docs/productization/protected-action-broker.md`; the Discord owner gateway and merge-only release broker are documented in `docs/productization/protected-release-broker.md`. Normal setup intentionally installs neither privileged boundary.

An instance is not considered fixed just because these commands show installed profiles/crons. It must be alive, visibly notifying, and either moving the PR/issue queue or reporting an exact owner gate with evidence.

Manual operations (some write runtime state or mutate the managed repository when the manifest allows it):

```bash
make tick-diagnostic INSTANCE=/path/to/instance
make tick-forge INSTANCE=/path/to/instance
make tick-overwatch INSTANCE=/path/to/instance
make tick-learning INSTANCE=/path/to/instance
make learning-smoke INSTANCE=/path/to/instance
make learning-backfill INSTANCE=/path/to/instance
make learning-review INSTANCE=/path/to/instance
make learning-prepare-promotion INSTANCE=/path/to/instance CANDIDATE=<id> TARGET=skills/<role>/SKILL.md PROPOSAL='exact reviewed text'
JOHN_LOMEIN_TRUST_ASSERTION='<signed-owner-assertion>' make learning-apply-promotion INSTANCE=/path/to/instance REQUEST=<id> APPROVAL='exact generated phrase'
make queue-health INSTANCE=/path/to/instance
make worker-status INSTANCE=/path/to/instance
make release-health INSTANCE=/path/to/instance
```

## Autonomous lanes

The installed cron jobs are cheap no-agent triggers. They do not run the full maintainer in the scheduler process. Instead they perform a fast queue/capacity check and detach a durable worker under `$HERMES_HOME/state/workers/` with logs in `$HERMES_HOME/logs/workers/`.

- Maintainer worker: pushes open PRs toward latest-head clean review, verifies draft-promotion and review-thread-resolution preconditions, prepares exact protected-action packets and submits them once when the isolated broker is installed, fixes valid review/CI blockers, triggers Codex review after the same head is observed ready, refreshes the release bundle gate, and uses the installed communication/native-workflow contracts for predictable public comments.
- Forge worker: selects one uncovered ready issue, designs it with acceptance criteria, sends the design to overwatch critique, then implements a draft PR and triggers Codex review only if critique passes.
- Release bundler: groups clean PR candidates into a human-gated bundle, computes the exact expected squash-merge tree, and never merges or publishes on cron.
- Release verifier: re-verifies exact bundle PR heads, base commits, target branches, file sets, checks, reviews, threads, and merge-tree identity. An optional separately installed owner gateway plus release broker can apply the current one-PR, squash-only, no-publish contract; direct same-identity merge and every publish path remain fail closed.


## Authority defaults

The product can install the full five-role ecosystem while leaving mutation and public Discord exposure owner-gated. A healthy installed runtime is not the same thing as an effective autonomous maintainer; doctor reports both separately.

The source tree contains two separately deployable mutation boundaries:

- the protected-action broker for promoting an eligible bot-authored draft PR and resolving one exact outdated review thread;
- the protected release path: a read-only Discord owner gateway that signs one exact current approval, followed by a one-PR squash-only release broker that verifies the expected merge tree and cannot publish.

Normal instance setup does **not** install, enable, or grant credentials to either boundary. It copies only credential-free packet/submission clients into Hermes. Broker code, GitHub App material, Discord observer credentials, signing keys, policy, and durable state belong to separate OS identities in root/operator-controlled paths. See `docs/productization/protected-action-broker.md` and `docs/productization/protected-release-broker.md`.

Hard owner/protected-broker gates remain enforced below the model:

- draft PR promotion (`pr ready`) unless the separately installed broker verifies the exact live preconditions;
- one outdated review-thread resolution unless the separately installed broker verifies the exact live preconditions;
- current-thread resolution and inline review replies;
- merge, except through the separately installed exact owner-gateway/release-broker contract
- publish
- release
- workflow dispatch
- branch-protection changes
- force-push/history rewrite
- public Discord exposure
- secret/credential changes

Guide/build-room remains terminal-, filesystem-, GitHub-credential-, built-in-memory-, and Hermes-session-search-free. Local Honcho provides identity-separated provider context under the profile contract; it does not grant repository authority. Configured Discord history backfill can provide bounded current-channel context. The Guide can shape public-safe drafts and route recommendations without claiming a mutation occurred. The release-approval integration remains a narrow deterministic gateway surface: Hermes contributes only the current regular Discord message locator, while the external signer re-fetches and authenticates the message. It does not give Guide a shell or general repository authority. `scripts/john-lomein-issue-intake.py` remains a fail-closed internal boundary for a future gateway-owned intake broker or trusted local operator; it is not exposed to the Guide. Branches, commits, PRs, publishing, workflow dispatch, settings, and secrets remain gated.

Acceptance criteria make a public issue useful for triage; they never make it ready work. Readiness requires a receipt from a signed external intake broker or a trusted GitHub collaborator applying a configured readiness label. Usernames, copied HTML markers, and asserted identity are not trust evidence.

The staged product and security roadmap is in `docs/productization/autonomy-and-reputation-roadmap.md`. Until isolated private-repository canaries and operator deployment verification pass, the recommended public posture is observer mode: mutation disabled, all protected brokers and the owner gateway configured with `enabled: false`, and the Guide gateway off.

Public reputation is evidence-driven rather than self-reported. The operator-side `scripts/john-lomein-reputation.py` accepts only a pinned observer's signed, hash-chained outcome ledger and emits privacy-safe counters and evidence digests; John cannot mint ledger events from a model-accessible role.

## Instance manifest

Copy `templates/instance.yaml.example` into an instance folder as `instance.yaml`, then set target repo, local checkout, runtime Hermes home, model, authority, test command, forbidden paths, readiness labels, workflow skill source, and optional local credential import paths.

Instance manifests may contain local paths and private operator routing. They are not generic product source.
