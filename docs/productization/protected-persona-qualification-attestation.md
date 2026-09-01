# Protected persona qualification attestation

Status: design and primitive implementation in progress. Production activation
is deliberately disabled.

## Claim boundary

The strongest local claim is:

`operator_verified_local_conformance`

It means that one installed verifier reproduced one retained persona
qualification run from a sealed local snapshot under the operator's pinned
policy. It does not mean:

- public reputation;
- independent third-party evaluation;
- freedom from model, judge, or verifier defects;
- resistance to operator, root, kernel, or whole-filesystem compromise;
- detection of a rollback of the entire local trust store.

Every public projection must retain
`public_reputation_eligible: false` until independently observed repository
outcomes feed a separate reputation system.

## Runtime roles

| Role | Reads | Writes | Explicitly denied |
| --- | --- | --- | --- |
| Evidence runtime | Its qualification state | Its public/private evidence | Attestor keys and protected state |
| Capture sandbox child | One fixed 17-source plan and its exact source entries | One bounded non-root staging snapshot | Coordinator/receipt code, adoption, keys, network, unrelated files, descendants |
| Root coordinator | Installed controls, capture protocol, opaque snapshot metadata, verifier result | Sandbox supervision, root adoption, transaction request, signed/public state | Semantic evidence parsing |
| Verifier account | One sealed snapshot and one immutable verifier bundle | Private bounded scratch only | Network, live evidence, keys, process creation, persistent writes |
| Signing transaction | Canonical verified claim, public key, chain store, private key | One immutable envelope and head update | Raw evidence, model execution, caller-selected paths |
| Public verifier | Public key, policy, head, latest envelope | Nothing | Private evidence and signing material |

Root remains an administrative trust anchor. The separation prevents
model-controlled or evidence-controlled parsing from casually inheriting key
authority; it is not a defense against a malicious root operator.

The implemented capture boundary uses a stdlib-only shared protocol module and
distinct coordinator and sandbox-child entrypoints. Startup dependency tests
prove that neither executable role imports the other: the child imports only
the capture protocol, plan contract, and opaque copier from the qualification
package. The dormant v2 protocol now binds separate evidence UID, capture UID,
export GID, verifier UID, and verifier GID values. Its short-lived child emits
one `C:export` `0500/0400` provisional tree and exits; only after the whole
process group is reaped may root adopt the same inode as `root:verifier`
`0550/0440` under a retained cleanup lease. Verifier/request v4 then
descriptor-relatively reobserves the receipt, root ownership, exact inode, and
complete content inventory; the signed v5 payload binds that proof plus a
root-produced receipt for a post-verifier reread of the same adopted tree and
all live E:export sources. Production remains disabled pending a production
per-session staging/recovery lifecycle, installed-route binding, and
privileged group-reaping, retained-authority, source-revalidation, and
platform canaries.

## Required process sequence

1. A fixed, root-owned configuration selects one instance. The command accepts
   no paths, payloads, keys, or output destinations.
2. The coordinator verifies the complete installed file/directory inventory
   and the installer-qualified native dependency closure.
3. The coordinator sends the strict root-owned exact 17-source current-run
   plan over the bounded shared protocol to a dedicated key-denied capture
   child. Checkout is an identity only and no `checkout/` capture directory
   exists. The child treats copied file contents as opaque bytes; the confined
   verifier owns qualification semantics.
4. The v2 child exits and root proves that its complete process group is
   absent. Root then adopts and seals the same snapshot inode as
   `root:<dedicated-verifier-group>` with `0550` directories and `0440` files.
5. The verifier starts with fixed absolute argv, environment, cwd, and closed
   descriptors. Real, effective, and saved UID/GID are permanently changed;
   supplementary groups and Linux capabilities are empty.
6. The kernel policy allows reads only from the installed bundle, one sealed
   snapshot, and the minimum immutable OS loader surface. Network, persistent
   writes, fork, exec, debugging, and live evidence are denied.
7. Output is drained incrementally under byte caps and a monotonic deadline.
   The entire session/process group is killed and reaped on every exit,
   including apparent success.
8. Verifier/request v4 first reobserves the root-owned adopted tree against the
   normalized v2 receipt and its creator, export-group, request, boundary, and
   helper-policy anchors. It then reconstructs the concrete plan from the
   sealed manifest, extracts the run from captured terminal `status.json`,
   recompiles the only permitted plan from the digest-bound selection policy,
   requires canonical equality, and reproduces the retained qualification.
9. Before the capture child relinquishes the source surface, it revalidates
   every selected live source and the sealed inventory.
10. After the verifier process is reaped and its canonical output is bound to
    the adoption receipt, root proves the retained lease still names the exact
    adopted object, revalidates that snapshot and every live E:export source
    against its manifest, repeats the lease/name/object check, and emits one
    canonical path-free receipt. The receipt binds the adoption, object, plan,
    manifest, exact verifier-output digest, root UID, and completion time. The
    signed v5 payload embeds the receipt and digest. This sequential
    operator/root observation is not independent evaluation, an atomic
    filesystem snapshot, or protection from a malicious concurrent root.
11. Installed controls are revalidated. The signing clock must be no earlier
    than receipt completion. One exclusive chain lock is then acquired. Under
    that same lock the transaction
   reconciles the complete archive, handles an exact existing run
   idempotently, rejects conflicts and capacity exhaustion, opens the private
   key, signs, publishes the immutable envelope, and advances the head.
12. After signing, the helper verifies the sealed snapshot but deliberately
    does not revalidate mutable live sources: the signed claim is about the
    snapshot and sources accepted at the pre-key gate, and later source
    mutation must not invalidate an already-published envelope.
13. Raw captures are deleted after publication. Crash orphans are recovered
    descriptor-relatively under count, byte, and age limits.
14. A separate root-owned public projection publishes only the public key,
    operator-policy v3, current head, and current signed envelope. The helper
    verifies the sealed snapshot once more before publication completion and
    cleanup.

No step may fall back to a weaker mode. Until crash-safe recovery is
production-bound, the installed launcher must create a fresh per-session
staging directory and activation remains disabled.

## Exact sparse current-run contract

The selection policy is
`john-lomein.persona-qualification-capture-selection.v1`. It binds the
instance slug, evidence UID, verifier GID, fixed source roots, checkout/runtime
path identities, five exact role-to-profile mappings, resource limits, and an
ephemeral lifecycle. It reads one fixed canonical `status.json`
descriptor-relatively and accepts only a self-digested terminal qualified
record.

For that record's `<run-id>`, the compiler emits exactly 17 sorted source
entries:

| Count | Kind | Capture destination |
| ---: | --- | --- |
| 1 | file | `instance/instance.yaml` |
| 1 | tree | `private/<run-id>/` |
| 1 | file | `runtime/instance.yaml` |
| 10 | files | `SOUL.md` and `config.yaml` under each of the five fixed profile directories |
| 1 | file | `runtime/state/john-lomein-persona.json` |
| 2 | files | `runtime/state/persona-qualification/latest.json` and `status.json` |
| 1 | tree | `runtime/state/persona-qualification/reports/<run-id>/` |

The checkout source and checkout identity remain policy-bound identity values,
but neither is a source entry. There are no checkout bytes and no
`checkout/` capture directory. The runtime root is not a tree source either;
12 entries originate from the runtime root and three from the public-evidence
root, all with exact destinations below `runtime/` in the capture. The two run
tree entries can contain multiple files under bounded limits. Exact plan
recompilation rejects extra, missing, renamed, aliased, or caller-selected
sources and destinations.

The v3 public operator policy binds
`capture_selection_sha256`, along with the instance and verifier identities,
bundle/interpreter/version, execution-policy digest, timeout, claim strength,
and false reputation eligibility. The v5 signed attestation binds the digest
of that public policy, the digest of the concrete per-run capture plan, and the
post-verifier live-source receipt.
Thus the stable selector and the exact selected run plan are authenticated
separately.

Verifier/request v3 also binds the sealed manifest digest, selection value and
digest, plan digest, checkout/runtime identities, installed verifier and
verification-policy digests, process identities, and verification time. The
verifier accepts no path-bearing command-line arguments.

## Installed layout

The disabled macOS installer scaffold now uses one global transaction lock and
instance-scoped role/digest namespaces:

```text
/usr/local/libexec/john-lomein-persona-qualification/
└── bundles/<instance-id>/<role>/<bundle-digest>/...
/usr/local/libexec/john-lomein-persona-qualification-instances/<slug>/
├── attest
├── trust
└── doctor
/private/etc/john-lomein-persona-qualification.d/<slug>/
├── keys/
├── attestor.json
├── capture-selection.json
├── install-record.json
├── native-closure.json
└── *-bundle-manifest.json
/private/etc/john-lomein-persona-qualification-public/<slug>/
├── attestor-ed25519.pub.pem
├── public-verifier.json
├── install-status.json
├── operator-policy.json
└── trust-projection.json
/private/var/db/john-lomein-persona-qualification/<slug>/
├── state/
├── staging/
├── captures/
├── verifier-scratch/
└── evidence-export/
```

The fixed instance attest wrapper and `/usr/local/bin` trust/Doctor commands
point only to that instance-scoped immutable installation. They currently
return a canonical disabled result. The scaffold creates separate signer,
capture, verifier, and export-group identities, validates trust continuity on
upgrade, and never loads its disabled launchd plist. Mutable repository files
are never executed with privilege. Uninstall preserves keys, signed archives,
and public proof by default.

## Bundle qualification

A declared file inventory is not a native dependency closure. Activation
requires all of the following:

- every bundle file and implied directory is manifested with exact digest,
  owner, group, and mode;
- the interpreter is a real executable for the current architecture;
- every native loader dependency is resolved to either a manifested bundle
  artifact or a measured immutable operating-system artifact;
- isolated imports cover PyYAML, cryptography, the verifier, schemas, and all
  native extensions;
- the exact `python -I -S -B <entrypoint>` command passes from the installed
  tree;
- a privileged canary proves permanent UID/GID drop, empty groups and
  capabilities, no privilege regain, network denial, filesystem allowlists,
  write denial, descendant denial/reaping, and bounded output.

Native-bundle v3 now proves the declared inventory, canonical descriptor-walked
ancestry, root control during live verification, thin 64-bit Mach-O structure,
the trusted system dynamic linker, forbidden dyld-environment injection, exact
system dependency names, and conservative unambiguous run-path resolution.
The retained-wheel primitive independently proves strict ZIP metadata/RECORD
integrity and an exact installed byte union. Neither primitive observes the
declared Python version/sys.path by running the interpreter, proves an exact
OS/shared-cache identity, or establishes complete Apple code-sign semantics.
Those remaining facts and the relocated import/privilege/sandbox canary keep
native closure unqualified and production disabled.

The repository engineering builder has successfully constructed a real
capture-role specimen from local CPython, including libpython, non-site
stdlib/lib-dynload, colocated Tcl dependencies, and the split capture package.
It rewrites the source runtime's absolute libpython ID, ad-hoc signs and
verifies that changed object, rescans the sealed bundle, and imports the exact
capture closure after relocation under `-I -S -B`. The resulting report and
external v3 manifest are engineering evidence only: upstream provenance,
installed root ownership, complete code-sign semantics, OS/shared-cache
binding, and the privileged route remain unproved.

## Dedicated group invariant

The verifier group is confidential read authority over raw captures. The
installer must inspect both primary-group IDs and explicit memberships and
prove:

- the verifier account is non-login and non-root;
- the evidence account and operator's ordinary account are not members;
- no unrelated account has that group as primary or supplementary group;
- capture paths are not world-readable;
- the verifier cannot read the attestor private key.

Numeric equality between a UID and an unrelated GID is not itself a collision.

## Capture lifecycle

Raw captures may contain prompts, responses, judge rationales, and private
diagnostics. The default is ephemeral:

- one capture per transaction;
- no checkout, `.git`, learning state, authentication state, logs, worktrees,
  or unrelated runtime files;
- count and aggregate-byte admission checks before creation;
- deletion after successful publication;
- deletion after every handled failure;
- descriptor-safe recovery of incomplete captures after a crash;
- a short maximum orphan age;
- no public projection of source paths or raw evidence.

Encrypted retention is a future opt-in policy, not the default.

## Chain and rollback semantics

The signed archive is contiguous from sequence one and binds each previous
envelope digest. Replaying an older head is rejected while that archive remains
intact. A rollback of the head and the entire archive together is outside the
local proof.

Before a public reputation claim is possible, checkpoints must be anchored to
an independently operated transparency log, hardware-backed monotonic state,
or an external repository outcome observer.

## Activation gates

Production remains stopped until all gates are green:

- [ ] privileged installed-route proof of descriptor-relative root adoption
  plus verifier/signed-policy binding of its receipt;
- [x] kernel-confined verifier launcher primitive;
- [x] single-lock sign/publish transaction;
- [ ] dedicated account/group installer and membership audit;
- [ ] real interpreter/native dependency closure;
- [x] bounded legacy ephemeral-capture recovery primitive;
- [ ] installed production v3 per-session staging, quarantine, and crash
  recovery;
- [ ] measured restart-surviving root lifecycle supervisor with provider-backed
  scope start/clearance evidence;
- [ ] supervisor-owned atomic clearance-capability mint/consume boundary;
  in-process Python slots and test seams are not production authority;
- [x] public trust projection and offline-verifier primitives;
- [ ] installed fixed-path public verifier and operator pin;
- [ ] Doctor checks effective installed state;
- [ ] privileged macOS canary;
- [ ] privileged Linux canary;
- [ ] route-faithful real-model qualification;
- [ ] full adversarial and repository verification.

Implemented, but not sufficient for activation:

- [x] strict root-owned, standard-library-only opaque capture-plan contract;
- [x] strict root-owned sparse selector and exact 17-source current-run
  compiler;
- [x] descriptor-relative opaque copy/seal/verify/live-revalidate/cleanup engine;
- [x] dormant v2 E/C/export/V identity handoff, process-group death proof,
  same-inode root adoption, and nonserializable adopted-capture lease;
- [x] disabled transactional account/group, role-bundle, fixed-command, public
  status, continuity, and uninstall scaffold;
- [x] dormant native-bundle v3 structural verifier with trusted-dyld,
  canonical-ancestry, root-control, and conservative run-path policies;
- [x] bounded Darwin host-evidence primitive with measured dyld file/slices and
  shared-cache inventory, explicitly not yet consumed for activation;
- [x] descriptor-bound retained-wheel ZIP/METADATA/WHEEL/RECORD and exact
  installed-byte closure primitive;
- [x] real relocated capture-role CPython engineering specimen and isolated
  import canary, explicitly not consumed by the installer;
- [x] fixed disabled qualification Doctor output plus ordinary product-Doctor
  discovery and consistency checks;
- [x] bounded key-denied helper protocols and protected-launcher primitives,
  held disabled by staging/recovery, post-verifier evidence, and privileged
  canaries;
- [x] verifier/request v4 with adoption-receipt/tree reobservation, independent
  sparse-plan reconstruction, and checkout identity-only reproduction;
- [x] public operator-policy v3 binding capture/adoption identities and the
  sparse-selection digest;
- [x] single-lock, key-late, idempotent sign/publish transaction;
- [x] coordinator equivalent-recapture recovery before public commit;
- [x] post-verifier adopted-tree/live-source revalidation receipt bound to the
  exact canonical verifier-output digest before private-key access;
- [x] irreversible `committed_cleanup_pending` result and cleanup-only
  in-process reconciliation after public commit;
- [x] strict path-free lifecycle activation/start/clearance/bundle receipt
  contract with provider/basis checks and an in-process one-shot,
  nonserializable linearity aid; that Python object is not an authority
  boundary, and authentic production minting remains disabled pending an
  isolated root supervisor;
- [x] dormant outer transaction journal v5 binding full lifecycle activation,
  start, clearance-intent, and scope-empty bundles; clean/abnormal exit status
  requires one supervisor epoch, reboot and unobserved-after-restart are
  cleanup-only, and adoption requires the exact measured final-parent identity
  and bounded capture policy; v5 additionally reserves one lifecycle operation
  against an exact live head, serializes every same-process mutation alias, and
  binds supervisor request/response, ledger-head, event, and local-evidence
  digests into the exact durable successor;
- [x] strict path-free dual-parent adoption-reconciliation receipt contract
  binding the outer adoption intent, lifecycle clearance, staging terminal,
  tombstone, namespace identities, final object identity, and one lock epoch;
  the descriptor-safe root producer remains an explicit activation blocker;
- [x] dormant capture-staging journal v3 with caller-selected transaction
  identity, canonical exposure/terminal receipts, durable tombstone ACK
  readback, absence archive, retained quarantine, and restart grammar;
- [ ] durable cleanup journal plus descriptor-safe cleanup-authority
  reconstruction after coordinator restart;
- [ ] one-shot nonserializable outer-ACK clearance capability proving the
  exact `staging_tombstone_acked` record is durable before any quarantined
  staging disposal; a caller-supplied record digest is not authority;
- [x] strict path-free recovered-adoption evidence v1 contract, separately
  typed from the historical normal-adoption v2 receipt and bound to a full
  reconciliation sidecar plus validated journal-v5 history capability;
- [x] dormant journal-v5 production-authority mint owned by the exact locked
  live session, with zero caller inputs, full transition validation, and
  recovered-result-only evidence derivation; production activation remains
  disabled;
- [x] strict pure normal/recovered adoption-result and compact provenance
  tagged unions, with exclusive kind/schema/status/digest coupling and no
  synthesized normal-only facts on the recovered branch;
- [x] dormant coordinator-only recovered-object lease acquired from an exact
  journal session plus retained final-parent descriptor: it performs the
  journal's zero-input mint, opens the evidence-derived leaf with
  descriptor-relative no-follow/close-on-exec/nonblocking semantics, retains
  the exact parent/object and journal head, revalidates both before and after
  verification, and never gains deletion authority;
- [x] side-by-side verifier request v5 and output-evidence v4 library contract:
  it consumes the full normal/recovered result, binds every duplicated claim,
  verifies the current adopted tree, and emits only common evidence plus
  compact provenance. The installed executable deliberately remains on
  request v4/output v3 until the coordinator and attestation chain migrate;
- [x] source-revalidation receipt v2 library contract binding either compact
  adoption provenance kind to the exact verifier-output digest while retaining
  historical receipt v1 verification;
- [ ] installed journal-mint runtime wiring and downstream tagged-union
  consumption by executable dispatch, orchestrator, attestor, journal
  continuation, and public verifier; the descriptor lease, verifier-v5 API,
  and source-revalidation-v2 contract are dormant library pieces, and the
  in-process history capability remains only a nominal guard that cannot
  substitute for the isolated root journal boundary;
- [x] strict, path-free root-supervisor wire protocol plus an inert durable
  lifecycle-ledger core and root-authenticated client scaffold, including a
  restart-stable scope incarnation derived from durable launch/activation
  coordinates, serialized supervisor-ledger mutation, response-v3 capture-event
  evidence, and a session-owned one-shot outer-journal operation reservation;
  production remains blocked on the daemon/provider boundary,
  separately measured installed service and server-side peer policy,
  daemon-side proof for the operation/commit-aware remote-error outcomes,
  root-owned recovered-clearance consumption, terminal-ledger retirement
  authority, privileged canaries, and mandatory use of the operation lease by
  the installed coordinator route; the inert library contract does not make
  the supervisor effect and outer append cross-process atomic, so ambiguous
  dispatch still resumes through durable recovery rather than blind retry;
- [x] privacy-safe self-contained trust projection, pinned offline verifier,
  and monotonic atomic projection publisher.

The former four-whole-tree verifier contract is not activatable: ordinary
checkouts contain normal executable/read-only modes and copying them would
also collect irrelevant `.git`, credential, learning, log, and worktree
surfaces. The sparse selector now removes that collection surface, but the
distinct staging/adoption phase remains a prerequisite rather than an optional
optimization. Its dormant mechanics and downstream adoption binding now exist,
but they are not an activation receipt: until installed per-session
staging/recovery, post-verifier source evidence, identities/native closure,
Doctor checks, and privileged canaries prove the real route, production
activation and the installed public command remain explicitly disabled.
