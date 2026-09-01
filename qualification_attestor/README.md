# Persona qualification attestor

This package defines the offline Ed25519 authentication boundary for a John
Lomein persona qualification. It makes no model calls. Its strongest permitted
claim is `operator_verified_local_conformance`, always with
`public_reputation_eligible: false`.

The intended production boundary has four roles:

1. the unprivileged runtime account produces qualification evidence;
2. a hermetic root coordinator launches a separate key-denied capture child
   and sends the only permitted 17-source plan over a bounded stdlib-only
   protocol; the child copies it into a bounded, no-follow staging snapshot;
3. a separate non-login verifier account reads only that snapshot and the
   pinned verifier bundle, with network, writes, and process creation denied;
4. a minimal signing boundary receives the root-recomputed canonical claim only
   after the verifier exits, all descendants are reaped, the adopted snapshot
   and installed controls are revalidated, and the chain transaction is
   locked. Live sources are revalidated before the capture child relinquishes
   them and again by root after canonical verifier output is adoption-bound.
   The second pass emits a path-free receipt bound to that exact verifier
   stdout digest before the private key can be opened.

The repository now contains a dormant v2 handoff for that ownership change.
Evidence is exported as `E:export` `0750/0640`; a short-lived dedicated
capture child runs as `C:export` with no supplementary groups and emits one
`0500/0400` provisional tree; at READY, root opens and retains the exact
provisional directory with `O_NOFOLLOW`, keeps that non-inheritable descriptor
through child/process-group death, and transfers the one-shot authority into
descriptor-relative adoption of the same inode as
`root:<dedicated-verifier-group>` `0550/0440`. The adopted object remains
behind a nonserializable cleanup lease. Its v2 adoption receipt is reobserved
descriptor-relatively by the verifier and binds the creator UID, export GID,
root adoption, complete content inventory, capture request, boundary policy,
and helper activation policy into the signed v5 payload. The v5 payload also
contains the root-produced post-verifier live-source receipt and its digest.
This is a sequential operator/root attestation, not an independent evaluator
or atomic source snapshot. Production is still disabled: the installed
launcher, per-session staging lifecycle, crash recovery, and real-identity
privileged canaries are incomplete.

The root-owned command reads one fixed, installer-generated configuration and
accepts no caller-selected payload, key, evidence, or output path. The strict
configuration body is:

```json
{
  "schema_version": 1,
  "instance_slug": "example-repo",
  "qualification_public_root": "/operator/evidence/public",
  "qualification_private_root": "/operator/evidence/private",
  "expected_evidence_uid": 501,
  "attestor_key_id": "example-repo-persona-ed25519-1",
  "private_key_path": "/private/etc/john-lomein/keys/persona-private.pem",
  "public_key_path": "/private/etc/john-lomein/keys/persona-public.pem",
  "public_key_sha256": "<sha256-of-exact-public-key-file-bytes>",
  "head_path": "/private/etc/john-lomein/persona-attestations/example-repo.json"
}
```

Configuration, private key, public key, and head paths must be distinct and
outside both evidence roots.

The v4 signed payload binds:

- instance, run, summary, and qualification-binding digests;
- qualification, verification, and expiry timestamps;
- evidence-producing, distinct capture-creator, export-group, root-adopter,
  and verifier identities;
- verifier bundle, verification policy, adopted-capture receipt and complete
  content inventory, capture request/boundary/helper policies, sealed-capture
  manifest, concrete sparse per-run capture-plan, and public operator-policy
  digests;
- the explicit local-conformance claim strength and false public-reputation
  eligibility;
- a monotonic sequence and previous-envelope digest.

The public operator policy is
`john-lomein.persona-qualification-operator-policy.v3`. It binds the distinct
capture/export/root-adoption identities, required adoption-binding schema, and
the digest of the installed sparse-selection policy. The signed per-run
`capture_plan_sha256` binds the concrete plan selected from the terminal
status. Consequently the stable public policy and the particular run plan are
both authenticated without publishing private source paths in the trust
projection.

Publication verifies the signature, clock, UID/key/config binding, and complete
bounded archive. The archive must begin at sequence one, remain contiguous,
have strictly increasing qualification/verification times, use each run once,
and match canonical filenames. A missing or stale head is reconstructed from
that signed archive; deleting the head and replaying an older run is rejected
while the signed archive remains intact. This local chain does not detect a
whole-store rollback; that requires an external transparency or hardware
anchor.

`john_lomein_persona_qualification_capture.py` and the opaque-capture modules
implement descriptor-relative copy, seal, inventory verification, live-source
revalidation, cleanup, and bounded orphan recovery. They reject symlinks,
hard-linked files, extended metadata, authority-granting ACL entries, unsafe
ownership/modes, entry aliases, source mutation, excessive
depth/count/bytes, and destination/source overlap.

The repository command remains fail-closed. A disabled transactional installer
scaffold now creates distinct signer/capture/verifier accounts, a separate
export group, instance-scoped content-addressed role bundles, fixed launchers,
public pin/status files, and upgrade-continuity checks under one global lock.
It does not load launchd, issue an activation receipt, or enable a route.
Activation still requires a production-bound per-session v2 launcher,
crash-safe adoption recovery, post-verifier live-source evidence, independently
consumed native runtime evidence, effective Doctor checks, and privileged
macOS/Linux canaries. Do not bypass the stop by executing mutable repository
code as root or by verifying as the evidence-producing UID. Until activation,
Doctor must continue to classify this as local evidence rather than public
reputation.

The dormant native-bundle v3 primitive proves a complete declared inventory,
canonical no-symlink ancestry, root control at live verification, thin 64-bit
Mach-O structure, an exact system-dependency allowlist, the trusted
`/usr/lib/dyld`, forbidden dyld-environment injection, and conservative
unambiguous `@rpath` resolution. It deliberately does **not** convert
caller-authored Python/runtime fields into observed facts or prove an exact
OS/shared-cache identity and code-signature policy. The protected installer
must consume independently measured native evidence and execute the real
relocated `python -I -S -B` privilege/import/sandbox canary before it can emit
a stronger operator policy.

`john_lomein_persona_qualification_native_host_evidence.py` records a bounded
Darwin host observation, including exact OS/build/architecture values, the
measured `/usr/lib/dyld` file and slices, the dyld shared-cache
UUID/component inventory, and a canonical digest. It deliberately makes no
CMS, notarization, AMFI, hardened-runtime, activation, or
installer-consumption claim. It is packaged as evidence machinery; the
protected installer does not yet promote it into a qualified native closure.

`scripts/build-persona-qualification-capture-native-bundle.py` now builds one
macOS capture-role engineering specimen from an operator-supplied local
CPython. It copies the non-site stdlib and native closure, rewrites an unsafe
absolute libpython install name to `@rpath`, ad-hoc signs and verifies the
changed object, seals and rescans the tree, emits the v3 manifest beside the
bundle, and runs the relocated five-module capture closure under `-I -S -B`.
Its stdout is a self-describing build report with both activation fields false;
the installer does not consume or bless this specimen.

`john_lomein_persona_qualification_wheel_provenance.py` separately proves one
retained local wheel and one exact installed vendor tree descriptor-relatively.
It derives the archive digest, validates bounded ZIP structure,
METADATA/WHEEL/RECORD, requires every payload hash and size, and compares the
exact installed byte union. It accepts no caller URL or digest claim. It proves
local exact extraction, not package-index origin, transport, lock resolution,
installer identity, or live import.

`john_lomein_persona_qualification_capture_plan.py` is the
standard-library-only contract for the replacement capture path. Its strict
root-owned plan selects fixed file/tree sources, hard resource limits, and an
ephemeral lifecycle. The installed policy must compile a sparse current-run
plan: whole checkout/runtime capture is forbidden because it is unnecessary
for reproduction and would collect unrelated private surfaces. It contains no
YAML or evidence semantics; qualification meaning remains the confined
verifier's job.

`john_lomein_persona_qualification_capture_selection.py` implements that
root-owned selection contract. It reads the fixed canonical `status.json`
descriptor-relatively, requires a self-digested terminal qualified status, and
compiles exactly these 17 sorted source entries:

- `instance/instance.yaml`;
- `private/<run-id>/` as the one matching private run tree;
- `runtime/instance.yaml`;
- `SOUL.md` and `config.yaml` for each of the five fixed profiles;
- `runtime/state/john-lomein-persona.json`;
- the public `latest.json` and `status.json`;
- `runtime/state/persona-qualification/reports/<run-id>/` as the one matching
  public report tree.

There is no checkout source entry and no `checkout/` directory in the capture.
The checkout remains only an independently supplied, policy-bound path
identity used when reproducing and checking the instance binding. The runtime
is likewise not copied wholesale: 12 entries originate from the runtime root
and three originate from the public-evidence root, all landing at explicitly
listed destinations below `runtime/` in the capture. The two selected run
trees may contain multiple files, but no additional source entry or
destination is accepted.

Capture is split into three measured roles.
`john_lomein_persona_qualification_capture_protocol.py` contains the
stdlib-only wire contracts; it imports no plan, evidence, sandbox, adoption,
signing, or projection implementation. V1 remains an explicit compatibility
grammar for the dormant long-lived-child tests. V2 is a separate
self-digested one-shot request/result grammar and does not accept lifecycle
commands after capture.
`john_lomein_persona_qualification_capture_helper.py` is the privileged
coordinator and sandbox launcher, while
`john_lomein_persona_qualification_capture_child.py` is the distinct confined
entrypoint that imports only the protocol, capture plan, and opaque-capture
engine from this package. Neither role imports the other at startup.

In the legacy v1 path, at the pre-private-key `complete_verification`
acknowledgement the child
verifies the sealed snapshot and revalidates every live source. After an
envelope has been published, `complete_signing` verifies the sealed snapshot
only: later live-source mutation cannot retroactively turn a valid signed
snapshot into an apparent failed signing transaction.
`complete_publication` verifies the sealed snapshot once more and deletes it.
The coordinator remains gated by both `PRODUCTION_ACTIVATION = False` and
`CAPTURE_ADOPTION_IMPLEMENTED = False`. The new v2 path does not translate
identities through v1's `helper_uid/helper_gid`: evidence UID, capture UID,
export GID, adopted UID, verifier UID, and verifier GID are separately
digest-bound. Adoption-receipt propagation is implemented and integration
tested. READY-time retained authority and reuse-safe process-group death
observation are implemented and focused-tested. The dormant v2 session also
rechecks the exact adopted object and all E:export live sources after verifier
exit, then returns a canonical receipt bound to the verifier-output digest
before signing authorization. Per-session staging, production crash recovery,
installed-route binding, and real root/cross-user/SIGKILL canaries remain
mandatory before either activation gate may change.

The verifier implementation identifies as
`john-lomein.persona.operator-verifier.v4`, accepts only
`john-lomein.persona.operator-verifier-request.v4`, and emits strict
`john-lomein.persona.operator-verification.v3` output over bounded standard
input/output. The request binds the normalized v2 adoption receipt and digest,
creator/export/adopted identities, capture session/request/boundary/helper
anchors, selection and concrete plan, sealed manifest, checkout/runtime
identities, installed verifier and policies, and verification time. The
verifier descriptor-relatively reobserves the complete root-owned adopted
tree, then reconstructs the plan from the sealed manifest, extracts the run
from captured terminal status, recompiles the only permitted 17-source plan,
requires canonical equality, verifies the entire inventory, and reproduces
the qualification. Checkout bytes are never an input.

`john_lomein_persona_qualification_trust_projection.py` builds and verifies a
single privacy-safe public object containing the public key, signed envelope,
digest-bound operator policy, explicit claim limits, and a head with the
private archive path removed. Verification requires an independently pinned
instance slug, key ID, and key fingerprint. Its low-level publisher uses one
locked atomic file replacement and enforces monotonic sequence/digest
transitions. Fixed installed paths, a zero-argument offline command, and Doctor
integration are still activation gates.

`john_lomein_persona_qualification_orchestrator.py` joins helper-held capture
metadata and adoption receipt, verifier/request v4, operator-policy v3, the
single-flight signer, and trust projection
with guaranteed cleanup. It supports keyless recovery when the process dies
after signing but before projection: a fresh verification of the exact same
run, plan, policy, and qualification may reuse the existing envelope while
only capture time/manifest differ. Once both signed head and public projection
are durable, cleanup failure is represented as the irreversible
`committed_cleanup_pending` state and can be retried in-process through a
cleanup-only authority that cannot sign, advance the chain, or republish.
Durable journaling and safe reconstruction of that narrow authority after a
coordinator restart are still required. The mutable-repository entrypoint
remains fail-closed.

`john_lomein_persona_qualification_public_verifier.py` implements the
zero-argument offline verification logic and an exact root-owned pin contract.
It emits a sanitized canonical result and makes no network calls. Installation
still needs a content-addressed `python -I -S -B` launcher, fixed per-instance
pin, and Doctor integration before this is an installed product surface. The
repository wrapper is a tested development surface, not an installed
production command.
