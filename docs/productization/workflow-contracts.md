# Workflow contracts and safe evolution

John Lomein separates configurable behavior from authority. A model, SOUL, hook, prompt, or transport can change without silently granting readiness, coding, merge, release, or publication authority.

## Versioned contracts

- Guide dialogue: `john-lomein.guide-dialogue.v1`
- Proposal: `john-lomein.proposal.v1`
- Owner override policy: `john-lomein.owner-override-policy.v1`
- Signed owner override: `john-lomein.owner-override-envelope.v1`
- Review quorum: `john-lomein.review-quorum-policy.v1`
- Collaboration: `john-lomein.collaboration.v1`

Unknown fields, unknown versions, malformed values, stale heads, missing identities, and missing runtime receipts fail closed.

## Guide lifecycle

The Guide may continue a useful shaping dialogue. It still emits at most one explicit clarification question per reply. Repeated questions, repeated exchanges, material-progress exhaustion, or the configured turn cap stop questioning. The post-generation output hook accepts only one correctly prefixed question or one complete proposal with all required sections. Invalid output is blocked rather than guessed.

The manifest can tune bounded dialogue signals, but cannot raise `max_questions_per_reply` above one or remove hard-stop behavior.

## Owner input and prompt separation

Readiness labels count only when the latest label event was performed by an explicitly configured GitHub owner login and no newer issue update exists. Forge records the exact issue-snapshot digest and re-fetches it immediately before coding. Repository namespace and author-association fallbacks grant no owner authority.

Issue bodies and comments are encoded as JSON data. Comment text cannot create its own trust metadata. A Discord acceptance-criteria override must arrive as a short-lived Ed25519 envelope bound to the instance, repository, issue, exact Discord event, configured owner identities, directive digest, key id, nonce, and pinned public-key SHA-256. The key, inbox, persistent digest/nonce consumption archive, exact-head review receipts, and release bundles live under private controller roots hidden from model sandboxes. Model invocations also drop GitHub environment credentials and mask every profile-local `gh` credential directory. Forge receives only sanitized verified evidence. This transport is disabled until a protected signer key is staged, fingerprinted in policy, and the owner enables it.

## Exact-head review quorum

A merge-ready candidate requires all evidence on the same full PR head:

- configured tests succeed;
- Maintainer returns `PASS`;
- Overwatch returns `PASS`;
- Codex has a current-head clean artifact;
- the configured minimum of manual human GitHub `APPROVED` reviews is present.

Role reviews create private digest-bound receipts. A repair or head change makes old receipts stale. The exact-head rerun utility verifies the open PR, clean isolated worktree, and full SHA before and after review. Queue health, the signed release-bundle schema, packet preparation, and the protected broker reject missing, stale, revoked, malformed, or policy-mismatched evidence. Reports include the full head, policy digest, and quorum digest. None of this merges the PR. Mutation remains blocked until Maintainer and Overwatch use independently qualified review-only profiles with read-only checkouts and no GitHub credentials. The owner records that host- and version-specific qualification explicitly as `runtime.review_only_profiles_qualified: true`; merely enabling mutation never implies qualification.

## Safe change procedure

1. Add a new schema version rather than reinterpreting an old field.
2. Write failing contract and adversarial tests first.
3. Update source manifest validation, deployment output, runtime receipt, and Doctor together.
4. Keep new transports and schedulers disabled in example manifests.
5. Deploy only after full verification and explicit activation approval.
6. Rehearse with disposable identities and repositories.
7. Roll back by restoring the prior manifest and product commit; stale receipts must not validate under a different policy digest.

Models, provider choices, prompts, role SOULs, hooks, and thresholds remain replaceable through normal versioned product changes. The following are invariant: only the owner marks readiness, only authenticated owner input changes acceptance constraints, only the owner merges, and messages never grant release or publication authority.
