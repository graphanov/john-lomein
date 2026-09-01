# Hermes v0.21 collaboration assessment

Status: researched and governed, transport inactive.

Hermes v0.21 adds useful multi-agent and operational surfaces, but transport is not authority. John must preserve its deterministic owner-readiness, review, merge, memory, and publication boundaries regardless of which agent delivered text.

## Two different messaging systems

### Local Bot Mode

`message_agent` is a same-host Bot Mode tool. It targets another managed profile's canonical `Bot Chat`, serializes turns for that target, and starts a detached target turn. The receiver sees a generated text prefix naming the apparent sender.

This is not Hermes Peer. It is local profile-to-profile delivery and it creates or reuses durable Bot Chat history.

### Remote Hermes Peer

`hermes peer` addresses a separate Hermes `api_server` gateway:

```text
hermes peer add <peer> --url https://host:8642 --key <API_SERVER_KEY>
hermes peer dm <peer>[/<profile>] "message"
hermes peer run <peer>[/<profile>] --idempotency-key <key> < request.txt
hermes peer status <peer>[/<profile>] <run-id>
hermes peer stop <peer>[/<profile>] <run-id>
```

`dm` is synchronous and has no idempotency key. `run` is asynchronous and can use durable idempotency when the remote gateway advertises that capability. Both resolve or create the destination's canonical Bot Chat and therefore reuse durable conversation context.

The bearer key protects a broad agent API, not a least-privilege message endpoint. The same API surface includes session operations, agent turns, runs and run control, skills, toolsets, artifacts, and other capabilities. Named-profile routing chooses a destination; it does not cryptographically prove a sender role.

Sources:

- <https://hermes-agent.nousresearch.com/docs/user-guide/bot-mode>
- <https://hermes-agent.nousresearch.com/docs/reference/cli-commands>
- <https://hermes-agent.nousresearch.com/docs/user-guide/features/api-server>
- `hermes_cli/subcommands/peer.py`
- `tools/bot_mode_dm.py`
- `gateway/platforms/api_server.py`

## John authority decision

Messages remain advisory data.

A local Bot Mode sender label, peer name, bearer token, model statement, `SHIP` verdict, readiness phrase, or signed transport envelope is not:

- owner readiness;
- coding approval;
- acceptance-criteria override;
- merge approval;
- release or publication approval;
- a mission change.

Forge must independently re-prove the existing owner-readiness source event. Maintainer and Overwatch must independently reconstruct repository and exact-head evidence. Only the owner merges.

## Role matrix

| Source | Destination | Future bounded use | Current decision |
|---|---|---|---|
| Guide | Forge | Proposal pointer after independent owner readiness | Transport disabled |
| Forge | Overwatch | One immutable design-critique request | Offline envelope fixture only |
| Overwatch | Forge | One correlated advisory verdict | Offline envelope fixture only |
| Forge | Maintainer | Exact PR/head notification | Deferred |
| Maintainer | Overwatch | Exact-head finding request | Deferred |
| Learning Steward | Any role | Bounded derived lesson pointer | Deferred |
| Any role | Learning Steward | Raw conversation or peer transcript | Prohibited |
| Any role | Owner authority | Readiness, merge, release, or publish | Prohibited |

Independent Overwatch review must not reuse a persuasive durable Bot Chat. A future live route needs a fresh, bounded context created by a product-owned broker.

## Phase 0 implemented in the product

The first slice is deliberately inactive:

1. `john-lomein.collaboration.v1` is a strict manifest contract.
2. The default mode is `disabled` with `authority: advisory_only`.
3. `bot_chat_protocol_enabled` and `peer_messaging_enabled` must remain `false`; attempts to enable either fail validation until a product broker exists.
4. Prepared role routes may be described without enabling transport.
5. `john-lomein.role-message.v1` validates deterministic advisory envelopes, exact source/destination roles, purpose, correlation ID, bounded public-safe text, route membership, and a content-bound message digest.
6. Envelopes always project `may_mark_ready=false`, `may_merge=false`, and `may_publish=false`.
7. Deployment explicitly writes `agent.bot_mode_protocol: false` for every role instead of inheriting Hermes defaults.
8. Doctor verifies profile policy, an empty Peer registry, and a private deterministic collaboration-policy receipt.
9. No peer is registered, no key is stored, no API server is started, no Bot Chat is created, and no message is sent.

## Threat model before any live pilot

A live broker must provide all of the following before model invocation:

- destination-specific credentials unavailable to agents;
- authenticated broker-derived source identity;
- TLS or an owner-controlled authenticated tunnel;
- an exact route allowlist;
- immutable artifact references and SHA-256 digests;
- durable message-ID deduplication and expiry;
- `hop_count=0` and one-way/no-reply default;
- strict token, cost, wall-clock, and concurrency budgets;
- redacted append-only evidence;
- revocation and incident-pause rehearsal;
- mechanically non-mutating destination profiles;
- fresh-context Overwatch execution;
- separate explicit owner activation.

`peer stop` is cooperative run cancellation, not rollback. It cannot be treated as containment for already-executed tools.

## Other v0.21 opportunities

### Adopt next

1. **Gateway supervision and identity** — align the Guide launchd service with Hermes' external-supervisor and canonical profile-identity contracts; verify code SHA, heartbeat freshness, PID identity, and restart state.
2. **Effective capability validation** — keep exact `platform_toolsets`, `agent.disabled_toolsets`, `no_mcp`, and plugin allowlists; reject dependence on deprecated top-level `toolsets`.
3. **Cron execution ledger** — surface `cron doctor`, durable outcomes, failure streaks, and overdue jobs in John Doctor and Overwatch without replacing John's worker supervisor.
4. **Security audit receipt** — run `hermes security audit --json --fail-on high` during disposable qualification, recording unavailable scans separately.
5. **Compression and routing pins** — explicitly pin role compression and model-routing policy rather than inheriting changing defaults; never add silent fallback to authority-bearing paths.
6. **Owner-only session operations** — add per-profile inventory, retention, export, and deletion checks while keeping model-facing `session_search` disabled.

### Prototype later

- one disposable, fresh-context Forge to Overwatch advisory exchange behind a product broker;
- owner-operated remote diagnostics over a private network;
- Hermes Kanban as a shadow board for non-mutating documentation or learning work only;
- attached cron sessions for owner-private diagnostics;
- Guide-only model aliases after persona, cost, and latency qualification;
- encrypted, isolated Hermes backup and restore rehearsal.

### Reject or defer

- Peer or Bot Mode text as readiness, acceptance override, or release evidence;
- production gateway multiplexing that weakens current process isolation;
- replacement of the John worker supervisor with generic Kanban dispatch;
- automatic provider fallback on Maintainer, Forge, signer, broker, or release paths;
- model-facing memory or session search for operational roles;
- unencrypted backups or public debug/state export;
- in-place Hermes update on a divergent or dirty source checkout.

## Hermes update posture

The running Hermes reports v0.21.0 but uses a locally carried history that is not a normal fast-forward of the current upstream snapshot. Update claims based only on “commits behind” are unsafe. Use a side-by-side candidate installation, disposable Hermes home, complete John regression suite, gateway/cron/session migration tests, observer-only soak, and explicit cutover/rollback. Do not reset, stash, or update the current source tree as part of John product deployment.

## Live activation gate

Phase 0 completion is not authorization to communicate. Live Bot Mode or Peer transport remains a later owner decision after the product-owned broker and security tests exist.
