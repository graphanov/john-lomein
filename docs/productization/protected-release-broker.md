# Protected release and Discord owner gateway

John's model-controlled runtime may prepare a release, but it is not allowed to authenticate the owner or hold merge credentials. The protected release path therefore uses three separate OS identities and two independently installed privileged components:

1. the Hermes requester prepares a canonical release bundle and may ask for one approval attempt;
2. the release-owner gateway re-fetches the named Discord message and signs a narrowly scoped owner assertion;
3. the protected release broker reconstructs live GitHub state and may perform one exact squash merge.

No component in this path can publish a package, create a GitHub Release, dispatch a workflow, delete a branch, change repository settings, or widen its own policy. The current live contract supports one pull request per bundle and requires `publish: false`.

## Trust boundary

Recommended macOS identities:

| Identity | Holds | Must not hold |
| --- | --- | --- |
| Hermes requester | public invocation configs, credential-free packet/submission clients, generated bundles and signed receipts | Discord observer token, owner signing key, release GitHub App key, receipt signing key |
| Owner signer | read-only Discord observer token, owner assertion key, signer policy and audit records | GitHub merge credential, Hermes/GitHub CLI profiles |
| Release broker | repository-scoped release GitHub App key, owner assertion public key, receipt key and durable effect store | Discord token, owner signing key, Hermes runtime files |

The requester and signer share only a dedicated submission group for the root-owned request spool. The requester must not belong to the signer's private group. The release broker uses a separate user, private group, submit group, socket, configuration, state database, and GitHub App.

Normal `setup.sh` installs none of these privileged assets. It only deploys credential-free runtime clients and keeps `release.protected_broker_enabled: false` by default.

The runtime mission, mutation, and protected-release checks stop John's
supported client path and bind it to the deployed instance. They are
cooperative controls, not the hard broker boundary: the configured requester
UID can speak the bounded Unix-socket protocol directly. Such a caller still
cannot manufacture the independent owner signature required by every release
packet. A hard operational stop requires the root operator to install the
release broker with `"enabled": false` or boot out/uninstall its LaunchDaemon;
changing only the requester-owned instance manifest does not revoke an already
running root-owned broker.

## Exact approval flow

1. The release bundler creates a canonical `john-lomein.release-bundle.v6`.
2. The bundle binds the repository, default branch, exact pull-request head and base OIDs, changed files, checks/reviews, merge policy, and `expected_merge_tree_sha`.
3. The owner posts the bundle's exact generated approval, without a bot mention
   or reply wrapper, as a new regular Discord message:

   ```text
   APPROVE JOHN-LOMEIN BUNDLE <bundle-id> DIGEST <bundle-digest>: squash-merge the listed PR with the protected release broker; DO NOT publish. Post-merge repository verification and any publication require separate gates.
   ```

4. The runtime passes only the current Discord channel ID, message ID, and the locally matched bundle to the owner-gateway wrapper. A Hermes-supplied actor ID is never authority.
5. The signer independently calls Discord API v10 for the current application, current bot user, configured channel, and exact message.
6. The signer requires the configured application, bot, guild, channel, owner actor, message snowflake/timestamp, freshness window, and exact bundle approval. Edited, bot, system, webhook, application-generated, reply/system-type, attachment, embed, component, sticker, or poll messages fail closed.
7. The signer emits a short-lived Ed25519 owner assertion and persists a mode-0600 audit record. The assertion nonce commits to the complete source event without exposing Discord metadata to the runtime packet.
8. The runtime prepares one packet, persists it atomically, and makes one broker submission attempt. It does not retry an ambiguous transport result.
9. The release broker verifies the assertion, packet, policy, current GitHub state, exact `[base, head]` potential-merge topology, and signed expected merge tree.
10. After the squash mutation, the broker reads back the merge commit, first parent, tree, and merge actor. A wrong tree or ambiguous readback is `indeterminate`, opens the release circuit under policy, and is never reported as success.
11. Only a signature-verified receipt with the exact packet/config/repository/App bindings and confirmed readback counts as completion.

An owner phrase copied by another user, posted in another channel, edited after posting, supplied through a webhook, or paired with a different bundle cannot mint a valid assertion. Compromising Hermes can cause refused attempts or replay an already approved exact request; it cannot manufacture a new owner approval.

Use a regular Discord message, not a slash interaction. Every approval channel
ID must be present in the instance manifest's `discord.allowed_channels`,
`discord.free_response_channels`, and `discord.no_thread_channels` lists. Free
response prevents Hermes from requiring and then stripping a bot mention before
the deterministic hook sees the message. No-thread routing keeps the session
channel/message locator aligned with the original fetchable Discord message;
an automatically created message thread uses a different channel locator and
fails closed. The current Hermes Discord adapter provides a fetchable message
ID for regular messages; native slash interactions do not provide the same
approval-source contract.

## Discord observer bot

The signer uses a bot token only for direct HTTPS GET requests to the fixed origin `https://discord.com/api/v10`. It refuses proxy, caller-selected CA, TLS-key-log, redirect, retry, compression, alternate-host, and alternate-API-base configuration.

The bot requires:

- installation in the configured guild;
- `VIEW_CHANNEL` and `READ_MESSAGE_HISTORY` in each approval channel;
- Message Content enabled for the application so the exact approval text is returned;
- no `SEND_MESSAGES`, webhook, moderation, role-management, or administration permission.

Discord documents that `Get Channel Message` requires `VIEW_CHANNEL` and `READ_MESSAGE_HISTORY`, and that message content may be empty without the Message Content privileged intent. See the official [Message resource](https://docs.discord.com/developers/resources/message), [Application resource](https://docs.discord.com/developers/resources/application), [User resource](https://docs.discord.com/developers/resources/user), [Channel resource](https://docs.discord.com/developers/resources/channel), and [API reference](https://docs.discord.com/developers/reference).

## Root-controlled installation

Stage a reviewed product snapshot into a root-owned, non-symlinked directory that is not group/other writable. Do not run either installer with `sudo` directly from a requester-writable checkout. Both installers require a root-owned Python 3.11+ runtime with the locked `cryptography` dependency.

Provision distinct existing users/groups first:

- `<runtime-user>` — the Hermes requester;
- `<owner-signer-user>` and its dedicated private primary group;
- `<owner-submit-group>` containing only the requester and owner signer;
- `<release-broker-user>` and its dedicated private primary group;
- `<release-submit-group>` containing only the requester and release broker.

### 1. Install the owner gateway disabled

Create configs from:

- `templates/protected-release-owner-signer-config.json.example`;
- `templates/protected-release-owner-discord-source-config.json.example`.

Keep both `"enabled": false`, make the source config fingerprint the complete normalized signer config, and use the canonical installed paths from the templates.

```bash
sudo /root-controlled/john-lomein-product/scripts/install-protected-release-owner-gateway.sh \
  --slug <instance> \
  --signer-config /private/operator/<instance>.owner-signer.json \
  --discord-source-config /private/operator/<instance>.discord-source.json \
  --signing-private-key /private/operator/owner-ed25519.pem \
  --signing-public-key /private/operator/owner-ed25519.pub.pem \
  --discord-bot-token /private/operator/discord-observer-bot.token \
  --python /absolute/root-owned/python3 \
  --signer-user <owner-signer-user> \
  --requester-user <runtime-user> \
  --submit-group <owner-submit-group>
```

Disabled installation writes the root-owned code, strict configs, credentials, public invocation descriptor, fixed wrapper, state directory, and request spool, but deliberately withholds the sudoers authorization.

### 2. Install the release broker disabled

Create a config from `templates/protected-release-broker-config.json.example`. Keep `"enabled": false`, `max_prs_per_bundle: 1`, `merge_method: "squash"`, `publish: false`, and `delete_branch: false`.

The release GitHub App must be installed only on the configured repository. Its installation permission set must exactly match the broker implementation: metadata read, contents write, pull requests read, issues read, checks read, and commit statuses read. Do not grant Actions, Workflows, Releases, Administration, Secrets, organization, or package-registry authority.

```bash
sudo /root-controlled/john-lomein-product/scripts/install-protected-release-broker.sh \
  --slug <instance> \
  --config /private/operator/<instance>.release-broker.json \
  --github-app-private-key /private/operator/release-github-app.pem \
  --owner-assertion-public-key /private/operator/owner-ed25519.pub.pem \
  --receipt-private-key /private/operator/release-receipt-ed25519.pem \
  --receipt-public-key /private/operator/release-receipt-ed25519.pub.pem \
  --python /absolute/root-owned/python3 \
  --broker-user <release-broker-user> \
  --requester-user <runtime-user> \
  --submit-group <release-submit-group>
```

Disabled installation retains all state and public trust material but does not start the LaunchDaemon.

### 3. Activate only after review

Activation is deliberately multi-step:

1. inspect installed ownership, modes, public descriptors, key fingerprints, repository IDs, GitHub App identity, Discord application/guild/channel/owner IDs, budgets, and forbidden paths;
2. run the disabled-install and adversarial checks below;
3. change both owner-gateway configs to `"enabled": true` and reinstall, which installs the narrow fixed-wrapper sudo rule;
4. change the release-broker config to `"enabled": true` and reinstall, which starts its LaunchDaemon;
5. set `runtime.mutation_enabled: true` and `release.protected_broker_enabled: true` in the instance manifest;
6. redeploy, run doctor, release health, and the private-repository canary.

The root-owned public owner-gateway descriptor is:

```text
/private/etc/john-lomein-release-owner-gateway-public/<instance>.json
```

The root-owned release client descriptor is:

```text
/private/etc/john-lomein-release-broker-public/<instance>.json
```

Their presence is not proof of enablement. The owner gateway is callable only when its sudoers rule is effective, and the release broker is callable only when its authenticated socket exists and matches the pinned client configuration.

Likewise, callability is not private health. An enabled path is ready only when
the fixed owner wrapper can run its non-network signer self-check under the
configured signer identity and the release client can authenticate the live
broker peer. A public descriptor, sudo authorization, socket file, or LaunchDaemon
label by itself must never produce a green readiness result.

## Operations

Runtime diagnostics:

```bash
make release-health INSTANCE=/path/to/instance
make release-dry-run INSTANCE=/path/to/instance
make doctor INSTANCE=/path/to/instance
```

The approval path must run from the current regular Discord turn so the gateway supplies its current channel/message IDs. Do not copy IDs into an operator shell as a substitute for the conversational path.

Do not automatically retry:

- signer refusal;
- broker transport failure after request bytes may have been sent;
- invalid or mismatched receipt;
- `indeterminate` merge/readback;
- a circuit-open response.

Inspect the signer audit record, runtime packet, broker database/logs, and signed receipt chain first. Replaying the exact packet is idempotent at the broker, but a human must decide whether the external effect is already present when transport was ambiguous.

Uninstalling removes invocation/service surfaces while preserving credentials and durable evidence:

```bash
sudo /root-controlled/john-lomein-product/scripts/uninstall-protected-release-owner-gateway.sh \
  --slug <instance>

sudo /root-controlled/john-lomein-product/scripts/uninstall-protected-release-broker.sh \
  --slug <instance>
```

## Canary requirement

Keep the public posture in observer mode until a private repository proves all of the following:

- disabled installation creates no callable signer or running broker;
- the deployed Guide profile discovers the deterministic approval plugin while
  every private profile keeps it disabled;
- every approval channel is simultaneously allowed, free-response, and
  no-thread, and the hook's channel/message locator re-fetches the same raw
  message content that the hook matched;
- an unauthorized actor, wrong guild/channel, edited message, stale message, reply, webhook, bot, attachment, embed, component, sticker, poll, wrong bundle, or wrong digest is refused;
- the observer bot can read the exact message with only the documented read permissions;
- a one-PR bundle signs and submits exactly once;
- the release GitHub App can read every configured check/status/review/file field and perform a squash merge;
- the live potential merge tree equals the owner-signed `expected_merge_tree_sha`;
- a concurrent PR head or target-base change is refused;
- a post-mutation tree, parent, or actor mismatch becomes `indeterminate`, never success;
- crash recovery reconciles confirmed presence and never blindly repeats an ambiguous merge;
- receipt signatures, chain links, and offline verification pass;
- branch deletion, publish, release creation, package publication, and workflow dispatch remain unavailable.

The code and local adversarial suites implement these contracts, but this repository has not yet performed the privileged root installation or private-repository canary. Until that evidence exists, describe the protected release lane as implemented and locally verified, not operationally proven.
