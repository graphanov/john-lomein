# Protected-action broker

John's model-controlled runtime is not the security boundary for credentialed GitHub mutations. The protected broker is a separate, deliberately boring service that accepts an untrusted request packet, reconstructs live GitHub truth, performs one narrowly allowed mutation, reads the result back, and returns a signed receipt.

Broker v1 supports only:

- marking an eligible bot-authored draft pull request ready for review;
- resolving one exact outdated review thread.

Merge, release, workflow dispatch, package publication, current-thread resolution, repository settings, secrets, force-push, and history rewriting remain unavailable.

## Identity boundary

Run one broker per John instance under a dedicated OS user that differs from the Hermes/runtime user. Install broker code and configuration into root-owned locations; keep the GitHub App key, receipt-signing key, and SQLite state outside every model-readable or model-writable runtime directory.

Recommended macOS layout:

```text
/usr/local/libexec/john-lomein-protected-broker/   root:wheel 0755
/private/etc/john-lomein-broker.d/<instance>.json  root:<broker> 0640
/private/etc/john-lomein-broker-public/             root:wheel 0755
/private/var/db/john-lomein-broker/state/<instance>/ <broker>:<broker> 0700
/private/var/db/john-lomein-broker/run/<instance>/  <broker>:<submit-group> 0750
/private/var/db/john-lomein-broker/run/<instance>/broker.sock <broker>:<submit-group> 0660
```

Use the canonical `/private/...` paths on macOS. `/etc` and `/var` are compatibility symlinks there, and the broker intentionally rejects symlink ancestors in trusted paths. Do not place the socket below `/private/var/run`: that system directory is group-writable on macOS and therefore intentionally fails the broker's trusted-parent check.

The socket authenticates the kernel-reported peer UID. File permissions are defense in depth; a caller-supplied identity field is never authority. The daemon refuses startup on a platform without a supported peer-credential mechanism.

The deployed client's mission and mutation checks are cooperative runtime
controls: they stop John's supported submission path and bind that client to
its own instance, repository, and branch. They are not the broker's hard
revocation boundary, because a process already running as the configured
requester UID can speak the bounded socket protocol directly. The broker still
reconstructs live state and permits only its two fixed actions, but a hard stop
requires the root operator to install an `"enabled": false` broker config or
boot out/uninstall the LaunchDaemon. Changing only the requester-owned
instance manifest cannot revoke a running root-owned broker.

## Operator installation

Normal `setup.sh` never installs this service. Provision the dedicated broker user, requester user, submit group, GitHub App key, Ed25519 receipt keypair, and a config based on `templates/protected-broker-config.json.example` first. Begin with `"enabled": false`.

Do not run the installer with `sudo` from the model/requester-writable product checkout. First verify the intended source revision and stage the complete product snapshot into a root-owned, non-symlinked directory that is not group/other writable. The installer refuses any weaker source chain; otherwise the requester could race privileged code while root copies it.

The supplied Python must be 3.11 or newer and live under a root-owned, non-writable, non-symlinked trust chain. Under isolated mode it must import the locked `cryptography` 50.0.1 dependency from equally trusted paths. A requester-owned Homebrew Python is intentionally rejected even if its absolute path looks plausible.

Install as root:

```bash
sudo /root-controlled/john-lomein-product/scripts/install-protected-broker.sh \
  --slug <instance> \
  --config /private/operator/<instance>.json \
  --github-app-private-key /private/operator/github-app.pem \
  --receipt-private-key /private/operator/receipt-ed25519.pem \
  --receipt-public-key /private/operator/receipt-ed25519.pub.pem \
  --python /absolute/root-owned/python3 \
  --broker-user <existing-broker-user> \
  --requester-user <existing-runtime-user> \
  --submit-group <existing-submit-group>
```

The installer validates identity membership and all trust paths, installs only the broker package under the root-owned libexec tree, writes a system LaunchDaemon, and derives the public client config. An upgrade snapshots code, config, keys, public assets, plist, and SQLite state with no-follow stable reads; failure restores the previous installation or leaves the service fail-closed. The installed code root is shared, so every other protected-broker instance must be stopped before an upgrade. With `enabled: false`, the installer writes the assets but does not start the daemon. Re-run after reviewing an `enabled: true` config to activate it.

Uninstalling boots out the service and removes its plist/socket only:

```bash
sudo scripts/uninstall-protected-broker.sh --slug <instance>
```

Code, config, keys, public verification material, and durable state are retained by default for auditability and deliberate operator cleanup.

## Credential envelope

Use a GitHub App installed only on the configured repository. Broker v1 requests a one-hour installation token restricted again to the exact repository ID and the following subset:

- metadata: read;
- pull requests: read/write;
- issues: read;
- checks: read;
- commit statuses: read.

The broker neither requests nor accepts Contents, Actions, Workflows, Administration, Secrets, Members, Releases, organization authority, PATs, `GH_TOKEN`, `gh` profiles, caller proxy configuration, or caller TLS configuration. GitHub documents repository-scoped installation-token issuance through `repository_ids` and permission narrowing through `permissions`; tokens expire after one hour. See [Generating an installation access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app).

## Request and evidence contract

The runtime prepares a `john-lomein.protected-action-packet.v1` with `scripts/john_lomein_protected_actions.py`. The socket submission contains only the submit schema and packet. It does not contain credentials, authority flags, a claimed UID, or a caller-selected policy.

Normal runtime deployment copies the public submit client and John Lomein's unprivileged runtime-control contract. The client derives its default trust file from the verified packet instance as `/private/etc/john-lomein-broker-public/<instance>.json`. That root-owned public file pins the broker/config digest, broker UID, socket, receipt key and fingerprint, instance/repository identity, and GitHub App identity. It contains no secret.

After preparing a packet, an enabled maintainer lane may submit it without asking for routine human approval:

```bash
"${HERMES_PYTHON:-python3}" "$HERMES_HOME/scripts/john-lomein-protected-submit.py" \
  --packet "$HERMES_HOME/state/protected-actions/outbox/<packet-id>.json" \
  --runtime-home "$HERMES_HOME" \
  --receipt-output "$HERMES_HOME/state/protected-actions/receipts/<packet-id>.json"
```

The client accepts success only after strict response parsing, Ed25519 verification against the pinned key, exact packet/config/repository/App context matching, and action-specific confirmed readback. A denial, transport failure, indeterminate receipt, mismatched context, or invalid signature exits non-zero. Replaying the same packet is safe, but the runtime must not create a retry loop.

Persisted evidence can be re-verified after packet expiry without contacting the daemon:

```bash
"${HERMES_PYTHON:-python3}" "$HERMES_HOME/scripts/john-lomein-protected-submit.py" \
  --packet "$HERMES_HOME/state/protected-actions/outbox/<packet-id>.json" \
  --verify-receipt "$HERMES_HOME/state/protected-actions/receipts/<packet-id>.json"
```

Before preparing the packet, the maintainer posts a top-level PR comment rendered by:

```bash
python scripts/john_lomein_comment_templates.py protected-evidence \
  --instance-slug <instance> \
  --action <mark_pr_ready-or-resolve_review_thread> \
  --head-sha <exact-head> \
  --commands-sha256 <verification-command-digest> \
  --result-sha256 <verification-result-digest> \
  --status <public-safe-status> \
  --evidence <public-safe-evidence> \
  --next <protected-broker-next-step>
```

The first line is a deterministic hidden marker. The broker fetches the referenced comment directly from GitHub and requires the exact bot author, URL, timestamp window, instance, action, head, and verification digests.

## Live authorization

Immediately before mutation the broker independently requires:

- exact repository ID/name and PR number/URL;
- `OPEN` state, configured base branch, exact packet head, allowed bot author, and same-repository head;
- fully paginated changed files below policy limits and clear of hard-coded plus configured forbidden paths;
- fully paginated check runs and commit statuses for the exact head, with every required context present and every observed context terminal and accepted;
- the exact evidence comment marker;
- fully paginated review threads and a count matching the packet.

For draft promotion, the PR must still be draft and have zero unresolved threads. For thread resolution, v1 accepts exactly one thread; it must belong to the PR, remain unresolved, match the exact discussion URL, and be outdated. A current finding needs a future independently signed verifier attestation.

GitHub's public GraphQL schema exposes both mutations and the review-thread `isOutdated` field. See [GitHub GraphQL pull-request reference](https://docs.github.com/en/graphql/reference/pulls).

## Durable effects and receipts

The broker reserves a semantic effect and charges budgets in broker-owned SQLite before attempting a mutation. The semantic keys are:

```text
mark_pr_ready:<repo>:<pr>:<head>
resolve_review_thread:<repo>:<pr>:<head>:<thread-node-id>
```

Every terminal outcome for a packet accepted into durable broker state is a canonical Ed25519-signed receipt bound to the broker/config/key identity, packet digest, repository ID, PR/head/target, GitHub App installation, precondition digest, mutation status, readback, reason code, timestamps, and previous receipt digest. Only a signature-verified success with confirmed exact-head readback counts as completion. Transport rejection, invalid protocol, wrong peer identity, disabled service, and admission refusal before durable reservation return a small unsigned error envelope and never count as execution evidence.

If the process dies after charging an attempt, startup/request recovery queries GitHub before doing anything else:

- desired state present on the same head: issue a reconciled receipt;
- desired state absent and the packet remains valid: record absence and permit at most one retry under a new charged attempt;
- expired packet, changed head, ambiguous API state, or unavailable readback: issue/retain an indeterminate outcome and open the circuit after the configured threshold.

The broker never blindly retries an externally visible mutation.

## Canary requirement

Keep `enabled: false` until a private repository canary proves:

- the installation token can call `markPullRequestReadyForReview`;
- the installation token can call `resolveReviewThread`;
- review-thread pagination and `isOutdated` are visible to the App;
- issue-comment lookup works with the chosen read permission;
- check-run and commit-status visibility matches the configured permissions;
- large file/thread collections fail closed rather than truncate;
- a concurrent head update produces `indeterminate`, never a success receipt.

Neither GraphQL mutation accepts an expected head SHA. The broker therefore cannot prevent the final compare-and-mutate race; it detects a changed readback and refuses to certify completion.
