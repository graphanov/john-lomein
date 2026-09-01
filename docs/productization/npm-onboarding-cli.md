# Thin npm onboarding CLI

Status: design prepared; implementation and publication are blocked until the intended npm publisher identity is verified.

Intended command after publisher verification:

```bash
npx @your-org/john-lomein init
```

The public package scope is an instance/owner publishing decision; the generic core does not hard-code an owner identity.

The package is a thin front door around the existing Python/Hermes product. It must not reimplement John, policy, runtime generation, Honcho, Forge, Doctor, or protected brokers in Node.

## Responsibilities

The wizard collects and validates:

1. target repository and default branch;
2. owner-authored mission candidate;
3. deterministic test command;
4. primary/fallback model provider and model;
5. Honcho base URL, dedicated workspace, owner peer, and retention policy;
6. owner authority identifiers and GitHub owner login provenance;
7. Discord guild/channel mapping, initially disabled;
8. schedules, initially disabled;
9. runtime budgets;
10. forbidden paths and protected actions.

It writes a local instance manifest, validates it with the Python product contract, and prints the exact next command. It does not silently install credentials, create channels, enable services, activate mutation, create a remote, push, merge, release, or publish.

## Default posture

```yaml
runtime:
  activation: owner_gated
  mutation_enabled: false
  discord_enabled: false
  guide_gateway_enabled: false
release:
  protected_broker_enabled: false
```

Observer mode is the only zero-decision default.

## Bridge design

The Node package should:

- require a supported macOS and Node version;
- discover or install no unreviewed binary payload;
- locate a pinned John Lomein product release;
- invoke the product's Python validation/setup commands as child processes with argument arrays, never shell-concatenated user input;
- redact credentials and private paths from logs;
- preserve exit codes and machine-readable receipts;
- support `--dry-run` and `--json`;
- show every managed-service cost before any optional hosted choice;
- make uninstall/rollback explicit.

## Verification gates before implementation

- `npm whoami` returns the intended publisher identity;
- ownership or creation of the intended npm scope is verified in npm, not inferred from GitHub;
- package name availability and organization permissions are verified;
- publishing requires 2FA/provenance policy chosen by the owner;
- public repository URL and support/security URLs exist;
- macOS clean-machine product test passes;
- exact package contents are reviewed with `npm pack --dry-run`;
- publication remains a separate owner action.

## Acceptance criteria for the future package

- no product behavior is duplicated in JavaScript;
- a dry run produces a deterministic redacted manifest preview;
- generated instances remain observer-only;
- invalid repo, path, authority, workspace, budget, or forbidden-path input fails closed;
- Ctrl-C leaves no partial runtime/service state;
- clean-machine macOS test covers init, validate, deploy-observer, status, and uninstall;
- package tarball contains only intended public files;
- no npm publish command appears in tests or automatic CI.
