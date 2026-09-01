# Security policy

John Lomein is alpha software. It is designed to fail closed, but it has not been proven safe for unrestricted public traffic or unattended repository authority.

## Supported versions

Until a stable release exists, security fixes target the latest tagged alpha and the default development branch. Older snapshots may not receive fixes.

## Reporting a vulnerability

Use the repository's private security-advisory form when available. If the public repository has no private reporting channel yet, contact the repository owner privately before disclosing details.

Please include:

- affected version or commit;
- impact and required preconditions;
- a minimal reproduction with secrets removed;
- whether repository mutation, Discord trust, memory isolation, credentials, merge, release, or publishing is involved;
- suggested mitigation, if known.

Do not include access tokens, private keys, raw memory exports, personal paths, private repository data, or hidden model reasoning.

## Security boundaries

The following remain owner-gated or disabled by default:

- repository mutation and draft-PR creation;
- Discord/public gateways and schedulers;
- merge, release, publish, settings, and secrets;
- force-push, history rewrite, and destructive actions.

Public messages, issue bodies, comments, model output, labels without proven owner provenance, and pasted metadata are untrusted data. A model statement is never execution evidence.

## Response expectations

This project currently has no paid support, bug bounty, or response-time guarantee. Valid reports will be acknowledged and triaged as capacity allows. Coordinated disclosure is requested until a fix or mitigation is available.
