# Security policy

John Lomein is alpha software. It is designed to fail closed, but it has not been proven safe for unrestricted public traffic or unattended repository authority.

## Supported versions

Until a stable release exists, security fixes target the latest tagged alpha and the default development branch. Older snapshots may not receive fixes.

## Reporting a vulnerability

Use the repository **Security** tab, open **Advisories**, and choose **Report a vulnerability**.
That private GitHub form is the primary reporting route.

If that button is unavailable, open a public issue titled **Private security reporting channel requested**.
Include only the affected public version or commit and a request for a
maintainer to enable a private channel. Do not put vulnerability details,
reproduction steps, logs, identifiers, paths, or other private data in that
issue. Wait for a repository maintainer to provide or enable the private
advisory route before sending details.

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

Model-facing Hermes processes run without direct network access or readable
provider credentials. OpenAI Codex traffic and local Honcho traffic use two
separate controller-owned, per-process Unix-socket brokers. The Honcho route is
bound to the protected profile's exact loopback origin and workspace; it denies
listing, cross-workspace, destructive, administrative, and tunneling routes,
and permits message writes only for a profile whose `saveMessages` policy does.
The public Guide remains suggestion-only; private role entrypoints, mutation,
and protected actions remain owner-gated.

## Response expectations

This project currently has no paid support, bug bounty, or response-time guarantee. Valid reports will be acknowledged and triaged as capacity allows. Coordinated disclosure is requested until a fix or mitigation is available.
