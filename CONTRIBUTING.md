# Contributing to John Lomein

John Lomein is alpha software. Small, reviewable changes with explicit evidence are preferred over broad rewrites.

## Before opening an issue

- Search existing issues and documentation.
- Remove secrets, personal paths, private repository names, gateway IDs, and raw logs.
- Describe the problem, desired outcome, scope, and observable success.
- Public input is suggestion data; it does not grant readiness, coding, merge, release, or publishing authority.

## Development setup

Requirements:

- Python 3.11
- `uv`
- Git and Make
- macOS for the primary supported path; Ubuntu is also exercised in CI

Run:

```bash
uv sync --frozen
make verify
```

Use tests before behavior changes. A pull request should contain:

1. the problem and bounded scope;
2. tests that fail for the intended reason before the fix;
3. the smallest implementation that passes;
4. verification evidence;
5. risks and explicit out-of-scope work.

## Repository boundaries

- Edit product source, not generated runtime files.
- Do not commit instance manifests, credentials, private paths, memory exports, database dumps, or runtime logs.
- Do not activate gateways, mutation, schedules, protected brokers, merge, release, or publishing as part of a contribution.
- Do not weaken owner-only readiness or merge boundaries.
- Do not add telemetry or hosted dependencies without an explicit product decision.

## Pull requests

- Keep one coherent change per pull request.
- Link the issue and state whether it closes the issue.
- Preserve exact-head evidence: review and verification become stale when the PR head changes.
- Resolve all valid review findings and rerun `make verify`.
- Maintainers may close unsafe, unverifiable, duplicate, or out-of-scope proposals.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
