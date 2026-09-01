# Release and version policy

John Lomein follows Semantic Versioning where practical.

## Alpha series

Versions below `1.0.0` are experimental. Minor releases may change manifests, generated runtime layout, hooks, profile contracts, state schemas, or operator workflows. Every alpha release must state breaking changes and migration steps.

## Version meaning

- Patch: compatible fixes, tests, and documentation.
- Minor before 1.0: new capability or an intentional contract change, possibly breaking.
- Major: stable-contract breaking change after 1.0.

## Release gate

A release requires:

1. a clean source tree and `make verify` on Ubuntu and macOS;
2. security/privacy scans with no unresolved failure;
3. migration and rollback notes for state or manifest changes;
4. exact-head review evidence;
5. an owner decision for tag, release notes, and any publication.

Automated agents may prepare evidence. They may not tag, release, publish, or change settings unless a separately approved protected mechanism is enabled. The invite-only pilot uses manual owner merges.

## Compatibility

macOS is the primary supported platform. Ubuntu CI protects portable product logic. Other platforms are unverified unless a release explicitly says otherwise.

## npm

The planned npm package is a thin onboarding front door around the Python/Hermes product. It is not a Node rewrite. No npm publication occurs until the intended publisher identity is verified and the owner approves the exact package contents and version.
