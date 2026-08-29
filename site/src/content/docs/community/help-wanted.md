---
title: Help wanted
description: Concrete evidence, reliability, packaging, documentation, and integration gaps where Peerborne needs contributors.
---

Peerborne already contains substantial CRDT, storage, networking, encryption, ACL, key-management, framework, and indexing primitives. The highest-priority work is proving and completing the end-to-end paths that compose them. See the [feature and verification audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md) for current evidence and the [contributing guide](../contributing/) before starting.

The issue tracker may not have curated beginner tasks. Use [Discussions](https://github.com/Peerborne/peerborne/discussions) to scope an idea and [Issues](https://github.com/Peerborne/peerborne/issues) for reproducible bugs or agreed actionable work. Security-sensitive findings must go through private vulnerability reporting from the repository **Security** tab.

## Priority end-to-end gaps

### Invitations, revocation, and key state

The initial founder-plus-one flow has a distinct-identity, cross-NAT acceptance
test. What remains is persisted KEM/BeeKEM and replay state, offline/delayed
acceptance, larger-group add-side updates, and multi-peer proof that a revoked
member cannot read or write subsequent content.

Useful work includes deterministic acceptance tests, state migration design, adversarial cases, and safe UX that never logs keys or private payloads.

### Persistence and restart recovery

Content-addressed blocks and IndexedDB-backed components exist, but document and identity recovery across browser/process restart needs executable coverage. Test key persistence separately from document blocks, include schema/version migrations, and verify explicit failure behavior when required state is absent.

### Partition and live convergence

CRDT adapters and isolated sync components are tested, and the dedicated
cross-NAT invitation job asserts live post-join mutation in both directions.
Add deterministic partition, concurrent edit, rejoin, and exact convergence
assertions without representing transport-only messaging as database
convergence.

### Pinning publisher and restore

Storage and pinning concepts are documented, but a complete publisher, durable remote retention flow, and tested restore path are not established. Contributions should specify trust, authorization, retention, encryption, failure, and recovery boundaries.

### Relay identity, failover, and scale

The relay has unit coverage and NAT acceptance paths. Needed work includes durable relay identity, deployment smoke tests, in-flight failover, multiple-relay selection, churn, abuse/resource limits, observability, and scale evidence.

### External package publication

The six `@peerborne/*` workspaces build, but they are unpublished. Prepare publication only with clean tarball inspection, external-consumer ESM and declaration tests on Node 22.19.0 and browsers, dependency/export verification, and reviewed release automation.

### Documentation and snippet tests

The Site workflow generates TypeDoc Markdown from source during `yarn workspace @peerborne/site build`; generated files are ignored. Improve source API comments or `site/astro.config.mjs`, not generated Markdown. Add executable snippet/link checks so quick-start and cookbook commands cannot silently drift. There is no legacy TypeDoc workflow.

### Benchmark runner and budgets

Core and index benchmark scenarios now execute reproducibly as ESM. Establish representative datasets, environment reporting, baselines, variance handling, and regression budgets before publishing performance claims.

### Distributed search integration

The signed manifest, expiring advertisement, direct-query, transport-adapter, and candidate-verification layers have isolated coverage. Build collection search membership and dedicated key distribution, register bounded libp2p handlers, implement the authorized document resolver, publish automatically rotated blind-token snapshots, and verify hostile peers, restart, revocation, partition/rejoin, and schema/key evolution. No current example demonstrates this end to end.

## Examples and evidence

`browser-test`, `wiki-swarm`, and `password-manager` build and pass Chromium startup smoke tests through `yarn test:e2e`. They are useful source examples, not complete showcases of invitations, persistence, convergence, pinning, or distributed search. Contributions should state precisely which boundary a new test crosses and avoid production-readiness claims.

Maintainer responses and reviews have no SLA. Small, focused proposals with a reproducible failing case or a clear acceptance criterion are easiest to evaluate.
