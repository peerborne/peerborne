---
title: Help wanted
description: Concrete evidence, reliability, packaging, documentation, and integration gaps where Peerborne needs contributors.
---

Peerborne already contains substantial CRDT, storage, networking, encryption, ACL, key-management, framework, and indexing primitives. The highest-priority work is proving and completing the end-to-end paths that compose them. See the [feature and verification audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md) for current evidence and the [contributing guide](../contributing/) before starting.

The issue tracker may not have curated beginner tasks. Use [Discussions](https://github.com/Peerborne/peerborne/discussions) to scope an idea and [Issues](https://github.com/Peerborne/peerborne/issues) for reproducible bugs or agreed actionable work. Security-sensitive findings must go through private vulnerability reporting from the repository **Security** tab.

## Priority end-to-end gaps

### Invitations, revocation, and key state

BeeKEM, encrypted welcome messages, ACLs, epochs, path updates, and revocation primitives have focused tests. What is missing is application-level invitation acceptance for a distinct identity, persisted KEM/BeeKEM state, offline/replayed invitation behavior, and multi-peer proof that a revoked member cannot read or write subsequent content.

Useful work includes deterministic acceptance tests, state migration design, adversarial cases, and safe UX that never logs keys or private payloads.

### Persistence and restart recovery

Content-addressed blocks and IndexedDB-backed components exist, but document and identity recovery across browser/process restart needs executable coverage. Test key persistence separately from document blocks, include schema/version migrations, and verify explicit failure behavior when required state is absent.

### Partition and live convergence

CRDT adapters and isolated sync components are tested; current example tests are startup smoke suites. Add deterministic multi-peer mutation, partition, concurrent edit, rejoin, and convergence assertions. Extend the cross-NAT path from initial encrypted retrieval to live post-load synchronization without representing transport-only messaging as database convergence.

### Pinning publisher and restore

Storage and pinning concepts are documented, but a complete publisher, durable remote retention flow, and tested restore path are not established. Contributions should specify trust, authorization, retention, encryption, failure, and recovery boundaries.

### Relay identity, failover, and scale

The relay has unit coverage and NAT acceptance paths. Needed work includes durable relay identity, deployment smoke tests, in-flight failover, multiple-relay selection, churn, abuse/resource limits, observability, and scale evidence.

### External package publication

The six `@peerborne/*` workspaces build, but they are unpublished. Prepare publication only with clean tarball inspection, external-consumer ESM and declaration tests on Node 22.19.0 and browsers, dependency/export verification, and reviewed release automation.

### Documentation and snippet tests

The Site workflow generates TypeDoc Markdown from source during `yarn workspace @peerborne/site build`; generated files are ignored. Improve source API comments or `site/astro.config.mjs`, not generated Markdown. Add executable snippet/link checks so quick-start and cookbook commands cannot silently drift. There is no legacy TypeDoc workflow.

### Benchmark runner and budgets

Core and index benchmark scenarios exist, but the runner currently has a module mismatch. Fix reproducible execution first, then establish representative datasets, environment reporting, baselines, variance handling, and regression budgets before publishing performance claims.

### Distributed search integration

Blind indexes, local stores, Bloom-filter CRDT/gossip, query logic, and React bindings have isolated coverage. Build an integration path that indexes changing encrypted documents across peers, propagates query metadata, handles false positives and token rotation, and verifies restart and schema-evolution behavior. No current example demonstrates this end to end.

## Examples and evidence

`browser-test`, `wiki-swarm`, and `password-manager` build and pass Chromium startup smoke tests through `yarn test:e2e`. They are useful source examples, not complete showcases of invitations, persistence, convergence, pinning, or distributed search. Contributions should state precisely which boundary a new test crosses and avoid production-readiness claims.

Maintainer responses and reviews have no SLA. Small, focused proposals with a reproducible failing case or a clear acceptance criterion are easiest to evaluate.
