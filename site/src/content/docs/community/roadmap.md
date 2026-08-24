---
title: Roadmap
description: Current development priorities and future directions for Peerborne.
---

Peerborne is under active development. This page tracks the most important gaps between the current implementation and a production-ready system.

## Priority gaps

These are the highest-impact areas of work. See the [help wanted page](../help-wanted/) for specific contribution opportunities.

### 1. Persistence and restart recovery

**Status: Not verified.** Documents store encrypted blocks in browser IndexedDB via Helia's blockstore, but complete close-reopen cycles have not been proven in CI. A browser tab refresh should restore documents without data loss.

What needs to happen:
- CI test that closes a browser, reopens it, and verifies document state
- CI test that persists state across multiple sessions
- CI test for IndexedDB quota handling and cleanup

### 2. Invitations, key exchange, and revocation

**Status: Partially implemented.** The BeeKEM key encapsulation mechanism and reader/writer ACL exist, but the full invitation flow (discover peer, exchange keys, onboard to document) has no end-to-end CI proof. BeeKEM rekey state is memory-only.

What needs to happen:
- End-to-end test of two distinct identities exchanging keys and accessing a shared document
- Durable BeeKEM state (survives restart)
- PathUpdate revocation tested with live peers

### 3. Partition and live convergence

**Status: Not proven.** Single-document convergence has been verified in CI, but system-level partition/rejoin scenarios (split network, make conflicting edits on both sides, heal partition, verify convergence) have no CI coverage.

What needs to happen:
- CI test for network partition → conflicting edits → heal → verify convergence
- CI test for multiple concurrent writers on different network paths
- CI test for slow/unreliable peer scenarios

### 4. Pinning publisher and restore

**Status: Incomplete.** A `PeerborneNode` listener exists for pinning events, but the core commit path does not publish to it. No generic IPFS pinning client exists. Blocks can be stored but cannot be recovered into a working document without the full key and graph state.

What needs to happen:
- Publisher integration so every block write fires a pinning event
- Generic pinning client (e.g., to a remote IPFS node or S3-compatible store)
- Restore flow with CI verification (pin → destroy local state → restore from remote)

### 5. Relay identity, failover, and scale

**Status: Limited.** The relay server is functional for development but restarts change peer IDs, there is no meshing or failover, and abuse resistance is unverified. Multi-relay topologies exist in Docker Compose but have no automated scale or failover tests.

What needs to happen:
- Stable relay identity (persistent peer ID across restarts)
- Relay meshing for multi-relay deployments
- CI test for relay failover (kill one relay, verify peers reconnect through another)

### 6. External package publication

**Status: Not implemented.** The `@peerborne/*` packages are source workspaces, not published to npm. The release workflow (#321) defines the publication pipeline but npm scope ownership, `NPM_TOKEN`, and publication gates are not yet configured.

What needs to happen:
- npm scope `@peerborne` claimed
- `NPM_TOKEN` and `NPM_PUBLISH_ENABLED` secrets configured
- First npm release published
- External consumer validation (import from npm, build, run)

### 7. Documentation and snippet tests

**Status: Ongoing.** Documentation code snippets are not validated against the actual API. Examples compile but cookbook snippets may drift.

What needs to happen:
- TypeScript snippet extraction and validation pipeline
- CI check that all code blocks in docs match the current API surface

### 8. Benchmark budgets and runner

**Status: Runner broken.** Benchmark suites exist for convergence simulation, CRDT sync latency, crypto overhead, blind-index performance, bloom-filter scaling, and index-query scaling, but the runner has a module mismatch. No pass/fail thresholds exist.

What needs to happen:
- Fix benchmark runner module resolution
- Establish baseline metrics in CI
- Set pass/fail thresholds for regressions

### 9. Distributed search integration

**Status: Deferred.** Bloom-filter gossip returns candidate peer IDs but does not execute remote queries or aggregate results.

What needs to happen:
- Remote query protocol (send query to candidate peers, collect results)
- CI test for multi-peer search with bloom pre-filtering
- Privacy analysis of bloom-filter information leakage

### 10. Examples as complete showcases

**Status: Startup smoke only.** The three examples (browser-test, wiki-swarm, password-manager) verify single-browser startup but do not demonstrate multi-peer collaboration, sharing, or recovery.

What needs to happen:
- Multi-browser CI tests for each example
- Document sharing flow in wiki-swarm
- Key exchange and permission management in password-manager
- Offline → online → convergence in browser-test

### 11. Transport abstraction and Reticulum adapter

**Status: Planned; not currently supported.** The core currently constructs Helia/libp2p networking directly. Reticulum is not a configuration switch for that stack, so claiming support would be premature.

What needs to happen:
- Separate document synchronization from the current Helia/libp2p transport implementation
- Define bounded message, retry, acknowledgement, and durable-outbox behavior
- Build a companion adapter over [Reticulum Links and Resources](https://reticulum.network/manual/understanding.html) or LXMF
- Verify two intermittently connected peers can edit during a partition, exchange encrypted state after reconnecting, and converge
- Document the metadata, identity, throughput, and operational trade-offs of the adapter

## Completed recently

- Rebrand the public packages and APIs as Peerborne while retaining legacy wire, key-derivation, Redux, and IndexedDB identifiers for compatibility
- Documentation site with Starlight (concepts, cookbook, API reference, community)
- Cross-NAT encrypted document retrieval verified in CI
- Release workflow with secretless validation and gated publishing
- Community contributor guide with Docker readiness helpers

## How to contribute

See the [contributing guide](../contributing/) for setup instructions and the [help wanted page](../help-wanted/) for specific tasks. The [feature audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md) is the definitive capability map — every claim should be backed by CI evidence.
