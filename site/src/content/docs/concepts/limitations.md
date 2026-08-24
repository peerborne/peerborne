---
title: Limitations
description: Current limitations — what is not yet implemented or verified in Peerborne.
---

Peerborne is under active development. This page catalogs the known gaps between the current implementation and a production-ready system. Every limitation listed here is either not yet implemented or not yet verified in CI.

See the [feature audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md) for the evidence backing each claim, and the [roadmap](../../community/roadmap/) for current development priorities.

## Distribution and operations

- **Packages are unpublished.** The `@peerborne/*` packages are source workspaces, not published to npm. Clean local-tarball installation, Node ESM imports, strict NodeNext typechecking, and a Vite build are automated; registry installation, browser runtime behavior, and packaged daemon execution remain unverified. You must clone and build from source.
- **No deployment automation.** There is no CI/CD pipeline for deploying relays, bootstrap nodes, or pinning services.
- **No upgrade or migration path.** API changes between commits may break your application without warning. There is no changelog, no semver, and no deprecation period.

## Offline and durability

- **Offline editing requires an already-loaded replica.** A document must be opened and loaded before it can be edited offline. Fresh documents cannot be created offline — `Peerborne.initialize()` starts local Helia/libp2p services which can run without network access, but onboarding a new document (resolving its ID to a CID, loading its blocks, establishing quorum agreement) requires network connectivity.
- **No durable outbox.** Changes are published to GossipSub and stored locally, but there is no queue with retry for unreachable peers. If a peer is offline when a change is published, it may never receive it.
- **No delivery acknowledgment.** There is no confirmation that remote peers received, verified, or applied a change. The `document.change()` promise covers local operations only.
- **No automatic reconnection.** If the libp2p connection drops, Peerborne does not reconnect. The application must detect and handle reconnection.
- **No guaranteed at-least-once delivery.** GossipSub is best-effort. Messages may be dropped, delayed, or duplicated.
- **Browser restart recovery not verified.** IndexedDB persists blocks locally, but complete browser restart → reopen → verify document state is not proven in CI.
- **Key loss may be unrecoverable.** Signing keys, KEM keys, and document keys are application-managed. Peerborne has no key backup, recovery, or rotation.

## Storage and persistence

- **No replication factor guarantee.** Peerborne does not ensure blocks are stored on at least N peers. The last online peer is the last surviving copy.
- **Pinning is incomplete.** A `PeerborneNode` listener exists but the core commit path does not publish to it. No generic IPFS pinning client exists. See [pinning cookbook](../../cookbook/pinning/).
- **Compaction is off by default.** Snapshots are not automatic. Compaction can prune blocks needed for recovery.
- **Bootstrap can fail after pruning.** If all pruned blocks are needed to reconstruct a document, and they are not available from any peer, the document cannot be loaded.
- **No garbage collection policy.** GC is manual and destructive. There is no LRU, TTL, or size-limit-based automatic cleanup.

## Networking and availability

- **Browsers typically need a relay.** Browser peers cannot accept incoming connections directly. A Circuit Relay is needed for initial connectivity and as a fallback; direct WebRTC or WebTransport connections may be possible when NAT traversal succeeds, but this is not yet verified in CI.
- **GossipSub is best-effort.** Message delivery is not guaranteed. Late-joining peers miss earlier announcements.
- **Many transports are untested in CI.** WebRTC, WebTransport, and DCUtR are configuration claims without transport-specific sync tests. Only WebSocket has verified end-to-end sync.
- **DHT and AutoNAT have no standalone CI tests.** They are included in the Docker-backed NAT topology but not stress-tested.
- **Relays can censor or drop traffic.** There is no protection against relay-level denial of service. A malicious relay can blackhole all traffic for a peer or topic.
- **Relay identity is not stable across restarts.** The relay generates a new libp2p peer ID on each start.
- **No relay meshing or failover.** Each relay operates independently. If your relay goes down, peers cannot reach each other (unless they have a direct connection).
- **No HTTP health endpoint on relay.** Load balancers and monitoring systems cannot probe relay health.

## Authorization and revocation

- **Signing is currently optional.** A change without a valid writer signature may be accepted depending on configuration.
- **Writer ACL admin is unguarded.** Any existing writer can add or remove other writers. There is no document owner concept or admin-only privilege.
- **Quorum is not Sybil-resistant.** K-of-Q loading can be subverted by a peer controlling multiple bootstrap identities.
- **BeeKEM rekey state is memory-only.** If the node restarts, all knowledge of key rotations is lost. Revoked readers may be able to decrypt content they previously had access to.
- **PathUpdate is best-effort.** There is no guarantee that ACL change notifications reach all peers.
- **No time-bound or conditional access.** Readers and writers are either in the ACL or not. There is no expiration, usage limit, or context-based access control.
- **UCAN capabilities are standalone.** The UCAN module can issue and verify capability tokens, but the document change path does not check them.
- **No automatic or restart-safe key rotation.** Document keys can be rotated on demand via `removeReader()`, which activates a new document key through BeeKEM, but rotation requires explicit application triggers, BeeKEM rekey state is memory-only, and PathUpdate delivery is best-effort.

## Convergence and verification

- **System-level partition/rejoin is not proven.** Single-document convergence works, but multi-document, multi-peer partition/rejoin cycles have no CI coverage.
- **No pass/fail performance budgets.** Benchmark suites exist but have no thresholds. A regression that doubles latency would not be caught in CI.
- **Benchmark runner is broken.** Module resolution errors prevent benchmarks from running. See [roadmap](../../community/roadmap/).
- **Cross-CRDT convergence is not tested.** A Yjs document and an Automerge document being edited by different peers in the same application has no CI coverage.

## Examples and documentation

- **Examples are startup smoke only.** The three example applications (browser-test, wiki-swarm, password-manager) verify single-browser startup. None demonstrate multi-peer collaboration end-to-end.
- **Cookbook snippets are not validated.** Code examples in documentation may drift from the actual API. There is no CI check that documentation code blocks compile against the current source.
- **No migration guide.** There is no guide for upgrading from one Peerborne commit to another.
- **No changelog.** Release notes and version history are not published.

## What is verified

Despite these limitations, several critical paths are verified end-to-end in CI:

- Encrypted document creation, mutation, and retrieval (single browser)
- Cross-NAT document retrieval through Circuit Relay (Docker-backed)
- Document signing and signature verification
- AES-GCM encryption and decryption
- Reader/writer ACL enforcement
- Libp2p peer discovery (bootstrap connection)
- GossipSub message delivery (NAT topology)

Every claim on this site should be understood against this evidence baseline. A positive unit test does not establish complete multi-peer behavior.

## Next steps

- [Roadmap](../../community/roadmap/) — current development priorities
- [Help wanted](../../community/help-wanted/) — specific contribution opportunities
- [Feature audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md) — capability-to-evidence map
- [FAQ](../../community/faq/) — answers to common questions
