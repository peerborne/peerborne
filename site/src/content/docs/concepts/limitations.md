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

- **Offline editing requires local document state.** An already-open replica can be edited without a peer connection, and a new local document can be created when no connected peer serves it. Loading an existing remote document or sharing the new one still requires reachable peers and the needed key material.
- **No durable outbox.** Changes are published to GossipSub and stored locally, but there is no queue with retry for unreachable peers. If a peer is offline when a change is published, it may never receive it.
- **No delivery acknowledgment.** There is no confirmation that remote peers received, verified, or applied a change. The `document.change()` promise covers the local mutation/storage pipeline and the GossipSub publish call, not remote receipt.
- **No durable reconnect-and-replay guarantee.** Libp2p may redial keep-alive peers, and an explicit load or later sync history may catch a peer up, but Peerborne does not durably guarantee connection restoration or replay of every missed update.
- **No guaranteed at-least-once delivery.** GossipSub is best-effort. Messages may be dropped, delayed, or duplicated.
- **Browser restart recovery not verified.** IndexedDB persists blocks locally, but complete browser restart → reopen → verify document state is not proven in CI.
- **Key loss may be unrecoverable.** Signing keys, KEM keys, and document keys are application-managed. Peerborne has no application-facing key backup or recovery service.

## Storage and persistence

- **No replication factor guarantee.** Peerborne does not ensure encrypted payloads are stored on at least N origins. No peer can serve a local copy while every holder is offline, and data is lost if every copy is cleared or otherwise unrecoverable.
- **Pinning is incomplete.** A `PeerborneNode` listener API exists but the normal core commit path does not publish to it. No generic IPFS pinning client exists. See [pinning cookbook](../../cookbook/pinning/).
- **Automatic compaction is off by default.** When enabled, snapshots can prune the in-memory shadow tree; stored blocks are deleted only with opt-in `gcAfterPrune`.
- **Snapshot-only first load can fail.** A quorum-bound first load has no prior writer set for snapshot authentication and rejects a response that contains only a snapshot.
- **No size-based garbage collection policy.** Opt-in post-prune GC is destructive for the local copy. There is no TTL, quota, or size-limit-based automatic cleanup.

## Networking and availability

- **Browsers typically need a relay.** Browser peers cannot accept incoming connections directly. A Circuit Relay is needed for initial connectivity and as a fallback; direct WebRTC or WebTransport connections may be possible when NAT traversal succeeds, but this is not yet verified in CI.
- **GossipSub is best-effort.** Message delivery is not guaranteed. Late-joining peers miss earlier announcements.
- **Many transports lack document-path evidence in CI.** The current cross-NAT proof verifies an initial document-history load through Circuit Relay. Live post-load convergence and transport-specific Peerborne assertions for direct WebRTC, WebTransport, and DCUtR remain unverified.
- **DHT and AutoNAT have no standalone CI tests.** They are included in the Docker-backed NAT topology but not stress-tested.
- **Relays can censor or drop traffic.** There is no protection against relay-level denial of service. A malicious relay can blackhole all traffic for a peer or topic.
- **Relay identity is not stable across restarts.** The relay generates a new libp2p peer ID on each start.
- **No relay meshing or failover.** Each relay operates independently. If your relay goes down, peers cannot reach each other (unless they have a direct connection).
- **No HTTP health endpoint on relay.** Load balancers and monitoring systems cannot probe relay health.

## Authorization and revocation

- **Ordinary document signing is configurable.** With `enableSigning: false`, ordinary sync/load signature gates are disabled for peers holding the needed document key; BeeKEM membership-control messages remain writer-signed.
- **Writer ACL admin is unguarded.** Any existing writer can add or remove other writers. There is no document owner concept or admin-only privilege.
- **Quorum is not Sybil-resistant.** Q-of-K frontier agreement can be subverted by one actor controlling multiple connected peer identities.
- **BeeKEM rekey state is memory-only.** If the node restarts, all knowledge of key rotations is lost. Revoked readers may be able to decrypt content they previously had access to.
- **PathUpdate is best-effort.** There is no guarantee that ACL change notifications reach all peers.
- **No time-bound or conditional access.** Readers and writers are either in the ACL or not. There is no expiration, usage limit, or context-based access control.
- **UCAN capabilities are standalone.** The UCAN module can issue and verify capability tokens, but the document change path does not check them.
- **No automatic or restart-safe key rotation.** Document keys can be rotated on demand via `removeReader()`, which activates a new document key through BeeKEM, but rotation requires explicit application triggers, BeeKEM rekey state is memory-only, and PathUpdate delivery is best-effort.

## Convergence and verification

- **System-level partition/rejoin is not proven.** Single-document convergence works, but multi-document, multi-peer partition/rejoin cycles have no CI coverage.
- **No pass/fail performance budgets.** Benchmark suites exist but have no thresholds. A regression that doubles latency would not be caught in CI.
- **Cross-CRDT convergence is not tested.** A Yjs document and an Automerge document being edited by different peers in the same application has no CI coverage.

## Indexing and distributed search

- **Local indexes are projections, not encrypted source data.** V2 is memory-only by default. Explicit IndexedDB mode stores indexed values and ordering keys in cleartext locally.
- **Pagination is not snapshot isolation.** Cursors are deterministic for one query and generation, but concurrent changes can move rows between pages.
- **Range execution is not yet early-terminating.** `first` limits returned rows, while executors may still exhaust a selected key range; exact counts always do.
- **Distributed search is not wired end to end.** Signed manifests, advertisements, codecs, transport adapters, and candidate federation exist as tested primitives, but production libp2p handlers, collection search-key distribution, automatic advertisement publication, and a secure document-resolver adapter remain unfinished.
- **Remote index claims are not truth.** The coordinator verifies returned candidates through local authorization and predicate checks, but malicious peers can omit results and Sybil identities can distort coverage. Exact global counts and completeness are not claimed.
- **Blind search still leaks metadata.** Equality/frequency and confirmation leakage remains for search-key holders; plaintext mode reveals the entire predicate to recipients.

## Examples and documentation

- **Reference applications are not invitation demos.** The three example applications (browser-test, wiki-swarm, password-manager) verify single-browser startup. A separate NAT-isolated acceptance job proves an encrypted load plus live bidirectional mutations for one identity restored onto two devices; distinct-identity invitation and collaboration remain unverified.
- **Cookbook snippets are not validated.** Code examples in documentation may drift from the actual API. There is no CI check that documentation code blocks compile against the current source.
- **No migration guide.** There is no guide for upgrading from one Peerborne commit to another.
- **No changelog.** Release notes and version history are not published.

## What is verified

CI evidence exists at different scopes:

- **Peerborne cross-NAT acceptance:** one Chromium process creates and mutates a real document; a second NAT-isolated Chromium process uses the same restored signing identity and an out-of-band exported document key, explicitly dials a `/p2p-circuit/` address, and verifies that existing history loads. This proves relay-backed history retrieval, not separate-user onboarding or live post-load convergence.
- **Browser smoke:** browser-test opens a document in one Chromium process; the wiki and password-manager suites assert startup and rendering.
- **Focused component suites:** cover individual protocol, authorization, encryption, and transport behaviors.
- **Transport integration:** exercises NAT and relay topologies independently of complete Peerborne document convergence.

See the feature audit for the per-capability level. A positive component or
transport test does not establish complete multi-peer document behavior.

## Next steps

- [Roadmap](../../community/roadmap/) — current development priorities
- [Help wanted](../../community/help-wanted/) — specific contribution opportunities
- [Feature audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md) — capability-to-evidence map
- [FAQ](../../community/faq/) — answers to common questions
