# Peerborne feature and verification audit

This document maps Peerborne's implemented and advertised features to executable
evidence. A passing unit test proves the named component in isolation; it does
not by itself prove browser interoperability, multi-peer behavior, persistence,
or production suitability.

Status meanings:

- **Verified**: a relevant build or test passes in the current repository.
- **Partial**: meaningful automated evidence exists, but an advertised runtime
  path or important interaction remains unverified.
- **Broken**: the repository contains the feature, but its intended acceptance
  path currently fails.
- **Claim only**: documentation advertises the behavior without sufficiently
  direct executable evidence.

## Core document and storage features

| Feature | Status | Current evidence | Missing or adversarial case |
| --- | --- | --- | --- |
| Create, open, change, close, and synchronize documents | Partial | Core and adapter suites; browser-test opens a real encrypted Automerge document in Chromium | Cross-browser mutation and convergence still require a relay-backed acceptance test. |
| Strong eventual consistency under concurrent edits | Partial | Automerge/Yjs adapter tests and convergence benchmark source | The benchmark is not an assertion-based CI gate; partition/rejoin convergence needs a deterministic acceptance test. |
| Automerge adapter | Verified | 77 passing adapter/serializer tests; wiki and browser-test typechecked production builds and Chromium smoke tests | Cross-browser convergence remains a system-level gap. |
| Yjs adapter | Verified | 92 passing tests; password-manager production build | Multi-browser convergence still depends on the separate Playwright/Docker path. |
| Merkle-DAG change history and serialization | Verified | Merkle serialization and cross-link suites | Maliciously deep/wide DAG resource-exhaustion limits need dedicated coverage. |
| Snapshots and history compaction | Verified | Snapshot, compaction, and blockstore-GC suites | Long-running multi-peer compaction during concurrent writes is not exercised. |
| Content-addressed Helia/IPFS persistence | Partial | Core document tests and implementations | Loss/recovery across browser restart and remote pinning are not default acceptance tests. |
| IndexedDB-backed browser storage | Partial | IDB index storage tests; real browser initialization opens document datastore/blockstore successfully | Restart/recovery from persisted document blocks still needs an acceptance test. |
| Bounded caches and block garbage collection | Verified | LRU and blockstore-GC suites | Memory/block growth is benchmarked but has no regression threshold. |

## Networking and availability

| Feature | Status | Current evidence | Missing or adversarial case |
| --- | --- | --- | --- |
| libp2p peer lifecycle and discovery | Partial | Core tests, peer-discovery integration spec | Requires Docker/integration services and is excluded from `yarn test`. |
| Gossipsub document updates | Partial | Core protocol code and integration specs | No default in-process multi-peer acceptance test. |
| WebRTC browser transport | Partial | Browser configuration tests and NAT Playwright specs | NAT suite is an opt-in Docker environment. |
| WebSockets and WebTransport | Claim only | Configured transports | No transport-specific successful synchronization assertion was located. |
| Circuit Relay v2 fallback | Partial | Relay builds; 57 relay tests; NAT specs | Relay failover while an edit is in flight is not a default gate. |
| DCUtR, AutoNAT, STUN/TURN configuration | Partial | Configuration tests and NAT specs | TURN-authenticated relay behavior and privacy-mode configuration need acceptance coverage. |
| Kademlia DHT and bootstrap discovery | Partial | Configuration and peer-discovery specs | Bootstrap outage/replacement and poisoned-peer scenarios are not directly asserted. |
| Document load across NAT boundaries | Verified | Real Peerborne cross-NAT Playwright acceptance test passed twice from clean Podman topologies and has a dedicated CI job | Live post-load pubsub convergence and partition/rejoin remain deferred. |
| Initial-load K-of-Q tip verification | Verified | Load-quorum and orchestrator suites | Real peers serving conflicting DAG blocks should be tested end to end. |
| Network statistics | Verified | Network statistics suite | Reference applications do not expose enough diagnostics for operators. |

## Security and membership

| Feature | Status | Current evidence | Missing or adversarial case |
| --- | --- | --- | --- |
| Public-key user identity and signatures | Verified | SubtleCrypto, ECIES, ACL, and serialization tests | Browser key persistence/export UX is not demonstrated. |
| AES-GCM document/change confidentiality | Verified | Encryption and tamper-failure tests | Metadata leakage and traffic analysis are not addressed by the product claim. |
| Reader/writer ACLs | Verified | ACL and both CRDT adapter ACL suites | A revoked online peer attempting subsequent writes needs a full-network test. |
| ACL chain of trust | Verified | ACL-chain suite | Forked ACL histories across a partition need end-to-end resolution evidence. |
| Capability hierarchy and field capabilities | Verified | Capability suite | Field-level enforcement through document mutation APIs is not demonstrated in an example. |
| UCAN creation, signatures, and delegation chains | Verified | UCAN suite | Expiry/revocation behavior should be demonstrated at the application boundary. |
| Epoch-based key rotation | Verified | Epoch and document-key suites | Rotation under simultaneous membership and document changes needs integration coverage. |
| BeeKEM group key agreement | Verified | BeeKEM tree and welcome suites | Large-group churn and out-of-order delivery need performance and convergence gates. |
| Encrypted welcome messages | Verified | Welcome encryption/wire/handler suites | Offline invite expiry and replay across devices need application-level evidence. |
| Member revocation and path updates | Verified | Revocation and path-update suites | Prove that removed peers cannot decrypt any post-removal content in a multi-peer test. |
| History visibility controls | Partial | Exported API and document implementation | No focused test/example demonstrates all visibility modes to users. |

## Query and framework integration

| Feature | Status | Current evidence | Missing or adversarial case |
| --- | --- | --- | --- |
| React hooks and lifecycle management | Verified | 42 passing hook/cache/lifecycle tests; password-manager typechecked build and Chromium smoke | StrictMode and real reconnect behavior should be browser-tested. |
| Redux actions and reducer integration | Verified | 30 passing tests; both Redux examples typecheck, build, and start in Chromium | Multi-peer action propagation is not yet asserted in a browser. |
| Field extraction and local indexes | Verified | Index manager and extractor suites | Schema evolution and heterogeneous documents need coverage. |
| Memory and IndexedDB index storage | Verified | Storage suites | Migration/versioning behavior is not specified. |
| Blind indexes for encrypted queries | Verified | Provider and query suites | Leakage characteristics, token rotation, and false-positive UX need documentation and tests. |
| Bloom-filter CRDT and peer gossip | Partial | Bloom CRDT/gossip suites; clean `--detectOpenHandles` run | Malformed/hostile high-volume gossip still needs resource limits. |
| React query subscription binding | Verified | Index React suite | No reference application demonstrates distributed search. |

## Applications, packaging, and operations

| Feature | Status | Current evidence | Missing or adversarial case |
| --- | --- | --- | --- |
| Buildable ESM workspace packages | Verified | Topological TypeScript build and full unit suite; exact packed tarballs are inspected and installed in a clean consumer for ESM imports, strict NodeNext typechecking, and a Vite build | Packages are not yet published; registry installation, browser runtime execution, and packaged daemon execution are not tested. |
| Node entry point | Verified | The packed `/node` export imports at runtime and typechecks from a clean consumer on Node 22.19.0 | No clean-consumer Node behavior beyond module import is exercised. |
| Password-manager reference app | Partial | Vite production build and strict Chromium startup smoke test pass | No two-browser synchronization test; bundle is about 2.0 MB minified. |
| Wiki reference app | Partial | Vite production build and strict Automerge-WASM Chromium startup test pass | Article mutation and cross-browser convergence are not yet asserted. |
| Generic browser-test app | Partial | Vite production build, real Helia/libp2p Chromium initialization, and relay-only cross-NAT document load pass | Live post-load cross-browser mutation is not yet asserted. |
| Relay server | Verified | TypeScript build and 57 tests | Deployment smoke test and live health/readiness behavior remain unverified. |
| Docker Compose development environment | Verified | Compose images build and the relay-backed Playwright topology passed twice from clean Podman networks | Docker Engine CI remains the authoritative portability gate. |
| Production deployment guide | Claim only | `docs/deployment.md` and Docker guide files | No automated deployment validation or upgrade/rollback test. |
| Performance benchmarks | Partial | Crypto, sync, convergence, Bloom, and query benchmarks | Results are informational and lack pass/fail budgets. |

## Cross-cutting design findings

1. Public packages, APIs, documentation, and error messages now use
   **Peerborne**. Historical `swarmdb` and `collabswarm` strings remain only
   where changing protocol, key-derivation, Redux, or persisted-storage
   identifiers would break compatibility; see `MIGRATING.md`.
2. The core barrel eagerly imports the complete networking/storage stack. This
   makes simple adapter and serializer consumers pay a large bundle cost and
   increases the chance that environment-specific dependencies leak across the
   browser/Node boundary.
3. The unit suite is broad, but the default command previously ran dependents
   concurrently with artifact-producing builds. A green component suite was
   therefore not equivalent to a reproducible consumer build.
4. The examples are not decorative: they uncovered packaging, router, Redux,
   WASM, Node/browser-boundary, and removed-API failures that unit mocks hid.
5. Security primitives have comparatively strong isolated coverage. The most
   important remaining security gap is system-level proof that revocation,
   quorum loading, and ACL forks behave correctly across hostile peers.
6. The removed legacy `multi-user.spec.ts` claimed data sharing but asserted
   only that several non-empty HTML bodies rendered. It also attached console
   listeners after navigation and logged errors without failing. The transport
   integration app similarly proves plain libp2p/Gossipsub messaging, not a
   Peerborne document, CRDT convergence, encryption, or ACL enforcement.
7. `yarn test:e2e` now runs the three strict application-specific Chromium
   suites. Relay-backed database convergence remains deliberately separate
   instead of being represented by a shell-rendering test.
8. The real cross-NAT topology places the Chromium processes themselves—not
   merely their web servers—on isolated Docker networks. Both apps use one
   persisted identity and must exchange actual encrypted Automerge document
   mutations through the relay. This isolates the networking proof from the
   separate multi-identity invitation workflow.
