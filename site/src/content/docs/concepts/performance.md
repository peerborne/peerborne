---
title: Performance
description: Performance characteristics, benchmarks, tuning guidance, and current limitations.
---

Peerborne makes several deliberate performance tradeoffs to balance security, consistency, and resource use. This page documents the design decisions, benchmark suites, and tuning guidance.

## Design decisions

### Load concurrency cap

Document loading fetches blocks via libp2p bitswap. Without a bound, every requested CID would fetch in parallel, exhausting per-connection stream quotas and pressuring memory. The loader caps concurrent inflight fetches at 8, chosen to overlap WAN-latency-bound bitswap requests while bounding peak resource use.

Source: [`peerborne-document.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/peerborne-document.ts) — `LOAD_PREFETCH_MAX_CONCURRENCY` and the bounded worker pool for blockstore fetches.

### Load quorum defaults

Document open verifies the tip state against K peers to defend against a dishonest or stale peer:

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| `loadQuorumK` | 3 | Majority of 3 defends against a single dishonest peer without noticeably impacting open latency |
| `loadQuorumTimeoutMs` | 5000 | Larger than typical WAN RTT + protocol negotiation, but bounds stall to ~5 seconds for partitioned peers |

Source: [`peerborne-config.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/peerborne-config.ts) — `loadQuorumK` and `loadQuorumTimeoutMs` documentation. Verified by [`load-quorum.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/load-quorum.test.ts) (pure decision logic) and [`load-quorum-orchestrator.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/load-quorum-orchestrator.test.ts) (integration: all-agree, majority-with-dissenter, insufficient responses, single-peer fallback).

### Parallel deserialization

Both CRDT adapters use parallel deserialization for cold-cache performance to reduce time-to-interactive when opening large documents:

- [`peerborne-automerge.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/automerge/src/peerborne-automerge.ts)
- [`peerborne-yjs.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/yjs/src/peerborne-yjs.ts)

### Revocation latency

The BeeKEM ratchet-tree key rotation closes the revocation-latency gap of earlier "encrypt new key under old key" schemes. A removed reader cannot derive the new key even if connected at the moment of revocation. Source: [`peerborne-document.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/peerborne-document.ts) and [`wire-protocols.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/wire-protocols.ts).

### GC and bounded caches

- **LRU cache**: Used for document change blocks and key material. Limits unbounded memory growth. Verified by [`lru-cache.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/lru-cache.test.ts).
- **Compaction**: Prunes in-memory CRDT nodes and removes unreferenced blocks. Verified by [`compaction.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/compaction.test.ts) and [`blockstore-gc.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/blockstore-gc.test.ts).
- **React hook caches**: Module-level task and subscriber-count caches with ref-counting eviction. Verified by [`hooks-cache.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/react/src/hooks-cache.test.ts) and [`hooks-lifecycle.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/react/src/hooks-lifecycle.test.ts).

## Benchmark suites

Peerborne includes six benchmark suites across two packages. Each suite uses a statistical runner that reports min, max, mean, median, p99, and standard deviation with warmup iterations and optional memory-delta tracking.

### Core benchmarks

Source: [`packages/core/src/__benchmarks__/`](https://github.com/Peerborne/peerborne/tree/main/packages/core/src/__benchmarks__)

| Suite | File | What it measures |
|-------|------|-----------------|
| **CRDT Sync Latency** | [`crdt-sync-latency.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/__benchmarks__/crdt-sync-latency.ts) | Per-operation latency of the change pipeline at payload sizes 1 KB to 1 MB: ECDSA P-384 sign/verify, AES-GCM encrypt/decrypt, combined sign+encrypt and decrypt+verify pipelines, JSON serialize/deserialize |
| **Crypto Overhead** | [`crypto-overhead.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/__benchmarks__/crypto-overhead.ts) | Key generation cost (ECDSA P-384, AES-GCM-256), key rotation at 10 KB, plaintext vs encrypted change propagation across sizes, isolated crypto operation overhead |
| **Convergence Simulation** | [`convergence-simulation.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/__benchmarks__/convergence-simulation.ts) | Simulated multi-peer convergence: 2–32 peers making concurrent edits through the full sign-encrypt-broadcast-decrypt-verify pipeline, measures time-to-convergence, message count, and bandwidth |

### Index benchmarks

Source: [`packages/index/src/__benchmarks__/`](https://github.com/Peerborne/peerborne/tree/main/packages/index/src/__benchmarks__)

| Suite | File | What it measures |
|-------|------|-----------------|
| **Index Query Scaling** | [`index-query-scaling.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/index/src/__benchmarks__/index-query-scaling.ts) | Query latency vs index size: 100–100K documents. Exact-match, range, prefix, compound, and sorted queries against MemoryIndexStorage, plus single-document update cost and full-scan baseline |
| **Bloom Filter Scaling** | [`bloom-filter-scaling.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/index/src/__benchmarks__/bloom-filter-scaling.ts) | Insert throughput at filter sizes 1K–1M bits, positive/negative query time, false-positive rate at fill counts 100–10K, serialization/deserialization time, CRDT merge (join) time, memory footprint |
| **Blind Index Performance** | [`blind-index-perf.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/index/src/__benchmarks__/blind-index-perf.ts) | Encrypted search operations: field-key derivation (HKDF), single/compound token generation, token match/mismatch comparison, field-count scaling (1–16 fields), batch throughput (100 tokens) |

## Performance-aware tests

Several test suites exercise performance-critical paths:

| Test suite | Path | What it covers |
|-----------|------|----------------|
| Load quorum | [`load-quorum.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/load-quorum.test.ts) | Quorum decision logic, hash-binding comparison, config validation |
| Load quorum orchestrator | [`load-quorum-orchestrator.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/load-quorum-orchestrator.test.ts) | Multi-peer quorum scenarios including timeout and insufficient-response paths |
| LRU cache | [`lru-cache.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/lru-cache.test.ts) | Eviction correctness, capacity bounds, size tracking |
| Blockstore GC | [`blockstore-gc.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/blockstore-gc.test.ts) | CID collection, deletable-filtering, tree-shape coverage |
| Compaction | [`compaction.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/compaction.test.ts) | Config defaults, GC decision logic, prune+GC integration |
| Network statistics | [`network-stats.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/network-stats.test.ts) | Message/byte counters, connection tracking, snapshot isolation |
| React hook caches | [`hooks-cache.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/react/src/hooks-cache.test.ts) and [`hooks-lifecycle.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/react/src/hooks-lifecycle.test.ts) | Cache population, ref-counted eviction, per-document isolation |
| Cross-NAT throughput | [`nat-resilience.spec.ts`](https://github.com/Peerborne/peerborne/blob/main/e2e/integration/nat-resilience.spec.ts) | 10-message bidirectional burst across NAT boundaries with delivery threshold |

## Document size guidance

- **~1 MB threshold**: Consider splitting documents when encoded state exceeds ~1 MB. Decoding and encoding cost degrades with very large documents.
- **Browser limits**: Tens of MB may cause performance issues in browsers.
- **Tombstone accumulation**: Operations that frequently delete and re-add items in Y.Array create permanent tombstones (~40–80 bytes each) that grow document size monotonically. Batch mutations in [Yjs transactions](https://docs.yjs.dev/getting-started/working-with-shared-types#transactions) to reduce overhead.
- **Nesting depth**: Keep nested types to 2–3 levels.

See the [Yjs schema design cookbook](../../cookbook/yjs-schema-design/) for detailed guidance on document structure and size management.

## Network latency

- GossipSub delivers updates with sub-second latency in typical deployments.
- Local writes apply with zero network latency — changes are visible immediately on the local replica.
- WebTransport provides a QUIC-based transport with reduced head-of-line blocking compared to TCP-based WebSockets.
- DCUtR establishes direct WebRTC connections between peers behind NATs, reducing relay load and latency.

## Relay tuning

When operating a Circuit Relay server under load:

- Increase `ulimit -n` for many concurrent connections.
- Set `NODE_OPTIONS=--max-old-space-size=4096` for memory headroom.
- Monitor event loop lag.
- For large deployments, tune GossipSub parameters (`D`, `Dlo`, `Dhi`, `heartbeatInterval`) in [`relay-server/src/index.ts`](https://github.com/Peerborne/peerborne/blob/main/relay-server/src/index.ts).
- Client-side: `circuitRelayTransport({ reservationConcurrency: 1 })` — increase for redundancy at the cost of additional relay connections.

See the [running a relay cookbook](../../cookbook/running-a-relay/) for setup instructions.

## Network statistics

`NetworkStats` provides counters for messages/bytes sent and received, document open/close lifecycle events, and connection tracking. Applications can use `snapshot()` to inspect current state. Verified by [`network-stats.test.ts`](https://github.com/Peerborne/peerborne/blob/main/packages/core/src/network-stats.test.ts).

## Current limitations

- **Benchmark runner is broken.** A module resolution mismatch (ESM output marked as CommonJS) prevents benchmarks from running. Fixing the runner is on the [roadmap](../../community/roadmap/).
- **No pass/fail performance budgets.** Benchmarks exist but have no thresholds in CI. A regression that doubles latency would not be caught automatically.
- **Bundle size.** The core barrel eagerly imports the complete networking/storage stack. Example application bundles are approximately 2.0 MB minified.
- **No automated bottleneck detection.** There is no profiling or flame-graph generation in CI.

## Running benchmarks

```sh
# Core benchmarks (currently broken — see limitations above)
yarn workspace @peerborne/core benchmark --iterations 100

# Index benchmarks (currently broken — see limitations above)
yarn workspace @peerborne/index benchmark --iterations 100
```

Both suites output Markdown tables with statistical summaries. The `--iterations` flag controls the sample count (default 100).
