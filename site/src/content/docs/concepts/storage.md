---
title: Storage
description: How Peerborne stores documents — local IndexedDB persistence, the Helia blockstore, pinning, recovery, and compaction.
---

## Overview

Peerborne uses **Helia** (the JavaScript IPFS implementation) for content-addressed storage. Every document block — a signed, encrypted CRDT update — is stored in a local Helia blockstore backed by IndexedDB in the browser or the filesystem in Node.js. Blocks are addressed by their **CID** (Content Identifier), a SHA-256 hash of the encrypted content.

## Implemented model

### Content-addressed blocks

Every `CRDTChangeBlock` is stored as an opaque blob:

```
┌─────────────────────────────────────┐
│          CRDTChangeBlock             │
├─────────────────────────────────────┤
│  parent: CID of previous tip        │
│  epoch:  current document epoch     │
│  signature: ECDSA P-384             │
│  payload: AES-GCM encrypted         │
│    └── serialized CRDT update       │
├─────────────────────────────────────┤
│  CID: sha256(entire block)          │
└─────────────────────────────────────┘
```

Blocks are immutable. Once stored, a block's CID is stable forever. The document's current state is materialized by the CRDT layer from the **frontier** — the most recent block(s) at the head of the sync graph. New blocks added via `document.change()` extend the frontier, and the CRDT layer resolves any concurrent heads.

### Inline vs deferred payloads

To reduce block size and improve deduplication, Peerborne can split payload content across referenced blocks:

- **Inline**: The full encrypted update is embedded in the `CRDTChangeBlock`.
- **Deferred**: The encrypted update is stored as a separate block referenced by CID from the `CRDTChangeBlock`. Useful when the same encrypted payload appears in multiple sync contexts.

### No Merkle-DAG parent commitment

Peerborne's shadow sync graph does **not** use Merkle hash linking. Blocks reference parents by CID but do not commit to parent hashes. This means the graph structure can change after blocks are written (e.g., adding new parents during catch-up). This is intentional — it allows the sync layer to add concurrent parents discovered later without rewriting blocks.

## Browser persistence

In the browser, Helia stores blocks in **IndexedDB**:

```ts
import { IDBBlockstore } from 'blockstore-idb';
import { IDBDatastore } from 'datastore-idb';

const blockstore = new IDBBlockstore('/collabswarm-blocks');
// In practice, pass these via PeerborneConfig.helia to initialize()
```

Encrypted blocks, IPNS records, and the libp2p peer store are all persisted to IndexedDB under the origin. This means a browser tab refresh should preserve document state.

**Current status**: Local block storage works in single-session tests. Complete restart recovery (close browser → reopen → verify document state) has **not been proven in CI**. The blockstore persists, but Helia/libp2p reinitialization and document re-opening after a browser restart are not end-to-end tested.

### No automatic replication factor

Peerborne does not replicate blocks automatically. If you have 3 peers and one stores a block, the other 2 may fetch it on demand (bitswap) or may not. There is no "store on at least N peers" guarantee.

## Pinning status

Pinning is **incomplete**. What exists:

- A `PeerborneNode` listener that fires when blocks are stored locally
- No publisher in the core commit path (the listener is never notified)
- No generic IPFS pinning client (e.g., to pin to a remote IPFS node, S3, or Filecoin)

Without pinning:

- The last online peer is the last surviving copy
- If all peers go offline and their IndexedDB is cleared, the document is lost
- A dedicated "pinning node" (always-on peer) can serve as a poor substitute, but is not integrated

See the [pinning cookbook](../../cookbook/pinning/) for the integration checklist.

## Recovery requirements

The components a peer needs depend on what it needs to do:

### Read-only recovery

A reader that only needs to reconstruct and verify existing document history requires:

1. **The block data** — encrypted CRDT change blocks (from any peer or pinning service)
2. **The graph structure** — which CIDs form the frontier and its ancestor chain (from the shadow sync graph)
3. **The document key history** — AES-GCM keys to decrypt blocks for each epoch
4. **The writers' public keys** — to verify signatures on existing blocks

### Write recovery

To issue new changes, a peer additionally needs:

5. **The identity key** — ECDSA P-384 signing key to prove authorship

### Membership recovery

To participate in dynamic group membership (add/remove readers), a peer additionally needs:

6. **The KEM state** — BeeKEM key material (memory-only currently; determining the set of active members requires this)

### Configurable prerequisites

7. **Network reachability** — connection to at least one peer or bootstrap node (needed to fetch missing blocks)
8. **Q-of-K quorum** — agreement from bootstrap peers on the current frontier hash (enabled by default but configurable via `loadQuorumK`/`loadQuorumQ`)

Losing any of these components may make the corresponding recovery path impossible. Key management and backup are application responsibilities.

## Compaction and garbage collection

### Compaction

Compaction replaces a chain of blocks with a full-state snapshot. It is **off by default**:

```ts
await document.compact();
```

When compaction runs:
1. The current CRDT state is serialized as a full snapshot
2. The snapshot is signed and encrypted like any other block
3. Older blocks in the chain may be pruned (removed from the local blockstore)

Compaction reduces storage and load time (starting from a snapshot instead of replaying all history), but:
- Pruned blocks cannot be recovered
- Peers that only have pruned blocks cannot reconstruct the document
- Snapshot-only bootstrap can fail if snapshots reference pruned data

### Garbage collection

GC removes blocks that are no longer referenced by any document. It is **destructive**:
- Pruned blocks are deleted from IndexedDB
- Recovery from GC is impossible — the data is gone
- GC is not automatic; the application must trigger it

## CI-backed evidence

Verified in CI:

- Block creation, storage, and retrieval in a single browser session
- Encrypted blocks transmitted through Circuit Relay and stored in the recipient's blockstore
- IndexedDB blockstore initialization and basic read/write

Not verified:

- Complete browser restart and document recovery
- Multi-session persistence (close → reopen → verify)
- Compaction and GC with subsequent recovery
- Pinning publisher integration
- Remote block fetch (bitswap/HTTP) of blocks stored by a different peer

## Next steps

- [Pinning cookbook](../../cookbook/pinning/) — what needs to happen for reliable remote persistence
- [Security model](../security/) — how encryption and signing protect stored data
- [Limitations](../limitations/) — storage-specific limitations