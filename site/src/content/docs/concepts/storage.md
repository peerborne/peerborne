---
title: Storage
description: How Peerborne stores documents — local IndexedDB persistence, the Helia blockstore, pinning, recovery, and compaction.
---

## Overview

Peerborne uses **Helia** (the JavaScript IPFS implementation) for
content-addressed storage. For each change, it serializes the CRDT update,
encrypts it with the document key (AES-GCM by default), and stores the resulting
key ID, mode-specific encryption parameters, and ciphertext bytes in the local
Helia blockstore. The CID addresses those encrypted bytes. A separate
signed-when-enabled, encrypted `CRDTSyncMessage` carries the CID and shadow
graph metadata; the stored payload itself has no writer signature or parent
links.

## Implemented model

### Content-addressed blocks

Each stored change payload is an opaque blob:

```
┌─────────────────────────────────────┐
│      Helia change payload bytes     │
├─────────────────────────────────────┤
│  document-key ID                    │
│  nonce / IV / counter               │
│  encrypted change bytes             │
│    └── serialized CRDT change       │
├─────────────────────────────────────┤
│  CID addresses all bytes above      │
└─────────────────────────────────────┘
```

Stored bytes are immutable under their CID. The document's current state is
materialized by the CRDT layer using the separately exchanged shadow sync tree.
Its **frontier** is the current set of unreferenced change CIDs. New local
changes and delivered remote messages update that in-memory graph, while the
CRDT layer resolves concurrent edits.

### Inline vs deferred payloads

The encrypted wire message may carry history inline or defer it to Helia:

- **Inline**: A `CRDTChangeNode` inside the encrypted `CRDTSyncMessage` carries the serialized CRDT change, allowing immediate application after any configured outer-signature check. A first load has no prior writer set for that check.
- **Deferred**: A shadow-tree node carries its kind but omits the change bytes. If the receiver does not already know that CID, it fetches the separately encrypted stored payload and decrypts it.

### No graph links in stored payloads

Peerborne's stored change payloads contain **no graph links**. Parent and
cross-link relationships live in the separately signed-when-enabled,
encrypted shadow tree, whose child map is keyed by stored-payload CIDs. Later
sync messages can therefore add references to known CIDs without rewriting the
stored ciphertext.

## Browser persistence

In the browser, Helia stores blocks in **IndexedDB**:

```ts
import { IDBBlockstore } from 'blockstore-idb';
import { IDBDatastore } from 'datastore-idb';

const blockstore = new IDBBlockstore('/collabswarm-blocks');
// In practice, pass these via PeerborneConfig.helia to initialize()
```

The configured blockstore, datastore, and libp2p peer store use IndexedDB under
the browser origin. Those backends can retain bytes across a tab refresh, but
complete Peerborne reconstruction from that persisted state is not yet an
end-to-end guarantee.

**Current status**: Local block storage works in single-session tests. Complete restart recovery (close browser → reopen → verify document state) has **not been proven in CI**. The blockstore persists, but Helia/libp2p reinitialization and document re-opening after a browser restart are not end-to-end tested.

### No automatic replication factor

Peerborne does not replicate blocks automatically. If you have 3 peers and one stores a block, the other 2 may fetch it on demand (bitswap) or may not. There is no "store on at least N peers" guarantee.

## Pinning status

Pinning is **incomplete**. What exists:

- A `PeerborneNode` listener API for document-publish announcements
- No publisher invocation in the normal core commit path
- No generic IPFS pinning client (e.g., to pin to a remote IPFS node, S3, or Filecoin)

Without pinning:

- No peer can serve its copy while every holder is offline
- If every local copy is cleared or otherwise unrecoverable, the document is lost
- A dedicated "pinning node" (always-on peer) can serve as a poor substitute, but is not integrated

See the [pinning cookbook](../../cookbook/pinning/) for the integration checklist.

![Two browser origins have separate local IndexedDB stores containing only payloads written or fetched there, while a relay forwards but does not retain document blocks; a recovery stack adds keys, graph and authentication context, writer authorization, and reader-membership state.](../../../assets/diagrams/durability-recovery.svg)

**Evidence boundary:** a stored encrypted block is only one recovery input. Full
restart recovery, remote pinning, cross-peer block fetch, and recovery after
compaction are not verified end to end. Clearing the last local copy or running
garbage collection can make data unrecoverable.

## Recovery requirements

The components a peer needs depend on what it needs to do:

### Read-only recovery

A reader that needs to reconstruct document history may require:

1. **The block data** — encrypted stored change payloads (from any peer or pinning service)
2. **The graph structure** — which CIDs form the frontier and its ancestor chain (from the shadow sync graph)
3. **The document key history** — per-epoch document encryption keys (AES-GCM by default)
4. **Authentication context** — the relevant writer ACL/public keys together with a signed sync envelope or snapshot when that verification is available

These inputs do not by themselves authenticate responder-supplied shadow-tree
node kinds or interior topology, nor do they prove that served history is
complete. A quorum-bound first load has no prior writer set for authenticating
the selected outer response and relies on its narrower frontier/CID checks.

### Write recovery

To issue new changes, a peer additionally needs:

5. **Writer capability** — current writer authorization, plus the ECDSA P-384 private key when ordinary document signing is enabled

### Membership recovery

To participate in dynamic group membership (add/remove readers), a peer additionally needs:

6. **The KEM state** — BeeKEM key material (memory-only currently; determining the set of active members requires this)

### Configurable prerequisites

7. **Network reachability** — connection to at least one peer that can serve missing blocks
8. **Q-of-K quorum** — agreement from distinct currently connected peers on the served-frontier hash (enabled by default but configurable)

Losing any of these components may make the corresponding recovery path impossible. Key management and backup are application responsibilities.

## Compaction and garbage collection

### Compaction

Compaction summarizes the current CRDT state in a full-state snapshot and can
prune older nodes from the in-memory shadow tree. Automatic compaction is **off
by default**; writers can still request one directly with
`await document.snapshot();`.

When compaction runs:
1. The current CRDT state is serialized as a full snapshot
2. Its state and boundary metadata are signed when signing is enabled
3. It is included in a signed-when-enabled, encrypted load response rather than stored as a CID-addressed change payload
4. Older nodes are pruned from the in-memory sync tree only when `pruneAfterSnapshot` is enabled
5. Eligible pruned blocks are scheduled for deletion only when both `pruneAfterSnapshot` and `gcAfterPrune` are enabled

Snapshots can reduce replay work, but:

- With pruning enabled, in-memory pruning does not delete Helia blocks unless `gcAfterPrune` is also enabled
- A locally deleted block may still be fetchable from another provider, but there is no replication guarantee
- A quorum-bound first load rejects a snapshot-only response because it has no prior writer set with which to authenticate the snapshot

### Garbage collection

When `pruneAfterSnapshot` and the opt-in `gcAfterPrune` setting are both enabled,
Peerborne asynchronously deletes eligible pruned blocks from the local Helia
blockstore. It protects blocks still reachable from the retained tree and the
snapshot boundary, but deletion is **destructive for that local copy**:

- Deleted blocks disappear from that origin's IndexedDB-backed blockstore
- Recovery then depends on another reachable provider still holding the bytes
- GC is disabled by default

## CI-backed evidence

Verified in CI:

- Block creation, storage, and retrieval in a single browser session
- Encrypted existing history loaded through Circuit Relay
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
