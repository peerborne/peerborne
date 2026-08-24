---
title: CRDTs
description: How Peerborne integrates Yjs and Automerge CRDT libraries — the sync model, convergence, snapshots, and quorum loading.
---

## Design intent

Peerborne does not implement its own CRDT. It adapts existing, well-tested CRDT libraries — Yjs and Automerge — wrapping them with encryption, signing, access control, and peer-to-peer transport. The application interacts with Yjs shared types or Automerge documents directly. Peerborne handles everything else.

The goal: merge edits from multiple peers without a central consensus service, a lock manager, or a leader election protocol. No server assigns a global write order. Two peers editing concurrently produce a deterministic merged result.

## Implemented model

### The `document.change()` lifecycle

```ts
const todos = swarm.doc('/todo-list');
await todos.open();

await todos.change((state) => {
  state.getArray<string>('items').push(['buy milk']);
});
```

Each `document.change()` call produces one committed, encrypted, CID-addressed block:

```
Application calls document.change(fn)
  │
  ▼
fn applied to local CRDT replica (Yjs doc.transact / Automerge doc.change)
  │
  ▼
CRDT update serialized
  │
  ▼
Wrapped in CRDTChangeBlock
  ├── parent: CID of previous tip
  ├── epoch: current document epoch
  ├── signature: ECDSA P-384 over block payload
  └── payload: encrypted CRDT update (AES-GCM)
  │
  ▼
Block stored in Helia blockstore (local IndexedDB)
  │
  ▼
CID published to GossipSub (document topic)
```

### The shadow sync graph

Peerborne does not use a conventional Merkle-DAG. Instead, each `CRDTChangeBlock` references its parent by CID, forming a **shadow sync graph**:

```
Tip (latest) ─── Block C ─── Block B ─── Block A (genesis)
                            └── Block B' (concurrent edit from another peer)

The CRDT layer merges B and B' when both arrive.
The shadow graph preserves the DAG structure for sync,
but the CRDT layer produces the resolved document state.
```

This means:

- Blocks reference their immediate parent(s) by CID — forming a DAG across concurrent writers
- The CRDT layer resolves concurrent edits (e.g., Yjs merges Y.Map updates from two peers)
- Blocks are immutable once stored; the frontier advances as new blocks are added
- The implementation tracks a tip-set (multiple concurrent heads), computing a combined tip-set hash
- The shadow graph is used for sync (walk backward to find missing blocks), not for data modeling

### `CRDTProvider` interface

The `CRDTProvider` interface abstracts the CRDT library from Peerborne's core:

```ts
interface CRDTProvider<DocType, ChangesType, ChangeFnType> {
  newDocument(): DocType;
  localChange(
    document: DocType,
    message: string,
    changeFn: ChangeFnType,
  ): [DocType, ChangesType];
  remoteChange(document: DocType, changes: ChangesType): DocType;
  getHistory(document: DocType): ChangesType;
  getSnapshot?(document: DocType): ChangesType;
  applySnapshot?(document: DocType, snapshot: ChangesType): DocType;
}
```

Four required methods (`newDocument`, `localChange`, `remoteChange`, `getHistory`)
and two optional snapshot methods.

Two implementations exist:

- **YjsProvider** — wraps Yjs `Doc`, `Y.encodeStateAsUpdate`, `Y.applyUpdate`, `Y.encodeStateVector`, `Y.diffUpdate`
- **AutomergeProvider** — wraps Automerge `Doc`, `Automerge.save`, `Automerge.loadIncremental`, `Automerge.getLastLocalChange`

### Yjs semantics

Yjs provides shared types that merge deterministically:

```ts
// Y.Map: deterministic per-key conflict resolution
const ymap = state.getMap('settings');
ymap.set('theme', 'dark');

// Y.Array: concurrent insertions preserved
const yarray = state.getArray('items');
yarray.insert(0, ['first']);

// Y.Text: concurrent character insertions merged
const ytext = state.getText('content');
ytext.insert(0, 'Hello');
```

See the [Yjs schema design cookbook](../../cookbook/yjs-schema-design/) for merge behavior tables, ID patterns, and migration strategies.

### Automerge semantics

Automerge provides a JSON-like CRDT document model:

```ts
// Automerge: concurrent field updates merged
state.title = 'New title';

// Automerge: concurrent list insertions preserved
state.items.push({ text: 'buy milk', done: false });

// Automerge: Text type for rich text
state.content = new Automerge.Text('Hello');
```

## Convergence boundaries

Peerborne does **not** provide:

- **Agreement-right-now.** Two peers editing concurrently will see different states until they exchange updates. There is no real-time synchronization lock.
- **Conflict-free in the database sense.** CRDTs resolve structural conflicts (concurrent edits to the same field), but application-level conflicts (e.g., two peers setting a title to different values) are handled by the CRDT's merge rule, not by application logic.
- **Guaranteed delivery.** Updates are published via GossipSub but not acknowledged. A peer that goes offline before publishing may lose updates.
- **Convergence under partition.** If a peer is partitioned for a long time, its replica diverges. When the partition heals, the CRDT merges. But if the local blocks are lost (e.g., IndexedDB cleared), convergence may fail.

## Snapshots and compaction

### Snapshots

Snapshots are **off by default**. A writer can create a signed, full-state snapshot:

```ts
await document.compact();
```

A snapshot contains the complete CRDT state at that point, signed and encrypted like any other block. Peers loading the document can start from the snapshot instead of replaying the entire change history.

### Compaction

Compaction is **off by default** and uses a preference rule based on compacted-change count. When enabled, it can reduce storage by pruning older blocks. However:

- Pruning removes in-memory CRDT nodes — the document cannot be reconstructed if all pruned blocks are lost
- Snapshot-only bootstrap can fail if snapshots reference pruned blocks
- Snapshot creation is not automatic — the application must trigger it

## Quorum loading

Before trusting a document's state, Peerborne can require Q-of-K bootstrap peers to agree on the current frontier hashes. Quorum is configured via `PeerborneConfig` fields `loadQuorumK` and `loadQuorumQ`, then runs automatically during `document.open()`. This prevents loading a fork or a stale version when multiple peers have written to the document. The quorum check is **not** Sybil-resistant — a peer that controls multiple identities can subvert it.

## CI-backed evidence

Verified end-to-end in CI:

- Document creation, mutation, and retrieval in a single browser
- Yjs and Automerge provider initialization
- Encrypted block storage and retrieval through Circuit Relay
- Cross-NAT document retrieval with Docker-backed topologies

Not verified:

- Multi-peer concurrent editing and convergence under partition
- Snapshot creation and bootstrap from snapshot
- Quorum loading with K > 1
- Compaction and GC with subsequent recovery

## Next steps

- [Yjs schema design](../../cookbook/yjs-schema-design/) — patterns for modeling data with Yjs shared types
- [Security model](../security/) — how signing, encryption, and ACL interact with the CRDT layer