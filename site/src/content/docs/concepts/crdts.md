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

Each `document.change()` call creates a CID-addressed stored payload and a
separate wire message:

```
Application calls document.change(fn)
  │
  ▼
fn applied to local CRDT replica (Yjs doc.transact / Automerge doc.change)
  │
  ▼
CRDT change serialized and encrypted with the document key
  (AES-GCM by default)
  │
  ▼
Ciphertext stored in Helia → CID
  │
  ▼
CRDTSyncMessage built
  ├── new CID
  ├── inline shadow change tree
  └── deferred CID references
  │
  ▼
Complete message signed when enabled, serialized, and encrypted with the document key
  (AES-GCM by default)
  │
  ▼
Full encrypted envelope published to GossipSub (document topic)
```

### The shadow sync graph

Peerborne does not put graph links inside each stored change payload. Instead,
the separately exchanged `CRDTSyncMessage` carries a **shadow sync graph** whose
node keys are CIDs:

```
CRDTSyncMessage root: CID C (inline change)
  └── CID B (inline prior change)
      ├── CID A (inline ancestor)
      └── CID B' (deferred concurrent cross-link)

The CRDT layer merges B and B' when both arrive.
The shadow tree guides discovery; stored payloads contain encrypted
serialized changes but no parent links.
```

This means:

- Child-map keys in the wire tree reference prior or concurrent change CIDs
- The CRDT layer resolves concurrent edits (e.g., Yjs merges Y.Map updates from two peers)
- Stored ciphertext is immutable under its CID; later messages can reference it without rewriting it
- The implementation tracks a tip-set (multiple concurrent heads), computing a combined tip-set hash
- Receivers apply inline tree content and fetch only missing or deferred stored payloads
- The shadow graph is used for synchronization, not for application data modeling

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

Automatic snapshots are **off by default**. A writer can create a full-state
snapshot, signed when signing is enabled (the signature field is empty otherwise):

```ts
await document.snapshot();
```

A snapshot contains the complete CRDT state at that point plus boundary
metadata, which is signed when signing is enabled. It is carried inside an
encrypted load or snapshot-load response rather than stored as a CID-addressed
Helia change payload. A peer that can authenticate and apply it can avoid
replaying the entire change history.

### Compaction

Automatic compaction is **off by default**. When enabled, configured change-count
thresholds call `snapshot()` and may prune older nodes from the in-memory shadow
tree. This does not delete stored block bytes unless opt-in `gcAfterPrune` is
also enabled. In particular:

- In-memory pruning can limit the history included in later sync messages
- Opt-in block GC deletes eligible local copies, so recovery then depends on another provider
- A quorum-bound first load rejects a snapshot-only response because it lacks a prior writer set for snapshot authentication
- Applications can call `snapshot()` manually even when automatic compaction is disabled

## Quorum loading

Before accepting a remote document state, Peerborne can require Q-of-K distinct
currently connected peers to agree on a served-frontier hash. Quorum is
configured through `PeerborneConfig` and runs automatically during
`document.open()` when enabled. Agreement and response binding reduce the risk
of one peer unilaterally selecting a frontier; they do not authenticate the
interior shadow tree or prove complete history. The check is **not
Sybil-resistant** — one actor controlling multiple peer identities can subvert
it.

## CI-backed evidence

Verified in CI:

- Document creation, mutation, and retrieval in a single browser
- Yjs and Automerge provider initialization
- Encrypted existing-history retrieval through Circuit Relay
- Cross-NAT document retrieval with Docker-backed topologies
- Snapshot, compaction, and blockstore-GC behavior in focused suites
- Initial-load quorum decisions and orchestration in focused suites

Not verified:

- Multi-peer concurrent editing and convergence under partition
- Snapshot bootstrap across real peers
- Conflicting real peers serving adversarial shadow trees during quorum loading
- Long-running multi-peer compaction and GC followed by recovery

## Next steps

- [Yjs schema design](../../cookbook/yjs-schema-design/) — patterns for modeling data with Yjs shared types
- [Security model](../security/) — how signing, encryption, and ACL interact with the CRDT layer
