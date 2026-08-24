# History Compaction Design

## 1. Problem Statement

Peerborne stores document changes as a Merkle-DAG where every edit produces a new `CRDTChangeNode` linked to its parent(s). This design provides causal ordering, deduplication, and tamper detection, but the change history **grows unboundedly**:

- **N edits = N DAG nodes** (plus ACL change nodes for reader/writer modifications)
- Each node is stored encrypted in Helia blockstore and referenced in the sync tree
- The `_lastSyncMessage` carries the entire DAG structure in its `changes` field
- When a new peer joins, `load()` transmits the **full Merkle-DAG** to reconstruct the document

### Impact

| Metric | 100 edits | 10,000 edits | 1,000,000 edits |
|--------|-----------|--------------|-----------------|
| DAG nodes | ~100 | ~10,000 | ~1,000,000 |
| Sync message size | Small | Megabytes | Hundreds of MB |
| Initial load time | < 1s | Seconds | Minutes+ |
| Memory (node refs) | Negligible | Noticeable | Problematic |
| Blockstore size | Small | Tens of MB | Gigabytes |

The core issue: **initial sync time grows linearly** with edit count, making long-lived documents progressively slower to join.

## 2. Proposed Solution: Snapshot Nodes

### 2.1 Overview

Introduce a new node type in the Merkle-DAG: **snapshot nodes**. A snapshot node contains the full serialized CRDT state at a given point in history, acting as a checkpoint. Peers can load from the latest snapshot instead of replaying the entire change history.

```text
Before compaction:
  [change-1] <- [change-2] <- ... <- [change-N] (root)

After compaction:
  [snapshot-at-500] <- [change-501] <- ... <- [change-N] (root)
```

### 2.2 Snapshot Creation

A snapshot is created by an authorized **writer** when the number of un-compacted change nodes exceeds a configurable threshold. The process:

1. Serialize the current CRDT document state via `CRDTProvider.getSnapshot(doc)` (already defined as optional on the interface)
2. Record the CID of the most recent change node included in the snapshot
3. Sign the snapshot with the writer's private key (see Section 2.6 for payload format)
4. Store the snapshot in-memory (`_latestSnapshot`) — it is included only in load/snapshot-load responses, **not** in incremental pubsub sync messages, to avoid bandwidth bloat
5. Optionally prune old change nodes from the in-memory sync tree via `_pruneChanges(keepCount)` (see Section 2.4)

### 2.3 Snapshot Node Format

```typescript
export interface CRDTSnapshotNode<ChangesType, PublicKey> {
  /** Full serialized CRDT state at this point */
  state: ChangesType;

  /** CID of the most recent change node included in this snapshot */
  lastChangeNodeCID: string;

  /** Number of change nodes compacted into this snapshot */
  compactedCount: number;

  /** Signature of the snapshot creator (see Section 2.6 for binary payload format) */
  signature: Uint8Array;

  /** Public key of the snapshot creator (optional; may be absent on the wire) */
  publicKey?: PublicKey;

  /** Timestamp of snapshot creation (milliseconds since epoch) */
  timestamp: number;
}
```

### 2.4 DAG Pruning

After a snapshot is created, the change nodes prior to `lastChangeNodeCID` can be pruned from the in-memory sync tree:

- **Sync tree pruning**: `_pruneChanges(keepCount)` traverses the existing change tree and removes children beyond the most recent `keepCount` document change nodes. ACL nodes (reader/writer changes) are preserved as leaf nodes (children stripped) regardless of depth. The snapshot is stored separately in `_latestSnapshot` and included only in load/snapshot-load responses.
- **Blockstore retention**: By default, blocks remain in the Helia blockstore after pruning. `_pruneChanges` only removes nodes from the in-memory sync message tree (`_lastSyncMessage.changes`). When `gcAfterPrune: true` is set in `CompactionConfig`, `_gcPrunedBlocks` runs after every successful prune to unpin and delete the pruned blocks from the blockstore. A safety filter (`filterDeletableCIDs`) excludes any CID that is still reachable from the post-prune sync tree (e.g. ACL nodes that were re-attached as leaves) as well as the snapshot boundary CID, so accidentally-re-referenced blocks are never deleted. The GC pass is fire-and-forget and its errors are logged rather than fatal.
- **Hash set retention**: The `_hashes` set retains all known CIDs to prevent re-processing, but the actual change data is no longer transmitted during sync. After GC, `_hashes` still contains the deleted CIDs so duplicate inbound sync messages continue to deduplicate; callers that want to fetch the underlying data must do so via the lazy-load API or accept that the block is unavailable locally.

### 2.4.1 Lazy Loading

Once a change has been pruned from `_lastSyncMessage.changes`, its `ChangesType` payload is no longer kept in memory. The public method `PeerborneDocument.loadChangeBlock(cid)` resolves an old CID on demand by calling `blockstore.get()` and decrypting via the document keychain.

Semantics:

- CIDs not in `_hashes` are rejected with `undefined` (refusing to load arbitrary blocks).
- CIDs whose underlying block is missing locally (e.g. it was GC'd and no peer has re-served it) return `undefined`. Callers can decide whether to surface the failure or dial peers via the existing sync protocols.
- Malformed CIDs throw.

`PeerborneDocument.hasChange(cid)` is a cheap synchronous check that callers can use before attempting a lazy load.

The key insight: **CRDTs are designed to converge from any state**. A Yjs `encodeStateAsUpdateV2` produces a snapshot directly applicable via `remoteChange()`. Automerge `save()` produces a compact binary blob that requires `CRDTProvider.applySnapshot()` (which uses `Automerge.load()` + `merge()`) since the save format differs from incremental changes. Either way, the peer arrives at the same state without needing individual change history.

### 2.5 Sync Protocol Update

The document load protocol (`/collabswarm/doc-load/1.0.0`) is updated to:

1. Check if a snapshot exists
2. If yes, send the snapshot node + only post-snapshot changes
3. If no, send the full change history (backward compatible)

A new protocol `/collabswarm/snapshot-load/1.0.0` is added for peers that explicitly request a snapshot (e.g., when they detect they are too far behind).

The `CRDTSyncMessage` type is extended with an optional `snapshot` field:

```typescript
export type CRDTSyncMessage<ChangesType, PublicKey = unknown> = {
  documentId: string;
  changeId?: string;
  changes?: CRDTChangeNode<ChangesType>;
  /** Optional snapshot for fast sync */
  snapshot?: CRDTSnapshotNode<ChangesType, PublicKey>;
  keychainChanges?: ChangesType;
  signature?: string;
};
```

When a peer receives a sync message with a `snapshot` field:
1. Load the snapshot state via `CRDTProvider.applySnapshot(doc, snapshot.state)` when available, or `CRDTProvider.remoteChange(doc, snapshot.state)` as fallback
2. Then apply any post-snapshot changes from the `changes` tree (the snapshot boundary CID is added to `_hashes` so `_mergeSyncTree` skips pre-snapshot nodes)
3. Update the hash set to include the snapshot CID and all post-snapshot CIDs

### 2.6 Snapshot Verification

A snapshot must be verified before applying:

1. **Writer authorization**: The snapshot signature is verified by trying all public keys in the document's writer ACL (the embedded `publicKey` field is not relied upon because some key types like `CryptoKey` do not survive JSON serialization). Before verification, an ACL pre-pass (`_applyACLFromTree`) populates writer keys from the change tree so that fresh `open()` calls can verify snapshots.
2. **Signature verification**: The signature must be valid for the binary signing payload described below
3. **Freshness**: `lastChangeNodeCID` is not currently checked against `_hashes`. New peers joining without existing state trust the snapshot based on writer authorization and the ACL signature chain. Peers with existing state accept snapshots with higher `compactedCount` (or lexicographically greater CID on tie). Freshness enforcement is intentionally deferred to avoid rejecting valid snapshots from peers that are ahead.

**Signing payload format** (binary, big-endian integers):

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 byte | Version (currently `1`) |
| 1 | 8 bytes | Timestamp (uint64, ms since epoch) |
| 9 | 4 bytes | compactedCount (uint32) |
| 13 | 4 bytes | cidLen — length of lastChangeNodeCID (uint32) |
| 17 | cidLen bytes | UTF-8 encoded lastChangeNodeCID |
| ... | 4 bytes | stateLen — length of serialized state (uint32) |
| ... | stateLen bytes | Serialized CRDT state bytes |

For new peers joining (who have no existing state), verification relies on:
- The snapshot being signed by a writer in the ACL they receive
- The ACL itself being verified via the existing signature chain

### 2.7 Concurrent Snapshots

Multiple peers may create snapshots concurrently. This is handled by:

1. **Deterministic tie-break**: Peers compare snapshots using a two-part tuple: (a) highest `compactedCount` wins; (b) if tied, the snapshot whose `lastChangeNodeCID` is lexicographically greatest wins. Timestamps are intentionally excluded from tie-breaking because clock skew between peers would cause divergent snapshot selection.
2. **No conflict**: Snapshots are not changes that need merging -- they are deterministic summaries of the CRDT state at a given point. Two snapshots at the same point produce equivalent CRDT state, but the metadata determines which snapshot is preferred.
3. **Convergence**: After receiving a peer's snapshot, a node replaces its own snapshot if the received one ranks higher by the tie-break tuple above

### 2.8 Configuration

```typescript
export interface CompactionConfig {
  /** Enable automatic compaction */
  enabled: boolean;

  /** Create a snapshot every N document change nodes */
  snapshotInterval: number;

  /** Minimum changes before first snapshot is created */
  minChangesBeforeSnapshot: number;

  /** Whether to prune old DAG nodes from sync messages after snapshot */
  pruneAfterSnapshot: boolean;

  /** Whether to also delete pruned blocks from the Helia blockstore */
  gcAfterPrune: boolean;

  /** Keep at least N most recent change nodes even after pruning */
  keepRecentNodes: number;
}
```

Default values:
- `enabled: false` (opt-in for backward compatibility)
- `snapshotInterval: 500`
- `minChangesBeforeSnapshot: 100`
- `pruneAfterSnapshot: true`
- `gcAfterPrune: false` (opt-in -- destructive; opt-in lets operators reason about retention separately from the cheap in-memory prune)
- `keepRecentNodes: 50`

## 3. Wire Protocol Changes

### 3.1 New Protocol

```text
/collabswarm/snapshot-load/1.0.0
```

Request: Same as `CRDTLoadRequest` (signed document ID)
Response: `CRDTSyncMessage` with `snapshot` field populated

### 3.2 Backward Compatibility

- Peers that do not support compaction ignore the `snapshot` field (it is optional in `CRDTSyncMessage`)
- The existing `/collabswarm/doc-load/1.0.0` protocol continues to work; the snapshot is included as an optimization when available
- Old peers can still sync via the full change tree in the `changes` field
- The `snapshot-load` protocol is only dialed if the peer advertises support (via protocol negotiation)

## 4. Implementation Plan

### Files to Create
1. `packages/core/src/snapshot-node.ts` -- `CRDTSnapshotNode` type
2. `packages/core/src/compaction-config.ts` -- `CompactionConfig` type with defaults

### Files to Modify
1. `packages/core/src/peerborne-document.ts` -- Snapshot creation, load-from-snapshot, compaction triggers
2. `packages/core/src/peerborne-config.ts` -- Add `CompactionConfig` to `PeerborneConfig`
3. `packages/core/src/crdt-sync-message.ts` -- Add optional `snapshot` field
4. `packages/core/src/wire-protocols.ts` -- Add `snapshotLoadV1` constant
5. `packages/core/src/crdt-provider.ts` -- Document `getSnapshot()` requirement for compaction
6. `packages/core/src/index.ts` -- Export new types

### Tests to Create
1. `packages/core/src/snapshot-node.test.ts` -- Snapshot node creation and field validation
2. `packages/core/src/compaction.test.ts` -- Compaction trigger logic, config validation, pruning behavior
