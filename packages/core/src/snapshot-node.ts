/**
 * A snapshot node represents a compacted point in the Merkle-DAG change history.
 *
 * Instead of replaying individual change nodes from the beginning, a peer can
 * load the snapshot state and then apply only post-snapshot changes.
 *
 * @typeParam ChangesType The serialized CRDT type used for both incremental changes
 *   and full-state snapshots. The `state` field contains a snapshot produced by
 *   `CRDTProvider.getSnapshot()`. When the snapshot format differs from incremental
 *   changes, it is applied via `CRDTProvider.applySnapshot()`; otherwise it falls
 *   back to `remoteChange()`.
 *   For Yjs this is `Uint8Array` (from `encodeStateAsUpdateV2`); for Automerge
 *   this is `BinaryChange[]` (wrapping `Automerge.save()` output).
 * @typeParam PublicKey The type of key used to identify a user publicly.
 */
export interface CRDTSnapshotNode<ChangesType, PublicKey> {
  /**
   * Full serialized CRDT state at this point.
   * Produced by `CRDTProvider.getSnapshot(doc)`.
   */
  state: ChangesType;

  /**
   * CID of the most recent change node included in this snapshot.
   * All change nodes up to (and including) this CID are represented by the snapshot state.
   */
  lastChangeNodeCID: string;

  /**
   * Number of change nodes compacted into this snapshot.
   * Used to compare snapshots -- higher count means more compaction.
   */
  compactedCount: number;

  /**
   * Signature of the snapshot creator.
   * Signs a versioned binary payload: [version(1B), timestamp(8B uint64),
   * compactedCount(4B uint32), cidLen(4B uint32), lastChangeNodeCID(cidLen B),
   * stateLen(4B uint32), stateBytes(stateLen B)]. All integers are big-endian.
   * Verified by trying all writer keys rather than relying on the `publicKey` field.
   */
  signature: Uint8Array;

  /**
   * Public key of the snapshot creator (optional on the wire).
   * Not relied upon for verification -- snapshot signatures are verified
   * by trying all writer keys in the ACL. May be absent or degraded
   * after serialization for non-JSON-safe key types (e.g. CryptoKey).
   */
  publicKey?: PublicKey;

  /**
   * Timestamp of snapshot creation (milliseconds since epoch).
   */
  timestamp: number;
}
