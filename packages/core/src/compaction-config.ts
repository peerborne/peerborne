/**
 * Configuration for history compaction behavior.
 *
 * Compaction creates snapshot nodes in the Merkle-DAG that summarize
 * the full CRDT state, allowing peers to skip replaying the full change history.
 */
export interface CompactionConfig {
  /** Enable automatic compaction; when false, only manual `document.snapshot()` is available. */
  enabled: boolean;

  /** Create a snapshot every N document changes (ACL changes do not count). */
  snapshotInterval: number;

  /** Minimum document changes before the first snapshot, to avoid premature snapshots. */
  minChangesBeforeSnapshot: number;

  /** Prune old nodes from the in-memory sync tree after a snapshot. ACL nodes are always preserved. */
  pruneAfterSnapshot: boolean;

  /**
   * After pruning the in-memory sync tree, delete the orphaned blocks from the
   * Helia blockstore. Opt-in because deletion is destructive: once a block is
   * gone, peers that lazy-load it via {@link PeerborneDocument.loadChangeBlock}
   * or that re-broadcast the change will not be able to fetch the data locally.
   *
   * Only blocks that are no longer reachable from the in-memory sync tree (and
   * are not the snapshot boundary CID) are deleted, so accidentally re-attached
   * ACL nodes are safe. CIDs remain in the in-memory `_hashes` set so duplicate
   * incoming sync messages are still deduplicated.
   *
   * Has no effect when `pruneAfterSnapshot` is false.
   */
  gcAfterPrune: boolean;

  /** Keep at least N recent change nodes after pruning so slightly-behind peers can catch up. */
  keepRecentNodes: number;
}

/**
 * Default compaction configuration.
 * Compaction is disabled by default for backward compatibility.
 */
export const defaultCompactionConfig: CompactionConfig = {
  enabled: false,
  snapshotInterval: 500,
  minChangesBeforeSnapshot: 100,
  pruneAfterSnapshot: true,
  gcAfterPrune: false,
  keepRecentNodes: 50,
};
