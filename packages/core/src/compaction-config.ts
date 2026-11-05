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
   * Deletion preserves current tree references, snapshot boundaries, recent
   * tips and existing Helia pins. A changed retention lease pauses the pass;
   * `collectGarbage()` can retry retained candidates. One block deletion holds
   * the mutation queue until its I/O settles, then yields to pending work.
   * Candidate metadata is bounded to 32,768 identifiers of at most 512 code
   * units each. This is not a total blockstore quota or browser heap bound.
   * CIDs remain in `_hashes` for incoming-message deduplication.
   *
   * Has no effect when `pruneAfterSnapshot` is false.
   */
  gcAfterPrune: boolean;

  /** Keep at least N recent change nodes after pruning so slightly-behind peers can catch up. */
  keepRecentNodes: number;
}

/**
 * Default compaction configuration.
 * Compaction is disabled by default until explicitly enabled.
 */
export const defaultCompactionConfig: CompactionConfig = {
  enabled: false,
  snapshotInterval: 500,
  minChangesBeforeSnapshot: 100,
  pruneAfterSnapshot: true,
  gcAfterPrune: false,
  keepRecentNodes: 50,
};

export function mergeCompactionConfig(
  overrides?: Partial<CompactionConfig> | null,
): CompactionConfig {
  const definedOverrides = Object.entries(overrides ?? {}).filter(
    ([, value]) => value != null,
  );

  return {
    ...defaultCompactionConfig,
    ...Object.fromEntries(definedOverrides),
  };
}
