/**
 * Blockstore garbage collection helpers for compaction.
 *
 * After compaction prunes the in-memory sync tree, these helpers identify
 * unreferenced blocks that can be deleted from the Helia blockstore.
 *
 * This module is intentionally free of libp2p/helia imports so it can be
 * unit-tested directly. The lazy-load helper used by
 * `PeerborneDocument.loadChangeBlock` lives here for the same reason.
 */

import {
  CRDTChangeNode,
  crdtChangeNodeDeferred,
} from './crdt-change-node.js';

/**
 * Walk a CRDTChangeNode tree (BFS) and collect the CID strings of every
 * node reachable from the root, including the root itself.
 *
 * Nodes whose children are deferred (`crdtChangeNodeDeferred`) are included
 * in the result, but their descendants are not traversed and are therefore
 * excluded from the returned set.
 *
 * @param rootCID  CID string of the root node.
 * @param root     The root CRDTChangeNode.
 * @returns Set of CID strings present in the tree.
 */
export function collectTreeCIDs<ChangesType>(
  rootCID: string,
  root: CRDTChangeNode<ChangesType>,
): Set<string> {
  const cids = new Set<string>();
  cids.add(rootCID);

  const queue: Array<CRDTChangeNode<ChangesType>> = [root];
  let qi = 0;

  while (qi < queue.length) {
    const current = queue[qi++]!;
    if (
      current.children !== undefined &&
      current.children !== crdtChangeNodeDeferred
    ) {
      for (const [childCID, childNode] of Object.entries(current.children)) {
        cids.add(childCID);
        queue.push(childNode);
      }
    }
  }

  return cids;
}

/**
 * Compute the set of CIDs that are safe to delete from the Helia blockstore
 * after pruning.
 *
 * A CID is safe to delete only if it is in the `candidates` set AND it is
 * NOT still reachable from the current in-memory sync tree (since a
 * post-prune sync tree may re-attach ACL nodes that were inside a pruned
 * subtree) AND it is not the snapshot boundary CID (which peers may still
 * request to verify their position in history).
 *
 * @param candidates       CIDs reported as pruned by `_pruneChanges()`.
 * @param retainedRootCID  CID of the root of the post-prune sync tree (or
 *   `undefined` when no sync tree exists yet).
 * @param retainedRoot     Root of the post-prune sync tree (or `undefined`).
 * @param protectedCIDs    Extra CIDs to protect (e.g. snapshot boundary CID,
 *   pinned blocks).
 * @returns Subset of `candidates` that are safe to delete.
 */
export function filterDeletableCIDs<ChangesType>(
  candidates: Iterable<string>,
  retainedRootCID: string | undefined,
  retainedRoot: CRDTChangeNode<ChangesType> | undefined,
  protectedCIDs: Iterable<string> = [],
): Set<string> {
  const reachable =
    retainedRootCID && retainedRoot
      ? collectTreeCIDs(retainedRootCID, retainedRoot)
      : new Set<string>();
  const protectedSet = new Set(protectedCIDs);
  const out = new Set<string>();
  for (const cid of candidates) {
    if (reachable.has(cid)) continue;
    if (protectedSet.has(cid)) continue;
    out.add(cid);
  }
  return out;
}

/**
 * Returns true when an error thrown by `Blockstore.get` indicates the block
 * is simply absent (vs. a decrypt/deserialize failure or other unexpected
 * error). The `interface-store` package exposes a stable `NotFoundError`
 * whose `code === 'ERR_NOT_FOUND'` and `name === 'NotFoundError'`. We
 * duck-type on those fields so we don't take a runtime dependency on
 * `interface-store` and so we still recognise the canonical error type when
 * a backing store wraps or re-throws it.
 */
export function isBlockNotFoundError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const e = err as { code?: unknown; name?: unknown };
  if (e.code === 'ERR_NOT_FOUND') return true;
  if (e.name === 'NotFoundError') return true;
  return false;
}

/**
 * Lazy-load a historical change block by CID.
 *
 * Backs `PeerborneDocument.loadChangeBlock`. Encodes the production
 * semantics for the lazy-load path so they can be exercised by unit tests
 * without standing up the full libp2p/helia stack:
 *
 * - Unknown CIDs (not in `knownHashes`) return `undefined` and the fetcher
 *   is NOT invoked -- callers should only request CIDs they have observed
 *   in the sync tree, snapshot boundary, or via remote tip references.
 * - Malformed CIDs (parse throws) bubble up wrapped in a descriptive Error.
 * - Blockstore "not found" errors (see `isBlockNotFoundError`) map to
 *   `undefined` so callers can fall back to peer fetches.
 * - All other errors (decryption failure, deserialization failure, IO
 *   errors, ...) are rethrown so callers can surface them rather than
 *   masking them as a missing block.
 *
 * Generic over the CID type so this module does not need to import
 * `multiformats` (which would prevent it from being unit-tested in jest's
 * default ts-jest setup). The document-level caller injects `CID.parse`
 * and `_getBlock` to bridge to the real types.
 *
 * @param cid          CID string of the change block to load.
 * @param knownHashes  The document's set of known change CIDs.
 * @param parseCID     Parser for the CID string (typically `CID.parse`).
 *                     Should throw on malformed input.
 * @param fetch        Loader that returns the decrypted+deserialized payload
 *   for a parsed CID. Typically delegates to `PeerborneDocument._getBlock`.
 * @param onMissing    Optional callback invoked when the fetcher reports the
 *   block is missing locally (ERR_NOT_FOUND). Lets callers decide how/whether
 *   to log -- the helper itself does NOT log so it doesn't spam consumers that
 *   routinely probe history for blocks that may have been GC'd locally.
 */
export async function loadChangeBlock<ParsedCID, ChangesType>(
  cid: string,
  knownHashes: Set<string>,
  parseCID: (cid: string) => ParsedCID,
  fetch: (parsedCID: ParsedCID) => Promise<ChangesType>,
  onMissing?: (cid: string, err: unknown) => void,
): Promise<ChangesType | undefined> {
  if (!knownHashes.has(cid)) {
    return undefined;
  }
  let parsedCID: ParsedCID;
  try {
    parsedCID = parseCID(cid);
  } catch (err) {
    // Normalize: parseCID may throw a non-Error value, in which case
    // `(err as Error).message` would yield `undefined`. Always produce a
    // useful message.
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid CID '${cid}': ${msg}`);
  }
  try {
    return await fetch(parsedCID);
  } catch (err) {
    if (isBlockNotFoundError(err)) {
      if (onMissing) {
        onMissing(cid, err);
      }
      return undefined;
    }
    throw err;
  }
}
