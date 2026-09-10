import { CID } from 'multiformats';

import type { CRDTChangeNode } from './crdt-change-node.js';
import { snapshotBoundedChangeTree } from './change-tree-walk.js';
import { validateRemoteSyncTreeAliases } from './merkle-cross-links.js';

/** Validate a complete inline tree and every CID before pinning can begin. */
export function collectChangeTreeCidsForPinning<ChangesType>(
  rootCid: string,
  root: CRDTChangeNode<ChangesType>,
): string[] {
  const cids: string[] = [];
  const { entries, root: snapshot } = snapshotBoundedChangeTree(rootCid, root, {
    rejectDeferred: true,
    canonicalizeNodeId: (nodeId) => CID.parse(nodeId).toString(),
  });
  validateRemoteSyncTreeAliases(rootCid, snapshot);
  for (const { nodeId } of entries) {
    if (nodeId === undefined) continue;
    cids.push(nodeId);
  }
  return cids;
}
