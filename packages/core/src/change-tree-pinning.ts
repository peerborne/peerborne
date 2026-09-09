import { CID } from 'multiformats';

import type { CRDTChangeNode } from './crdt-change-node.js';
import { collectBoundedChangeTree } from './change-tree-walk.js';
import { validateRemoteSyncTreeAliases } from './merkle-cross-links.js';

/** Validate a complete inline tree and every CID before pinning can begin. */
export function collectChangeTreeCidsForPinning<ChangesType>(
  rootCid: string,
  root: CRDTChangeNode<ChangesType>,
): string[] {
  const cids: string[] = [];
  const entries = collectBoundedChangeTree(rootCid, root, {
    rejectDeferred: true,
  });
  validateRemoteSyncTreeAliases(rootCid, root);
  for (const { nodeId } of entries) {
    if (nodeId === undefined) continue;
    try {
      CID.parse(nodeId);
    } catch {
      throw new TypeError('Change tree contains a malformed CID');
    }
    cids.push(nodeId);
  }
  return cids;
}
