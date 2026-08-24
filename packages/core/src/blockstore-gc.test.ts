import { describe, expect, test } from '@jest/globals';
import { collectTreeCIDs, filterDeletableCIDs } from './blockstore-gc.js';
import {
  CRDTChangeNode,
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
  crdtChangeNodeDeferred,
} from './crdt-change-node.js';

type Changes = Uint8Array;

function docNode(
  children?: Record<string, CRDTChangeNode<Changes>>,
): CRDTChangeNode<Changes> {
  return { kind: crdtDocumentChangeNode, children };
}

function aclNode(
  kind: typeof crdtReaderChangeNode | typeof crdtWriterChangeNode,
  children?: Record<string, CRDTChangeNode<Changes>>,
): CRDTChangeNode<Changes> {
  return { kind, children };
}

describe('collectTreeCIDs', () => {
  test('returns only root CID for a leaf node', () => {
    const root = docNode();
    const result = collectTreeCIDs('cid-root', root);
    expect(result).toEqual(new Set(['cid-root']));
  });

  test('collects all CIDs in a linear chain', () => {
    const root = docNode({
      'cid-1': docNode({
        'cid-2': docNode({
          'cid-3': docNode(),
        }),
      }),
    });

    const result = collectTreeCIDs('cid-root', root);
    expect(result).toEqual(new Set(['cid-root', 'cid-1', 'cid-2', 'cid-3']));
  });

  test('collects CIDs across branching children', () => {
    const root = docNode({
      'cid-a': docNode(),
      'cid-b': docNode({
        'cid-c': docNode(),
      }),
    });

    const result = collectTreeCIDs('cid-root', root);
    expect(result).toEqual(new Set(['cid-root', 'cid-a', 'cid-b', 'cid-c']));
  });

  test('includes ACL node CIDs', () => {
    const root = docNode({
      'cid-doc': docNode(),
      'cid-reader': aclNode(crdtReaderChangeNode),
      'cid-writer': aclNode(crdtWriterChangeNode),
    });

    const result = collectTreeCIDs('cid-root', root);
    expect(result).toEqual(
      new Set(['cid-root', 'cid-doc', 'cid-reader', 'cid-writer']),
    );
  });

  test('skips deferred children', () => {
    const root: CRDTChangeNode<Changes> = {
      kind: crdtDocumentChangeNode,
      children: crdtChangeNodeDeferred,
    };

    const result = collectTreeCIDs('cid-root', root);
    expect(result).toEqual(new Set(['cid-root']));
  });

  test('handles undefined children (leaf)', () => {
    const root: CRDTChangeNode<Changes> = {
      kind: crdtDocumentChangeNode,
      children: undefined,
    };

    const result = collectTreeCIDs('cid-root', root);
    expect(result).toEqual(new Set(['cid-root']));
  });

  test('deeply nested tree with mixed ACL and document nodes', () => {
    const root = docNode({
      'cid-1': docNode({
        'cid-2': docNode({
          'cid-3': docNode(),
          'cid-acl-deep': aclNode(crdtReaderChangeNode),
        }),
      }),
      'cid-acl-top': aclNode(crdtWriterChangeNode, {
        'cid-acl-child': aclNode(crdtReaderChangeNode),
      }),
    });

    const result = collectTreeCIDs('cid-root', root);
    expect(result).toEqual(
      new Set([
        'cid-root',
        'cid-1',
        'cid-2',
        'cid-3',
        'cid-acl-deep',
        'cid-acl-top',
        'cid-acl-child',
      ]),
    );
  });
});

describe('blockstore GC integration with pruning', () => {
  /**
   * Simulate what _pruneChanges does: given a tree and keepCount,
   * prune document nodes beyond the limit and collect pruned CIDs.
   * This validates that pruned CID collection is correct; it does NOT
   * mirror the full _pruneChanges() behavior (e.g. preserved ACL nodes
   * are not re-attached to the retained subtree).
   */
  function simulatePrune(
    rootCID: string,
    root: CRDTChangeNode<Changes>,
    keepCount: number,
  ): { prunedCIDs: Set<string>; retainedCIDs: Set<string> } {
    // BFS prune (same algorithm as _pruneChanges)
    const prunedCIDs = new Set<string>();
    const queue: Array<CRDTChangeNode<Changes>> = [root];
    let documentNodesVisited = 0;
    let qi = 0;

    const collectPrunedDocCIDs = (
      children: Record<string, CRDTChangeNode<Changes>>,
    ) => {
      for (const [childHash, childNode] of Object.entries(children)) {
        if (
          childNode.kind !== crdtReaderChangeNode &&
          childNode.kind !== crdtWriterChangeNode
        ) {
          prunedCIDs.add(childHash);
        }
        if (
          childNode.children !== undefined &&
          childNode.children !== crdtChangeNodeDeferred
        ) {
          collectPrunedDocCIDs(childNode.children);
        }
      }
    };

    while (qi < queue.length) {
      const current = queue[qi++]!;
      const isACL =
        current.kind === crdtReaderChangeNode ||
        current.kind === crdtWriterChangeNode;

      if (!isACL) documentNodesVisited++;

      if (
        current.children !== undefined &&
        current.children !== crdtChangeNodeDeferred
      ) {
        if (!isACL && documentNodesVisited >= keepCount) {
          collectPrunedDocCIDs(current.children);
          // Simulate pruning: remove children
          delete current.children;
        } else {
          for (const [, childNode] of Object.entries(current.children)) {
            queue.push(childNode);
          }
        }
      }
    }

    const afterCIDs = collectTreeCIDs(rootCID, root);
    return { prunedCIDs, retainedCIDs: afterCIDs };
  }

  test('keepCount=2 on a 4-node chain prunes 2 document nodes', () => {
    const root = docNode({
      'cid-1': docNode({
        'cid-2': docNode({
          'cid-3': docNode(),
        }),
      }),
    });

    const { prunedCIDs, retainedCIDs } = simulatePrune('cid-root', root, 2);

    // Root + cid-1 are kept (2 document nodes). cid-2 and cid-3 are pruned.
    expect(retainedCIDs).toEqual(new Set(['cid-root', 'cid-1']));
    expect(prunedCIDs).toEqual(new Set(['cid-2', 'cid-3']));
  });

  test('ACL nodes are never pruned even when beyond keepCount', () => {
    const root = docNode({
      'cid-1': docNode({
        'cid-2': docNode({
          'cid-acl': aclNode(crdtReaderChangeNode),
          'cid-3': docNode(),
        }),
      }),
    });

    const { prunedCIDs } = simulatePrune('cid-root', root, 2);

    // cid-2 and cid-3 are pruned document nodes, but cid-acl is ACL and should NOT be pruned
    expect(prunedCIDs).toEqual(new Set(['cid-2', 'cid-3']));
    expect(prunedCIDs.has('cid-acl')).toBe(false);
  });

  test('keepCount larger than tree size prunes nothing', () => {
    const root = docNode({
      'cid-1': docNode(),
    });

    const { prunedCIDs, retainedCIDs } = simulatePrune('cid-root', root, 100);

    expect(prunedCIDs.size).toBe(0);
    expect(retainedCIDs).toEqual(new Set(['cid-root', 'cid-1']));
  });

  test('branching tree prunes across all branches', () => {
    // root -> cid-a, cid-b
    // cid-a -> cid-a1
    // cid-b -> cid-b1
    const root = docNode({
      'cid-a': docNode({
        'cid-a1': docNode(),
      }),
      'cid-b': docNode({
        'cid-b1': docNode(),
      }),
    });

    // keepCount=2: root (1) + first child visited (2) -> prune rest
    const { prunedCIDs } = simulatePrune('cid-root', root, 2);

    // BFS order: root (1), cid-a (2, at limit -> prune children),
    // cid-b (3, beyond limit -> prune children).
    // cid-a and cid-b are retained but their children cid-a1 and cid-b1 are pruned.
    expect(prunedCIDs).toEqual(new Set(['cid-a1', 'cid-b1']));
  });
});

describe('filterDeletableCIDs', () => {
  type Case = {
    name: string;
    candidates: string[];
    retainedRootCID: string | undefined;
    retainedRoot: CRDTChangeNode<Changes> | undefined;
    protectedCIDs?: string[];
    expected: string[];
  };

  const cases: Case[] = [
    {
      name: 'returns all candidates when no retained tree',
      candidates: ['cid-1', 'cid-2'],
      retainedRootCID: undefined,
      retainedRoot: undefined,
      expected: ['cid-1', 'cid-2'],
    },
    {
      name: 'excludes CIDs still reachable from retained tree',
      candidates: ['cid-1', 'cid-2', 'cid-3'],
      retainedRootCID: 'cid-root',
      retainedRoot: docNode({
        'cid-1': docNode(),
      }),
      expected: ['cid-2', 'cid-3'],
    },
    {
      name: 'excludes explicitly protected CIDs (e.g. snapshot boundary)',
      candidates: ['cid-1', 'cid-snap-boundary', 'cid-2'],
      retainedRootCID: undefined,
      retainedRoot: undefined,
      protectedCIDs: ['cid-snap-boundary'],
      expected: ['cid-1', 'cid-2'],
    },
    {
      name: 'protects re-attached ACL leaves inside retained tree',
      candidates: ['cid-doc-1', 'cid-doc-2', 'cid-acl-leaf'],
      retainedRootCID: 'cid-root',
      retainedRoot: docNode({
        'cid-acl-leaf': aclNode(crdtReaderChangeNode),
      }),
      expected: ['cid-doc-1', 'cid-doc-2'],
    },
    {
      name: 'returns empty set when all candidates are reachable or protected',
      candidates: ['cid-1', 'cid-snap'],
      retainedRootCID: 'cid-root',
      retainedRoot: docNode({
        'cid-1': docNode(),
      }),
      protectedCIDs: ['cid-snap'],
      expected: [],
    },
    {
      name: 'returns empty set on empty candidates iterable',
      candidates: [],
      retainedRootCID: 'cid-root',
      retainedRoot: docNode({ 'cid-1': docNode() }),
      expected: [],
    },
    {
      name: 'protects the retained root CID itself',
      candidates: ['cid-root', 'cid-other'],
      retainedRootCID: 'cid-root',
      retainedRoot: docNode(),
      expected: ['cid-other'],
    },
  ];

  for (const c of cases) {
    test(c.name, () => {
      const result = filterDeletableCIDs(
        c.candidates,
        c.retainedRootCID,
        c.retainedRoot,
        c.protectedCIDs ?? [],
      );
      expect(result).toEqual(new Set(c.expected));
    });
  }
});
