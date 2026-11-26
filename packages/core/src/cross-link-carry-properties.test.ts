import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  crdtChangeNodeDeferred,
  crdtDocumentChangeNode,
  type CRDTChangeNode,
} from './crdt-change-node.js';
import { collectBoundedChangeTree } from './change-tree-walk.js';
import {
  carryRemoteSubtree,
  citedWithoutChanges,
  collectCoveredBySnapshot,
  describedCids,
  findInlineNodes,
  validateRemoteSyncTreeAliases,
} from './merkle-cross-links.js';

type Node = CRDTChangeNode<string>;

function inline(rootId: string, root: Node): Set<string> {
  return new Set(
    collectBoundedChangeTree(rootId, root).flatMap(({ nodeId, change }) =>
      nodeId !== undefined && change !== undefined ? [nodeId] : [],
    ),
  );
}

// Changes `root` carries inline on a path that does not pass a CID in `cut`.
function reachableChanges(
  rootId: string,
  root: Node,
  cut: ReadonlySet<string>,
): Set<string> {
  const found = new Set<string>();
  const walked = new Set<string>();
  const pending: Array<[string, Node]> = [[rootId, root]];
  while (pending.length > 0) {
    const [nodeId, node] = pending.pop()!;
    if (cut.has(nodeId)) continue;
    if (node.change !== undefined) found.add(nodeId);
    if (walked.has(nodeId) || node.change === undefined) continue;
    walked.add(nodeId);
    if (node.children !== undefined && node.children !== crdtChangeNodeDeferred)
      pending.push(...Object.entries(node.children));
  }
  return found;
}

const SIZE = 10;

// How one tree describes a CID: with its change and children, without its
// change (a content-stripped load), or with its children pruned.
const description = fc.constantFrom('full', 'stripped', 'pruned');

const history = fc.record({
  parents: fc.array(fc.array(fc.nat(SIZE - 1), { maxLength: 3 }), {
    minLength: SIZE,
    maxLength: SIZE,
  }),
  primary: fc.array(description, { minLength: SIZE, maxLength: SIZE }),
  delivered: fc.array(description, { minLength: SIZE, maxLength: SIZE }),
  sparse: fc.array(fc.boolean(), { minLength: 64, maxLength: 64 }),
  primaryRoot: fc.nat(SIZE - 1),
  tip: fc.nat(SIZE - 1),
  kept: fc.array(fc.nat(SIZE - 1), { maxLength: 4 }),
});

const cid = (index: number) => `c${index}`;

// Each CID references only lower indices, so every history is acyclic.
function parentsOf(parents: number[][], index: number): number[] {
  return index === 0 ? [] : [...new Set(parents[index]!.map((p) => p % index))];
}

// Render the tree below `root`. Within one tree a CID has one description;
// repeated occurrences are either that description or a sparse citation.
function render(
  parents: number[][],
  modes: string[],
  sparse: boolean[],
  root: number,
): Node {
  let occurrence = 0;
  const seen = new Set<number>();
  const visit = (index: number, top: boolean): Node => {
    const kind = crdtDocumentChangeNode;
    if (!top && seen.has(index) && sparse[occurrence++ % sparse.length])
      return { kind };
    seen.add(index);
    const mode = modes[index];
    const node: Node =
      mode === 'stripped' ? { kind } : { kind, change: `change-${index}` };
    const children = parentsOf(parents, index);
    if (mode === 'pruned') {
      if (children.length > 0) node.children = crdtChangeNodeDeferred;
    } else if (children.length > 0) {
      node.children = Object.fromEntries(
        children.map((child) => [cid(child), visit(child, false)]),
      );
    } else if (mode === 'stripped') {
      node.children = {};
    }
    return node;
  };
  return visit(root, true);
}

describe('carrying a delivered remote tip beside the retained tree', () => {
  test('describes each CID once, keeps every delivered change carried or described, and cites only what it may', () => {
    fc.assert(
      fc.property(history, (input) => {
        const primary = render(
          input.parents,
          input.primary,
          input.sparse,
          input.primaryRoot,
        );
        const delivered = render(
          input.parents,
          input.delivered,
          input.sparse.slice().reverse(),
          input.tip,
        );
        const primaryId = cid(input.primaryRoot);
        const tipId = cid(input.tip);
        validateRemoteSyncTreeAliases(primaryId, primary);
        validateRemoteSyncTreeAliases(tipId, delivered);

        const carried = describedCids(primaryId, primary);
        fc.pre(!carried.has(tipId) && delivered.change !== undefined);
        const keepCited = new Set(
          input.kept.map(cid).filter((kept) => !carried.has(kept)),
        );
        const copy = carryRemoteSubtree(tipId, delivered, carried, keepCited);
        const merged: Node = {
          kind: crdtDocumentChangeNode,
          change: 'merge',
          children: { [primaryId]: primary, [tipId]: copy },
        };

        expect(() => validateRemoteSyncTreeAliases('m', merged)).not.toThrow();
        for (const described of describedCids(tipId, copy))
          expect(carried.has(described)).toBe(false);
        const inlineCopy = inline(tipId, copy);
        for (const change of reachableChanges(tipId, delivered, carried))
          expect(inlineCopy.has(change)).toBe(true);
        for (const cited of citedWithoutChanges(tipId, copy))
          expect(carried.has(cited) || keepCited.has(cited)).toBe(true);
      }),
      { seed: 7120501, numRuns: 400 },
    );
  });
});

describe('cited and covered CIDs', () => {
  const leaf = (change?: string): Node =>
    change === undefined
      ? { kind: crdtDocumentChangeNode }
      : { kind: crdtDocumentChangeNode, change };
  const tree: Node = {
    kind: crdtDocumentChangeNode,
    change: 'root',
    children: {
      A: {
        kind: crdtDocumentChangeNode,
        change: 'a',
        children: { B: leaf(), C: leaf('c') },
      },
      C: leaf(),
      D: leaf(),
    },
  };

  test('a CID the tree carries inline elsewhere is not cited', () => {
    expect(citedWithoutChanges('R', tree).sort()).toEqual(['B', 'D']);
  });

  test('nothing beneath a snapshot boundary is cited or counts as carried', () => {
    expect(citedWithoutChanges('R', tree, new Set(['A'])).sort()).toEqual([
      'C',
      'D',
    ]);
  });

  test('the first occurrence carrying its change is found', () => {
    const found = findInlineNodes('R', tree, new Set(['C', 'D', 'A']));
    expect([...found.keys()].sort()).toEqual(['A', 'C']);
    expect(found.get('C')!.change).toBe('c');
  });

  test('a snapshot at a boundary covers it and everything it references', () => {
    expect([...collectCoveredBySnapshot('R', tree, 'A')].sort()).toEqual([
      'A',
      'B',
      'C',
    ]);
    expect([...collectCoveredBySnapshot('R', tree, 'X')]).toEqual(['X']);
  });
});
