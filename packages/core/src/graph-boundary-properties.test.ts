import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { reachableCids } from './policy/graph-reachability.js';
import { collectTreeCIDs } from './blockstore-gc.js';
import {
  crdtDocumentChangeNode,
  type CRDTChangeNode,
} from './crdt-change-node.js';

describe('decoded graph and native collection correspondence', () => {
  test('matches independent edge saturation through cycles, duplicates, and disconnected vertices', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 12 }),
        fc.array(fc.tuple(fc.nat(), fc.nat()), { maxLength: 60 }),
        fc.nat(),
        (count, pairs, start) => {
          const nodes = Array.from(
            { length: count },
            (_, index) => 'cid-' + index,
          );
          const edges = pairs.map(([from, to]) => ({
            from: nodes[from % count],
            to: nodes[to % count],
          }));
          const root = nodes[start % count],
            expected = new Set([root]);
          for (let pass = 0; pass < count; pass++) {
            for (const { from, to } of edges)
              if (expected.has(from)) expected.add(to);
          }
          expect([...reachableCids(nodes, edges, root)].sort()).toEqual(
            [...expected].sort(),
          );
        },
      ),
      { seed: 9602, numRuns: 500 },
    );
  });

  test('the validated heap adapter preserves CID occurrences and aliases', () => {
    fc.assert(
      fc.property(
        fc.array(fc.array(fc.integer({ min: 0, max: 7 }), { maxLength: 7 }), {
          maxLength: 7,
        }),
        (branches) => {
          const expected = new Set(['root']);
          const children: Record<
            string,
            CRDTChangeNode<unknown>
          > = Object.create(null);
          for (let branch = 0; branch < branches.length; branch++) {
            const label = 'branch-' + branch;
            const nested: Record<
              string,
              CRDTChangeNode<unknown>
            > = Object.create(null);
            expected.add(label);
            for (const cid of branches[branch]) {
              const key = 'cid-' + cid;
              expected.add(key);
              nested[key] = { kind: crdtDocumentChangeNode };
            }
            children[label] = {
              kind: crdtDocumentChangeNode,
              children: nested,
            };
          }
          expect(
            [
              ...collectTreeCIDs('root', {
                kind: crdtDocumentChangeNode,
                children,
              }),
            ].sort(),
          ).toEqual([...expected].sort());
        },
      ),
      { seed: 9603, numRuns: 200 },
    );
  });
});
