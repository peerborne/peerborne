import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  crdtDocumentChangeNode,
  type CRDTChangeNode,
} from './crdt-change-node.js';
import {
  KNOWN_CHANGE_GENERATION,
  knownChangesNeedTrim,
  retainedKnownChanges,
  trimKnownChanges,
} from './known-changes.js';

const step = fc.oneof(
  fc.record({
    kind: fc.constant('change' as const),
    parents: fc.array(fc.nat(), { maxLength: 4 }),
    hole: fc.boolean(),
  }),
  fc.record({ kind: fc.constant('redeliver' as const), index: fc.nat() }),
  fc.record({
    kind: fc.constant('trim' as const),
    keep: fc.array(fc.nat(), { maxLength: 12 }),
  }),
);

function frontier(
  hashes: ReadonlySet<string>,
  ancestors: ReadonlySet<string>,
): string[] {
  return [...hashes].filter((cid) => !ancestors.has(cid)).sort();
}

describe('known-change trimming', () => {
  test('keeps the current generation, retained CIDs and the frontier, and forgets the rest', () => {
    fc.assert(
      fc.property(fc.array(step, { maxLength: 120 }), (steps) => {
        const hashes = new Set<string>();
        const ancestors = new Set<string>();
        const created: string[] = [];
        let previousHashes = new Set<string>();
        let previousAncestors = new Set<string>();
        let holes = 0;
        for (const next of steps) {
          if (next.kind === 'change') {
            const cid = `c${created.length}`;
            for (const parent of next.parents) {
              if (created.length > 0)
                ancestors.add(created[parent % created.length]!);
            }
            if (next.hole) ancestors.add(`h${holes++}`);
            created.push(cid);
            hashes.add(cid);
          } else if (next.kind === 'redeliver') {
            if (created.length > 0)
              hashes.add(created[next.index % created.length]!);
          } else {
            const heads = frontier(hashes, ancestors);
            const candidates = [...hashes, ...ancestors];
            const retained = new Set<string>(heads);
            for (const index of next.keep) {
              if (candidates.length > 0)
                retained.add(candidates[index % candidates.length]!);
            }
            const hashesBefore = new Set(hashes);
            const ancestorsBefore = new Set(ancestors);
            trimKnownChanges(hashes, ancestors, retained);

            const expectedHashes = [...hashesBefore].filter(
              (cid) => !previousHashes.has(cid) || retained.has(cid),
            );
            expect([...hashes]).toEqual(expectedHashes);
            expect([...ancestors]).toEqual(
              [...ancestorsBefore].filter(
                (cid) =>
                  !previousAncestors.has(cid) ||
                  retained.has(cid) ||
                  hashes.has(cid),
              ),
            );
            expect(frontier(hashes, ancestors)).toEqual(heads);
            previousHashes = new Set(hashes);
            previousAncestors = new Set(ancestors);
          }
        }
      }),
      { seed: 6720401, numRuns: 300 },
    );
  });

  test('a CID outside the retained set is forgotten by the second trim after it is learned', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 40 }),
        fc.integer({ min: 0, max: 40 }),
        (first, second) => {
          const hashes = new Set<string>();
          const ancestors = new Set<string>();
          const add = (from: number, count: number) => {
            for (let index = from; index < from + count; index++) {
              if (index > 0) ancestors.add(`c${index - 1}`);
              hashes.add(`c${index}`);
            }
          };
          const retainHead = () => new Set(frontier(hashes, ancestors));
          add(0, first);
          trimKnownChanges(hashes, ancestors, retainHead());
          expect(hashes.size).toBe(first);
          add(first, second);
          trimKnownChanges(hashes, ancestors, retainHead());
          const head = `c${first + second - 1}`;
          for (let index = 0; index < first; index++) {
            const cid = `c${index}`;
            expect(hashes.has(cid)).toBe(cid === head);
          }
          for (let index = first; index < first + second; index++)
            expect(hashes.has(`c${index}`)).toBe(true);
          expect(frontier(hashes, ancestors)).toEqual([head]);
        },
      ),
      { seed: 6720402, numRuns: 200 },
    );
  });

  test('trims only once a set outgrows its generation', () => {
    const hashes = new Set<string>();
    const ancestors = new Set<string>();
    for (let index = 0; index < KNOWN_CHANGE_GENERATION; index++)
      hashes.add(`c${index}`);
    expect(knownChangesNeedTrim(hashes, ancestors)).toBe(false);
    hashes.add('next');
    expect(knownChangesNeedTrim(hashes, ancestors)).toBe(true);
    trimKnownChanges(hashes, ancestors, new Set());
    expect(hashes.size).toBe(KNOWN_CHANGE_GENERATION + 1);
    expect(knownChangesNeedTrim(hashes, ancestors)).toBe(false);
    for (let index = 0; index <= KNOWN_CHANGE_GENERATION; index++)
      ancestors.add(`a${index}`);
    expect(knownChangesNeedTrim(hashes, ancestors)).toBe(true);
    expect(knownChangesNeedTrim(new Set(hashes), new Set())).toBe(true);
  });

  test('retains only the newest generation of frontier heads', () => {
    const heads = Array.from(
      { length: KNOWN_CHANGE_GENERATION + 10 },
      (_, index) => `head-${index}`,
    );
    const retained = retainedKnownChanges(
      undefined,
      undefined,
      undefined,
      [],
      heads,
    );
    expect(retained.size).toBe(KNOWN_CHANGE_GENERATION);
    expect(retained.has('head-9')).toBe(false);
    expect(retained.has('head-10')).toBe(true);
    expect(retained.has(heads.at(-1)!)).toBe(true);
  });

  test('retains every node of the tree, the snapshot boundary, the tips and the heads', () => {
    const leaf = (kind = crdtDocumentChangeNode): CRDTChangeNode<string> => ({
      kind,
    });
    const tree: CRDTChangeNode<string> = {
      kind: crdtDocumentChangeNode,
      change: 'root',
      children: {
        parent: {
          kind: crdtDocumentChangeNode,
          change: 'parent',
          children: { grandparent: leaf() },
        },
        crossLink: leaf(),
      },
    };
    expect(
      [
        ...retainedKnownChanges('root', tree, 'boundary', ['tip'], ['head']),
      ].sort(),
    ).toEqual([
      'boundary',
      'crossLink',
      'grandparent',
      'head',
      'parent',
      'root',
      'tip',
    ]);
    expect([...retainedKnownChanges(undefined, undefined, '', [], [])]).toEqual(
      [],
    );
  });
});
