import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import { PeerborneDocument } from './peerborne-document.js';
import { filterDeletableCIDs } from './blockstore-gc.js';
import { selectDeletableCids } from './policy/retention.js';
import { MAX_CHANGE_TREE_NODES } from './change-tree-walk.js';
import {
  type CRDTChangeNode,
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
} from './crdt-change-node.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock(
  'multiformats',
  () => ({
    CID: { parse: (value: string) => ({ toString: () => value }) },
  }),
  { virtual: true },
);
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({
    TopicValidatorResult: { Accept: 'accept', Reject: 'reject' },
  }),
  { virtual: true },
);
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock('./peerborne.js', () => ({
  MAX_DOCUMENT_PATH_LENGTH: 4096,
  Peerborne: class {},
}));

type Node = CRDTChangeNode<Uint8Array>;
const kinds = [
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
] as const;
const shape = fc.array(
  fc.record({
    parent: fc.nat({ max: 10000 }),
    kind: fc.integer({ min: 0, max: 2 }),
    alias: fc.boolean(),
  }),
  { maxLength: 80 },
);
type Shape = typeof shape extends fc.Arbitrary<infer Value> ? Value : never;

function tree(specs: Shape): Node {
  const root: Node = {
    kind: crdtDocumentChangeNode,
    change: new Uint8Array([0]),
  };
  const nodes = [root];
  for (const [index, spec] of specs.entries()) {
    const node: Node = {
      kind: kinds[spec.kind],
      change: new Uint8Array([index + 1]),
    };
    const parent = nodes[spec.parent % nodes.length];
    if (!parent.children) parent.children = Object.create(null);
    (parent.children as Record<string, Node>)[`cid-${index + 1}`] = node;
    nodes.push(node);
  }
  for (const [index, spec] of specs.entries()) {
    const id = `cid-${index + 1}`;
    if (
      spec.alias &&
      spec.kind !== 0 &&
      !(root.children as Record<string, Node> | undefined)?.[id]
    ) {
      if (!root.children) root.children = Object.create(null);
      (root.children as Record<string, Node>)[id] = { kind: kinds[spec.kind] };
    }
  }
  return root;
}

function entries(root: Node): Map<string, Node> {
  const result = new Map<string, Node>();
  const queue: Array<[string, Node]> = [['root', root]];
  for (let index = 0; index < queue.length; index++) {
    const [id, node] = queue[index];
    if (!result.has(id) || node.change !== undefined) result.set(id, node);
    if (node.children && typeof node.children === 'object')
      queue.push(...Object.entries(node.children));
  }
  return result;
}

function document(root: Node) {
  return Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath: '/generated-pruning',
    _lastSyncMessage: {
      documentId: '/generated-pruning',
      changeId: 'root',
      changes: root,
    },
  }) as {
    _lastSyncMessage: { changes: Node };
    _pruneChanges(keep: number): Set<string>;
  };
}

test('actual pruning preserves every ACL payload and filters deletions against the retained tree', () => {
  const log = jest.spyOn(console, 'log').mockImplementation(() => undefined);
  try {
    fc.assert(
      fc.property(
        shape,
        fc.integer({ min: 1, max: 90 }),
        fc.nat({ max: 16 }),
        (specs, keep, modulus) => {
          const root = tree(specs),
            before = JSON.stringify(root),
            original = entries(root);
          const doc = document(root),
            pruned = doc._pruneChanges(keep);
          expect(JSON.stringify(root)).toBe(before);
          const retained = entries(doc._lastSyncMessage.changes);
          expect(pruned).toEqual(
            new Set(
              [...original]
                .filter(
                  ([id, node]) =>
                    node.kind === crdtDocumentChangeNode && !retained.has(id),
                )
                .map(([id]) => id),
            ),
          );
          for (const [id, node] of original)
            if (node.kind !== crdtDocumentChangeNode) {
              expect(retained.get(id)?.kind).toBe(node.kind);
              expect(retained.get(id)?.change).toEqual(node.change);
              expect(pruned.has(id)).toBe(false);
            }
          const protectedIds = new Set(
            [...original.keys()].filter(
              (_, index) => index % (modulus + 1) === 0,
            ),
          );
          const candidates = [...pruned, ...original.keys(), 'unrelated'];
          const expected = new Set(
            candidates.filter(
              (id) => !retained.has(id) && !protectedIds.has(id),
            ),
          );
          const actual = filterDeletableCIDs(
            candidates,
            'root',
            doc._lastSyncMessage.changes,
            protectedIds,
          );
          expect(actual).toEqual(expected);
          candidates.fill('changed-after-selection');
          protectedIds.clear();
          expect(actual).toEqual(expected);
        },
      ),
      { seed: 2012101, numRuns: 200 },
    );
  } finally {
    log.mockRestore();
  }
});

test('malformed pruning input cannot partially publish a replacement tree', () => {
  fc.assert(
    fc.property(
      shape,
      fc.nat(),
      fc.constantFrom('kind', 'children', 'cycle'),
      (specs, chosen, mode) => {
        const root = tree(specs),
          nodes = [...entries(root).values()];
        const bad = nodes[chosen % nodes.length];
        if (mode === 'kind') Object.assign(bad, { kind: 'invalid' });
        else if (mode === 'children') Object.assign(bad, { children: null });
        else bad.children = { cycle: root };
        const doc = document(root),
          message = doc._lastSyncMessage;
        expect(() => doc._pruneChanges(1)).toThrow();
        expect(doc._lastSyncMessage).toBe(message);
        expect(doc._lastSyncMessage.changes).toBe(root);
      },
    ),
    { seed: 2012102, numRuns: 120 },
  );
});

test('pruning captures each structural occurrence once without reading source getters', () => {
  const log = jest.spyOn(console, 'log').mockImplementation(() => undefined);
  try {
    fc.assert(
      fc.property(shape, (specs) => {
        let occurrences = 0,
          scans = 0,
          descriptors = 0,
          gets = 0,
          writes = 0;
        const traps: ProxyHandler<object> = {
          ownKeys(target) {
            scans++;
            return Reflect.ownKeys(target);
          },
          getOwnPropertyDescriptor(target, key) {
            descriptors++;
            return Reflect.getOwnPropertyDescriptor(target, key);
          },
          get() {
            gets++;
            throw new Error('source property access');
          },
          set() {
            writes++;
            throw new Error('source mutation');
          },
          deleteProperty() {
            writes++;
            throw new Error('source mutation');
          },
        };
        const wrap = (node: Node): Node => {
          occurrences++;
          const target: Node = { kind: node.kind, change: node.change };
          if (node.children && typeof node.children === 'object') {
            const children: Record<string, Node> = Object.create(null);
            for (const [id, child] of Object.entries(node.children))
              children[id] = wrap(child);
            target.children = new Proxy<Record<string, Node>>(children, traps);
          }
          return new Proxy<Node>(target, traps);
        };
        const doc = document(wrap(tree(specs)));
        doc._pruneChanges(1);
        expect(gets).toBe(0);
        expect(writes).toBe(0);
        expect(scans).toBeLessThanOrEqual(2 * occurrences - 1);
        expect(descriptors).toBeLessThanOrEqual(4 * occurrences - 1);
      }),
      {
        seed: 2012104,
        numRuns: 60,
        examples: [
          [
            Array.from({ length: MAX_CHANGE_TREE_NODES - 1 }, () => ({
              parent: 0,
              kind: 0,
              alias: false,
            })),
          ],
        ],
      },
    );
  } finally {
    log.mockRestore();
  }
});

test('native sweep histories preserve protected and unrelated blocks across repeated candidate batches', () => {
  fc.assert(
    fc.property(
      fc.array(fc.array(fc.integer({ min: 0, max: 70 }), { maxLength: 50 }), {
        maxLength: 40,
      }),
      fc.array(fc.integer({ min: 0, max: 70 }), { maxLength: 50 }),
      fc.array(fc.integer({ min: 0, max: 70 }), { maxLength: 50 }),
      (batches, retainedValues, protectedValues) => {
        const retained = new Set(retainedValues.map(String)),
          protectedIds = new Set(protectedValues.map(String));
        const initial = Array.from({ length: 72 }, (_, index) => String(index));
        const remaining = new Set(initial),
          candidates: string[] = [];
        for (const batch of batches) {
          const values = batch.map(String);
          candidates.push(...values);
          const selected = selectDeletableCids(values, retained, protectedIds);
          for (const id of selected) remaining.delete(id);
          const expected = initial.filter(
            (id) =>
              !candidates.includes(id) ||
              retained.has(id) ||
              protectedIds.has(id),
          );
          expect(remaining).toEqual(new Set(expected));
          const addedProtection = new Set(
            values.filter((_, index) => index % 2 === 0),
          );
          const stronger = selectDeletableCids(
            values,
            new Set([...retained, ...addedProtection]),
            protectedIds,
          );
          expect(stronger).toEqual(
            new Set([...selected].filter((id) => !addedProtection.has(id))),
          );
        }
        const whole = selectDeletableCids(candidates, retained, protectedIds);
        expect(remaining).toEqual(
          new Set(initial.filter((id) => !whole.has(id))),
        );
      },
    ),
    { seed: 2012103, numRuns: 150 },
  );
});
