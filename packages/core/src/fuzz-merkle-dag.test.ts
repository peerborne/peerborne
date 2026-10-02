import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { deserializeChangeNodeFromJSON } from './merkle-dag-serialization';
import { crdtDocumentChangeNode, crdtWriterChangeNode, crdtChangeNodeDeferred } from './crdt-change-node';

const id = <T>(x: T): T => x;

describe('merkle-dag-serialization fuzz', () => {
  test('deserialize never throws unexpectedly on random objects', () => {
    fc.assert(
      fc.property(fc.object(), (obj) => {
        try {
          deserializeChangeNodeFromJSON(obj as any, id);
        } catch (err) {
          if (err instanceof Error) {
            expect(err.message).toMatch(
              /expected a plain object|"kind"|"keyID"|"children"|child at key/i,
            );
          }
        }
      }),
      { numRuns: 2000 },
    );
  });

  test('deserialize rejects null and primitives', () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.constant(null),
          fc.string(),
          fc.integer(),
          fc.boolean(),
          fc.array(fc.string()),
        ),
        (value) => {
          expect(() => deserializeChangeNodeFromJSON(value as any, id)).toThrow(/expected a plain object/);
        },
      ),
      { numRuns: 500 },
    );
  });

  test('round-trip for any valid leaf node', () => {
    fc.assert(
      fc.property(
        fc.oneof(fc.constant(crdtDocumentChangeNode), fc.constant(crdtWriterChangeNode)),
        fc.option(fc.string(), { nil: undefined }),
        fc.option(
          fc.oneof(
            fc.constant(crdtChangeNodeDeferred),
            fc.constant(undefined),
          ),
          { nil: undefined },
        ),
        (kind, change, children) => {
          const node: any = { kind };
          if (change !== undefined) node.change = change;
          if (children !== undefined) node.children = children;

          const result = deserializeChangeNodeFromJSON(node, id);
          expect(result.kind).toBe(kind);
          expect(Object.prototype.hasOwnProperty.call(result, 'keyID')).toBe(false);
          if (change) expect(result.change).toBe(change);
        },
      ),
      { numRuns: 500 },
    );
  });

  test('rejects a keyID field of any value', () => {
    fc.assert(
      fc.property(
        fc.oneof(fc.constant(crdtDocumentChangeNode), fc.constant(crdtWriterChangeNode)),
        fc.anything(),
        (kind, keyID) => {
          expect(() =>
            deserializeChangeNodeFromJSON({ kind, keyID, change: 'leaf' } as any, id),
          ).toThrow(/"keyID" is not a change-node field/);
        },
      ),
      { numRuns: 500 },
    );
  });
});