import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { deserializePathUpdateFromWire, serializePathUpdateForWire } from './path-update-wire';

describe('path-update-wire fuzz', () => {
  test('deserialize never throws unexpectedly on random objects', () => {
    fc.assert(
      fc.property(fc.object(), (obj) => {
        try {
          deserializePathUpdateFromWire(obj);
        } catch (err) {
          if (err instanceof Error) {
            expect(err.message).toMatch(
              /Invalid PathUpdate|path-update wire/i,
            );
          }
        }
      }),
      { numRuns: 2000 },
    );
  });

  test('round-trip for any valid shape', () => {
    fc.assert(
      fc.property(
        fc.nat(8191).map((leafPosition) => leafPosition * 2),
        fc.uint8Array({ minLength: 65, maxLength: 65 }),
        fc.uniqueArray(
          fc.record({
            nodeIndex: fc.nat(8190).map((position) => position * 2 + 1),
            publicKey: fc.uint8Array({ minLength: 65, maxLength: 65 }),
            encryptedPrivateKey: fc.oneof(
              fc.constant(new Uint8Array(0)),
              fc.uint8Array({ minLength: 125, maxLength: 128 }),
            ),
          }),
          {
            minLength: 0,
            maxLength: 13,
            selector: (node) => node.nodeIndex,
          },
        ),
        (senderLeafIndex, senderLeafPublicKey, nodes) => {
          const update = { senderLeafIndex, senderLeafPublicKey, nodes };
          const wire = serializePathUpdateForWire(update);
          const result = deserializePathUpdateFromWire(wire);
          expect(result.senderLeafIndex).toBe(senderLeafIndex);
          expect(result.senderLeafPublicKey).toEqual(senderLeafPublicKey);
          expect(result.nodes).toHaveLength(nodes.length);
          for (let i = 0; i < nodes.length; i++) {
            expect(result.nodes[i].nodeIndex).toBe(nodes[i].nodeIndex);
            expect(result.nodes[i].publicKey).toEqual(nodes[i].publicKey);
            expect(result.nodes[i].encryptedPrivateKey).toEqual(nodes[i].encryptedPrivateKey);
          }
        },
      ),
      { numRuns: 500 },
    );
  });
});
