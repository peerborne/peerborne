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
              /expected a plain object|senderLeafIndex|senderLeafPublicKey|'nodes' must be an array|must be a plain object|nodeIndex|must be a base64 string|invalid base64/i,
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
        fc.nat(100),
        fc.uint8Array({ minLength: 1, maxLength: 65 }),
        fc.array(
          fc.record({
            nodeIndex: fc.nat(200),
            publicKey: fc.uint8Array({ minLength: 1, maxLength: 65 }),
            encryptedPrivateKey: fc.uint8Array({ minLength: 1, maxLength: 128 }),
          }),
          { minLength: 0, maxLength: 20 },
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