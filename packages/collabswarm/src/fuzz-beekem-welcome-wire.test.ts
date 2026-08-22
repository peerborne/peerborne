import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { deserializeBeeKEMWelcomeFromWire, serializeBeeKEMWelcomeForWire } from './beekem-welcome-wire';

describe('beekem-welcome-wire fuzz', () => {
  test('deserialize never throws unexpectedly on random objects', () => {
    fc.assert(
      fc.property(fc.object(), (obj) => {
        try {
          deserializeBeeKEMWelcomeFromWire(obj);
        } catch (err) {
          if (err instanceof Error) {
            expect(err.message).toMatch(
              /expected a plain object|leafIndex|'pathKeys' must be an array|'treeNodePublicKeys' must be an array|'treeHash' must be a base64|must be a plain object|nodeIndex|must be a base64 string|invalid base64/i,
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
        fc.uint8Array({ minLength: 1, maxLength: 32 }),
        fc.array(
          fc.record({
            nodeIndex: fc.nat(200),
            publicKey: fc.uint8Array({ minLength: 1, maxLength: 65 }),
            encryptedPrivateKey: fc.uint8Array({ minLength: 1, maxLength: 128 }),
          }),
          { minLength: 0, maxLength: 10 },
        ),
        fc.array(
          fc.oneof(
            fc.record({ nodeIndex: fc.nat(200), publicKey: fc.uint8Array({ minLength: 1, maxLength: 65 }) }),
            fc.record({ nodeIndex: fc.nat(200), publicKey: fc.constant(null) }),
          ),
          { minLength: 0, maxLength: 10 },
        ),
        (leafIndex, treeHash, pathKeys, treeNodePublicKeys) => {
          const welcome = { leafIndex, pathKeys, treeNodePublicKeys, treeHash };
          const wire = serializeBeeKEMWelcomeForWire(welcome);
          const result = deserializeBeeKEMWelcomeFromWire(wire);
          expect(result.leafIndex).toBe(leafIndex);
          expect(result.pathKeys).toHaveLength(pathKeys.length);
          expect(result.treeNodePublicKeys).toHaveLength(treeNodePublicKeys.length);
          expect(result.treeHash).toEqual(treeHash);
        },
      ),
      { numRuns: 500 },
    );
  });
});