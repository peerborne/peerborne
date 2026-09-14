import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  deserializeBeeKEMWelcomeFromWire,
  serializeBeeKEMWelcomeForWire,
} from './beekem-welcome-wire';
import * as TreeMath from './beekem/tree-math.js';

describe('beekem-welcome-wire fuzz', () => {
  test('deserialize never throws unexpectedly on random objects', () => {
    fc.assert(
      fc.property(fc.object(), (obj) => {
        try {
          deserializeBeeKEMWelcomeFromWire(obj);
        } catch (err) {
          if (err instanceof Error) {
            expect(err.message).toMatch(
              /Invalid BeeKEMWelcome|BeeKEMWelcome wire/i,
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
        fc.integer({ min: 2, max: 64 }),
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        (numLeaves, treeHash) => {
          const leafIndex = TreeMath.leafToNodeIndex(numLeaves - 1);
          const directPath = TreeMath.directPath(leafIndex, numLeaves);
          const pathKeys = directPath.map((nodeIndex, index) => ({
            nodeIndex,
            publicKey: new Uint8Array(65).fill((index % 254) + 1),
            encryptedPrivateKey: new Uint8Array([(index % 254) + 1]),
          }));
          const covered = new Set([leafIndex, ...directPath]);
          const treeNodePublicKeys = Array.from(
            { length: 2 * numLeaves - 1 },
            (_, nodeIndex) => nodeIndex,
          )
            .filter((nodeIndex) => !covered.has(nodeIndex))
            .map((nodeIndex) => ({
              nodeIndex,
              publicKey:
                nodeIndex % 3 === 0
                  ? null
                  : new Uint8Array(65).fill((nodeIndex % 254) + 1),
            }));
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
