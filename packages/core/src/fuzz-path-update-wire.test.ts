import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { serializePathUpdateV2ForWire, deserializePathUpdateV2FromWire } from './path-update-wire.js';
import { pathUpdateFixture } from './__mocks__/beekem-v2.js';

describe('path-update-wire current-format fuzz', () => {
  test('rejects arbitrary malformed records with a bounded validation error', () => {
    fc.assert(fc.property(fc.object(), (input) => {
      try {
        const decoded = deserializePathUpdateV2FromWire(input);
        expect(deserializePathUpdateV2FromWire(serializePathUpdateV2ForWire(decoded))).toEqual(decoded);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toMatch(/Invalid/);
      }
    }), { numRuns: 2000 });
  });

  test('round-trips current tree shapes across generation and byte boundaries', () => {
    fc.assert(fc.property(
      fc.integer({ min: 1, max: 0xffffffff }),
      fc.uint8Array({ minLength: 65, maxLength: 65 }),
      fc.uint8Array({ minLength: 1, maxLength: 512 }),
      (generation, publicKey, ciphertext) => {
          const value = pathUpdateFixture(generation);
          value.senderLeafPublicKey = publicKey;
          value.treeNodePublicKeys[0].publicKey = publicKey;
          value.nodes[0].encryptedPathKeyBundles[0].ciphertext = ciphertext;
          const encoded = serializePathUpdateV2ForWire(value);
          expect(deserializePathUpdateV2FromWire(encoded)).toEqual(value);
      },
    ), { numRuns: 500 });
  });
});
