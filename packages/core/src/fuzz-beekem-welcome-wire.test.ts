import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { serializeBeeKEMWelcomeV2ForWire, deserializeBeeKEMWelcomeV2FromWire } from './beekem-welcome-wire.js';
import { welcomeFixture } from './__mocks__/beekem-v2.js';

describe('beekem-welcome-wire current-format fuzz', () => {
  test('rejects arbitrary malformed records with a bounded validation error', () => {
    fc.assert(fc.property(fc.object(), (input) => {
      try {
        const decoded = deserializeBeeKEMWelcomeV2FromWire(input);
        expect(deserializeBeeKEMWelcomeV2FromWire(serializeBeeKEMWelcomeV2ForWire(decoded))).toEqual(decoded);
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
          const value = welcomeFixture(generation);
          value.pathKeys[0].publicKey = publicKey;
          value.pathKeys[0].encryptedPrivateKey = ciphertext;
          const encoded = serializeBeeKEMWelcomeV2ForWire(value);
          expect(deserializeBeeKEMWelcomeV2FromWire(encoded)).toEqual(value);
      },
    ), { numRuns: 500 });
  });
});
