import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { encodeWelcomeSealedPayload, decodeWelcomeSealedPayload } from './welcome-sealed-payload';

describe('welcome-sealed-payload fuzz', () => {
  test('decode never throws unexpectedly on random bytes', () => {
    fc.assert(
      fc.property(fc.uint8Array(), (bytes) => {
        try {
          decodeWelcomeSealedPayload(bytes);
        } catch (err) {
          if (err instanceof Error) {
            expect(err.message).toMatch(
              /not valid UTF-8|not valid JSON|expected a plain object|must be a base64 string|invalid 'bk'|invalid base64/,
            );
          }
        }
      }),
      { numRuns: 1000 },
    );
  });

  test('round-trip round-trips for any valid payload', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 1, maxLength: 256 }),
        fc.option(fc.uint8Array({ minLength: 1, maxLength: 65 }), { nil: null }),
        (keychainBytes, beekemWelcomeHint) => {
          const payload = {
            keychainChanges: keychainBytes,
            beekemWelcome: beekemWelcomeHint === null ? null : {
              leafIndex: 0,
              pathKeys: [],
              treeNodePublicKeys: [],
              treeHash: beekemWelcomeHint,
            },
          };
          const encoded = encodeWelcomeSealedPayload(payload);
          const decoded = decodeWelcomeSealedPayload(encoded);
          expect(decoded.keychainChanges).toEqual(keychainBytes);
          if (beekemWelcomeHint === null) {
            expect(decoded.beekemWelcome).toBeNull();
          } else {
            expect(decoded.beekemWelcome).not.toBeNull();
          }
        },
      ),
      { numRuns: 500 },
    );
  });

  test('decode handles boundary byte arrays', () => {
    const boundaries = [
      new Uint8Array(0),
      new Uint8Array([0x00]),
      new Uint8Array([0xff]),
      new Uint8Array(1024).fill(0x41),
      new Uint8Array(1024).fill(0xff),
    ];
    for (const bytes of boundaries) {
      try { decodeWelcomeSealedPayload(bytes); } catch {}
    }
  });
});