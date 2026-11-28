import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { SubtleCrypto } from './auth-subtlecrypto.js';
import {
  documentPayloadAAD,
  type DocumentPayloadKind,
} from './document-payload-aad.js';

async function rejected(operation: () => Promise<unknown>): Promise<boolean> {
  try {
    await operation();
    return false;
  } catch {
    return true;
  }
}

const payloadKind = fc.constantFrom<DocumentPayloadKind>(
  'block',
  'frame',
  'response',
  'invitation-bootstrap',
);

describe('generated Web Crypto adapter integrity cases', () => {
  test('round trips and rejects ciphertext, nonce, key and associated-data substitutions for every shipped AES mode', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(
          'AES-GCM' as const,
          'AES-CTR' as const,
          'AES-CBC' as const,
        ),
        fc.integer({ min: 0, max: 255 }),
        fc.uint8Array({ maxLength: 512 }),
        fc.uint8Array({ maxLength: 64 }),
        fc.nat(),
        async (algorithm, seed, plaintext, associatedData, position) => {
          const provider = new SubtleCrypto(undefined, algorithm);
          const key = async (offset: number) =>
            crypto.subtle.importKey(
              'raw',
              Uint8Array.from(
                { length: 32 },
                (_, index) => (seed + index + offset) % 256,
              ),
              { name: algorithm },
              true,
              ['encrypt', 'decrypt'],
            );
          const [validKey, wrongKey] = await Promise.all([key(0), key(1)]);
          const encrypted = await provider.encrypt(
            new Uint8Array(plaintext),
            validKey,
            associatedData,
          );
          const opened = await provider.decrypt(
            encrypted.data,
            validKey,
            encrypted.nonce,
            associatedData,
          );
          expect(Buffer.from(opened).equals(Buffer.from(plaintext))).toBe(true);
          const tampered = new Uint8Array(encrypted.data);
          tampered[position % tampered.length] ^= 1;
          const wrongNonce = new Uint8Array(encrypted.nonce);
          wrongNonce[position % wrongNonce.length] ^= 1;
          const wrongAssociatedData =
            associatedData.length === 0
              ? new Uint8Array([position % 256])
              : new Uint8Array(associatedData);
          if (associatedData.length > 0)
            wrongAssociatedData[position % associatedData.length] ^= 1;
          expect(
            await rejected(() =>
              provider.decrypt(
                tampered,
                validKey,
                encrypted.nonce,
                associatedData,
              ),
            ),
          ).toBe(true);
          expect(
            await rejected(() =>
              provider.decrypt(
                encrypted.data,
                validKey,
                wrongNonce,
                associatedData,
              ),
            ),
          ).toBe(true);
          expect(
            await rejected(() =>
              provider.decrypt(
                encrypted.data,
                wrongKey,
                encrypted.nonce,
                associatedData,
              ),
            ),
          ).toBe(true);
          expect(
            await rejected(() =>
              provider.decrypt(
                encrypted.data,
                validKey,
                encrypted.nonce,
                wrongAssociatedData,
              ),
            ),
          ).toBe(true);
        },
      ),
      {
        seed: 9516,
        numRuns: 90,
        examples: [
          ['AES-GCM', 0, new Uint8Array(), new Uint8Array(), 0],
          ['AES-CTR', 0, new Uint8Array(), new Uint8Array(), 0],
          ['AES-CBC', 0, new Uint8Array(), new Uint8Array(), 0],
        ],
      },
    );
  });

  test('document payload associated data is injective in path, key ID and kind', () => {
    const input = fc.tuple(
      fc.string({ unit: 'grapheme', maxLength: 24 }),
      fc.uint8Array({ maxLength: 24 }),
      payloadKind,
    );
    fc.assert(
      fc.property(input, input, (left, right) => {
        const same =
          left[0] === right[0] &&
          Buffer.from(left[1]).equals(Buffer.from(right[1])) &&
          left[2] === right[2];
        expect(
          Buffer.from(documentPayloadAAD(...left)).equals(
            Buffer.from(documentPayloadAAD(...right)),
          ),
        ).toBe(same);
      }),
      {
        seed: 9517,
        numRuns: 500,
        examples: [
          [
            ['/a', new Uint8Array([1]), 'frame'],
            ['/a\u0000', new Uint8Array(), 'frame'],
          ],
          [
            ['', new Uint8Array([0, 0, 0, 5]), 'block'],
            ['', new Uint8Array(), 'block'],
          ],
        ],
      },
    );
  });
});
