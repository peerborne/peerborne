import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { SubtleCrypto } from './auth-subtlecrypto.js';

async function rejected(operation: () => Promise<unknown>): Promise<boolean> {
  try {
    await operation();
    return false;
  } catch {
    return true;
  }
}

describe('generated Web Crypto adapter integrity cases', () => {
  test('round trips and rejects ciphertext, nonce and key substitutions for every shipped AES mode', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(
          'AES-GCM' as const,
          'AES-CTR' as const,
          'AES-CBC' as const,
        ),
        fc.integer({ min: 0, max: 255 }),
        fc.uint8Array({ maxLength: 512 }),
        fc.nat(),
        async (algorithm, seed, plaintext, position) => {
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
          );
          const opened = await provider.decrypt(
            encrypted.data,
            validKey,
            encrypted.nonce,
          );
          expect(Buffer.from(opened).equals(Buffer.from(plaintext))).toBe(true);
          const tampered = new Uint8Array(encrypted.data);
          tampered[position % tampered.length] ^= 1;
          const wrongNonce = new Uint8Array(encrypted.nonce);
          wrongNonce[position % wrongNonce.length] ^= 1;
          expect(
            await rejected(() =>
              provider.decrypt(tampered, validKey, encrypted.nonce),
            ),
          ).toBe(true);
          expect(
            await rejected(() =>
              provider.decrypt(encrypted.data, validKey, wrongNonce),
            ),
          ).toBe(true);
          expect(
            await rejected(() =>
              provider.decrypt(encrypted.data, wrongKey, encrypted.nonce),
            ),
          ).toBe(true);
        },
      ),
      {
        seed: 9516,
        numRuns: 90,
        examples: [
          ['AES-GCM', 0, new Uint8Array(), 0],
          ['AES-CTR', 0, new Uint8Array(), 0],
          ['AES-CBC', 0, new Uint8Array(), 0],
        ],
      },
    );
  });
});
