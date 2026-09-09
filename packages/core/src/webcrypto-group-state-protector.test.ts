import { describe, expect, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';

import {
  WEBCRYPTO_GROUP_STATE_NONCE_LENGTH,
  WebCryptoGroupStateProtector,
} from './webcrypto-group-state-protector.js';

describe('WebCryptoGroupStateProtector', () => {
  test('uses fresh AES-GCM nonces and authenticates associated data', async () => {
    const protector = await WebCryptoGroupStateProtector.generate('key-1');
    const plaintext = new Uint8Array([1, 2, 3, 4]);
    const associatedData = new Uint8Array([5, 6, 7]);
    const first = await protector.seal(plaintext, associatedData);
    const second = await protector.seal(plaintext, associatedData);

    expect(first.nonce).toHaveLength(WEBCRYPTO_GROUP_STATE_NONCE_LENGTH);
    expect(first.nonce).not.toEqual(second.nonce);
    await expect(protector.open(first, associatedData)).resolves.toEqual(
      plaintext,
    );
    await expect(
      protector.open(first, new Uint8Array([5, 6, 8])),
    ).rejects.toBeDefined();
  });

  test('rejects ciphertext and nonce tampering', async () => {
    const protector = await WebCryptoGroupStateProtector.generate('key-1');
    const sealed = await protector.seal(
      new Uint8Array([1]),
      new Uint8Array([2]),
    );
    sealed.ciphertext[0] ^= 1;
    await expect(
      protector.open(sealed, new Uint8Array([2])),
    ).rejects.toBeDefined();
    await expect(
      protector.open(
        { ...sealed, nonce: new Uint8Array(11) },
        new Uint8Array([2]),
      ),
    ).rejects.toThrow(/nonce.*invalid length/);
  });

  test('snapshots seal inputs before asynchronous encryption', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const delayedCrypto = {
      getRandomValues: crypto.getRandomValues.bind(crypto),
      subtle: {
        encrypt: async (
          algorithm: AlgorithmIdentifier,
          cryptoKey: CryptoKey,
          data: BufferSource,
        ) => {
          await gate;
          return crypto.subtle.encrypt(algorithm, cryptoKey, data);
        },
      },
    } as unknown as Crypto;
    const protector = new WebCryptoGroupStateProtector(
      'key-1',
      key,
      delayedCrypto,
    );
    const plaintext = new Uint8Array([1, 2, 3, 4]);
    const associatedData = new Uint8Array([5, 6, 7]);
    const expectedPlaintext = new Uint8Array(plaintext);
    const expectedAssociatedData = new Uint8Array(associatedData);

    const pending = protector.seal(plaintext, associatedData);
    plaintext.fill(0xee);
    associatedData.fill(0xdd);
    release();

    const sealed = await pending;
    const verifier = new WebCryptoGroupStateProtector('key-1', key);
    await expect(
      verifier.open(sealed, expectedAssociatedData),
    ).resolves.toEqual(expectedPlaintext);
  });

  test('snapshots open inputs before asynchronous decryption', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    const protector = new WebCryptoGroupStateProtector('key-1', key);
    const plaintext = new Uint8Array([1, 2, 3, 4]);
    const associatedData = new Uint8Array([5, 6, 7]);
    const sealed = await protector.seal(plaintext, associatedData);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const delayedCrypto = {
      subtle: {
        decrypt: async (
          algorithm: AlgorithmIdentifier,
          cryptoKey: CryptoKey,
          data: BufferSource,
        ) => {
          await gate;
          return crypto.subtle.decrypt(algorithm, cryptoKey, data);
        },
      },
    } as unknown as Crypto;
    const delayedProtector = new WebCryptoGroupStateProtector(
      'key-1',
      key,
      delayedCrypto,
    );

    const pending = delayedProtector.open(sealed, associatedData);
    sealed.nonce.fill(0xee);
    sealed.ciphertext.fill(0xdd);
    associatedData.fill(0xcc);
    release();

    await expect(pending).resolves.toEqual(plaintext);
  });

  test('accepts cross-realm byte inputs', async () => {
    const protector = await WebCryptoGroupStateProtector.generate('key-1');
    const crossRealm = (bytes: Uint8Array): Uint8Array =>
      runInNewContext(
        `new Uint8Array([${Array.from(bytes).join(',')}])`,
      ) as Uint8Array;
    const plaintext = new Uint8Array([1, 2, 3, 4]);
    const associatedData = new Uint8Array([5, 6, 7]);
    const sealed = await protector.seal(
      crossRealm(plaintext),
      crossRealm(associatedData),
    );

    await expect(
      protector.open(
        {
          nonce: crossRealm(sealed.nonce),
          ciphertext: crossRealm(sealed.ciphertext),
        },
        crossRealm(associatedData),
      ),
    ).resolves.toEqual(plaintext);
  });

  test('rejects SharedArrayBuffer-backed byte inputs', async () => {
    if (typeof SharedArrayBuffer === 'undefined') return;
    const protector = await WebCryptoGroupStateProtector.generate('key-1');
    const shared = (length: number) =>
      new Uint8Array(new SharedArrayBuffer(length));
    const plaintext = new Uint8Array([1]);
    const associatedData = new Uint8Array([2]);
    const sealed = await protector.seal(plaintext, associatedData);

    await expect(protector.seal(shared(1), associatedData)).rejects.toThrow(
      /plaintext.*backing buffer/,
    );
    await expect(protector.seal(plaintext, shared(1))).rejects.toThrow(
      /associatedData.*backing buffer/,
    );
    await expect(
      protector.open(
        { ...sealed, nonce: shared(WEBCRYPTO_GROUP_STATE_NONCE_LENGTH) },
        associatedData,
      ),
    ).rejects.toThrow(/nonce.*backing buffer/);
    await expect(
      protector.open(
        { ...sealed, ciphertext: shared(sealed.ciphertext.byteLength) },
        associatedData,
      ),
    ).rejects.toThrow(/ciphertext.*backing buffer/);
    await expect(protector.open(sealed, shared(1))).rejects.toThrow(
      /associatedData.*backing buffer/,
    );
  });

  test('reports unavailable Web Crypto from generate', async () => {
    await expect(
      WebCryptoGroupStateProtector.generate(
        'key-1',
        null as unknown as Crypto,
      ),
    ).rejects.toThrow('Web Crypto is unavailable');
    await expect(
      WebCryptoGroupStateProtector.generate(
        'key-1',
        {} as unknown as Crypto,
      ),
    ).rejects.toThrow('Web Crypto is unavailable');
  });

  test('rejects an incompatible key and invalid key id', async () => {
    const wrongKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 128 },
      false,
      ['encrypt', 'decrypt'],
    );
    expect(
      () => new WebCryptoGroupStateProtector('key', wrongKey),
    ).toThrow(/256-bit AES-GCM/);
    await expect(
      WebCryptoGroupStateProtector.generate('bad key id'),
    ).rejects.toThrow(/keyId/);
  });
});
