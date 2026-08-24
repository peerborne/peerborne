import { describe, expect, test } from '@jest/globals';
import { SubtleCrypto } from './auth-subtlecrypto.js';
import type { AesAlgorithmName } from './auth-provider.js';
import { importSymmetricKey } from './utils.js';

const auth = new SubtleCrypto();

const privateKeyData1 = {
  key_ops: ['sign'],
  ext: true,
  kty: 'EC',
  x: 'iV0DESMDz3fcubTpUCMK4YLWbU9gDslDgdflc5OGrQVII_wCViDdqGbMTOmQLY0F',
  y: 'CQyfju2lK2mT0TIVDI-olIqFC3m3AayX0deHkw4JPCU-GwzV9k0BT295OSQ495kK',
  d: 'kr28U5k3zRtFMXAQuoUZgmqnpI0w01p9sh0spOXZBnkc6Ez6rdbN2W6ZcAJBXxge',
  crv: 'P-384',
};
const publicKeyData1 = {
  key_ops: ['verify'],
  ext: true,
  kty: 'EC',
  x: 'iV0DESMDz3fcubTpUCMK4YLWbU9gDslDgdflc5OGrQVII_wCViDdqGbMTOmQLY0F',
  y: 'CQyfju2lK2mT0TIVDI-olIqFC3m3AayX0deHkw4JPCU-GwzV9k0BT295OSQ495kK',
  crv: 'P-384',
};
const privateKeyData2 = {
  key_ops: ['sign'],
  ext: true,
  kty: 'EC',
  x: 'oodHRfDRDsXcpe2FvwctaK1y4pt8Lhx5tmiXZ-35vzXuDUD5zWhzPxgC8FZvyY0K',
  y: 'KhgG-mU2-mNbhgdK9_8nEMwPa2_bWWl_zlqY6Q4xuXYMOjhSLGydbFIDSAGBaNaJ',
  d: 'ZtP5zRvBLPK82BAwNs49-Y9227v2vtSdwhgUgH965LTdyZ-9R3qTQEPS7F6vwhyM',
  crv: 'P-384',
};
const publicKeyData2 = {
  key_ops: ['verify'],
  ext: true,
  kty: 'EC',
  x: 'oodHRfDRDsXcpe2FvwctaK1y4pt8Lhx5tmiXZ-35vzXuDUD5zWhzPxgC8FZvyY0K',
  y: 'KhgG-mU2-mNbhgdK9_8nEMwPa2_bWWl_zlqY6Q4xuXYMOjhSLGydbFIDSAGBaNaJ',
  crv: 'P-384',
};
const docKeyData1 = {
  key_ops: ['encrypt', 'decrypt'],
  ext: true,
  kty: 'oct',
  k: 'LMP1XEE0zwpmZF0XXwFg5MYr_o5ZVpJ7vyVRyPXLC1o',
  alg: 'A256GCM',
};
const docKeyData2 = {
  key_ops: ['encrypt', 'decrypt'],
  ext: true,
  kty: 'oct',
  k: '3TX-u2qZ6XAdIXL31LYVdUnspykU6J4DbQtYssWswKs',
  alg: 'A256GCM',
};

/**
 * Import a JWK key for the given algorithm.
 */
async function importKey(
  keyData: JsonWebKey,
  usage: KeyUsage[],
  algorithmName = 'ECDSA',
  format: KeyFormat = 'jwk',
) {
  let algorithm:
    | AlgorithmIdentifier
    | RsaHashedImportParams
    | EcKeyImportParams
    | HmacImportParams
    | AesKeyAlgorithm;
  switch (algorithmName) {
    case 'ECDSA': {
      algorithm = {
        name: algorithmName,
        namedCurve: 'P-384',
      };
      break;
    }
    case 'AES-GCM':
    case 'AES-CTR':
    case 'AES-CBC': {
      algorithm = {
        name: algorithmName,
      };
      break;
    }
    default: {
      throw new Error(`Unsupported algorithm: ${algorithmName}`);
    }
  }
  if (format !== 'jwk') {
    console.warn('Warning: key import format is not jwk.');
  }
  const key = await crypto.subtle.importKey(
    format as 'jwk',
    keyData,
    algorithm,
    true,
    usage,
  );
  return key;
}

/** Generate a raw 256-bit key for the given algorithm. */
async function generateKey(algorithmName: AesAlgorithmName): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: algorithmName, length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
}

describe('sign and verify', () => {
  test.each([
    [
      new Uint8Array([11, 12, 250]),
      privateKeyData1,
      publicKeyData1,
      true,
      false,
      false,
    ],
    [
      new Uint8Array([11, 44, 250]),
      privateKeyData1,
      publicKeyData2,
      false,
      false,
      false,
    ],
    [
      new Uint8Array([11, 44, 250]),
      publicKeyData1,
      publicKeyData1,
      false,
      true,
      false,
    ],
    [
      new Uint8Array([11, 44, 250]),
      privateKeyData1,
      privateKeyData1,
      false,
      false,
      true,
    ],
  ])(
    `sign and verify`,
    async (
      data: Uint8Array,
      privateKeyData: JsonWebKey,
      publicKeyData: JsonWebKey,
      success: boolean,
      expectedSignCrashed: boolean,
      expectedVerifyCrashed: boolean,
    ) => {
      const privateKey = await importKey(privateKeyData, ['sign']);
      const publicKey = await importKey(publicKeyData, ['verify']);
      let signCrashed = false;
      let sig: Uint8Array | undefined;
      try {
        sig = await auth.sign(data, privateKey);
      } catch {
        signCrashed = true;
      }
      expect(signCrashed).toStrictEqual(expectedSignCrashed);
      if (sig !== undefined) {
        let verifyCrashed = false;
        let result: boolean | undefined;
        try {
          result = await auth.verify(data, publicKey, sig);
        } catch {
          verifyCrashed = true;
        }
        expect(verifyCrashed).toStrictEqual(expectedVerifyCrashed);
        if (result !== undefined) {
          expect(result).toStrictEqual(success);
        }
      }
    },
  );
});

describe('encrypt and decrypt', () => {
  const algorithms: AesAlgorithmName[] = ['AES-GCM', 'AES-CTR', 'AES-CBC'];

  test.each(algorithms)(
    'roundtrip with %s',
    async (alg) => {
      const instance = new SubtleCrypto(undefined, alg);
      const key = await generateKey(alg);
      const plaintext = new Uint8Array([43, 99, 250, 83, 89, 90, 111]);

      const { data: encrypted, nonce } = await instance.encrypt(plaintext, key);
      expect(encrypted.length).toBeGreaterThan(0);
      expect(nonce.length).toBe(instance.nonceBits);

      const decrypted = await instance.decrypt(encrypted, key, nonce);
      expect(decrypted).toStrictEqual(plaintext);
    },
  );

  test.each([docKeyData1, docKeyData2])(
    'roundtrip with AES-GCM JWK key',
    async (keyData) => {
      const key = await importKey(keyData, ['encrypt', 'decrypt'], 'AES-GCM');
      const plaintext = new Uint8Array([43, 99, 250, 83]);

      const { data: encrypted, nonce } = await auth.encrypt(plaintext, key);
      const decrypted = await auth.decrypt(encrypted, key, nonce);
      expect(decrypted).toStrictEqual(plaintext);
    },
  );

  test('empty plaintext roundtrip', async () => {
    const key = await generateKey('AES-GCM');
    const plaintext = new Uint8Array([]);

    const { data: encrypted, nonce } = await auth.encrypt(plaintext, key);
    const decrypted = await auth.decrypt(encrypted, key, nonce);
    expect(decrypted).toStrictEqual(plaintext);
  });
});

describe('nonce size', () => {
  test('AES-GCM nonceBits is 12 bytes', () => {
    const instance = new SubtleCrypto(undefined, 'AES-GCM');
    expect(instance.nonceBits).toBe(12);
  });

  test('AES-CTR nonceBits is 16 bytes', () => {
    const instance = new SubtleCrypto(undefined, 'AES-CTR');
    expect(instance.nonceBits).toBe(16);
  });

  test('AES-CBC nonceBits is 16 bytes', () => {
    const instance = new SubtleCrypto(undefined, 'AES-CBC');
    expect(instance.nonceBits).toBe(16);
  });

  test.each(['AES-GCM', 'AES-CTR', 'AES-CBC'] as AesAlgorithmName[])(
    'encrypt generates nonce of correct size for %s',
    async (alg) => {
      const instance = new SubtleCrypto(undefined, alg);
      const key = await generateKey(alg);
      const result = await instance.encrypt(new Uint8Array([1, 2, 3]), key);
      expect(result.nonce.length).toBe(instance.nonceBits);
    },
  );
});

describe('HMAC tamper detection (CTR/CBC)', () => {
  const nonGcmAlgorithms: AesAlgorithmName[] = ['AES-CTR', 'AES-CBC'];

  test.each(nonGcmAlgorithms)(
    '%s: flipping a ciphertext byte causes HMAC failure',
    async (alg) => {
      const instance = new SubtleCrypto(undefined, alg);
      const key = await generateKey(alg);
      const plaintext = new Uint8Array([10, 20, 30, 40, 50]);

      const { data, nonce } = await instance.encrypt(plaintext, key);
      // Flip a byte in the ciphertext portion (before the 32-byte HMAC tag)
      const tampered = new Uint8Array(data);
      tampered[0] ^= 0xff;

      await expect(instance.decrypt(tampered, key, nonce)).rejects.toThrow(
        'HMAC verification failed',
      );
    },
  );

  test.each(nonGcmAlgorithms)(
    '%s: flipping a byte in the HMAC tag causes failure',
    async (alg) => {
      const instance = new SubtleCrypto(undefined, alg);
      const key = await generateKey(alg);
      const plaintext = new Uint8Array([10, 20, 30, 40, 50]);

      const { data, nonce } = await instance.encrypt(plaintext, key);
      // Flip the last byte (inside the HMAC tag)
      const tampered = new Uint8Array(data);
      tampered[tampered.length - 1] ^= 0xff;

      await expect(instance.decrypt(tampered, key, nonce)).rejects.toThrow(
        'HMAC verification failed',
      );
    },
  );

  test.each(nonGcmAlgorithms)(
    '%s: data too short for HMAC tag throws',
    async (alg) => {
      const instance = new SubtleCrypto(undefined, alg);
      const key = await generateKey(alg);

      await expect(
        instance.decrypt(new Uint8Array(10), key, new Uint8Array(16)),
      ).rejects.toThrow('Ciphertext too short');
    },
  );
});

describe('AES-GCM tamper detection', () => {
  test('flipping a ciphertext byte causes GCM auth failure', async () => {
    const key = await generateKey('AES-GCM');
    const { data, nonce } = await auth.encrypt(new Uint8Array([1, 2, 3]), key);
    const tampered = new Uint8Array(data);
    tampered[0] ^= 0xff;

    await expect(auth.decrypt(tampered, key, nonce)).rejects.toThrow();
  });
});

describe('_extractNonce', () => {
  const extractNonce = (params: any) => (auth as any)._extractNonce(params);

  test('extracts iv from AesGcmParams', () => {
    const iv = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    const result = extractNonce({ name: 'AES-GCM', iv });
    expect(result).toBe(iv);
  });

  test('extracts counter from AesCtrParams', () => {
    const counter = new Uint8Array(16);
    const result = extractNonce({ name: 'AES-CTR', counter, length: 64 });
    expect(result).toBe(counter);
  });

  test('handles ArrayBuffer input', () => {
    const buf = new ArrayBuffer(12);
    new Uint8Array(buf).set([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    const result = extractNonce({ name: 'AES-GCM', iv: buf });
    expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]));
  });

  test('handles ArrayBufferView with byteOffset', () => {
    const buf = new ArrayBuffer(20);
    // Create a view starting at offset 4 with length 12
    const view = new DataView(buf, 4, 12);
    // Write known values into the view region
    for (let i = 0; i < 12; i++) {
      view.setUint8(i, i + 1);
    }
    const result = extractNonce({ name: 'AES-GCM', iv: view });
    expect(result.length).toBe(12);
    expect(result[0]).toBe(1);
    expect(result[11]).toBe(12);
  });

  test('throws for params without iv or counter', () => {
    expect(() => extractNonce({ name: 'unknown' })).toThrow(
      'Cannot extract nonce from algorithm',
    );
  });
});

describe('cross-algorithm failure', () => {
  test('GCM-encrypted data cannot be decrypted by CTR instance using same key material', async () => {
    const gcm = new SubtleCrypto(undefined, 'AES-GCM');
    const ctr = new SubtleCrypto(undefined, 'AES-CTR');

    // Use the same raw key material imported under both algorithms
    const rawKeyBytes = new Uint8Array(32);
    crypto.getRandomValues(rawKeyBytes);
    const gcmKey = await importSymmetricKey(rawKeyBytes, 'raw', 'AES-GCM');
    const ctrKey = await importSymmetricKey(rawKeyBytes, 'raw', 'AES-CTR');

    const { data, nonce } = await gcm.encrypt(new Uint8Array([1, 2, 3]), gcmKey);
    // Same key material but different algorithm = failure
    await expect(ctr.decrypt(data, ctrKey, nonce)).rejects.toThrow();
  });
});
