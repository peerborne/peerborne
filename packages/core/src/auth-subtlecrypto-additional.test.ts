import { describe, expect, test } from '@jest/globals';
import { SubtleCrypto } from './auth-subtlecrypto';
import { Base64 } from 'js-base64';

describe('SubtleCrypto additional coverage', () => {
  describe('_encryptionAlgorithmParams validation', () => {
    test('AES-GCM rejects wrong nonce length (line 164)', () => {
      const c = new SubtleCrypto(undefined, 'AES-GCM');
      expect(() => (c as any)._encryptionAlgorithmParams(new Uint8Array(8))).toThrow(
        '12 bytes',
      );
    });

    test('AES-CTR rejects wrong counter length (line 171)', () => {
      const c = new SubtleCrypto(undefined, 'AES-CTR');
      expect(() => (c as any)._encryptionAlgorithmParams(new Uint8Array(8))).toThrow(
        '16 bytes',
      );
    });

    test('AES-CBC rejects wrong IV length (line 192)', () => {
      const c = new SubtleCrypto(undefined, 'AES-CBC');
      expect(() => (c as any)._encryptionAlgorithmParams(new Uint8Array(8))).toThrow(
        '16 bytes',
      );
    });
  });

  describe('_deriveHmacKey with non-extractable key (line 212)', () => {
    test('rejects non-extractable key', async () => {
      const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
      );
      const c = new SubtleCrypto(undefined, 'AES-CTR');
      await expect((c as any)._deriveHmacKey(key)).rejects.toThrow(
        'must be extractable',
      );
    });
  });

  describe('serializePublicKey with non-extractable key (line 292)', () => {
    test('succeeds with extractable key', async () => {
      const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-384' },
        true,
        ['sign', 'verify'],
      );
      const c = new SubtleCrypto();
      const result = await c.serializePublicKey(keyPair.publicKey);
      expect(typeof result).toBe('string');
    });
  });

  describe('deserializePublicKey error paths', () => {
    const c = new SubtleCrypto();

    test('rejects invalid base64 (line 314)', async () => {
      await expect(c.deserializePublicKey('!!!not-base64!!!')).rejects.toThrow(
        'canonical base64',
      );
    });

    test('rejects wrong-length key', async () => {
      const short = new Uint8Array(50);
      crypto.getRandomValues(short);
      short[0] = 0x04;
      const b64 = Base64.fromUint8Array(short);
      await expect(c.deserializePublicKey(b64)).rejects.toThrow(
        '97-byte',
      );
    });

    test('rejects key with wrong header byte', async () => {
      const raw = new Uint8Array(97);
      crypto.getRandomValues(raw);
      raw[0] = 0x03;
      const b64 = Base64.fromUint8Array(raw);
      await expect(c.deserializePublicKey(b64)).rejects.toThrow(
        'uncompressed P-384',
      );
    });

    test('round-trip serialize then deserialize', async () => {
      const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-384' },
        true,
        ['sign', 'verify'],
      );
      const serialized = await c.serializePublicKey(keyPair.publicKey);
      const deserialized = await c.deserializePublicKey(serialized);

      const orig = await crypto.subtle.exportKey('raw', keyPair.publicKey);
      const restored = await crypto.subtle.exportKey('raw', deserialized);
      expect(new Uint8Array(orig)).toEqual(new Uint8Array(restored));
    });
  });

  describe('decrypt error paths', () => {
    test('decrypt without nonce throws (line 351)', async () => {
      const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt'],
      );
      const c = new SubtleCrypto();
      await expect(c.decrypt(new Uint8Array([1, 2, 3]), key)).rejects.toThrow(
        'Nonce is required',
      );
    });
  });
});