import { describe, expect, test, beforeAll } from '@jest/globals';
import { SubtleBlindIndexProvider } from './subtle-blind-index-provider.js';

describe('SubtleBlindIndexProvider', () => {
  let provider: SubtleBlindIndexProvider;
  let masterKey: CryptoKey;

  beforeAll(async () => {
    provider = new SubtleBlindIndexProvider();
    // Generate a random master key
    masterKey = await crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' },
      true, // extractable so we can use it with HKDF
      ['sign'],
    );
  });

  describe('deriveFieldKey', () => {
    test('should derive different keys for different field paths', async () => {
      const key1 = await provider.deriveFieldKey(masterKey, 'title');
      const key2 = await provider.deriveFieldKey(masterKey, 'author');
      // Keys should be different CryptoKey objects
      expect(key1).not.toBe(key2);
      // Compute tokens with each to verify they produce different results
      const token1 = await provider.computeToken(key1, 'test');
      const token2 = await provider.computeToken(key2, 'test');
      expect(token1).not.toEqual(token2);
    });

    test('should derive the same key for the same field path (deterministic)', async () => {
      const key1 = await provider.deriveFieldKey(masterKey, 'title');
      const key2 = await provider.deriveFieldKey(masterKey, 'title');
      const token1 = await provider.computeToken(key1, 'hello');
      const token2 = await provider.computeToken(key2, 'hello');
      expect(token1).toEqual(token2);
    });
  });

  describe('computeToken', () => {
    test('should produce deterministic tokens', async () => {
      const fieldKey = await provider.deriveFieldKey(masterKey, 'name');
      const token1 = await provider.computeToken(fieldKey, 'Alice');
      const token2 = await provider.computeToken(fieldKey, 'Alice');
      expect(token1).toEqual(token2);
    });

    test('should produce different tokens for different values', async () => {
      const fieldKey = await provider.deriveFieldKey(masterKey, 'name');
      const token1 = await provider.computeToken(fieldKey, 'Alice');
      const token2 = await provider.computeToken(fieldKey, 'Bob');
      expect(token1).not.toEqual(token2);
    });

    test('should normalize case for string values', async () => {
      const fieldKey = await provider.deriveFieldKey(masterKey, 'name');
      const token1 = await provider.computeToken(fieldKey, 'Alice');
      const token2 = await provider.computeToken(fieldKey, 'alice');
      expect(token1).toEqual(token2);
    });

    test('should handle numeric values', async () => {
      const fieldKey = await provider.deriveFieldKey(masterKey, 'age');
      const token1 = await provider.computeToken(fieldKey, 42);
      const token2 = await provider.computeToken(fieldKey, 42);
      expect(token1).toEqual(token2);
    });

    test('should distinguish strings from numbers', async () => {
      const fieldKey = await provider.deriveFieldKey(masterKey, 'value');
      const tokenStr = await provider.computeToken(fieldKey, '42');
      const tokenNum = await provider.computeToken(fieldKey, 42);
      expect(tokenStr).not.toEqual(tokenNum);
    });

    test('should return base64url-encoded string', async () => {
      const fieldKey = await provider.deriveFieldKey(masterKey, 'field');
      const token = await provider.computeToken(fieldKey, 'test');
      // Base64url: only alphanumeric, -, _
      expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
      // Should not contain padding
      expect(token).not.toContain('=');
    });
  });

  describe('computeCompoundToken', () => {
    test('should produce deterministic tokens', async () => {
      const fieldKey = await provider.deriveFieldKey(masterKey, 'compound');
      const token1 = await provider.computeCompoundToken(fieldKey, ['Alice', 42]);
      const token2 = await provider.computeCompoundToken(fieldKey, ['Alice', 42]);
      expect(token1).toEqual(token2);
    });

    test('should produce different tokens for different value sets', async () => {
      const fieldKey = await provider.deriveFieldKey(masterKey, 'compound');
      const token1 = await provider.computeCompoundToken(fieldKey, ['Alice', 42]);
      const token2 = await provider.computeCompoundToken(fieldKey, ['Bob', 42]);
      expect(token1).not.toEqual(token2);
    });

    test('should be order-sensitive', async () => {
      const fieldKey = await provider.deriveFieldKey(masterKey, 'compound');
      const token1 = await provider.computeCompoundToken(fieldKey, ['a', 'b']);
      const token2 = await provider.computeCompoundToken(fieldKey, ['b', 'a']);
      expect(token1).not.toEqual(token2);
    });
  });

  describe('deriveFieldKeyFromRaw', () => {
    test('should derive a usable field key from raw bytes', async () => {
      const rawKey = crypto.getRandomValues(new Uint8Array(32));
      const fieldKey = await provider.deriveFieldKeyFromRaw(rawKey, 'title');
      const token = await provider.computeToken(fieldKey, 'hello');
      expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    test('should produce deterministic tokens from same raw material', async () => {
      const rawKey = crypto.getRandomValues(new Uint8Array(32));
      const key1 = await provider.deriveFieldKeyFromRaw(rawKey, 'title');
      const key2 = await provider.deriveFieldKeyFromRaw(rawKey, 'title');
      const token1 = await provider.computeToken(key1, 'test');
      const token2 = await provider.computeToken(key2, 'test');
      expect(token1).toEqual(token2);
    });

    test('should produce different keys for different field paths', async () => {
      const rawKey = crypto.getRandomValues(new Uint8Array(32));
      const key1 = await provider.deriveFieldKeyFromRaw(rawKey, 'title');
      const key2 = await provider.deriveFieldKeyFromRaw(rawKey, 'author');
      const token1 = await provider.computeToken(key1, 'test');
      const token2 = await provider.computeToken(key2, 'test');
      expect(token1).not.toEqual(token2);
    });

    test('should produce same tokens as deriveFieldKey with equivalent raw material', async () => {
      // Export the master key to raw bytes, then use both paths
      const rawMaster = await crypto.subtle.exportKey('raw', masterKey);
      const rawBytes = new Uint8Array(rawMaster);

      const keyFromCrypto = await provider.deriveFieldKey(masterKey, 'name');
      const keyFromRaw = await provider.deriveFieldKeyFromRaw(rawBytes, 'name');

      const tokenCrypto = await provider.computeToken(keyFromCrypto, 'Alice');
      const tokenRaw = await provider.computeToken(keyFromRaw, 'Alice');
      expect(tokenCrypto).toEqual(tokenRaw);
    });

    test('should reject raw material shorter than 16 bytes', async () => {
      const shortKey = new Uint8Array(8);
      await expect(provider.deriveFieldKeyFromRaw(shortKey, 'title')).rejects.toThrow(RangeError);
    });

    test('should reject empty fieldPath', async () => {
      const rawKey = crypto.getRandomValues(new Uint8Array(32));
      await expect(provider.deriveFieldKeyFromRaw(rawKey, '')).rejects.toThrow('non-empty');
    });
  });

  describe('token truncation', () => {
    test('should produce shorter tokens with smaller tokenLengthBytes', async () => {
      const shortProvider = new SubtleBlindIndexProvider(8);
      const longProvider = new SubtleBlindIndexProvider(16);
      const fieldKey8 = await shortProvider.deriveFieldKey(masterKey, 'field');
      const fieldKey16 = await longProvider.deriveFieldKey(masterKey, 'field');
      const shortToken = await shortProvider.computeToken(fieldKey8, 'test');
      const longToken = await longProvider.computeToken(fieldKey16, 'test');
      expect(shortToken.length).toBeLessThan(longToken.length);
    });
  });
});
