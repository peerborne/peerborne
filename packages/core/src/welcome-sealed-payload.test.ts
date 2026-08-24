import { describe, expect, test } from '@jest/globals';
import { Base64 } from 'js-base64';
import {
  encodeWelcomeSealedPayload,
  decodeWelcomeSealedPayload,
} from './welcome-sealed-payload';

describe('welcome-sealed-payload round-trip', () => {
  const keychainBytes = new Uint8Array([1, 2, 3, 4, 5]);

  test('encode then decode with beekemWelcome present', () => {
    const beekemWelcome = {
      leafIndex: 3,
      pathKeys: [{
        nodeIndex: 4,
        publicKey: new Uint8Array([10, 20, 30]),
        encryptedPrivateKey: new Uint8Array([40, 50, 60]),
      }],
      treeNodePublicKeys: [
        { nodeIndex: 0, publicKey: new Uint8Array([70, 80]) },
        { nodeIndex: 1, publicKey: null },
      ],
      treeHash: new Uint8Array([99, 100, 101]),
    };
    const encoded = encodeWelcomeSealedPayload({
      keychainChanges: keychainBytes,
      beekemWelcome,
    });
    const decoded = decodeWelcomeSealedPayload(encoded);
    expect(decoded.keychainChanges).toEqual(keychainBytes);
    expect(decoded.beekemWelcome).not.toBeNull();
    expect(decoded.beekemWelcome!.leafIndex).toBe(3);
    expect(decoded.beekemWelcome!.pathKeys).toHaveLength(1);
  });

  test('encode then decode with beekemWelcome null', () => {
    const encoded = encodeWelcomeSealedPayload({
      keychainChanges: keychainBytes,
      beekemWelcome: null,
    });
    const decoded = decodeWelcomeSealedPayload(encoded);
    expect(decoded.keychainChanges).toEqual(keychainBytes);
    expect(decoded.beekemWelcome).toBeNull();
  });
});

describe('decodeWelcomeSealedPayload error paths', () => {
  test('throws on invalid UTF-8', () => {
    const invalidUtf8 = new Uint8Array([0xff, 0xfe, 0xfd]);
    expect(() => decodeWelcomeSealedPayload(invalidUtf8)).toThrow(/not valid UTF-8/);
  });

  test('throws on invalid JSON', () => {
    expect(() => decodeWelcomeSealedPayload(new TextEncoder().encode('not json {{{'))).toThrow(/not valid JSON/);
  });

  test('throws on array instead of object', () => {
    expect(() => decodeWelcomeSealedPayload(new TextEncoder().encode('[]'))).toThrow(/expected a plain object/);
  });

  test('throws on null', () => {
    expect(() => decodeWelcomeSealedPayload(new TextEncoder().encode('null'))).toThrow(/expected a plain object/);
  });

  test('throws on string', () => {
    expect(() => decodeWelcomeSealedPayload(new TextEncoder().encode('"hello"'))).toThrow(/expected a plain object/);
  });

  test('throws on number', () => {
    expect(() => decodeWelcomeSealedPayload(new TextEncoder().encode('42'))).toThrow(/expected a plain object/);
  });

  test('throws when k is missing', () => {
    expect(() => decodeWelcomeSealedPayload(new TextEncoder().encode('{}'))).toThrow(/'k'.*base64/);
  });

  test('throws when k is not a string', () => {
    expect(() => decodeWelcomeSealedPayload(new TextEncoder().encode('{"k":123}'))).toThrow(/'k'.*base64/);
  });

  test('throws when bk is invalid', () => {
    const k = Base64.fromUint8Array(new Uint8Array([1, 2, 3]));
    const text = new TextEncoder().encode(JSON.stringify({ k, bk: 'bad' }));
    expect(() => decodeWelcomeSealedPayload(text)).toThrow(/invalid 'bk'.*BeeKEM welcome/);
  });

  test('allows bk absent', () => {
    const k = Base64.fromUint8Array(new Uint8Array([1, 2, 3]));
    const result = decodeWelcomeSealedPayload(new TextEncoder().encode(JSON.stringify({ k })));
    expect(result.keychainChanges).toEqual(new Uint8Array([1, 2, 3]));
    expect(result.beekemWelcome).toBeNull();
  });

  test('allows bk null', () => {
    const k = Base64.fromUint8Array(new Uint8Array([1, 2, 3]));
    const result = decodeWelcomeSealedPayload(new TextEncoder().encode(JSON.stringify({ k, bk: null })));
    expect(result.keychainChanges).toEqual(new Uint8Array([1, 2, 3]));
    expect(result.beekemWelcome).toBeNull();
  });
});