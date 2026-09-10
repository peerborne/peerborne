import { describe, expect, test } from '@jest/globals';
import { Base64 } from 'js-base64';
import {
  encodeWelcomeSealedPayload,
  encodeWelcomeSealedPayloadV2,
  decodeWelcomeSealedPayload,
  decodeWelcomeSealedPayloadV2,
} from './welcome-sealed-payload';
import { serializeBeeKEMWelcomeV2ForWire } from './beekem-welcome-wire.js';

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

describe('welcome-sealed-payload V2 boundary', () => {
  const keychainChanges = new Uint8Array([1, 2, 3]);
  const beekemWelcome = {
    version: 2 as const,
    generation: 1,
    numLeaves: 2,
    leafIndex: 2,
    pathKeys: [
      {
        nodeIndex: 1,
        publicKey: new Uint8Array(65).fill(4),
        encryptedPrivateKey: new Uint8Array([5]),
      },
    ],
    treeNodePublicKeys: [
      { nodeIndex: 0, publicKey: new Uint8Array(65).fill(6) },
    ],
    treeHash: new Uint8Array(32).fill(7),
  };

  test('round-trips the strict V2 envelope exactly', () => {
    const encoded = encodeWelcomeSealedPayloadV2({
      keychainChanges,
      beekemWelcome,
    });
    const wire = JSON.parse(new TextDecoder().decode(encoded));

    expect(Object.keys(wire)).toEqual(['k', 'bk']);
    expect(decodeWelcomeSealedPayloadV2(encoded)).toEqual({
      keychainChanges,
      beekemWelcome,
    });
  });

  test('rejects malformed runtime V2 fields before returning wire data', () => {
    expect(() =>
      serializeBeeKEMWelcomeV2ForWire({
        ...beekemWelcome,
        generation: 0,
      }),
    ).toThrow(/generation/);
    expect(() =>
      serializeBeeKEMWelcomeV2ForWire({
        ...beekemWelcome,
        treeHash: new Uint8Array(31),
      }),
    ).toThrow(/treeHash.*32 bytes/);
    expect(() =>
      serializeBeeKEMWelcomeV2ForWire({
        ...beekemWelcome,
        pathKeys: [
          {
            ...beekemWelcome.pathKeys[0],
            publicKey: new Uint8Array(64),
          },
        ],
      }),
    ).toThrow(/publicKey.*65 bytes/);
  });

  test('preserves and requires the exact runtime V2 version', () => {
    expect(serializeBeeKEMWelcomeV2ForWire(beekemWelcome).version).toBe(2);
    expect(() =>
      serializeBeeKEMWelcomeV2ForWire({
        ...beekemWelcome,
        version: 1,
      } as unknown as typeof beekemWelcome),
    ).toThrow(/version.*must be 2/);
  });

  test('uses intrinsic byte lengths instead of shadowed properties', () => {
    const shadowedPublicKey = new Uint8Array([1]);
    Object.defineProperty(shadowedPublicKey, 'length', { value: 65 });
    const shadowedTreeHash = new Uint8Array([2]);
    Object.defineProperty(shadowedTreeHash, 'byteLength', { value: 32 });

    expect(() =>
      serializeBeeKEMWelcomeV2ForWire({
        ...beekemWelcome,
        pathKeys: [
          { ...beekemWelcome.pathKeys[0], publicKey: shadowedPublicKey },
        ],
      }),
    ).toThrow(/pathKeys\[0\]\.publicKey.*65/);
    expect(() =>
      serializeBeeKEMWelcomeV2ForWire({
        ...beekemWelcome,
        treeHash: shadowedTreeHash,
      }),
    ).toThrow(/treeHash.*32/);
  });

  test('rejects byte lookalikes and SharedArrayBuffer-backed views', () => {
    expect(() =>
      serializeBeeKEMWelcomeV2ForWire({
        ...beekemWelcome,
        treeHash: {
          length: 32,
          byteLength: 32,
          buffer: new ArrayBuffer(32),
        } as unknown as Uint8Array,
      }),
    ).toThrow(/treeHash.*Uint8Array/);

    if (typeof SharedArrayBuffer !== 'undefined') {
      expect(() =>
        serializeBeeKEMWelcomeV2ForWire({
          ...beekemWelcome,
          pathKeys: [
            {
              ...beekemWelcome.pathKeys[0],
              publicKey: new Uint8Array(new SharedArrayBuffer(65)),
            },
          ],
        }),
      ).toThrow(/publicKey.*unshared/);
    }
  });

  test('rejects oversized path arrays before reading their entries', () => {
    let entryReads = 0;
    const oversizedPath = new Array(65);
    Object.defineProperty(oversizedPath, '0', {
      enumerable: true,
      get() {
        entryReads++;
        throw new Error('must not read an oversized path array');
      },
    });

    expect(() =>
      serializeBeeKEMWelcomeV2ForWire({
        ...beekemWelcome,
        pathKeys: oversizedPath,
      }),
    ).toThrow(/pathKeys has invalid length/);
    expect(entryReads).toBe(0);
  });

  test('detaches keychain bytes using their intrinsic length', () => {
    const shadowedKeychain = new Uint8Array([7]);
    Object.defineProperty(shadowedKeychain, 'length', { value: 4 });

    const encoded = encodeWelcomeSealedPayloadV2({
      keychainChanges: shadowedKeychain,
      beekemWelcome,
    });
    expect(decodeWelcomeSealedPayloadV2(encoded).keychainChanges).toEqual(
      new Uint8Array([7]),
    );
  });

  test('rejects non-genuine and shared keychain byte views', () => {
    expect(() =>
      encodeWelcomeSealedPayloadV2({
        keychainChanges: {
          length: 3,
          byteLength: 3,
          0: 1,
          1: 2,
          2: 3,
        } as unknown as Uint8Array,
        beekemWelcome,
      }),
    ).toThrow(/keychainChanges.*unshared Uint8Array/);

    if (typeof SharedArrayBuffer !== 'undefined') {
      expect(() =>
        encodeWelcomeSealedPayloadV2({
          keychainChanges: new Uint8Array(new SharedArrayBuffer(3)),
          beekemWelcome,
        }),
      ).toThrow(/keychainChanges.*unshared Uint8Array/);
    }
  });

  test('rejects oversized keychain bytes before Base64 encoding', () => {
    expect(() =>
      encodeWelcomeSealedPayloadV2({
        keychainChanges: new Uint8Array(10 * 1024 * 1024 + 1),
        beekemWelcome,
      }),
    ).toThrow(/keychainChanges.*no larger than/);
  });

  test.each([
    ['missing bk', { k: Base64.fromUint8Array(keychainChanges) }],
    [
      'extra envelope field',
      {
        ...JSON.parse(
          new TextDecoder().decode(
            encodeWelcomeSealedPayloadV2({
              keychainChanges,
              beekemWelcome,
            }),
          ),
        ),
        extra: true,
      },
    ],
    ['null bk', { k: Base64.fromUint8Array(keychainChanges), bk: null }],
    [
      'malformed nested bk',
      {
        ...JSON.parse(
          new TextDecoder().decode(
            encodeWelcomeSealedPayloadV2({
              keychainChanges,
              beekemWelcome,
            }),
          ),
        ),
        bk: { version: 2, generation: 0 },
      },
    ],
  ])('rejects %s', (_name, envelope) => {
    expect(() =>
      decodeWelcomeSealedPayloadV2(
        new TextEncoder().encode(JSON.stringify(envelope)),
      ),
    ).toThrow(/welcome-sealed-payload v2/);
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

  test.each([
    decodeWelcomeSealedPayload,
    decodeWelcomeSealedPayloadV2,
  ])('does not expose decrypted plaintext through parse errors', (decode) => {
    const privateMarker = 'PRIVATE-WELCOME-PLAINTEXT';
    let caught: unknown;
    try {
      decode(
        new TextEncoder().encode(
          `{"k":"AQ==","private":"${privateMarker}"`,
        ),
      );
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(Error);
    expect(String(caught)).not.toContain(privateMarker);
    expect((caught as Error).cause).toBeUndefined();
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
