import { welcomeFixture } from './__testutils__/beekem-v2.js';
import { describe, expect, jest, test } from '@jest/globals';
import { Base64 } from 'js-base64';
import {
  encodeWelcomeSealedPayloadV2,
  decodeWelcomeSealedPayloadV2,
  MAX_WELCOME_SEALED_PLAINTEXT_BYTES,
} from './welcome-sealed-payload';
import {
  deserializeBeeKEMWelcomeV2FromWire,
  serializeBeeKEMWelcomeV2ForWire,
} from './beekem-welcome-wire.js';
import { MAX_SHARED_PROTOCOL_REQUEST_BYTES } from './utils.js';

describe('welcome-sealed-payload round-trip', () => {
  const keychainBytes = new Uint8Array([1, 2, 3, 4, 5]);

  test('encode then decode with beekemWelcome present', () => {
    const beekemWelcome = welcomeFixture();
    const encoded = encodeWelcomeSealedPayloadV2({
      keychainChanges: keychainBytes,
      beekemWelcome,
    });
    const decoded = decodeWelcomeSealedPayloadV2(encoded);
    expect(decoded.keychainChanges).toEqual(keychainBytes);
    expect(decoded.beekemWelcome).not.toBeNull();
    expect(decoded.beekemWelcome!.leafIndex).toBe(2);
    expect(decoded.beekemWelcome!.pathKeys).toHaveLength(1);
  });

  test('rejects a key-only envelope at encoding', () => {
    expect(() => encodeWelcomeSealedPayloadV2({
      keychainChanges: keychainBytes,
      beekemWelcome: null as never,
    })).toThrow(/BeeKEMWelcomeV2/);
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

  test('requires every Welcome path key from the new leaf through the root', () => {
    const publicKey = (fill: number) => new Uint8Array(65).fill(fill);
    const completeWelcome = {
      ...beekemWelcome,
      numLeaves: 4,
      leafIndex: 6,
      pathKeys: [
        {
          nodeIndex: 5,
          publicKey: publicKey(5),
          encryptedPrivateKey: new Uint8Array([15]),
        },
        {
          nodeIndex: 3,
          publicKey: publicKey(3),
          encryptedPrivateKey: new Uint8Array([13]),
        },
      ],
      treeNodePublicKeys: [
        { nodeIndex: 0, publicKey: publicKey(10) },
        { nodeIndex: 1, publicKey: publicKey(11) },
        { nodeIndex: 2, publicKey: publicKey(12) },
        { nodeIndex: 4, publicKey: publicKey(14) },
      ],
    };
    const completeWire = serializeBeeKEMWelcomeV2ForWire(completeWelcome);
    const nonContiguousWire = {
      ...completeWire,
      pathKeys: [completeWire.pathKeys[1]],
      treeNodePublicKeys: [
        ...completeWire.treeNodePublicKeys,
        { nodeIndex: 5, publicKey: null },
      ],
    };

    expect(() =>
      deserializeBeeKEMWelcomeV2FromWire(nonContiguousWire),
    ).toThrow(/non-contiguous/);
    expect(() =>
      serializeBeeKEMWelcomeV2ForWire({
        ...completeWelcome,
        pathKeys: [completeWelcome.pathKeys[1]],
        treeNodePublicKeys: [
          ...completeWelcome.treeNodePublicKeys,
          { nodeIndex: 5, publicKey: null },
        ],
      }),
    ).toThrow(/non-contiguous/);
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

  test('detaches V2 plaintext before handing it to the parser', () => {
    const encoded = encodeWelcomeSealedPayloadV2({
      keychainChanges,
      beekemWelcome,
    });
    const nativeDecode = TextDecoder.prototype.decode;
    let parserInput: AllowSharedBufferSource | undefined;
    const decodeSpy = jest
      .spyOn(TextDecoder.prototype, 'decode')
      .mockImplementation(function (
        this: TextDecoder,
        input?: AllowSharedBufferSource,
        options?: TextDecodeOptions,
      ) {
        parserInput = input;
        encoded.fill(0);
        return Reflect.apply(nativeDecode, this, [input, options]);
      });

    try {
      expect(decodeWelcomeSealedPayloadV2(encoded)).toEqual({
        keychainChanges,
        beekemWelcome,
      });
      expect(parserInput).not.toBe(encoded);
    } finally {
      decodeSpy.mockRestore();
    }
  });

  test('the sealed plaintext limit leaves room for base64 and framing', () => {
    expect(
      Math.ceil(MAX_WELCOME_SEALED_PLAINTEXT_BYTES / 3) * 4,
    ).toBeLessThan(MAX_SHARED_PROTOCOL_REQUEST_BYTES);
  });

  test('rejects oversized or shared V2 plaintext before parsing', () => {
    const decodeSpy = jest.spyOn(TextDecoder.prototype, 'decode');
    try {
      expect(() =>
        decodeWelcomeSealedPayloadV2(
          new Uint8Array(MAX_WELCOME_SEALED_PLAINTEXT_BYTES + 1),
        ),
      ).toThrow(/plaintext must be an unshared Uint8Array no larger than/);
      expect(decodeSpy).not.toHaveBeenCalled();

      if (typeof SharedArrayBuffer !== 'undefined') {
        expect(() =>
          decodeWelcomeSealedPayloadV2(
            new Uint8Array(new SharedArrayBuffer(1)),
          ),
        ).toThrow(/plaintext must be an unshared Uint8Array/);
        expect(decodeSpy).not.toHaveBeenCalled();
      }
    } finally {
      decodeSpy.mockRestore();
    }
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

  test('enforces the exact sealed-payload cap across Base64 expansion', () => {
    const baseline = encodeWelcomeSealedPayloadV2({
      keychainChanges: new Uint8Array(1),
      beekemWelcome,
    });
    const remainingBase64Quartets = Math.floor(
      (MAX_WELCOME_SEALED_PLAINTEXT_BYTES - baseline.byteLength) / 4,
    );
    const boundaryKeychainLength = 3 * (1 + remainingBase64Quartets);

    const boundary = encodeWelcomeSealedPayloadV2({
      keychainChanges: new Uint8Array(boundaryKeychainLength),
      beekemWelcome,
    });
    expect(boundary.byteLength).toBeLessThanOrEqual(
      MAX_WELCOME_SEALED_PLAINTEXT_BYTES,
    );
    expect(
      MAX_WELCOME_SEALED_PLAINTEXT_BYTES - boundary.byteLength,
    ).toBeLessThan(4);

    expect(() =>
      encodeWelcomeSealedPayloadV2({
        keychainChanges: new Uint8Array(boundaryKeychainLength + 1),
        beekemWelcome,
      }),
    ).toThrow(/Welcome v2 sealed payload exceeds/);
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

describe('decodeWelcomeSealedPayloadV2 error paths', () => {
  test('throws on invalid UTF-8', () => {
    const invalidUtf8 = new Uint8Array([0xff, 0xfe, 0xfd]);
    expect(() => decodeWelcomeSealedPayloadV2(invalidUtf8)).toThrow(/not valid UTF-8/);
  });

  test('throws on invalid JSON', () => {
    expect(() => decodeWelcomeSealedPayloadV2(new TextEncoder().encode('not json {{{'))).toThrow(/not valid JSON/);
  });

  test.each([decodeWelcomeSealedPayloadV2])('does not expose decrypted plaintext through parse errors', (decode) => {
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
    expect(() => decodeWelcomeSealedPayloadV2(new TextEncoder().encode('[]'))).toThrow(/expected a plain object/);
  });

  test('throws on null', () => {
    expect(() => decodeWelcomeSealedPayloadV2(new TextEncoder().encode('null'))).toThrow(/expected a plain object/);
  });

  test('throws on string', () => {
    expect(() => decodeWelcomeSealedPayloadV2(new TextEncoder().encode('"hello"'))).toThrow(/expected a plain object/);
  });

  test('throws on number', () => {
    expect(() => decodeWelcomeSealedPayloadV2(new TextEncoder().encode('42'))).toThrow(/expected a plain object/);
  });

  test('throws when k is missing', () => {
    expect(() => decodeWelcomeSealedPayloadV2(new TextEncoder().encode('{}'))).toThrow(/'k'/);
  });

  test('throws when k is not a string', () => {
    expect(() => decodeWelcomeSealedPayloadV2(new TextEncoder().encode('{"k":123}'))).toThrow(/'k'/);
  });

  test('throws when bk is invalid', () => {
    const k = Base64.fromUint8Array(new Uint8Array([1, 2, 3]));
    const text = new TextEncoder().encode(JSON.stringify({ k, bk: 'bad' }));
    expect(() => decodeWelcomeSealedPayloadV2(text)).toThrow(/invalid 'bk'/);
  });

  test.each([{ k: 'AQ==' }, { k: 'AQ==', bk: null }])(
    'rejects a key-only envelope %j',
    (value) => {
      expect(() => decodeWelcomeSealedPayloadV2(
        new TextEncoder().encode(JSON.stringify(value)),
      )).toThrow(/'bk'/);
    },
  );
});
