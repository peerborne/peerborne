import { describe, expect, jest, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';
import { JSONSerializer } from './json-serializer.js';
import { CRDTChangeBlock } from './crdt-change-block.js';
import { CRDTChangeNode } from './crdt-change-node.js';
import { MAX_MERKLE_DAG_DEPTH } from './merkle-dag-serialization.js';

const jsonSerializer = new JSONSerializer<any>();

let testObject = { key: 'val' };
let testObjectSerialized = '{"key":"val"}';
let testString = 'Hello';
let testStringAsUint8Array = Uint8Array.from([72, 101, 108, 108, 111]);

test('serialize json object to string', () => {
  expect(jsonSerializer.serialize(testObject)).toMatch(testObjectSerialized);
});

test('deserialize string to json object', () => {
  expect(jsonSerializer.deserialize(testObjectSerialized)).toMatchObject(
    testObject,
  );
});

test('does not log malformed plaintext JSON payloads', () => {
  const error = jest.spyOn(console, 'error').mockImplementation(() => {});
  const privatePayload = '{"private":"do-not-log"';
  expect(() => jsonSerializer.deserialize(privatePayload)).toThrow();
  expect(error).toHaveBeenCalledWith('Failed to parse JSON message');
  expect(error.mock.calls.flat().join(' ')).not.toContain('do-not-log');
  error.mockRestore();
});

test('encode string to Uint8Array', () => {
  expect(jsonSerializer.encode(testString)).toStrictEqual(
    testStringAsUint8Array,
  );
});

test('decode Uint8Array to string', () => {
  expect(jsonSerializer.decode(testStringAsUint8Array)).toMatch(testString);
});

describe('load-request stream framing', () => {
  const encoder = new TextEncoder();

  test('detects one fragmented top-level object in linear passes', () => {
    const detector = jsonSerializer.createLoadRequestCompletionDetector();
    const payload = encoder.encode(
      ' \n{"documentId":"/quoted-}\\"","signature":"sig","extra":[{"ok":true}]}',
    );

    for (let index = 0; index < payload.length - 1; index++) {
      expect(detector(payload.subarray(index, index + 1))).toBe(false);
    }
    expect(detector(payload.subarray(payload.length - 1))).toBe(true);
    expect(detector(encoder.encode('\r\n '))).toBe(true);
  });

  test('creates independent state for concurrent request streams', () => {
    const first = jsonSerializer.createLoadRequestCompletionDetector();
    const second = jsonSerializer.createLoadRequestCompletionDetector();

    expect(first(encoder.encode('{"documentId":'))).toBe(false);
    expect(second(encoder.encode('{"documentId":"/two"}'))).toBe(true);
    expect(first(encoder.encode('"/one"}'))).toBe(true);
  });

  test('rejects non-object roots and same-chunk trailing data', () => {
    const nonObject = jsonSerializer.createLoadRequestCompletionDetector();
    expect(() => nonObject(encoder.encode('[]'))).toThrow(/must be an object/);

    const trailing = jsonSerializer.createLoadRequestCompletionDetector();
    expect(() => trailing(encoder.encode('{"documentId":"/doc"}x'))).toThrow(
      /after JSON load request/,
    );
  });

  test('defers mismatched delimiters to the single JSON parse attempt', () => {
    const detector = jsonSerializer.createLoadRequestCompletionDetector();
    expect(detector(encoder.encode('{"extra":[}'))).toBe(false);
    expect(detector(encoder.encode(']'))).toBe(true);
  });
});

describe('keyID in serializeChangeBlock / deserializeChangeBlock', () => {
  const nonce = new Uint8Array([1, 2, 3, 4]);

  test('round-trips a change block with keyID', () => {
    const block: CRDTChangeBlock<any> = {
      changes: { foo: 'bar' },
      nonce,
      keyID: 'dGVzdC1rZXktaWQ=',
    };
    const serialized = jsonSerializer.serializeChangeBlock(block);
    const deserialized = jsonSerializer.deserializeChangeBlock(serialized);

    expect(deserialized.keyID).toBe('dGVzdC1rZXktaWQ=');
  });

  test('round-trips a change block without keyID', () => {
    const block: CRDTChangeBlock<any> = {
      changes: { foo: 'bar' },
      nonce,
    };
    const serialized = jsonSerializer.serializeChangeBlock(block);
    const deserialized = jsonSerializer.deserializeChangeBlock(serialized);

    expect(deserialized.keyID).toBeUndefined();
  });
});

describe('keyID validation in deserializeChangeBlock', () => {
  test('rejects keyID that is a number', () => {
    const raw = JSON.stringify({
      changes: { foo: 'bar' },
      nonce: 'AQIDBA==',
      keyID: 123,
    });
    expect(() => jsonSerializer.deserializeChangeBlock(raw)).toThrow(
      'keyID must be a string',
    );
  });

  test('rejects keyID that is an object', () => {
    const raw = JSON.stringify({
      changes: { foo: 'bar' },
      nonce: 'AQIDBA==',
      keyID: {},
    });
    expect(() => jsonSerializer.deserializeChangeBlock(raw)).toThrow(
      'keyID must be a string',
    );
  });

  test('rejects keyID that is null', () => {
    const raw = JSON.stringify({
      changes: { foo: 'bar' },
      nonce: 'AQIDBA==',
      keyID: null,
    });
    expect(() => jsonSerializer.deserializeChangeBlock(raw)).toThrow(
      'keyID must be a string',
    );
  });
});

describe('blindIndexTokens in serializeChangeBlock / deserializeChangeBlock', () => {
  const nonce = new Uint8Array([1, 2, 3, 4]);

  test('round-trips a change block without blindIndexTokens', () => {
    const block: CRDTChangeBlock<any> = {
      changes: { foo: 'bar' },
      nonce,
    };
    const serialized = jsonSerializer.serializeChangeBlock(block);
    const deserialized = jsonSerializer.deserializeChangeBlock(serialized);

    expect(deserialized.changes).toEqual({ foo: 'bar' });
    expect(deserialized.nonce).toEqual(nonce);
    expect(deserialized.blindIndexTokens).toBeUndefined();
    expect('blindIndexTokens' in deserialized).toBe(false);
  });

  test('round-trips a change block with a populated blindIndexTokens map', () => {
    const tokens = { 'field.name': 'hmac-token-abc', email: 'hmac-token-def' };
    const block: CRDTChangeBlock<any> = {
      changes: { foo: 'bar' },
      nonce,
      blindIndexTokens: tokens,
    };
    const serialized = jsonSerializer.serializeChangeBlock(block);
    const deserialized = jsonSerializer.deserializeChangeBlock(serialized);

    expect(deserialized.blindIndexTokens).toEqual(tokens);
  });

  test('round-trips a change block with an empty blindIndexTokens map', () => {
    const block: CRDTChangeBlock<any> = {
      changes: { foo: 'bar' },
      nonce,
      blindIndexTokens: {},
    };
    const serialized = jsonSerializer.serializeChangeBlock(block);
    const deserialized = jsonSerializer.deserializeChangeBlock(serialized);

    expect(deserialized.blindIndexTokens).toEqual({});
    expect('blindIndexTokens' in deserialized).toBe(true);
  });

  test('rejects blindIndexTokens that is an array', () => {
    const raw = JSON.stringify({
      changes: { foo: 'bar' },
      nonce: 'AQIDBA==',
      blindIndexTokens: ['not', 'an', 'object'],
    });
    expect(() => jsonSerializer.deserializeChangeBlock(raw)).toThrow(
      'blindIndexTokens must be a plain object',
    );
  });

  test('rejects blindIndexTokens that is null', () => {
    const raw = JSON.stringify({
      changes: { foo: 'bar' },
      nonce: 'AQIDBA==',
      blindIndexTokens: null,
    });
    expect(() => jsonSerializer.deserializeChangeBlock(raw)).toThrow(
      'blindIndexTokens must be a plain object',
    );
  });

  test('rejects blindIndexTokens with non-string values', () => {
    const raw = JSON.stringify({
      changes: { foo: 'bar' },
      nonce: 'AQIDBA==',
      blindIndexTokens: { field: 123 },
    });
    expect(() => jsonSerializer.deserializeChangeBlock(raw)).toThrow(
      'blindIndexTokens values must be strings',
    );
  });
});

describe('V4 initial-load challenge JSON boundary', () => {
  const challenge = new Uint8Array(32).fill(9);

  test('round-trips load requests', () => {
    expect(
      jsonSerializer.deserializeLoadRequest(
        jsonSerializer.serializeLoadRequest({
          documentId: '/doc',
          signature: 'request-signature',
          loadChallenge: challenge,
        }),
      ).loadChallenge,
    ).toEqual(challenge);
  });

  test('rejects malformed challenge width and non-canonical base64', () => {
    const encode = (value: unknown) =>
      new TextEncoder().encode(
        JSON.stringify({ documentId: '/doc', loadChallenge: value }),
      );
    expect(() =>
      jsonSerializer.deserializeLoadRequest(encode('AQ==')),
    ).toThrow(/32-byte/);
    expect(() =>
      jsonSerializer.deserializeLoadRequest(
        encode('CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk'),
      ),
    ).toThrow(/canonical base64|32-byte/);
  });
});

describe('signed top-level wire field order', () => {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  test('preserves sync-message bytes with recognized and unknown fields in different orders', () => {
    const wires = [
      '{"changes":{"kind":"writer","change":{"delta":1}},"documentId":"/doc","signature":"sig","extension":{"version":1}}',
      '{"documentId":"/doc","extension":{"version":1},"changes":{"kind":"writer","change":{"delta":1}},"signature":"sig"}',
      '{"extension":{"version":1},"signature":"sig","documentId":"/doc","changes":{"kind":"writer","change":{"delta":1}}}',
    ];

    for (const wire of wires) {
      const decoded = jsonSerializer.deserializeSyncMessage(
        encoder.encode(wire),
      );
      expect(decoder.decode(jsonSerializer.serializeSyncMessage(decoded))).toBe(
        wire,
      );
    }
  });

  test('preserves load-request bytes with the transformed challenge in different positions', () => {
    const challengeWire = JSON.parse(
      decoder.decode(
        jsonSerializer.serializeLoadRequest({
          documentId: '/doc',
          signature: 'sig',
          loadChallenge: new Uint8Array(32).fill(7),
        }),
      ),
    ).loadChallenge as string;
    const wires = [
      JSON.stringify({
        loadChallenge: challengeWire,
        documentId: '/doc',
        signature: 'sig',
        extension: 1,
      }),
      JSON.stringify({
        documentId: '/doc',
        extension: 1,
        loadChallenge: challengeWire,
        signature: 'sig',
      }),
      JSON.stringify({
        extension: 1,
        signature: 'sig',
        documentId: '/doc',
        loadChallenge: challengeWire,
      }),
    ];

    for (const wire of wires) {
      const decoded = jsonSerializer.deserializeLoadRequest(
        encoder.encode(wire),
      );
      expect(decoder.decode(jsonSerializer.serializeLoadRequest(decoded))).toBe(
        wire,
      );
    }
  });

  test('keeps dangerous unknown keys inert while retaining signed bytes', () => {
    const wire =
      '{"documentId":"/doc","__proto__":{"polluted":true},' +
      '"changes":{"kind":"document"},"extension":"kept"}';
    const decoded = jsonSerializer.deserializeSyncMessage(
      encoder.encode(wire),
    ) as unknown as Record<string, unknown>;

    expect(Object.getPrototypeOf(decoded)).toBe(Object.prototype);
    expect(Object.prototype.hasOwnProperty.call(decoded, '__proto__')).toBe(
      true,
    );
    expect((decoded.__proto__ as Record<string, unknown>).polluted).toBe(true);
    expect(
      Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted'),
    ).toBe(false);
    expect(
      decoder.decode(
        jsonSerializer.serializeSyncMessage(
          decoded as unknown as Parameters<
            typeof jsonSerializer.serializeSyncMessage
          >[0],
        ),
      ),
    ).toBe(wire);
  });

  test('rejects enumerable accessors without invoking them', () => {
    let reads = 0;
    const accessorMessage = { documentId: '/doc' } as Record<string, unknown>;
    Object.defineProperty(accessorMessage, 'changes', {
      enumerable: true,
      get: () => {
        reads++;
        return { kind: 'document' };
      },
    });

    expect(() =>
      jsonSerializer.serializeSyncMessage(
        accessorMessage as Parameters<
          typeof jsonSerializer.serializeSyncMessage
        >[0],
      ),
    ).toThrow(/wire field "changes" must be a data property/);

    class InjectedSerializer extends JSONSerializer<any> {
      override deserialize(): unknown {
        return accessorMessage;
      }
    }
    expect(() =>
      new InjectedSerializer().deserializeSyncMessage(new Uint8Array()),
    ).toThrow(/wire field "changes" must be a data property/);
    expect(reads).toBe(0);
  });
});

describe('stack-safe JSON serialization', () => {
  const chain = (depth: number): CRDTChangeNode<unknown> => {
    const root: CRDTChangeNode<unknown> = { kind: 'document' };
    let cursor = root;
    for (let level = 2; level <= depth; level++) {
      const child: CRDTChangeNode<unknown> = { kind: 'document' };
      cursor.children = { [`N${level}`]: child };
      cursor = child;
    }
    return root;
  };

  test('matches native bytes for ordinary JSON edge cases', () => {
    const shared = { value: 1 };
    const boxedBoolean = new Boolean(false) as Boolean & {
      valueOf: () => boolean;
    };
    boxedBoolean.valueOf = () => true;
    const boxedNumber = new Number(3);
    Object.defineProperty(boxedNumber, Symbol.toPrimitive, {
      value: () => 4,
    });
    const boxedString = new String('a');
    boxedString.toString = () => 'b';
    const fakeNumber = Object.create(Number.prototype) as Record<
      string,
      unknown
    >;
    fakeNumber.value = 2;
    const proxiedNumber = new Proxy(new Number(3), {});
    const crossRealmValues = runInNewContext(
      '[new Number(3), new String("a"), new Boolean(false)]',
    ) as unknown[];
    const values: unknown[] = [
      {
        z: undefined,
        fn: () => undefined,
        finite: 3,
        nan: Number.NaN,
        infinity: Number.POSITIVE_INFINITY,
        negativeZero: -0,
        sparse: [1, , undefined, () => undefined],
        sharedFirst: shared,
        sharedSecond: shared,
      },
      { toJSON: () => ({ replacement: true }) },
      boxedBoolean,
      boxedNumber,
      boxedString,
      fakeNumber,
      proxiedNumber,
      ...crossRealmValues,
    ];
    for (const value of values) {
      expect(jsonSerializer.serialize(value)).toBe(JSON.stringify(value));
    }
    expect(
      (jsonSerializer.serialize as (value: unknown) => unknown)(undefined),
    ).toBe(JSON.stringify(undefined));

    expect(() => jsonSerializer.serialize(Object(1n))).toThrow(TypeError);
    const throwingNumber = new Number(1);
    Object.defineProperty(throwingNumber, Symbol.toPrimitive, {
      value: () => {
        throw new TypeError('conversion failed');
      },
    });
    const invalidString = new String('value');
    Object.defineProperty(invalidString, Symbol.toPrimitive, {
      value: () => ({}),
    });
    for (const value of [throwingNumber, invalidString]) {
      expect(() => JSON.stringify(value)).toThrow(TypeError);
      expect(() => jsonSerializer.serialize(value)).toThrow(TypeError);
    }
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => jsonSerializer.serialize(cyclic)).toThrow(/circular/i);
  });

  test('matches native primitive BigInt.prototype.toJSON behavior', () => {
    const prototype = BigInt.prototype as typeof BigInt.prototype & {
      toJSON?: (key: string) => unknown;
    };
    const original = Object.getOwnPropertyDescriptor(prototype, 'toJSON');
    const message = {
      documentId: '/doc',
      extension: 1n,
    } as any;

    try {
      delete prototype.toJSON;
      expect(() => JSON.stringify(message)).toThrow(TypeError);
      expect(() => jsonSerializer.serializeSyncMessage(message)).toThrow(
        TypeError,
      );

      const toJSON = jest.fn(function (this: bigint, key: string) {
        return `${this.toString()}:${key}`;
      });
      Object.defineProperty(prototype, 'toJSON', {
        configurable: true,
        value: toJSON,
        writable: true,
      });

      const native = JSON.stringify(message);
      expect(
        jsonSerializer.decode(jsonSerializer.serializeSyncMessage(message)),
      ).toBe(native);
      expect(toJSON).toHaveBeenCalledTimes(2);
      expect(toJSON).toHaveBeenNthCalledWith(1, 'extension');
      expect(toJSON).toHaveBeenNthCalledWith(2, 'extension');
    } finally {
      if (original === undefined) {
        delete prototype.toJSON;
      } else {
        Object.defineProperty(prototype, 'toJSON', original);
      }
    }
  });

  test('round-trips and re-encodes a 4096-node legacy history byte-identically', () => {
    const legacyDepth = MAX_MERKLE_DAG_DEPTH * 8;
    const first = jsonSerializer.serializeSyncMessage({
      documentId: '/doc',
      changes: chain(legacyDepth),
    });
    const decoded = jsonSerializer.deserializeSyncMessage(first);
    const second = jsonSerializer.serializeSyncMessage(decoded);
    expect(second).toEqual(first);

    let actualDepth = 0;
    let current = decoded.changes;
    while (current !== undefined) {
      actualDepth++;
      if (current.children === undefined || current.children === false) break;
      current = Object.values(current.children)[0];
    }
    expect(actualDepth).toBe(legacyDepth);
  });
});
