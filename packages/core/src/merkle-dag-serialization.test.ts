import { describe, expect, test } from '@jest/globals';
import {
  CRDTChangeNode,
  crdtChangeNodeDeferred,
} from './crdt-change-node.js';
import {
  CRDTChangeNodeWire,
  deserializeChangeNodeFromJSON,
  serializeChangeNodeForJSON,
} from './merkle-dag-serialization.js';

// --- Test encoders -------------------------------------------------------

// Hex codec: keeps tests dependency-free while exercising the same shape as
// the base64 codec used by the real providers.
function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function hexDecode(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('hex string must have even length');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const encodeBytes = (b: Uint8Array): string => hexEncode(b);
const decodeBytes = (s: string): Uint8Array => hexDecode(s);

const encodeBytesArray = (bs: Uint8Array[]): string[] =>
  bs.map((b) => hexEncode(b));
const decodeBytesArray = (ss: string[]): Uint8Array[] =>
  ss.map((s) => hexDecode(s));

function expectBytesEqual(actual: Uint8Array, expected: Uint8Array): void {
  expect(Array.from(actual)).toEqual(Array.from(expected));
}

function expectBytesArrayEqual(
  actual: Uint8Array[],
  expected: Uint8Array[],
): void {
  expect(actual.length).toBe(expected.length);
  for (let i = 0; i < actual.length; i++) {
    expectBytesEqual(actual[i], expected[i]);
  }
}

// --- Tests ---------------------------------------------------------------

describe('serializeChangeNodeForJSON / deserializeChangeNodeFromJSON', () => {
  test('round-trips a leaf-only Uint8Array node (no children)', () => {
    const original: CRDTChangeNode<Uint8Array> = {
      kind: 'document',
      change: new Uint8Array([1, 2, 3, 4]),
    };

    const wire = serializeChangeNodeForJSON(original, encodeBytes);
    expect(wire.kind).toBe('document');
    expect(wire.change).toBe('01020304');
    expect(wire.children).toBeUndefined();

    const restored = deserializeChangeNodeFromJSON(wire, decodeBytes);
    expect(restored.kind).toBe('document');
    expect(restored.change).toBeDefined();
    expectBytesEqual(restored.change as Uint8Array, original.change as Uint8Array);
    expect(restored.children).toBeUndefined();
  });

  test('round-trips a leaf-only Uint8Array[] node (mirrors automerge)', () => {
    const original: CRDTChangeNode<Uint8Array[]> = {
      kind: 'writer',
      keyID: 'key-1',
      change: [new Uint8Array([5, 6]), new Uint8Array([7, 8, 9])],
    };

    const wire = serializeChangeNodeForJSON(original, encodeBytesArray);
    expect(wire.kind).toBe('writer');
    expect(wire.keyID).toBe('key-1');
    expect(wire.change).toEqual(['0506', '070809']);

    const restored = deserializeChangeNodeFromJSON(wire, decodeBytesArray);
    expect(restored.kind).toBe('writer');
    expect(restored.keyID).toBe('key-1');
    expectBytesArrayEqual(
      restored.change as Uint8Array[],
      original.change as Uint8Array[],
    );
  });

  test('preserves an empty tree where change is undefined and children is undefined', () => {
    const original: CRDTChangeNode<Uint8Array> = { kind: 'reader' };

    const wire = serializeChangeNodeForJSON(original, encodeBytes);
    expect(wire).toEqual({ kind: 'reader', change: undefined, children: undefined });

    const restored = deserializeChangeNodeFromJSON(wire, decodeBytes);
    expect(restored.kind).toBe('reader');
    expect(restored.change).toBeUndefined();
    expect(restored.children).toBeUndefined();
  });

  test('round-trips a multi-level tree with multiple children at each level (Uint8Array)', () => {
    const original: CRDTChangeNode<Uint8Array> = {
      kind: 'document',
      change: new Uint8Array([0xaa]),
      children: {
        h1: {
          kind: 'document',
          change: new Uint8Array([0xbb, 0xcc]),
          children: {
            h1a: {
              kind: 'writer',
              keyID: 'k-1',
              change: new Uint8Array([0x01]),
            },
            h1b: {
              kind: 'reader',
              change: new Uint8Array([0x02]),
            },
          },
        },
        h2: {
          kind: 'document',
          change: new Uint8Array([0xdd]),
          children: {
            h2a: {
              kind: 'document',
              change: new Uint8Array([0x03, 0x04, 0x05]),
            },
          },
        },
        h3: {
          kind: 'writer',
          change: new Uint8Array([]),
        },
      },
    };

    const wire = serializeChangeNodeForJSON(original, encodeBytes);

    // Wire form must be plain-JSON-safe: round-trip through JSON.
    const json = JSON.stringify(wire);
    const reparsed = JSON.parse(json) as CRDTChangeNodeWire<string>;

    const restored = deserializeChangeNodeFromJSON(reparsed, decodeBytes);

    expect(restored.kind).toBe('document');
    expectBytesEqual(restored.change as Uint8Array, new Uint8Array([0xaa]));

    // children should be present and structurally identical.
    expect(restored.children).not.toBe(crdtChangeNodeDeferred);
    expect(restored.children).toBeDefined();
    const children = restored.children as Record<
      string,
      CRDTChangeNode<Uint8Array>
    >;
    expect(Object.keys(children).sort()).toEqual(['h1', 'h2', 'h3']);

    expectBytesEqual(
      children.h1.change as Uint8Array,
      new Uint8Array([0xbb, 0xcc]),
    );
    const h1Children = children.h1.children as Record<
      string,
      CRDTChangeNode<Uint8Array>
    >;
    expect(Object.keys(h1Children).sort()).toEqual(['h1a', 'h1b']);
    expect(h1Children.h1a.kind).toBe('writer');
    expect(h1Children.h1a.keyID).toBe('k-1');
    expectBytesEqual(h1Children.h1a.change as Uint8Array, new Uint8Array([0x01]));
    expect(h1Children.h1b.kind).toBe('reader');
    expectBytesEqual(h1Children.h1b.change as Uint8Array, new Uint8Array([0x02]));

    const h2Children = children.h2.children as Record<
      string,
      CRDTChangeNode<Uint8Array>
    >;
    expect(Object.keys(h2Children)).toEqual(['h2a']);
    expectBytesEqual(
      h2Children.h2a.change as Uint8Array,
      new Uint8Array([0x03, 0x04, 0x05]),
    );

    expect(children.h3.kind).toBe('writer');
    expectBytesEqual(children.h3.change as Uint8Array, new Uint8Array([]));
    expect(children.h3.children).toBeUndefined();
  });

  test('round-trips a multi-level tree with Uint8Array[] leaves (mirrors automerge)', () => {
    const original: CRDTChangeNode<Uint8Array[]> = {
      kind: 'document',
      change: [new Uint8Array([1])],
      children: {
        a: {
          kind: 'writer',
          change: [new Uint8Array([2]), new Uint8Array([3, 4])],
          children: {
            'a.1': {
              kind: 'reader',
              keyID: 'reader-key',
              change: [new Uint8Array([5, 6, 7])],
            },
          },
        },
        b: {
          kind: 'document',
          change: [],
        },
      },
    };

    const wire = serializeChangeNodeForJSON(original, encodeBytesArray);
    const restored = deserializeChangeNodeFromJSON(wire, decodeBytesArray);

    expectBytesArrayEqual(
      restored.change as Uint8Array[],
      original.change as Uint8Array[],
    );
    const children = restored.children as Record<
      string,
      CRDTChangeNode<Uint8Array[]>
    >;
    expectBytesArrayEqual(
      children.a.change as Uint8Array[],
      [new Uint8Array([2]), new Uint8Array([3, 4])],
    );
    const aChildren = children.a.children as Record<
      string,
      CRDTChangeNode<Uint8Array[]>
    >;
    expect(aChildren['a.1'].keyID).toBe('reader-key');
    expectBytesArrayEqual(
      aChildren['a.1'].change as Uint8Array[],
      [new Uint8Array([5, 6, 7])],
    );
    // Empty array leaves must round-trip as empty arrays (not undefined).
    expect(children.b.change).toEqual([]);
  });

  test('preserves crdtChangeNodeDeferred children sentinel through round-trip', () => {
    const original: CRDTChangeNode<Uint8Array> = {
      kind: 'document',
      change: new Uint8Array([9]),
      children: crdtChangeNodeDeferred,
    };

    const wire = serializeChangeNodeForJSON(original, encodeBytes);
    expect(wire.children).toBe(crdtChangeNodeDeferred);

    const restored = deserializeChangeNodeFromJSON(wire, decodeBytes);
    expect(restored.children).toBe(crdtChangeNodeDeferred);
    expectBytesEqual(restored.change as Uint8Array, new Uint8Array([9]));
  });

  test('children maps use a null prototype to resist prototype pollution', () => {
    // A peer could send `__proto__` / `constructor` as hash keys. The
    // resulting `children` dictionaries must not alter `Object.prototype`
    // and must expose those keys as plain own properties rather than as
    // inherited members.
    const polluted: CRDTChangeNodeWire<string> = {
      kind: 'document',
      change: '01',
      children: JSON.parse(
        '{"__proto__":{"kind":"writer","change":"02"},' +
          '"constructor":{"kind":"reader","change":"03"}}',
      ) as { [hash: string]: CRDTChangeNodeWire<string> },
    };

    const restored = deserializeChangeNodeFromJSON(polluted, decodeBytes);

    // `Object.prototype` must remain pristine.
    expect(
      Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted'),
    ).toBe(false);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();

    expect(restored.children).toBeDefined();
    expect(restored.children).not.toBe(crdtChangeNodeDeferred);
    const children = restored.children as Record<
      string,
      CRDTChangeNode<Uint8Array>
    >;
    // Null-prototype dictionary: no inherited members.
    expect(Object.getPrototypeOf(children)).toBeNull();
    // Special-cased keys round-trip as own properties.
    expect(Object.keys(children).sort()).toEqual(['__proto__', 'constructor']);
    expect(children['__proto__'].kind).toBe('writer');
    expectBytesEqual(
      children['__proto__'].change as Uint8Array,
      new Uint8Array([0x02]),
    );
    expect(children['constructor'].kind).toBe('reader');
    expectBytesEqual(
      children['constructor'].change as Uint8Array,
      new Uint8Array([0x03]),
    );

    // The serializer side likewise produces a null-prototype map.
    const original: CRDTChangeNode<Uint8Array> = {
      kind: 'document',
      children: {
        h1: { kind: 'writer', change: new Uint8Array([1]) },
      },
    };
    const wire = serializeChangeNodeForJSON(original, encodeBytes);
    expect(wire.children).toBeDefined();
    expect(wire.children).not.toBe(crdtChangeNodeDeferred);
    expect(
      Object.getPrototypeOf(
        wire.children as Record<string, CRDTChangeNodeWire<string>>,
      ),
    ).toBeNull();
  });

  describe('deserialize input validation (untrusted wire shapes)', () => {
    test('throws with a descriptive Error (not TypeError) when node is null', () => {
      // Regression: prior to the upfront guard this read `node.kind` first
      // and threw `TypeError: Cannot read properties of null`, which is a
      // trivial DoS vector if a peer puts `null` in a `changes` field.
      const malformed = null as unknown as CRDTChangeNodeWire<string>;
      const call = () => deserializeChangeNodeFromJSON(malformed, decodeBytes);
      expect(call).toThrow(Error);
      expect(call).not.toThrow(TypeError);
      expect(call).toThrow(/expected a plain object.*got null/);
    });

    test('throws a descriptive Error when node is the number 0', () => {
      const malformed = 0 as unknown as CRDTChangeNodeWire<string>;
      const call = () => deserializeChangeNodeFromJSON(malformed, decodeBytes);
      expect(call).toThrow(Error);
      expect(call).not.toThrow(TypeError);
      expect(call).toThrow(/expected a plain object.*got number/);
    });

    test('throws a descriptive Error when node is an empty string', () => {
      const malformed = '' as unknown as CRDTChangeNodeWire<string>;
      const call = () => deserializeChangeNodeFromJSON(malformed, decodeBytes);
      expect(call).toThrow(Error);
      expect(call).not.toThrow(TypeError);
      expect(call).toThrow(/expected a plain object.*got string/);
    });

    test('throws a descriptive Error when node is an array', () => {
      const malformed = [1, 2, 3] as unknown as CRDTChangeNodeWire<string>;
      expect(() =>
        deserializeChangeNodeFromJSON(malformed, decodeBytes),
      ).toThrow(/expected a plain object.*got array/);
    });

    test('throws a descriptive Error when node is undefined', () => {
      const malformed = undefined as unknown as CRDTChangeNodeWire<string>;
      const call = () => deserializeChangeNodeFromJSON(malformed, decodeBytes);
      expect(call).toThrow(Error);
      expect(call).not.toThrow(TypeError);
      expect(call).toThrow(/expected a plain object.*got undefined/);
    });

    test('throws when "kind" is missing', () => {
      // Simulate a peer message that omits `kind` entirely. Cast through
      // unknown because the field is required by the type, but malformed
      // JSON has no such guarantee at runtime.
      const malformed = { change: '01' } as unknown as CRDTChangeNodeWire<string>;
      expect(() => deserializeChangeNodeFromJSON(malformed, decodeBytes)).toThrow(
        /"kind" must be one of/,
      );
    });

    test('throws when "kind" is an unknown string', () => {
      const malformed: CRDTChangeNodeWire<string> = {
        kind: 'evil' as unknown as 'document',
        change: '01',
      };
      expect(() => deserializeChangeNodeFromJSON(malformed, decodeBytes)).toThrow(
        /"kind" must be one of.*got "evil"/,
      );
    });

    test('throws when "kind" is the wrong type (e.g. a number)', () => {
      const malformed = {
        kind: 7,
        change: '01',
      } as unknown as CRDTChangeNodeWire<string>;
      expect(() => deserializeChangeNodeFromJSON(malformed, decodeBytes)).toThrow(
        /"kind" must be one of/,
      );
    });

    test('accepts all three documented kinds: document, writer, reader', () => {
      for (const kind of ['document', 'writer', 'reader'] as const) {
        const node: CRDTChangeNodeWire<string> = { kind, change: '01' };
        const restored = deserializeChangeNodeFromJSON(node, decodeBytes);
        expect(restored.kind).toBe(kind);
      }
    });

    test('throws when a child node is null', () => {
      const malformed = JSON.parse(
        '{"kind":"document","change":"01","children":{"h1":null}}',
      ) as CRDTChangeNodeWire<string>;
      expect(() => deserializeChangeNodeFromJSON(malformed, decodeBytes)).toThrow(
        /child at key "h1" must be a plain object.*got null/,
      );
    });

    test('throws when a child node is an array', () => {
      const malformed = JSON.parse(
        '{"kind":"document","change":"01","children":{"h1":[1,2]}}',
      ) as CRDTChangeNodeWire<string>;
      expect(() => deserializeChangeNodeFromJSON(malformed, decodeBytes)).toThrow(
        /child at key "h1" must be a plain object.*got array/,
      );
    });

    test('throws when a child node is a primitive (string)', () => {
      const malformed = JSON.parse(
        '{"kind":"document","change":"01","children":{"h1":"not-an-object"}}',
      ) as CRDTChangeNodeWire<string>;
      expect(() => deserializeChangeNodeFromJSON(malformed, decodeBytes)).toThrow(
        /child at key "h1" must be a plain object.*got string/,
      );
    });

    test('throws when a nested child has an invalid "kind"', () => {
      const malformed = JSON.parse(
        '{"kind":"document","change":"01","children":' +
          '{"h1":{"kind":"hacker","change":"02"}}}',
      ) as CRDTChangeNodeWire<string>;
      expect(() => deserializeChangeNodeFromJSON(malformed, decodeBytes)).toThrow(
        /"kind" must be one of.*got "hacker"/,
      );
    });

    test('throws when "keyID" is a number', () => {
      // Regression: prior to keyID validation a peer could send
      // `keyID: 123` and the value would flow through `...node` into the
      // typed `CRDTChangeNode`, silently violating the `keyID?: string`
      // contract.
      const malformed = {
        kind: 'writer',
        keyID: 123,
        change: '01',
      } as unknown as CRDTChangeNodeWire<string>;
      expect(() => deserializeChangeNodeFromJSON(malformed, decodeBytes)).toThrow(
        /"keyID" must be a string when present.*got number/,
      );
    });

    test('throws when "keyID" is null', () => {
      const malformed = {
        kind: 'writer',
        keyID: null,
        change: '01',
      } as unknown as CRDTChangeNodeWire<string>;
      expect(() => deserializeChangeNodeFromJSON(malformed, decodeBytes)).toThrow(
        /"keyID" must be a string when present.*got null/,
      );
    });

    test('throws when "keyID" is an object', () => {
      const malformed = {
        kind: 'writer',
        keyID: { evil: true },
        change: '01',
      } as unknown as CRDTChangeNodeWire<string>;
      expect(() => deserializeChangeNodeFromJSON(malformed, decodeBytes)).toThrow(
        /"keyID" must be a string when present.*got object/,
      );
    });

    test('throws when a nested child has an invalid "keyID"', () => {
      const malformed = JSON.parse(
        '{"kind":"document","change":"01","children":' +
          '{"h1":{"kind":"writer","keyID":42,"change":"02"}}}',
      ) as CRDTChangeNodeWire<string>;
      expect(() => deserializeChangeNodeFromJSON(malformed, decodeBytes)).toThrow(
        /"keyID" must be a string when present.*got number/,
      );
    });

    test('accepts omitted "keyID" (optional field)', () => {
      const node: CRDTChangeNodeWire<string> = { kind: 'document', change: '01' };
      const restored = deserializeChangeNodeFromJSON(node, decodeBytes);
      expect(restored.keyID).toBeUndefined();
      // Explicit construction must not set `keyID` as an own property when
      // omitted; consumers iterating own keys should not see it.
      expect(Object.prototype.hasOwnProperty.call(restored, 'keyID')).toBe(false);
    });

    test('accepts a string "keyID"', () => {
      const node: CRDTChangeNodeWire<string> = {
        kind: 'writer',
        keyID: 'k-1',
        change: '01',
      };
      const restored = deserializeChangeNodeFromJSON(node, decodeBytes);
      expect(restored.keyID).toBe('k-1');
    });

    test('strips unknown extra wire properties via explicit construction', () => {
      // Regression: `...node` spread would silently propagate peer-supplied
      // extras (e.g. a forged `signature` field) into our typed
      // `CRDTChangeNode`. Explicit construction keeps the in-memory shape
      // tight to the documented type.
      const malformed = JSON.parse(
        '{"kind":"document","change":"01","attackerField":"surprise",' +
          '"__proto__":{"hijack":true}}',
      ) as CRDTChangeNodeWire<string>;
      const restored = deserializeChangeNodeFromJSON(malformed, decodeBytes);
      expect(Object.keys(restored).sort()).toEqual(['change', 'kind']);
      expect(
        (restored as unknown as { attackerField?: unknown }).attackerField,
      ).toBeUndefined();
    });
  });

  test('encoder is not invoked for nodes whose change is undefined', () => {
    const original: CRDTChangeNode<Uint8Array> = {
      kind: 'document',
      children: {
        only: {
          kind: 'writer',
          change: new Uint8Array([42]),
        },
      },
    };

    let calls = 0;
    const wire = serializeChangeNodeForJSON(original, (b) => {
      calls++;
      return hexEncode(b);
    });
    expect(calls).toBe(1);
    expect(wire.change).toBeUndefined();
    const wireChildren = wire.children as Record<
      string,
      CRDTChangeNodeWire<string>
    >;
    expect(wireChildren.only.change).toBe('2a');

    let decCalls = 0;
    const restored = deserializeChangeNodeFromJSON(wire, (s) => {
      decCalls++;
      return hexDecode(s);
    });
    expect(decCalls).toBe(1);
    expect(restored.change).toBeUndefined();
    const restoredChildren = restored.children as Record<
      string,
      CRDTChangeNode<Uint8Array>
    >;
    expectBytesEqual(
      restoredChildren.only.change as Uint8Array,
      new Uint8Array([42]),
    );
  });
});
