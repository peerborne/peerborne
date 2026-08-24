import { describe, expect, test } from '@jest/globals';
import { Doc } from 'yjs';
import { Base64 } from 'js-base64';
import { YjsJSONSerializer } from './peerborne-yjs.js';

// Test the core Yjs functionality that YjsProvider wraps
describe('Yjs Core Functionality', () => {
  test('should create a new Yjs document', () => {
    const doc = new Doc();
    expect(doc).toBeDefined();
    expect(doc).toBeInstanceOf(Doc);
  });

  test('should handle basic document operations', () => {
    const doc = new Doc();
    const map = doc.getMap('test');
    map.set('key', 'value');
    
    expect(map.get('key')).toBe('value');
  });

  test('should create multiple independent documents', () => {
    const doc1 = new Doc();
    const doc2 = new Doc();
    
    const map1 = doc1.getMap('test');
    map1.set('key', 'value1');
    
    const map2 = doc2.getMap('test');
    map2.set('key', 'value2');
    
    expect(map1.get('key')).toBe('value1');
    expect(map2.get('key')).toBe('value2');
  });

  test('should handle Uint8Array serialization', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    const base64 = Base64.fromUint8Array(data);
    const decoded = Base64.toUint8Array(base64);
    
    expect(base64).toBeDefined();
    expect(typeof base64).toBe('string');
    expect(decoded).toEqual(data);
  });

  test('should handle empty Uint8Array', () => {
    const data = new Uint8Array([]);
    const base64 = Base64.fromUint8Array(data);
    const decoded = Base64.toUint8Array(base64);
    
    expect(decoded).toEqual(data);
  });

  test('should handle document arrays', () => {
    const doc = new Doc();
    const arr = doc.getArray('testArray');
    
    arr.push(['item1']);
    arr.push(['item2']);
    
    expect(arr.length).toBe(2);
    expect(arr.get(0)).toBe('item1');
    expect(arr.get(1)).toBe('item2');
  });

  test('should handle nested structures', () => {
    const doc = new Doc();
    const map = doc.getMap('root');

    map.set('nested', 'value');
    map.set('another', 'data');

    expect(map.get('nested')).toBe('value');
    expect(map.get('another')).toBe('data');
  });
});

// Initial-load quorum tip-set hash wire-encoding (#189 §5.4.2). Parity with
// the equivalent tests under peerborne-automerge so both serializers stay
// in lockstep on the new optional field.
describe('YjsJSONSerializer tipsHash round-trip (quorum)', () => {
  const serializer = new YjsJSONSerializer();

  // Table-driven round-trip cases. Each entry asserts that a populated
  // `tipsHash` survives serialize/deserialize unchanged. We exercise both
  // the deterministic-pattern hash and the all-zeros boundary because the
  // base64 encoder's leading-zero handling is a common source of regressions.
  test.each([
    [
      'deterministic-pattern',
      (() => {
        const h = new Uint8Array(32);
        for (let i = 0; i < h.length; i++) h[i] = (i * 7 + 3) & 0xff;
        return h;
      })(),
    ],
    ['all-zeros', new Uint8Array(32)],
  ])(
    'serializeSyncMessage/deserializeSyncMessage preserves tipsHash (%s)',
    (_label, hash) => {
      const wire = serializer.serializeSyncMessage({
        documentId: 'quorum-doc',
        tipsHash: hash,
      });
      const deserialized = serializer.deserializeSyncMessage(wire);
      expect(deserialized.tipsHash).toEqual(hash);
    },
  );

  test('deserializeSyncMessage omits tipsHash when absent on wire', () => {
    const message = { documentId: 'no-quorum-doc' };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.tipsHash).toBeUndefined();
  });

  // Left as a standalone `test` (not folded into the round-trip table)
  // because it builds a malformed wire payload directly to exercise the
  // deserialize-side validator -- the setup (TextEncoder + handcrafted JSON)
  // does not fit the round-trip `serialize -> deserialize` shape that the
  // table cases share.
  test('deserializeSyncMessage rejects non-string tipsHash', () => {
    const wire = new TextEncoder().encode(
      JSON.stringify({ documentId: 'doc', tipsHash: 42 }),
    );
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(/tipsHash/);
  });

  // PR #284 r24 Copilot review: `tipsHash` is defined as a fixed 32-byte
  // SHA-256 digest; the deserializer previously accepted any base64-decoded
  // length and let downstream quorum logic mis-bucket the value. Reject
  // wrong-length payloads at the wire boundary.
  test.each([
    ['empty', new Uint8Array(0)],
    ['short (16 bytes)', new Uint8Array(16)],
    ['long (64 bytes)', new Uint8Array(64)],
  ])(
    'deserializeSyncMessage rejects tipsHash that is not exactly 32 bytes (%s)',
    (_label, malformedHash) => {
      // Hand-encode the base64 directly so we exercise the deserialize-side
      // validator (the serializer's encoder pre-validation is not in play).
      const b64 = Buffer.from(malformedHash).toString('base64');
      const wire = new TextEncoder().encode(
        JSON.stringify({ documentId: 'doc', tipsHash: b64 }),
      );
      expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
        /tipsHash.*32 bytes/,
      );
    },
  );
});

// Quorum frontier binding wire-encoding (#186 / #189 §5.4.2). The `tips`
// field carries an explicit string[] of CIDs on load responses so the loader
// can bind the served state to the responder's frontier hash.
describe('YjsJSONSerializer tips round-trip (quorum frontier)', () => {
  const serializer = new YjsJSONSerializer();

  test.each([
    ['typical', ['bafy1', 'bafy2', 'bafy3']],
    ['single-tip', ['bafyOnly']],
    ['empty-frontier', [] as string[]],
  ])(
    'serializeSyncMessage/deserializeSyncMessage preserves tips (%s)',
    (_label, tips) => {
      const wire = serializer.serializeSyncMessage({
        documentId: 'frontier-doc',
        tips,
      });
      const deserialized = serializer.deserializeSyncMessage(wire);
      expect(deserialized.tips).toEqual(tips);
    },
  );

  test('deserializeSyncMessage omits tips when absent on wire', () => {
    const wire = serializer.serializeSyncMessage({
      documentId: 'no-frontier-doc',
    });
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.tips).toBeUndefined();
  });

  test('deserializeSyncMessage rejects non-array tips', () => {
    const wire = new TextEncoder().encode(
      JSON.stringify({ documentId: 'doc', tips: 'not-an-array' }),
    );
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(/tips/);
  });

  test('deserializeSyncMessage rejects non-string tips entries', () => {
    const wire = new TextEncoder().encode(
      JSON.stringify({ documentId: 'doc', tips: ['ok', 42] }),
    );
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(/tips/);
  });
});


