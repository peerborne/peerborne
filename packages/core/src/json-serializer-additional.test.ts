import { describe, expect, test } from '@jest/globals';
import { JSONSerializer, validateChangeBlockMetadata } from './json-serializer';
import { Base64 } from 'js-base64';
import { CRDTChangeBlock } from './crdt-change-block';

const serializer = new JSONSerializer<any>();

describe('JSONSerializer additional coverage', () => {
  describe('serializeChanges / deserializeChanges', () => {
    test('round-trip changes', () => {
      const changes = { nested: { deep: [1, 2, 3] } };
      const encoded = serializer.serializeChanges(changes);
      const decoded = serializer.deserializeChanges(encoded);
      expect(decoded).toEqual(changes);
    });

    test('round-trip primitive changes', () => {
      const encoded = serializer.serializeChanges('hello');
      const decoded = serializer.deserializeChanges(encoded);
      expect(decoded).toBe('hello');
    });
  });

  describe('serializeSyncMessage / deserializeSyncMessage', () => {
    test('round-trip sync message', () => {
      const msg = { changes: { foo: 'bar' }, nonce: 'AQIDBA==' };
      const encoded = serializer.serializeSyncMessage(msg);
      const decoded = serializer.deserializeSyncMessage(encoded);
      expect(decoded).toEqual(msg);
    });

    test('round-trip sync message with additional fields', () => {
      const msg = {
        changes: { foo: 'bar' },
        nonce: 'AQIDBA==',
        keyUpdate: { epoch: 3 },
        eciesSealed: 'base64-sealed',
      };
      const encoded = serializer.serializeSyncMessage(msg);
      const decoded = serializer.deserializeSyncMessage(encoded);
      expect(decoded).toEqual(msg);
    });

    test('deserializeSyncMessage rejects invalid JSON', () => {
      const bad = new TextEncoder().encode('{broken');
      expect(() => serializer.deserializeSyncMessage(bad)).toThrow();
    });
  });

  describe('serializeLoadRequest / deserializeLoadRequest', () => {
    test('round-trip load request', () => {
      const msg = { documentPath: '/test/doc' };
      const encoded = serializer.serializeLoadRequest(msg);
      const decoded = serializer.deserializeLoadRequest(encoded);
      expect(decoded).toEqual(msg);
    });

    test('round-trip load request with optional fields', () => {
      const msg = { documentPath: '/test/doc', requesterKey: 'key-b64' };
      const encoded = serializer.serializeLoadRequest(msg);
      const decoded = serializer.deserializeLoadRequest(encoded);
      expect(decoded).toEqual(msg);
    });

    test('deserializeLoadRequest rejects invalid JSON', () => {
      const bad = new TextEncoder().encode('not-json');
      expect(() => serializer.deserializeLoadRequest(bad)).toThrow();
    });
  });

  describe('deserialize error path', () => {
    test('deserialize of invalid JSON logs and rethrows', () => {
      expect(() => serializer.deserialize('{invalid')).toThrow();
    });
  });
});

describe('validateChangeBlockMetadata additional coverage', () => {
  test('rejects blindIndexTokens with non-Object non-null prototype', () => {
    class CustomProto {}
    const tokens = Object.create(CustomProto.prototype);
    (tokens as any).field = 'value';

    const deserialized = { blindIndexTokens: tokens };
    const result: CRDTChangeBlock<any> = { changes: {}, nonce: new Uint8Array([1]) };

    expect(() => validateChangeBlockMetadata(deserialized, result)).toThrow(
      'blindIndexTokens must be a plain object',
    );
  });

  test('accepts blindIndexTokens with null prototype', () => {
    const tokens = Object.create(null);
    (tokens as any).field = 'value';

    const deserialized = { blindIndexTokens: tokens };
    const result: CRDTChangeBlock<any> = { changes: {}, nonce: new Uint8Array([1]) };

    expect(() => validateChangeBlockMetadata(deserialized, result)).not.toThrow();
    expect(result.blindIndexTokens).toEqual({ field: 'value' });
  });
});