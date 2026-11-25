import { describe, expect, test } from '@jest/globals';
import { JSONSerializer } from './json-serializer';
import { Base64 } from 'js-base64';

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
      const msg = {
        signatureContext: 'ordinary-sync-v1' as const,
        documentId: '/doc',
        changes: { kind: 'document' as const, change: { foo: 'bar' } },
        nonce: 'AQIDBA==',
      };
      const encoded = serializer.serializeSyncMessage(msg);
      const decoded = serializer.deserializeSyncMessage(encoded);
      expect(decoded).toEqual(msg);
    });

    test('round-trip sync message with additional fields', () => {
      const msg = {
        signatureContext: 'ordinary-sync-v1' as const,
        documentId: '/doc',
        changes: { kind: 'document' as const, change: { foo: 'bar' } },
        nonce: 'AQIDBA==',
        extension: { epoch: 3 },
        eciesSealed: new Uint8Array([1, 2, 3]),
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
      const msg = {
        documentId: '/test/doc', signature: 'AQ==', loadChallenge: new Uint8Array(32), responder: 'writer',
      };
      const encoded = serializer.serializeLoadRequest(msg);
      const decoded = serializer.deserializeLoadRequest(encoded);
      expect(decoded).toEqual(msg);
    });

    test('rejects an omitted challenge and unexpected request fields', () => {
      expect(() => serializer.serializeLoadRequest({ documentId: '/test/doc', signature: 'AQ==', responder: 'writer' } as any)).toThrow();
      const wire = JSON.parse(new TextDecoder().decode(serializer.serializeLoadRequest({
        documentId: '/test/doc', signature: 'AQ==', loadChallenge: new Uint8Array(32), responder: 'writer',
      })));
      expect(() => serializer.deserializeLoadRequest(new TextEncoder().encode(JSON.stringify({ ...wire, extra: true })))).toThrow();
    });

    test.each([
      ['an omitted responder', { responder: undefined }],
      ['an empty responder', { responder: '' }],
      ['a numeric responder', { responder: 7 }],
      ['an array responder', { responder: ['writer'] }],
      ['an oversized responder', { responder: 'p'.repeat(129) }],
      ['a lone-surrogate responder', { responder: '\ud800' }],
    ])('rejects a request with %s', (_label, replacement) => {
      const wire = JSON.parse(new TextDecoder().decode(serializer.serializeLoadRequest({
        documentId: '/test/doc', signature: 'AQ==', loadChallenge: new Uint8Array(32), responder: 'writer',
      })));
      const malformed = new TextEncoder().encode(JSON.stringify({ ...wire, ...replacement }));
      expect(() => serializer.deserializeLoadRequest(malformed)).toThrow();
      expect(() => serializer.serializeLoadRequest({
        documentId: '/test/doc', signature: 'AQ==', loadChallenge: new Uint8Array(32), ...replacement,
      } as any)).toThrow();
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
