import { describe, expect, jest, test } from '@jest/globals';
import {
  decodeDocumentPublishMessage,
  MAX_DOCUMENT_PUBLISH_MESSAGE_BYTES,
} from './document-publish-message.js';
import type { SyncMessageSerializer } from './sync-message-serializer.js';

const expectedTopic = '/documents';
const payload = new Uint8Array([1]);

function serializerReturning(message: unknown): {
  serializer: SyncMessageSerializer<unknown, unknown>;
  deserialize: jest.Mock;
} {
  const deserialize = jest.fn(() => message);
  return {
    serializer: {
      deserializeSyncMessage: deserialize,
    } as unknown as SyncMessageSerializer<unknown, unknown>,
    deserialize,
  };
}

describe('document publish message boundary', () => {
  test('ignores another topic before deserialization', () => {
    const { serializer, deserialize } = serializerReturning({
      documentId: '/doc',
      signatureContext: 'document-publish-v1',
    });

    expect(
      decodeDocumentPublishMessage(
        { topic: '/other', data: payload },
        expectedTopic,
        4096,
        serializer,
      ),
    ).toBeUndefined();
    expect(deserialize).not.toHaveBeenCalled();
  });

  test.each([
    ['missing', undefined],
    ['non-string', 1],
    ['empty', ''],
    ['overlong UTF-8', `/${'😀'.repeat(1024)}`],
  ])('rejects a %s document ID', (_label, documentId) => {
    const { serializer } = serializerReturning({
      documentId,
      signatureContext: 'document-publish-v1',
    });

    expect(() =>
      decodeDocumentPublishMessage(
        { topic: expectedTopic, data: payload },
        expectedTopic,
        4096,
        serializer,
      ),
    ).toThrow(/documentId/);
  });

  test('rejects specialized fields before returning a document route', () => {
    const { serializer } = serializerReturning({
      documentId: '/doc',
      signatureContext: 'document-publish-v1',
      keychainChanges: {},
    });

    expect(() =>
      decodeDocumentPublishMessage(
        { topic: expectedTopic, data: payload },
        expectedTopic,
        4096,
        serializer,
      ),
    ).toThrow(/unexpected field/);
  });

  test('passes a bounded detached byte snapshot to the serializer', () => {
    const { serializer, deserialize } = serializerReturning({
      documentId: '/doc',
      signatureContext: 'document-publish-v1',
    });

    const message = decodeDocumentPublishMessage(
      { topic: expectedTopic, data: payload },
      expectedTopic,
      4096,
      serializer,
    );

    expect(message).toEqual({ documentId: '/doc' });
    expect(deserialize.mock.calls[0]?.[0]).toEqual(payload);
    expect(deserialize.mock.calls[0]?.[0]).not.toBe(payload);
  });

  test('rejects oversized bytes before deserialization', () => {
    const { serializer, deserialize } = serializerReturning({
      documentId: '/doc',
      signatureContext: 'document-publish-v1',
    });

    expect(() =>
      decodeDocumentPublishMessage(
        {
          topic: expectedTopic,
          data: new Uint8Array(MAX_DOCUMENT_PUBLISH_MESSAGE_BYTES + 1),
        },
        expectedTopic,
        4096,
        serializer,
      ),
    ).toThrow(/Document publish message/);
    expect(deserialize).not.toHaveBeenCalled();
  });

  test.each([
    ['missing', undefined],
    ['non-byte', 'not bytes'],
    ['empty', new Uint8Array()],
  ])('rejects %s wire data before deserialization', (_label, data) => {
    const { serializer, deserialize } = serializerReturning({
      documentId: '/doc',
      signatureContext: 'document-publish-v1',
    });

    expect(() =>
      decodeDocumentPublishMessage(
        { topic: expectedTopic, data },
        expectedTopic,
        4096,
        serializer,
      ),
    ).toThrow(/Document publish message/);
    expect(deserialize).not.toHaveBeenCalled();
  });

  test('rejects captured signed sync bodies instead of treating them as routes', () => {
    const { serializer } = serializerReturning({
      documentId: '/doc',
      signatureContext: 'ordinary-sync-v1',
      changeId: 'bafy-change',
      changes: { kind: 'document', change: { value: 1 } },
      signature: 'captured-signature',
    });

    expect(() =>
      decodeDocumentPublishMessage(
        { topic: expectedTopic, data: payload },
        expectedTopic,
        4096,
        serializer,
      ),
    ).toThrow(/unexpected field/);
  });
});

describe('disabled legacy document publish shape', () => {
  test('replay has no mutable decoder state or authenticated meaning', () => {
    const { serializer, deserialize } = serializerReturning({
      documentId: '/doc',
      signatureContext: 'document-publish-v1',
    });

    const first = decodeDocumentPublishMessage(
      { topic: expectedTopic, data: payload },
      expectedTopic,
      4096,
      serializer,
    );
    const replay = decodeDocumentPublishMessage(
      { topic: expectedTopic, data: payload },
      expectedTopic,
      4096,
      serializer,
    );

    expect(first).toEqual({ documentId: '/doc' });
    expect(replay).toEqual(first);
    expect(replay).not.toBe(first);
    expect(deserialize).toHaveBeenCalledTimes(2);
  });
});
