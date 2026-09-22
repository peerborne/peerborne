import { describe, expect, jest, test } from '@jest/globals';
import { decodeDocumentPublishMessage } from './document-publish-message.js';
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

  test('returns a detached ordinary document announcement', () => {
    const changes = { kind: 'document', change: { value: 1 } };
    const { serializer } = serializerReturning({
      documentId: '/doc',
      signatureContext: 'document-publish-v1',
      changes,
    });

    const message = decodeDocumentPublishMessage(
      { topic: expectedTopic, data: payload },
      expectedTopic,
      4096,
      serializer,
    );
    changes.change.value = 2;

    expect(message).toEqual({
      documentId: '/doc',
      signatureContext: 'document-publish-v1',
      changes: { kind: 'document', change: { value: 1 } },
    });
  });
});
