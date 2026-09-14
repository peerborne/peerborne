let documentPublishTextEncoder: TextEncoder | undefined;

import type { SyncMessageSerializer } from './sync-message-serializer.js';
import { snapshotSyncMessageForContext } from './sync-message-context.js';
import { copyUnsharedUint8Array } from './utils.js';

export const MAX_DOCUMENT_PUBLISH_MESSAGE_BYTES = 64 * 1024;

interface DocumentPublishEnvelope {
  readonly topic?: unknown;
  readonly data: unknown;
}

export interface DocumentPublishHint {
  readonly documentId: string;
}

/**
 * Decode the exact document-publish wire context without performing effects.
 *
 * V1 has no domain-separated signer identity or replay token, so this result is
 * deliberately only an untrusted route hint. Callers must not treat it as an
 * authenticated change, open request, or pin request. `PeerborneNode` does not
 * register this decoder as a network receiver.
 */
export function decodeDocumentPublishMessage<ChangesType, PublicKey>(
  envelope: DocumentPublishEnvelope,
  expectedTopic: string,
  maxDocumentPathBytes: number,
  serializer: SyncMessageSerializer<ChangesType, PublicKey>,
): DocumentPublishHint | undefined {
  if (envelope.topic !== expectedTopic) return undefined;

  const data = copyUnsharedUint8Array(
    envelope.data,
    1,
    MAX_DOCUMENT_PUBLISH_MESSAGE_BYTES,
    'Document publish message',
  );

  const message = snapshotSyncMessageForContext<ChangesType, PublicKey>(
    serializer.deserializeSyncMessage(data),
    'document-publish-v1',
  );
  if (
    typeof message.documentId !== 'string' ||
    message.documentId.length === 0 ||
    (documentPublishTextEncoder ??= new TextEncoder()).encode(message.documentId).byteLength >
      maxDocumentPathBytes
  ) {
    throw new TypeError('Invalid document publish documentId');
  }
  return { documentId: message.documentId };
}
