let documentPublishTextEncoder: TextEncoder | undefined;

import type { CRDTSyncMessage } from './crdt-sync-message.js';
import type { SyncMessageSerializer } from './sync-message-serializer.js';
import { snapshotSyncMessageForContext } from './sync-message-context.js';

interface DocumentPublishEnvelope {
  readonly topic?: unknown;
  readonly data: Uint8Array;
}

/** Decode the exact document-publish wire context without performing effects. */
export function decodeDocumentPublishMessage<ChangesType, PublicKey>(
  envelope: DocumentPublishEnvelope,
  expectedTopic: string,
  maxDocumentPathBytes: number,
  serializer: SyncMessageSerializer<ChangesType, PublicKey>,
): CRDTSyncMessage<ChangesType, PublicKey> | undefined {
  if (envelope.topic !== expectedTopic) return undefined;

  const message = snapshotSyncMessageForContext<ChangesType, PublicKey>(
    serializer.deserializeSyncMessage(envelope.data),
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
  return message;
}
