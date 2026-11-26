import type { DocumentReplayReceipt } from './document-replay-journal.js';
import {
  readDocumentReceipts,
  writeDocumentReceipts,
  type DocumentCatchUpBinding,
} from './document-catch-up-wire.js';
import {
  readDocumentContext,
  writeDocumentContext,
} from './document-security-wire.js';
import {
  DocumentBinaryReader,
  DocumentBinaryWriter,
  documentBytesEqual,
} from './internal/document-binary.js';
import { copyUnsharedUint8Array } from './utils.js';

const MAGIC = Uint8Array.from(
  'peerborne/document-redelivery/v1\0',
  (character) => character.charCodeAt(0),
);
/** Outer format marker that routes an encrypted redelivery request. */
export const DOCUMENT_REDELIVERY_MARKER = Uint8Array.of(0x50, 0x42, 0x44, 2);
export const MAX_DOCUMENT_REDELIVERY_REQUEST_BYTES = 32 * 1024;
const MAX_PEER_LENGTH = 128;
const PEER = /^[1-9A-HJ-NP-Za-km-z]+$/;

/** A member's accepted heads, bound to the libp2p peer that publishes them. */
export interface DocumentRedeliveryRequest extends DocumentCatchUpBinding {
  readonly requesterId: Uint8Array;
  /** The base58btc libp2p PeerId that GossipSub signs as the message sender. */
  readonly requesterPeer: string;
  readonly nonce: Uint8Array;
  readonly receipts: readonly DocumentReplayReceipt[];
}

function bindingWriter(value: DocumentCatchUpBinding): DocumentBinaryWriter {
  const writer = new DocumentBinaryWriter()
    .fixed(MAGIC)
    .text(value.documentId)
    .fixed(copyUnsharedUint8Array(value.genesisId, 32, 32, 'redelivery genesis'))
    .fixed(
      copyUnsharedUint8Array(
        value.authorityHead,
        32,
        32,
        'redelivery authority head',
      ),
    );
  writeDocumentContext(writer, value.context);
  return writer;
}

export function documentRedeliveryAAD(value: DocumentCatchUpBinding): Uint8Array {
  return bindingWriter(value).finish();
}

function assertPeer(value: string): void {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_PEER_LENGTH ||
    !PEER.test(value)
  )
    throw new TypeError('Invalid document redelivery peer');
}

export function encodeDocumentRedeliveryRequest(
  value: DocumentRedeliveryRequest,
): Uint8Array {
  assertPeer(value.requesterPeer);
  const writer = bindingWriter(value)
    .fixed(copyUnsharedUint8Array(value.requesterId, 32, 32, 'redelivery member'))
    .text(value.requesterPeer, MAX_PEER_LENGTH)
    .fixed(copyUnsharedUint8Array(value.nonce, 16, 16, 'redelivery nonce'));
  writeDocumentReceipts(writer, value.receipts);
  return writer.finish();
}

export function decodeDocumentRedeliveryRequest(
  value: Uint8Array,
): DocumentRedeliveryRequest {
  const reader = new DocumentBinaryReader(
    value,
    MAX_DOCUMENT_REDELIVERY_REQUEST_BYTES,
  );
  if (!documentBytesEqual(reader.fixed(MAGIC.length), MAGIC))
    throw new TypeError('Invalid document redelivery domain');
  const documentId = reader.text(),
    genesisId = reader.fixed(32),
    authorityHead = reader.fixed(32),
    context = readDocumentContext(reader),
    requesterId = reader.fixed(32),
    requesterPeer = reader.text(MAX_PEER_LENGTH);
  assertPeer(requesterPeer);
  const nonce = reader.fixed(16);
  const receipts = readDocumentReceipts(reader);
  reader.end();
  return {
    documentId,
    genesisId,
    authorityHead,
    context,
    requesterId,
    requesterPeer,
    nonce,
    receipts,
  };
}

export function isDocumentRedeliveryFrame(frame: Uint8Array): boolean {
  return (
    frame.length >= DOCUMENT_REDELIVERY_MARKER.length &&
    documentBytesEqual(
      frame.subarray(0, DOCUMENT_REDELIVERY_MARKER.length),
      DOCUMENT_REDELIVERY_MARKER,
    )
  );
}

export function encodeEncryptedDocumentRedelivery(
  epochTag: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  return new DocumentBinaryWriter()
    .fixed(DOCUMENT_REDELIVERY_MARKER)
    .fixed(copyUnsharedUint8Array(epochTag, 16, 16, 'redelivery epoch tag'))
    .fixed(copyUnsharedUint8Array(nonce, 12, 12, 'redelivery nonce'))
    .bytes(ciphertext, MAX_DOCUMENT_REDELIVERY_REQUEST_BYTES)
    .finish();
}

export function decodeEncryptedDocumentRedelivery(value: Uint8Array): {
  epochTag: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
} {
  const reader = new DocumentBinaryReader(
    value,
    MAX_DOCUMENT_REDELIVERY_REQUEST_BYTES + 64,
  );
  if (!documentBytesEqual(reader.fixed(4), DOCUMENT_REDELIVERY_MARKER))
    throw new TypeError('Invalid encrypted document redelivery domain');
  const epochTag = reader.fixed(16),
    nonce = reader.fixed(12),
    ciphertext = reader.bytes(MAX_DOCUMENT_REDELIVERY_REQUEST_BYTES);
  reader.end();
  if (ciphertext.length < 16)
    throw new TypeError('Invalid encrypted document redelivery body');
  return { epochTag, nonce, ciphertext };
}
