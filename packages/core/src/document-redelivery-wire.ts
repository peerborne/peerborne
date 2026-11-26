import type { DocumentReplayReceipt } from './document-replay-journal.js';
import {
  assertDocumentPeer,
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
  documentBytesId,
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
/** Held frames a request names so responders do not resend them. */
export const MAX_DOCUMENT_REDELIVERY_HELD = 64;

export interface DocumentRedeliveryHeldFrame {
  readonly memberId: Uint8Array;
  readonly sequence: number;
}

/** A member's accepted heads, bound to the libp2p peer that publishes them. */
export interface DocumentRedeliveryRequest extends DocumentCatchUpBinding {
  readonly requesterId: Uint8Array;
  /** The base58btc libp2p PeerId that GossipSub signs as the message sender. */
  readonly requesterPeer: string;
  readonly nonce: Uint8Array;
  /** Milliseconds since the Unix epoch; responders accept only newer, fresh requests. */
  readonly issuedAt: number;
  readonly receipts: readonly DocumentReplayReceipt[];
  /** Frames the requester already holds, in member then sequence order. */
  readonly held: readonly DocumentRedeliveryHeldFrame[];
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

export function encodeDocumentRedeliveryRequest(
  value: DocumentRedeliveryRequest,
): Uint8Array {
  assertDocumentPeer(value.requesterPeer);
  const writer = bindingWriter(value)
    .fixed(copyUnsharedUint8Array(value.requesterId, 32, 32, 'redelivery member'))
    .text(value.requesterPeer, MAX_PEER_LENGTH)
    .fixed(copyUnsharedUint8Array(value.nonce, 16, 16, 'redelivery nonce'));
  if (!Number.isSafeInteger(value.issuedAt) || value.issuedAt < 0)
    throw new TypeError('Invalid document redelivery time');
  writer.integer(value.issuedAt, 8);
  writeDocumentReceipts(writer, value.receipts);
  if (value.held.length > MAX_DOCUMENT_REDELIVERY_HELD)
    throw new RangeError('Too many held document frames');
  writer.integer(value.held.length, 1);
  let previous = '';
  for (const { memberId, sequence } of value.held) {
    const member = copyUnsharedUint8Array(memberId, 32, 32, 'held member');
    const key = `${documentBytesId(member)}:${String(sequence).padStart(16, '0')}`;
    if (key <= previous || !Number.isSafeInteger(sequence) || sequence < 1)
      throw new TypeError('Noncanonical held document frame');
    writer.fixed(member).integer(sequence, 8);
    previous = key;
  }
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
  assertDocumentPeer(requesterPeer);
  const nonce = reader.fixed(16);
  const issuedAt = reader.number(8);
  const receipts = readDocumentReceipts(reader);
  const count = reader.number(1);
  if (count > MAX_DOCUMENT_REDELIVERY_HELD)
    throw new RangeError('Too many held document frames');
  const held: DocumentRedeliveryHeldFrame[] = [];
  let previous = '';
  for (let index = 0; index < count; index++) {
    const memberId = reader.fixed(32),
      sequence = reader.number(8);
    const key = `${documentBytesId(memberId)}:${String(sequence).padStart(16, '0')}`;
    if (key <= previous || sequence < 1)
      throw new TypeError('Noncanonical held document frame');
    held.push({ memberId, sequence });
    previous = key;
  }
  reader.end();
  return {
    documentId,
    genesisId,
    authorityHead,
    context,
    requesterId,
    requesterPeer,
    nonce,
    issuedAt,
    receipts,
    held,
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
