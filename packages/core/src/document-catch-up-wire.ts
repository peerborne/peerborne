import type { DocumentReplayReceipt } from './document-replay-journal.js';
import type { GroupSecurityDocumentContext } from './group-security-coordinator.js';
import {
  DocumentBinaryReader,
  DocumentBinaryWriter,
} from './internal/document-binary.js';
import { bytesToHex } from './internal/hex.js';
import {
  MAX_DOCUMENT_CONTENT_BYTES,
  MAX_DOCUMENT_SECURITY_FRAME_BYTES,
  readDocumentContext,
  writeDocumentContext,
} from './document-security-wire.js';
import { copyUnsharedUint8Array, equalBytes } from './internal/bytes.js';

const MAGIC = Uint8Array.from('peerborne/document-catch-up/v1\0', (character) =>
  character.charCodeAt(0),
);
const MAX_RECEIPTS = 256;
export const MAX_DOCUMENT_CATCH_UP_REQUEST_BYTES = 32 * 1024;
/** Signed author frames proving that an offered receipt extends the requester's. */
export const MAX_DOCUMENT_CATCH_UP_SUFFIX_FRAMES = 256;
/** The sealed checkpoint frame bounds the suffix together with the snapshot. */
export const MAX_DOCUMENT_CATCH_UP_SUFFIX_BYTES = MAX_DOCUMENT_SECURITY_FRAME_BYTES;

export interface DocumentCatchUpBinding {
  readonly documentId: string;
  readonly genesisId: Uint8Array;
  readonly authorityHead: Uint8Array;
  readonly context: GroupSecurityDocumentContext;
}

export interface DocumentCatchUpRequest extends DocumentCatchUpBinding {
  readonly requesterId: Uint8Array;
  readonly challenge: Uint8Array;
  /** The requester's accepted heads in this context, in member order. */
  readonly receipts: readonly DocumentReplayReceipt[];
}

/** A request carried on the document topic, bound to the libp2p peer that publishes it. */
export interface DocumentTopicCatchUpRequest extends DocumentCatchUpRequest {
  /** The base58btc libp2p PeerId that GossipSub signs as the message sender. */
  readonly requesterPeer: string;
  /** Milliseconds since the Unix epoch; the controller answers only newer, fresh requests. */
  readonly issuedAt: number;
}

export interface DocumentCatchUpCheckpoint
  extends Omit<DocumentCatchUpRequest, 'receipts'> {
  readonly controllerId: Uint8Array;
  readonly receipts: readonly DocumentReplayReceipt[];
  /** Signed content frames, by author then sequence, that extend requester heads. */
  readonly suffixes: readonly Uint8Array[];
  readonly snapshot: Uint8Array;
}

/** Why a controller answered a topic request without a checkpoint. */
export type DocumentCatchUpRefusalReason = 'snapshot-too-large' | 'denied';

/** The controller's signed answer when it sends no checkpoint for a topic request. */
export interface DocumentCatchUpRefusal
  extends Omit<DocumentCatchUpRequest, 'receipts'> {
  readonly controllerId: Uint8Array;
  readonly reason: DocumentCatchUpRefusalReason;
  /** The encoded snapshot size for `snapshot-too-large`, otherwise zero. */
  readonly snapshotBytes: number;
}

/** Application-relayed messages and those carried on the document topic use separate domains. */
export type DocumentCatchUpKind =
  | 'request'
  | 'checkpoint'
  | 'topic-request'
  | 'topic-checkpoint'
  | 'topic-refusal';
type CheckpointKind = 'checkpoint' | 'topic-checkpoint';
type TopicKind = 'topic-request' | 'topic-checkpoint' | 'topic-refusal';
const KINDS: Readonly<Record<DocumentCatchUpKind, number>> = {
  request: 0,
  checkpoint: 1,
  'topic-request': 2,
  'topic-checkpoint': 3,
  'topic-refusal': 4,
};
/** Outer format markers that route catch-up messages carried on the document topic. */
export const DOCUMENT_CATCH_UP_REQUEST_MARKER = Uint8Array.of(0x50, 0x42, 0x44, 3);
export const DOCUMENT_CATCH_UP_CHECKPOINT_MARKER = Uint8Array.of(
  0x50,
  0x42,
  0x44,
  4,
);
export const DOCUMENT_CATCH_UP_REFUSAL_MARKER = Uint8Array.of(0x50, 0x42, 0x44, 5);
/** Room for the signature, its framing and the AEAD tag around a request body. */
export const MAX_DOCUMENT_CATCH_UP_TOPIC_REQUEST_BYTES =
  MAX_DOCUMENT_CATCH_UP_REQUEST_BYTES + 2048;
const MAX_PEER_LENGTH = 128;
const PEER = /^[1-9A-HJ-NP-Za-km-z]+$/;

export function assertDocumentPeer(value: string): void {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_PEER_LENGTH ||
    !PEER.test(value)
  )
    throw new TypeError('Invalid document peer');
}

function fixed32(value: Uint8Array): Uint8Array {
  return copyUnsharedUint8Array(value, 32, 32, 'catch-up commitment');
}

function bindingWriter(
  kind: DocumentCatchUpKind,
  value: DocumentCatchUpBinding,
) {
  const writer = new DocumentBinaryWriter()
    .fixed(MAGIC)
    .integer(KINDS[kind], 1)
    .text(value.documentId)
    .fixed(fixed32(value.genesisId))
    .fixed(fixed32(value.authorityHead));
  writeDocumentContext(writer, value.context);
  return writer;
}

export function documentCatchUpAAD(
  kind: DocumentCatchUpKind,
  value: DocumentCatchUpBinding,
): Uint8Array {
  return bindingWriter(kind, value).finish();
}

function writeRequest(
  kind: DocumentCatchUpKind,
  value: Omit<DocumentCatchUpRequest, 'receipts'>,
) {
  return bindingWriter(kind, value)
    .fixed(fixed32(value.requesterId))
    .fixed(fixed32(value.challenge));
}

function readRequest(
  reader: DocumentBinaryReader,
  kind: DocumentCatchUpKind,
): Omit<DocumentCatchUpRequest, 'receipts'> {
  if (
    !equalBytes(reader.fixed(MAGIC.length), MAGIC) ||
    reader.number(1) !== KINDS[kind]
  )
    throw new TypeError('Invalid document catch-up domain');
  return {
    documentId: reader.text(),
    genesisId: reader.fixed(32),
    authorityHead: reader.fixed(32),
    context: readDocumentContext(reader),
    requesterId: reader.fixed(32),
    challenge: reader.fixed(32),
  };
}

export function writeDocumentReceipts(
  writer: DocumentBinaryWriter,
  receipts: readonly DocumentReplayReceipt[],
): void {
  if (receipts.length > MAX_RECEIPTS)
    throw new RangeError('Too many document catch-up receipts');
  writer.integer(receipts.length, 2);
  let previous = '';
  for (const receipt of receipts) {
    const memberId = fixed32(receipt.memberId);
    const id = bytesToHex(memberId);
    if (
      id <= previous ||
      !Number.isSafeInteger(receipt.sequence) ||
      receipt.sequence < 1
    )
      throw new TypeError('Noncanonical document catch-up receipt');
    writer
      .fixed(memberId)
      .integer(receipt.sequence, 8)
      .fixed(fixed32(receipt.hash));
    previous = id;
  }
}

export function readDocumentReceipts(reader: DocumentBinaryReader): DocumentReplayReceipt[] {
  const count = reader.number(2);
  if (count > MAX_RECEIPTS)
    throw new RangeError('Too many document catch-up receipts');
  const receipts: DocumentReplayReceipt[] = [];
  let previous = '';
  for (let index = 0; index < count; index++) {
    const memberId = reader.fixed(32);
    const id = bytesToHex(memberId);
    const sequence = reader.number(8);
    if (id <= previous || sequence === 0)
      throw new TypeError('Noncanonical document catch-up receipt');
    receipts.push({ memberId, sequence, hash: reader.fixed(32) });
    previous = id;
  }
  return receipts;
}

export function encodeDocumentCatchUpRequest(
  value: DocumentCatchUpRequest,
): Uint8Array {
  const writer = writeRequest('request', value);
  writeDocumentReceipts(writer, value.receipts);
  return writer.finish();
}

export function decodeDocumentCatchUpRequest(
  value: Uint8Array,
): DocumentCatchUpRequest {
  const reader = new DocumentBinaryReader(
    value,
    MAX_DOCUMENT_CATCH_UP_REQUEST_BYTES,
  );
  const request = readRequest(reader, 'request');
  const receipts = readDocumentReceipts(reader);
  reader.end();
  return { ...request, receipts };
}

export function encodeDocumentTopicCatchUpRequest(
  value: DocumentTopicCatchUpRequest,
): Uint8Array {
  assertDocumentPeer(value.requesterPeer);
  if (!Number.isSafeInteger(value.issuedAt) || value.issuedAt < 0)
    throw new TypeError('Invalid document catch-up time');
  const writer = writeRequest('topic-request', value)
    .text(value.requesterPeer, MAX_PEER_LENGTH)
    .integer(value.issuedAt, 8);
  writeDocumentReceipts(writer, value.receipts);
  return writer.finish();
}

export function decodeDocumentTopicCatchUpRequest(
  value: Uint8Array,
): DocumentTopicCatchUpRequest {
  const reader = new DocumentBinaryReader(
    value,
    MAX_DOCUMENT_CATCH_UP_REQUEST_BYTES,
  );
  const request = readRequest(reader, 'topic-request');
  const requesterPeer = reader.text(MAX_PEER_LENGTH);
  assertDocumentPeer(requesterPeer);
  const issuedAt = reader.number(8);
  const receipts = readDocumentReceipts(reader);
  reader.end();
  return { ...request, requesterPeer, issuedAt, receipts };
}

export function encodeDocumentCatchUpCheckpoint(
  value: DocumentCatchUpCheckpoint,
  kind: CheckpointKind = 'checkpoint',
): Uint8Array {
  const writer = writeRequest(kind, value).fixed(
    fixed32(value.controllerId),
  );
  writeDocumentReceipts(writer, value.receipts);
  if (value.suffixes.length > MAX_DOCUMENT_CATCH_UP_SUFFIX_FRAMES)
    throw new RangeError('Too many document catch-up suffix frames');
  writer.integer(value.suffixes.length, 2);
  let bytes = 0;
  for (const frame of value.suffixes) {
    bytes += frame.length;
    if (frame.length === 0 || bytes > MAX_DOCUMENT_CATCH_UP_SUFFIX_BYTES)
      throw new RangeError('Document catch-up suffix exceeds its bound');
    writer.bytes(frame, MAX_DOCUMENT_CATCH_UP_SUFFIX_BYTES);
  }
  return writer.bytes(value.snapshot, MAX_DOCUMENT_CONTENT_BYTES).finish();
}

export function decodeDocumentCatchUpCheckpoint(
  value: Uint8Array,
  kind: CheckpointKind = 'checkpoint',
): DocumentCatchUpCheckpoint {
  const reader = new DocumentBinaryReader(value);
  const request = readRequest(reader, kind);
  const controllerId = reader.fixed(32);
  const receipts = readDocumentReceipts(reader);
  const count = reader.number(2);
  if (count > MAX_DOCUMENT_CATCH_UP_SUFFIX_FRAMES)
    throw new RangeError('Too many document catch-up suffix frames');
  const suffixes: Uint8Array[] = [];
  let bytes = 0;
  for (let index = 0; index < count; index++) {
    const frame = reader.bytes(MAX_DOCUMENT_CATCH_UP_SUFFIX_BYTES);
    bytes += frame.length;
    if (frame.length === 0 || bytes > MAX_DOCUMENT_CATCH_UP_SUFFIX_BYTES)
      throw new RangeError('Document catch-up suffix exceeds its bound');
    suffixes.push(frame);
  }
  const snapshot = reader.bytes(MAX_DOCUMENT_CONTENT_BYTES);
  reader.end();
  return { ...request, controllerId, receipts, suffixes, snapshot };
}

export function encodeDocumentCatchUpRefusal(
  value: DocumentCatchUpRefusal,
): Uint8Array {
  if (
    !Number.isSafeInteger(value.snapshotBytes) ||
    (value.reason === 'snapshot-too-large'
      ? value.snapshotBytes <= MAX_DOCUMENT_CONTENT_BYTES
      : value.reason !== 'denied' || value.snapshotBytes !== 0)
  )
    throw new TypeError('Invalid document catch-up refusal');
  return writeRequest('topic-refusal', value)
    .fixed(fixed32(value.controllerId))
    .integer(value.reason === 'snapshot-too-large' ? 1 : 2, 1)
    .integer(value.snapshotBytes, 8)
    .finish();
}

export function decodeDocumentCatchUpRefusal(
  value: Uint8Array,
): DocumentCatchUpRefusal {
  const reader = new DocumentBinaryReader(
    value,
    MAX_DOCUMENT_CATCH_UP_REQUEST_BYTES,
  );
  const request = readRequest(reader, 'topic-refusal');
  const controllerId = reader.fixed(32);
  const code = reader.number(1);
  const snapshotBytes = reader.number(8);
  reader.end();
  if (
    code === 1
      ? snapshotBytes <= MAX_DOCUMENT_CONTENT_BYTES
      : code !== 2 || snapshotBytes !== 0
  )
    throw new TypeError('Invalid document catch-up refusal');
  return {
    ...request,
    controllerId,
    reason: code === 1 ? 'snapshot-too-large' : 'denied',
    snapshotBytes,
  };
}

function topicMarker(kind: TopicKind) {
  return kind === 'topic-checkpoint'
    ? {
        marker: DOCUMENT_CATCH_UP_CHECKPOINT_MARKER,
        maximum: MAX_DOCUMENT_SECURITY_FRAME_BYTES - 64,
      }
    : {
        marker:
          kind === 'topic-request'
            ? DOCUMENT_CATCH_UP_REQUEST_MARKER
            : DOCUMENT_CATCH_UP_REFUSAL_MARKER,
        maximum: MAX_DOCUMENT_CATCH_UP_TOPIC_REQUEST_BYTES,
      };
}

function hasMarker(frame: Uint8Array, marker: Uint8Array): boolean {
  return (
    frame.length >= marker.length &&
    equalBytes(frame.subarray(0, marker.length), marker)
  );
}

export function isDocumentCatchUpRequestFrame(frame: Uint8Array): boolean {
  return hasMarker(frame, DOCUMENT_CATCH_UP_REQUEST_MARKER);
}

export function isDocumentCatchUpCheckpointFrame(frame: Uint8Array): boolean {
  return hasMarker(frame, DOCUMENT_CATCH_UP_CHECKPOINT_MARKER);
}

export function isDocumentCatchUpRefusalFrame(frame: Uint8Array): boolean {
  return hasMarker(frame, DOCUMENT_CATCH_UP_REFUSAL_MARKER);
}

export function encodeEncryptedDocumentCatchUp(
  kind: TopicKind,
  epochTag: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const { marker, maximum } = topicMarker(kind);
  return new DocumentBinaryWriter()
    .fixed(marker)
    .fixed(copyUnsharedUint8Array(epochTag, 16, 16, 'catch-up epoch tag'))
    .fixed(copyUnsharedUint8Array(nonce, 12, 12, 'catch-up nonce'))
    .bytes(ciphertext, maximum)
    .finish();
}

export function decodeEncryptedDocumentCatchUp(
  kind: TopicKind,
  value: Uint8Array,
): { epochTag: Uint8Array; nonce: Uint8Array; ciphertext: Uint8Array } {
  const { marker, maximum } = topicMarker(kind);
  const reader = new DocumentBinaryReader(value, maximum + 64);
  if (!equalBytes(reader.fixed(4), marker))
    throw new TypeError('Invalid encrypted document catch-up domain');
  const epochTag = reader.fixed(16),
    nonce = reader.fixed(12),
    ciphertext = reader.bytes(maximum);
  reader.end();
  if (ciphertext.length < 16)
    throw new TypeError('Invalid encrypted document catch-up body');
  return { epochTag, nonce, ciphertext };
}
