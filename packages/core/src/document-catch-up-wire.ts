import type { DocumentReplayReceipt } from './document-replay-journal.js';
import type { GroupSecurityDocumentContext } from './group-security-coordinator.js';
import {
  DocumentBinaryReader,
  DocumentBinaryWriter,
  documentBytesEqual,
  documentBytesId,
} from './internal/document-binary.js';
import {
  MAX_DOCUMENT_CONTENT_BYTES,
  MAX_DOCUMENT_SECURITY_FRAME_BYTES,
  readDocumentContext,
  writeDocumentContext,
} from './document-security-wire.js';
import { copyUnsharedUint8Array } from './utils.js';

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

export interface DocumentCatchUpCheckpoint
  extends Omit<DocumentCatchUpRequest, 'receipts'> {
  readonly controllerId: Uint8Array;
  readonly receipts: readonly DocumentReplayReceipt[];
  /** Signed content frames, by author then sequence, that extend requester heads. */
  readonly suffixes: readonly Uint8Array[];
  readonly snapshot: Uint8Array;
}

export type DocumentCatchUpKind = 'request' | 'checkpoint';

function fixed32(value: Uint8Array): Uint8Array {
  return copyUnsharedUint8Array(value, 32, 32, 'catch-up commitment');
}

function bindingWriter(
  kind: DocumentCatchUpKind,
  value: DocumentCatchUpBinding,
) {
  const writer = new DocumentBinaryWriter()
    .fixed(MAGIC)
    .integer(kind === 'request' ? 0 : 1, 1)
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
    !documentBytesEqual(reader.fixed(MAGIC.length), MAGIC) ||
    reader.number(1) !== (kind === 'request' ? 0 : 1)
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
    const id = documentBytesId(memberId);
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
    const id = documentBytesId(memberId);
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

export function encodeDocumentCatchUpCheckpoint(
  value: DocumentCatchUpCheckpoint,
): Uint8Array {
  const writer = writeRequest('checkpoint', value).fixed(
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
): DocumentCatchUpCheckpoint {
  const reader = new DocumentBinaryReader(value);
  const request = readRequest(reader, 'checkpoint');
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
