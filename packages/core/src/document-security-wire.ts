import type { GroupSecurityDocumentContext } from './group-security-coordinator.js';
import {
  DocumentBinaryReader,
  DocumentBinaryWriter,
  documentBytesEqual,
} from './internal/document-binary.js';
import { copyUnsharedUint8Array } from './utils.js';

export const MAX_DOCUMENT_CONTENT_BYTES = 512 * 1024;
export const MAX_DOCUMENT_SECURITY_FRAME_BYTES = 1024 * 1024;
export const DOCUMENT_SECURITY_EPOCH_TAG_BYTES = 16;
const MAGIC = Uint8Array.from('peerborne/document-content/v1\0', (value) =>
  value.charCodeAt(0),
);
const ENCRYPTED_MAGIC = new Uint8Array([0x50, 0x42, 0x44, 1]);

export interface DocumentContentFrame {
  readonly documentId: string;
  readonly genesisId: Uint8Array;
  readonly context: GroupSecurityDocumentContext;
  readonly memberId: Uint8Array;
  readonly sequence: number;
  readonly parent: Uint8Array;
  readonly kind: 'change' | 'snapshot';
  readonly changes: Uint8Array;
}

export function writeDocumentContext(
  writer: DocumentBinaryWriter,
  context: GroupSecurityDocumentContext,
): void {
  const state = context.state;
  writer
    .text(state.protocol.id, 128)
    .integer(state.protocol.version, 2)
    .bytes(state.groupId, 512)
    .integer(state.epoch, 8)
    .bytes(state.treeHash, 128)
    .bytes(state.confirmedTranscriptHash, 128)
    .fixed(
      copyUnsharedUint8Array(
        context.controlHead,
        32,
        32,
        'document control head',
      ),
    );
}

export function readDocumentContext(
  reader: DocumentBinaryReader,
): GroupSecurityDocumentContext {
  return {
    state: {
      protocol: { id: reader.text(128), version: reader.number(2) },
      groupId: reader.bytes(512),
      epoch: reader.integer(8),
      treeHash: reader.bytes(128),
      confirmedTranscriptHash: reader.bytes(128),
    },
    controlHead: reader.fixed(32),
  };
}

export function documentContextsMatch(
  a: GroupSecurityDocumentContext,
  b: GroupSecurityDocumentContext,
): boolean {
  const x = new DocumentBinaryWriter();
  writeDocumentContext(x, a);
  const y = new DocumentBinaryWriter();
  writeDocumentContext(y, b);
  return documentBytesEqual(x.finish(), y.finish());
}

export function documentContentAAD(
  documentId: string,
  context: GroupSecurityDocumentContext,
): Uint8Array {
  const writer = new DocumentBinaryWriter();
  writer.fixed(MAGIC).text(documentId);
  writeDocumentContext(writer, context);
  return writer.finish();
}

export function encodeDocumentContent(frame: DocumentContentFrame): Uint8Array {
  if (!Number.isSafeInteger(frame.sequence) || frame.sequence < 1)
    throw new TypeError('Invalid document sequence');
  if (frame.kind !== 'change' && frame.kind !== 'snapshot')
    throw new TypeError('Invalid document content kind');
  const writer = new DocumentBinaryWriter();
  writer
    .fixed(MAGIC)
    .text(frame.documentId)
    .fixed(copyUnsharedUint8Array(frame.genesisId, 32, 32, 'document genesis'));
  writeDocumentContext(writer, frame.context);
  writer
    .fixed(copyUnsharedUint8Array(frame.memberId, 32, 32, 'document member'))
    .integer(frame.sequence, 8)
    .fixed(copyUnsharedUint8Array(frame.parent, 32, 32, 'document parent'))
    .integer(frame.kind === 'change' ? 0 : 1, 1)
    .bytes(frame.changes, MAX_DOCUMENT_CONTENT_BYTES);
  return writer.finish();
}

export function decodeDocumentContent(value: Uint8Array): DocumentContentFrame {
  const reader = new DocumentBinaryReader(value);
  if (!documentBytesEqual(reader.fixed(MAGIC.length), MAGIC))
    throw new TypeError('Invalid document content domain');
  const documentId = reader.text(),
    genesisId = reader.fixed(32),
    context = readDocumentContext(reader),
    memberId = reader.fixed(32);
  const sequence = reader.number(8),
    parent = reader.fixed(32),
    kind = reader.number(1);
  if (sequence === 0 || kind > 1)
    throw new TypeError('Invalid document content header');
  const changes = reader.bytes(MAX_DOCUMENT_CONTENT_BYTES);
  reader.end();
  return {
    documentId,
    genesisId,
    context,
    memberId,
    sequence,
    parent,
    kind: kind === 0 ? 'change' : 'snapshot',
    changes,
  };
}

export function encodeSignedDocumentContent(
  unsigned: Uint8Array,
  signature: Uint8Array,
): Uint8Array {
  return new DocumentBinaryWriter()
    .bytes(unsigned, MAX_DOCUMENT_SECURITY_FRAME_BYTES - 2048)
    .bytes(signature, 1024)
    .finish();
}

export function decodeSignedDocumentContent(value: Uint8Array): {
  unsigned: Uint8Array;
  signature: Uint8Array;
} {
  const reader = new DocumentBinaryReader(value);
  const unsigned = reader.bytes(MAX_DOCUMENT_SECURITY_FRAME_BYTES - 2048),
    signature = reader.bytes(1024);
  reader.end();
  if (!signature.length) throw new TypeError('Missing document signature');
  return { unsigned, signature };
}

export function encodeEncryptedDocumentContent(
  epochTag: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  return new DocumentBinaryWriter()
    .fixed(ENCRYPTED_MAGIC)
    .fixed(copyUnsharedUint8Array(epochTag, 16, 16, 'document epoch tag'))
    .fixed(copyUnsharedUint8Array(nonce, 12, 12, 'document nonce'))
    .bytes(ciphertext, MAX_DOCUMENT_SECURITY_FRAME_BYTES - 64)
    .finish();
}

export function decodeEncryptedDocumentContent(value: Uint8Array): {
  epochTag: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
} {
  const reader = new DocumentBinaryReader(value);
  if (!documentBytesEqual(reader.fixed(4), ENCRYPTED_MAGIC))
    throw new TypeError('Invalid encrypted document domain');
  const epochTag = reader.fixed(16),
    nonce = reader.fixed(12),
    ciphertext = reader.bytes(MAX_DOCUMENT_SECURITY_FRAME_BYTES - 64);
  reader.end();
  if (ciphertext.length < 16)
    throw new TypeError('Invalid encrypted document body');
  return { epochTag, nonce, ciphertext };
}
