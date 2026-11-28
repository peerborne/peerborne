import { Base64 } from 'js-base64';
import { CID } from 'multiformats';
import { isPaddedBase64 } from './internal/base64.js';
import { snapshotEnumerableOwnDataObject } from './internal/data-snapshot.js';
import { copyUnsharedUint8Array } from './internal/bytes.js';
import type { SerializedBeeKEMWelcomeV2 } from './beekem-welcome-wire.js';
import { snapshotBoundedChangeTree } from './change-tree-walk.js';
import type { CRDTSyncMessage } from './crdt-sync-message.js';
import {
  MAX_RECENT_TIPS,
  validateRemoteSyncTreeAliases,
} from './merkle-cross-links.js';
import { canRetainGcCandidate } from './policy/retention.js';

export const MAX_DOCUMENT_CHECKPOINT_BYTES = 16 * 1024 * 1024;
const MAX_CHECKPOINT_CIDS = 100_000;
const MAX_CHECKPOINT_SIGNATURE_BYTES = 8192;
const ENCRYPTED_CHECKPOINT_FORMAT = 'peerborne/encrypted-document-checkpoint/1';
const ENCRYPTED_CHECKPOINT_NONCE_BYTES = 12;
const ENCRYPTED_CHECKPOINT_TAG_BYTES = 16;
const MIN_ENCRYPTED_CHECKPOINT_BYTES =
  ENCRYPTED_CHECKPOINT_NONCE_BYTES + 4 + 2 + ENCRYPTED_CHECKPOINT_TAG_BYTES;
const MAX_ENCRYPTED_CHECKPOINT_BYTES =
  ENCRYPTED_CHECKPOINT_NONCE_BYTES +
  4 +
  MAX_DOCUMENT_CHECKPOINT_BYTES +
  MAX_CHECKPOINT_SIGNATURE_BYTES +
  ENCRYPTED_CHECKPOINT_TAG_BYTES;

/**
 * A plaintext checkpoint from `exportPlaintextCheckpoint()`. The payload is
 * unencrypted JSON holding the document's state and its raw document keys.
 * Never store it unencrypted and never send it over a network. Prefer
 * `exportEncryptedCheckpoint()`.
 */
export interface DocumentCheckpoint {
  payload: Uint8Array;
  signature: Uint8Array;
}

/** @internal Capture the signed envelope once before any asynchronous work. */
export function captureDocumentCheckpoint(
  checkpoint: DocumentCheckpoint,
): DocumentCheckpoint {
  const record = snapshotEnumerableOwnDataObject<Record<string, unknown>>(
    checkpoint,
    'Document checkpoint',
  );
  if (Object.keys(record).sort().join() !== 'payload,signature')
    throw new TypeError('Invalid checkpoint envelope');
  return {
    payload: copyUnsharedUint8Array(
      record.payload,
      1,
      MAX_DOCUMENT_CHECKPOINT_BYTES,
      'Checkpoint payload',
    ),
    signature: copyUnsharedUint8Array(
      record.signature,
      1,
      MAX_CHECKPOINT_SIGNATURE_BYTES,
      'Checkpoint signature',
    ),
  };
}

/** @internal Copy sealed checkpoint bytes once before any asynchronous work. */
export function captureEncryptedDocumentCheckpoint(
  sealed: unknown,
): Uint8Array<ArrayBuffer> {
  return copyUnsharedUint8Array(
    sealed,
    MIN_ENCRYPTED_CHECKPOINT_BYTES,
    MAX_ENCRYPTED_CHECKPOINT_BYTES,
    'Encrypted checkpoint',
  ) as Uint8Array<ArrayBuffer>;
}

/** @internal */
export function assertCheckpointStorageKey(
  key: unknown,
  usage: 'encrypt' | 'decrypt',
): asserts key is CryptoKey {
  const candidate = key as CryptoKey;
  if (
    Object.prototype.toString.call(key) !== '[object CryptoKey]' ||
    candidate.type !== 'secret' ||
    candidate.algorithm.name !== 'AES-GCM' ||
    (candidate.algorithm as AesKeyAlgorithm).length !== 256 ||
    !candidate.usages.includes(usage)
  )
    throw new TypeError(
      `Checkpoint storage key must be a 256-bit AES-GCM key that can ${usage}`,
    );
}

function encryptedCheckpointAssociatedData(
  documentPath: string,
): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(
    JSON.stringify([ENCRYPTED_CHECKPOINT_FORMAT, documentPath]),
  );
}

/** @internal Seal a captured checkpoint to one document path under an AES-GCM storage key. */
export async function sealDocumentCheckpoint(
  checkpoint: DocumentCheckpoint,
  documentPath: string,
  storageKey: CryptoKey,
): Promise<Uint8Array> {
  assertCheckpointStorageKey(storageKey, 'encrypt');
  const { payload, signature } = captureDocumentCheckpoint(checkpoint);
  const cleartext = new Uint8Array(4 + payload.length + signature.length);
  try {
    new DataView(cleartext.buffer).setUint32(0, payload.length);
    cleartext.set(payload, 4);
    cleartext.set(signature, 4 + payload.length);
    const nonce = crypto.getRandomValues(
      new Uint8Array(ENCRYPTED_CHECKPOINT_NONCE_BYTES),
    );
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: nonce,
          additionalData: encryptedCheckpointAssociatedData(documentPath),
        },
        storageKey,
        cleartext,
      ),
    );
    const sealed = new Uint8Array(nonce.length + ciphertext.length);
    sealed.set(nonce);
    sealed.set(ciphertext, nonce.length);
    return sealed;
  } finally {
    cleartext.fill(0);
    payload.fill(0);
  }
}

/** @internal Authenticate and decrypt a sealed checkpoint for one document path. */
export async function openSealedDocumentCheckpoint(
  sealed: unknown,
  documentPath: string,
  storageKey: CryptoKey,
): Promise<DocumentCheckpoint> {
  assertCheckpointStorageKey(storageKey, 'decrypt');
  const bytes = captureEncryptedDocumentCheckpoint(sealed);
  let cleartext: Uint8Array<ArrayBuffer>;
  try {
    cleartext = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: bytes.subarray(0, ENCRYPTED_CHECKPOINT_NONCE_BYTES),
          additionalData: encryptedCheckpointAssociatedData(documentPath),
        },
        storageKey,
        bytes.subarray(ENCRYPTED_CHECKPOINT_NONCE_BYTES),
      ),
    );
  } catch {
    throw new Error('Encrypted checkpoint could not be authenticated');
  }
  try {
    const payloadLength = new DataView(cleartext.buffer).getUint32(0);
    const signatureLength = cleartext.length - 4 - payloadLength;
    if (
      payloadLength < 1 ||
      payloadLength > MAX_DOCUMENT_CHECKPOINT_BYTES ||
      signatureLength < 1 ||
      signatureLength > MAX_CHECKPOINT_SIGNATURE_BYTES
    )
      throw new TypeError('Invalid encrypted checkpoint');
    return {
      payload: cleartext.slice(4, 4 + payloadLength),
      signature: cleartext.slice(4 + payloadLength),
    };
  } finally {
    cleartext.fill(0);
  }
}

/** @internal Hash only owned, validated checkpoint payload bytes. */
export async function digestDocumentCheckpointPayload(
  payload: Uint8Array,
): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest('SHA-256', payload as Uint8Array<ArrayBuffer>),
  );
}

/**
 * Compute the SHA-256 commitment of a locally exported checkpoint: of the
 * bytes `exportEncryptedCheckpoint()` returned, or of the payload of a
 * `exportPlaintextCheckpoint()` result. Pass it to the matching restore
 * method. Store this digest independently of rollbackable checkpoint storage.
 */
export async function documentCheckpointCommitment(
  checkpoint: Uint8Array | DocumentCheckpoint,
): Promise<Uint8Array> {
  if (ArrayBuffer.isView(checkpoint))
    return digestDocumentCheckpointPayload(
      captureEncryptedDocumentCheckpoint(checkpoint),
    );
  const { payload } = captureDocumentCheckpoint(checkpoint);
  return digestDocumentCheckpointPayload(payload);
}

/** @internal Current local checkpoint format; independent of network message formats. */
export interface DocumentCheckpointState {
  format: 'peerborne/local-document-checkpoint/4';
  documentPath: string;
  owner: string;
  document: string;
  readers: string;
  writers: string;
  keychain: string;
  actors: string;
  writerActors: string;
  readerActors: string;
  message: string;
  hashes: string[];
  ancestors: string[];
  recentTips: [string, string][];
  ownBlocks: string[];
  gcCandidates: string[];
  documentChangeCount: number;
  changesSinceSnapshot: number;
  historyVisibility: 'full_history' | 'current_only' | 'since_invited';
  invitationEpoch: string | null;
  beekem: {
    generation: number;
    leafPublicKey: string;
    sealedLeafPrivateKey: string | null;
    welcome: SerializedBeeKEMWelcomeV2 | null;
    digest: string | null;
    parentTreeHash: string | null;
  } | null;
  readerLeaves: [string, number][];
  readerKemKeys: [string, string][];
  welcomes: [number, SerializedBeeKEMWelcomeV2][];
}

export function checkpointEncode(bytes: Uint8Array): string {
  return Base64.fromUint8Array(
    copyUnsharedUint8Array(
      bytes,
      0,
      MAX_DOCUMENT_CHECKPOINT_BYTES,
      'Checkpoint bytes',
    ),
  );
}

export function checkpointDecode(value: unknown): Uint8Array {
  if (
    typeof value !== 'string' ||
    value.length > (MAX_DOCUMENT_CHECKPOINT_BYTES * 4) / 3 + 4 ||
    !isPaddedBase64(value)
  ) {
    throw new TypeError('Invalid checkpoint byte encoding');
  }
  const bytes = Base64.toUint8Array(value);
  if (
    bytes.length > MAX_DOCUMENT_CHECKPOINT_BYTES ||
    Base64.fromUint8Array(bytes) !== value
  ) {
    throw new TypeError('Invalid checkpoint byte encoding');
  }
  return bytes;
}

/** Encode only a state that `decodeCheckpointState` accepts, so a stored checkpoint always restores. */
export function encodeCheckpointState(
  state: DocumentCheckpointState,
): Uint8Array {
  const encoded = new TextEncoder().encode(JSON.stringify(state));
  if (encoded.length > MAX_DOCUMENT_CHECKPOINT_BYTES)
    throw new RangeError('Document checkpoint exceeds its size limit');
  decodeCheckpointState(encoded);
  return encoded;
}

/**
 * Require a checkpoint's retained change tree to be well formed and rooted at
 * a known CID. Everything beneath a known CID is covered by it, as in a merge,
 * so an adopted tree may still name ancestors the document has forgotten.
 */
export function assertCheckpointChangeHistory<ChangesType>(
  documentPath: string,
  message: CRDTSyncMessage<ChangesType>,
  hashes: ReadonlySet<string>,
): void {
  if (
    message.documentId !== documentPath ||
    !message.changeId ||
    !message.changes ||
    !hashes.has(message.changeId)
  )
    throw new Error('Invalid checkpoint change root');
  const tree = snapshotBoundedChangeTree(message.changeId, message.changes, {
    canonicalizeNodeId: (value) => CID.parse(value).toString(),
  });
  validateRemoteSyncTreeAliases(message.changeId, tree.root);
}

export function decodeCheckpointState(
  bytes: Uint8Array,
): DocumentCheckpointState {
  const state = JSON.parse(
    new TextDecoder('utf-8', { fatal: true }).decode(bytes),
  );
  const fields = [
    'format',
    'documentPath',
    'owner',
    'document',
    'readers',
    'writers',
    'keychain',
    'actors',
    'writerActors',
    'readerActors',
    'message',
    'hashes',
    'ancestors',
    'recentTips',
    'ownBlocks',
    'gcCandidates',
    'documentChangeCount',
    'changesSinceSnapshot',
    'historyVisibility',
    'invitationEpoch',
    'beekem',
    'readerLeaves',
    'readerKemKeys',
    'welcomes',
  ];
  if (
    state === null ||
    typeof state !== 'object' ||
    Array.isArray(state) ||
    Object.keys(state).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(state, field)) ||
    state.format !== 'peerborne/local-document-checkpoint/4' ||
    typeof state.documentPath !== 'string' ||
    state.documentPath.length === 0 ||
    state.documentPath.length > 4096 ||
    typeof state.owner !== 'string' ||
    state.owner.length === 0 ||
    state.owner.length > 1024 ||
    !['full_history', 'current_only', 'since_invited'].includes(
      state.historyVisibility,
    ) ||
    !Number.isSafeInteger(state.documentChangeCount) ||
    state.documentChangeCount < 0 ||
    !Number.isSafeInteger(state.changesSinceSnapshot) ||
    state.changesSinceSnapshot < 0 ||
    state.changesSinceSnapshot > state.documentChangeCount
  ) {
    throw new TypeError('Invalid document checkpoint');
  }
  for (const name of [
    'document',
    'readers',
    'writers',
    'keychain',
    'actors',
    'writerActors',
    'readerActors',
    'message',
  ])
    checkpointDecode(state[name]);
  const cid = (value: unknown): void => {
    if (
      typeof value !== 'string' ||
      value.length > 1024 ||
      CID.parse(value).toString() !== value
    ) {
      throw new TypeError('Invalid checkpoint CID');
    }
  };
  function array(value: unknown): asserts value is unknown[] {
    if (!Array.isArray(value) || value.length > MAX_CHECKPOINT_CIDS)
      throw new TypeError('Invalid checkpoint collection');
  }
  for (const name of ['hashes', 'ancestors']) {
    array(state[name]);
    state[name].forEach(cid);
    if (new Set(state[name]).size !== state[name].length)
      throw new TypeError('Duplicate checkpoint CID');
  }
  if (state.hashes.length === 0)
    throw new TypeError('Checkpoint has no document history');
  const hashes = new Set(state.hashes);
  array(state.recentTips);
  if (state.recentTips.length > MAX_RECENT_TIPS)
    throw new TypeError('Too many checkpoint tips');
  state.recentTips.forEach((entry: unknown) => {
    if (
      !Array.isArray(entry) ||
      entry.length !== 2 ||
      !['document', 'reader', 'writer'].includes(entry[1]) ||
      !hashes.has(entry[0])
    ) {
      throw new TypeError('Invalid checkpoint tip');
    }
    cid(entry[0]);
  });
  array(state.ownBlocks);
  const ownBlocks = new Set<string>();
  for (const block of state.ownBlocks) {
    cid(block);
    if (
      ownBlocks.has(block) ||
      !canRetainGcCandidate(false, ownBlocks.size, block.length)
    )
      throw new TypeError('Invalid checkpoint own block');
    ownBlocks.add(block);
  }
  array(state.gcCandidates);
  const gcCandidates = new Set<string>();
  for (const candidate of state.gcCandidates) {
    cid(candidate);
    if (
      gcCandidates.has(candidate) ||
      !ownBlocks.has(candidate) ||
      !canRetainGcCandidate(false, gcCandidates.size, candidate.length)
    )
      throw new TypeError('Invalid checkpoint garbage collection candidate');
    gcCandidates.add(candidate);
  }
  if (
    state.invitationEpoch !== null &&
    checkpointDecode(state.invitationEpoch).length !== 32
  )
    throw new TypeError('Invalid checkpoint epoch');
  for (const name of ['readerLeaves', 'readerKemKeys', 'welcomes']) {
    array(state[name]);
    const seen = new Set();
    for (const entry of state[name]) {
      if (!Array.isArray(entry) || entry.length !== 2 || seen.has(entry[0]))
        throw new TypeError('Invalid checkpoint membership collection');
      seen.add(entry[0]);
      if (name === 'welcomes') {
        if (!Number.isSafeInteger(entry[0]) || entry[0] < 0)
          throw new TypeError('Invalid checkpoint leaf');
      } else if (
        typeof entry[0] !== 'string' ||
        entry[0].length === 0 ||
        entry[0].length > 1024
      )
        throw new TypeError('Invalid checkpoint authority');
      if (
        name === 'readerLeaves' &&
        (!Number.isSafeInteger(entry[1]) || entry[1] < 0)
      )
        throw new TypeError('Invalid checkpoint leaf');
      if (name === 'readerKemKeys' && checkpointDecode(entry[1]).length !== 65)
        throw new TypeError('Invalid checkpoint KEM key');
    }
  }
  if (state.beekem !== null) {
    if (
      typeof state.beekem !== 'object' ||
      Object.keys(state.beekem).sort().join() !==
        'digest,generation,leafPublicKey,parentTreeHash,sealedLeafPrivateKey,welcome'
    )
      throw new TypeError('Invalid checkpoint BeeKEM state');
    if (
      !Number.isSafeInteger(state.beekem.generation) ||
      Object.is(state.beekem.generation, -0) ||
      state.beekem.generation < 0 ||
      state.beekem.generation > 0xffff_ffff
    )
      throw new TypeError('Invalid checkpoint BeeKEM generation');
    if (checkpointDecode(state.beekem.leafPublicKey).length !== 65)
      throw new TypeError('Invalid checkpoint leaf key');
    if (state.beekem.sealedLeafPrivateKey !== null) {
      const sealed = checkpointDecode(state.beekem.sealedLeafPrivateKey);
      if (sealed.length === 0 || sealed.length > 8192)
        throw new TypeError('Invalid checkpoint sealed leaf key');
    }
    if (
      state.beekem.digest !== null &&
      checkpointDecode(state.beekem.digest).length !== 32
    )
      throw new TypeError('Invalid checkpoint replay digest');
    if (
      state.beekem.parentTreeHash !== null &&
      checkpointDecode(state.beekem.parentTreeHash).length !== 32
    )
      throw new TypeError('Invalid checkpoint BeeKEM predecessor');
  }
  return state as DocumentCheckpointState;
}
