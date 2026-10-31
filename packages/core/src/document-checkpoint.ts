import { Base64 } from 'js-base64';
import { CID } from 'multiformats';
import { copyUnsharedUint8Array } from './utils.js';
import type { SerializedBeeKEMWelcomeV2 } from './beekem-welcome-wire.js';
import { MAX_RECENT_TIPS } from './merkle-cross-links.js';

export const MAX_DOCUMENT_CHECKPOINT_BYTES = 16 * 1024 * 1024;
const MAX_CHECKPOINT_CIDS = 100_000;

/** Contains document keys. Encrypt before persisting; never send over a network. */
export interface DocumentCheckpoint {
  payload: Uint8Array;
  signature: Uint8Array;
}

/** @internal Current local checkpoint format; independent of network message formats. */
export interface DocumentCheckpointState {
  format: 'peerborne/local-document-checkpoint/1';
  documentPath: string;
  owner: string;
  document: string;
  readers: string;
  writers: string;
  keychain: string;
  message: string;
  hashes: string[];
  ancestors: string[];
  recentTips: [string, string][];
  documentChangeCount: number;
  changesSinceSnapshot: number;
  historyVisibility: 'full_history' | 'current_only' | 'since_invited';
  invitationEpoch: string | null;
  beekem: {
    leafPublicKey: string;
    sealedLeafPrivateKey: string | null;
    welcome: SerializedBeeKEMWelcomeV2 | null;
    digest: string | null;
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
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
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

export function encodeCheckpointState(
  state: DocumentCheckpointState,
): Uint8Array {
  const encoded = new TextEncoder().encode(JSON.stringify(state));
  if (encoded.length > MAX_DOCUMENT_CHECKPOINT_BYTES)
    throw new RangeError('Document checkpoint exceeds its size limit');
  return encoded;
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
    'message',
    'hashes',
    'ancestors',
    'recentTips',
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
    state.format !== 'peerborne/local-document-checkpoint/1' ||
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
  for (const name of ['document', 'readers', 'writers', 'keychain', 'message'])
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
        'digest,leafPublicKey,sealedLeafPrivateKey,welcome'
    )
      throw new TypeError('Invalid checkpoint BeeKEM state');
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
  }
  return state as DocumentCheckpointState;
}
