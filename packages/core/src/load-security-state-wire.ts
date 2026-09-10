import { Base64 } from 'js-base64';
import {
  LOAD_SECURITY_HASH_LENGTH,
  LOAD_SECURITY_STATE_VERSION,
  LoadSecurityCommitments,
  MAX_LOAD_SECURITY_EPOCH,
  validateLoadSecurityCommitments,
} from './load-security-state.js';
import { snapshotEnumerableOwnDataObject } from './utils.js';

export interface LoadSecurityCommitmentsWire {
  version: typeof LOAD_SECURITY_STATE_VERSION;
  controlHead: string;
  groupId: string;
  epoch: string;
  treeHash: string;
  confirmedTranscriptHash: string;
}

const WIRE_KEYS = [
  'version',
  'controlHead',
  'groupId',
  'epoch',
  'treeHash',
  'confirmedTranscriptHash',
] as const;

function canonicalBase64(name: string, value: unknown): Uint8Array {
  if (
    typeof value !== 'string' ||
    value.length !== 44 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  ) {
    throw new TypeError(`${name} must be canonical padded base64`);
  }
  const bytes = Base64.toUint8Array(value);
  if (
    bytes.length !== LOAD_SECURITY_HASH_LENGTH ||
    Base64.fromUint8Array(bytes) !== value
  ) {
    throw new TypeError(
      `${name} must be canonical base64 for exactly ${LOAD_SECURITY_HASH_LENGTH} bytes`,
    );
  }
  return new Uint8Array(bytes);
}

function requireExactObject(value: unknown): Record<string, unknown> {
  const record = snapshotEnumerableOwnDataObject<Record<string, unknown>>(
    value,
    'loadSecurityState',
  );
  const keys = Reflect.ownKeys(record);
  const expected = new Set<string>(WIRE_KEYS);
  if (
    keys.length !== expected.size ||
    keys.some((key) => typeof key !== 'string' || !expected.has(key))
  ) {
    throw new TypeError(
      `loadSecurityState must contain exactly: ${WIRE_KEYS.join(', ')}`,
    );
  }
  return record;
}

export function serializeLoadSecurityCommitmentsForWire(
  commitments: LoadSecurityCommitments,
): LoadSecurityCommitmentsWire {
  validateLoadSecurityCommitments(commitments);
  return {
    version: LOAD_SECURITY_STATE_VERSION,
    controlHead: Base64.fromUint8Array(commitments.controlHead),
    groupId: commitments.groupId,
    epoch: commitments.epoch.toString(10),
    treeHash: Base64.fromUint8Array(commitments.treeHash),
    confirmedTranscriptHash: Base64.fromUint8Array(
      commitments.confirmedTranscriptHash,
    ),
  };
}

export function deserializeLoadSecurityCommitmentsFromWire(
  value: unknown,
): LoadSecurityCommitments {
  const record = requireExactObject(value);
  if (record.version !== LOAD_SECURITY_STATE_VERSION) {
    throw new RangeError('loadSecurityState.version must be 1');
  }
  if (typeof record.groupId !== 'string') {
    throw new TypeError('loadSecurityState.groupId must be a string');
  }
  if (
    typeof record.epoch !== 'string' ||
    record.epoch.length > 20 ||
    !/^(?:0|[1-9][0-9]*)$/.test(record.epoch)
  ) {
    throw new TypeError('loadSecurityState.epoch must be a canonical decimal string');
  }
  const epoch = BigInt(record.epoch);
  if (epoch > MAX_LOAD_SECURITY_EPOCH) {
    throw new RangeError('loadSecurityState.epoch exceeds unsigned 64-bit range');
  }
  const commitments: LoadSecurityCommitments = {
    version: LOAD_SECURITY_STATE_VERSION,
    controlHead: canonicalBase64('loadSecurityState.controlHead', record.controlHead),
    groupId: record.groupId,
    epoch,
    treeHash: canonicalBase64('loadSecurityState.treeHash', record.treeHash),
    confirmedTranscriptHash: canonicalBase64(
      'loadSecurityState.confirmedTranscriptHash',
      record.confirmedTranscriptHash,
    ),
  };
  validateLoadSecurityCommitments(commitments);
  return commitments;
}
