import { defineEnumerableDataProperty } from './internal/data-property.js';
import { copyUnsharedUint8Array } from './utils.js';

const LOAD_SECURITY_STATE_DOMAIN = 'peerborne/load-security-state/v1\0';

export const LOAD_SECURITY_STATE_VERSION = 1 as const;
export const LOAD_SECURITY_HASH_LENGTH = 32;
export const MAX_LOAD_SECURITY_GROUP_ID_BYTES = 1024;
export const MAX_LOAD_SECURITY_DOCUMENT_ID_BYTES = 4096;
export const MAX_LOAD_SECURITY_FRONTIER_ENTRIES = 4096;
export const MAX_LOAD_SECURITY_FRONTIER_ENTRY_BYTES = 1024;
export const MAX_LOAD_SECURITY_EPOCH = (1n << 64n) - 1n;

const LOAD_SECURITY_COMMITMENT_FIELDS = [
  'version',
  'controlHead',
  'groupId',
  'epoch',
  'treeHash',
  'confirmedTranscriptHash',
] as const;
const LOAD_SECURITY_STATE_FIELDS = [
  ...LOAD_SECURITY_COMMITMENT_FIELDS,
  'documentId',
  'frontier',
] as const;
const objectCreate = Object.create;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const arrayIsArray = Array.isArray;
const reflectApply = Reflect.apply;



export interface LoadSecurityCommitments {
  version: typeof LOAD_SECURITY_STATE_VERSION;
  controlHead: Uint8Array;
  groupId: string;
  epoch: bigint;
  treeHash: Uint8Array;
  confirmedTranscriptHash: Uint8Array;
}

export interface LoadSecurityState extends LoadSecurityCommitments {
  documentId: string;
  frontier: readonly string[];
}

export type LoadSecurityCommitmentsResolver = (
  documentPath: string,
) => unknown | Promise<unknown>;

/**
 * Raised when a security-aware load cannot obtain one valid locally trusted
 * commitment tuple. V4 callers must fail closed on this error before probing
 * any peer; accepting a remote tuple as the trust root would make the quorum
 * circular.
 */
export class TrustedLoadSecurityCommitmentsError extends Error {
  constructor(documentPath: string, detail: string, cause?: unknown) {
    super(
      `Cannot start security-aware load for ${documentPath}: ${detail}`,
      cause === undefined ? undefined : { cause },
    );
    this.name = 'TrustedLoadSecurityCommitmentsError';
  }
}

function encodeUtf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function requirePlainString(name: string, value: unknown, maxBytes: number): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  for (let index = 0; index < value.length; index++) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError(`${name} must be well-formed UTF-16`);
      }
      index++;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new TypeError(`${name} must be well-formed UTF-16`);
    }
  }
  const bytes = encodeUtf8(value);
  if (bytes.length > maxBytes) {
    throw new RangeError(`${name} exceeds ${maxBytes} UTF-8 bytes`);
  }
  return value;
}

function requireHash(name: string, value: unknown): Uint8Array {
  try {
    return copyUnsharedUint8Array(
      value,
      LOAD_SECURITY_HASH_LENGTH,
      LOAD_SECURITY_HASH_LENGTH,
      name,
    );
  } catch {
    throw new TypeError(
      `${name} must be a ${LOAD_SECURITY_HASH_LENGTH}-byte unshared Uint8Array`,
    );
  }
}

export function validateLoadSecurityCommitments(
  commitments: LoadSecurityCommitments,
): void {
  validateAndCloneLoadSecurityCommitments(commitments);
}

function validateAndCloneCommitmentFields(
  tuple: Record<(typeof LOAD_SECURITY_COMMITMENT_FIELDS)[number], unknown>,
): LoadSecurityCommitments {
  if (tuple.version !== LOAD_SECURITY_STATE_VERSION) {
    throw new RangeError('unsupported load security version');
  }
  const controlHead = requireHash('controlHead', tuple.controlHead);
  const groupId = requirePlainString(
    'groupId',
    tuple.groupId,
    MAX_LOAD_SECURITY_GROUP_ID_BYTES,
  );
  if (
    typeof tuple.epoch !== 'bigint' ||
    tuple.epoch < 0n ||
    tuple.epoch > MAX_LOAD_SECURITY_EPOCH
  ) {
    throw new RangeError('epoch must be an unsigned 64-bit bigint');
  }
  return {
    version: LOAD_SECURITY_STATE_VERSION,
    controlHead,
    groupId,
    epoch: tuple.epoch,
    treeHash: requireHash('treeHash', tuple.treeHash),
    confirmedTranscriptHash: requireHash(
      'confirmedTranscriptHash',
      tuple.confirmedTranscriptHash,
    ),
  };
}

function validateAndCloneLoadSecurityCommitments(
  value: unknown,
): LoadSecurityCommitments {
  return validateAndCloneCommitmentFields(
    snapshotLoadSecurityOwnDataFields(
      value,
      LOAD_SECURITY_COMMITMENT_FIELDS,
      'load security commitments',
    ),
  );
}

/**
 * Return a defensive copy of the six known own-data tuple fields. Other
 * top-level fields are not part of the security commitment.
 */
export function cloneLoadSecurityCommitments(
  commitments: LoadSecurityCommitments,
): LoadSecurityCommitments {
  return validateAndCloneLoadSecurityCommitments(commitments);
}

function snapshotLoadSecurityOwnDataFields<Fields extends readonly string[]>(
  value: unknown,
  fields: Fields,
  label: string,
): Record<Fields[number], unknown> {
  if (value === null || typeof value !== 'object') {
    throw new TypeError(`${label} must be an object`);
  }
  let prototype: object | null;
  let prototypeParent: object | null = null;
  let isArray: boolean;
  try {
    isArray = reflectApply(arrayIsArray, Array, [value]) as boolean;
    prototype = reflectApply(objectGetPrototypeOf, Object, [value]) as
      | object
      | null;
    if (prototype !== null) {
      prototypeParent = reflectApply(objectGetPrototypeOf, Object, [
        prototype,
      ]) as object | null;
    }
  } catch {
    throw new TypeError(`${label} must be a plain record`);
  }
  // A realm's ordinary Object.prototype has a null parent. This accepts
  // ordinary cross-realm and null-prototype records. Only the captured own
  // fields are consumed, so inherited properties never become tuple data.
  if (isArray || (prototype !== null && prototypeParent !== null)) {
    throw new TypeError(`${label} must be a plain record`);
  }
  const snapshot = reflectApply(objectCreate, Object, [null]) as Record<
    Fields[number],
    unknown
  >;
  for (const field of fields) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = reflectApply(objectGetOwnPropertyDescriptor, Object, [
        value,
        field,
      ]) as PropertyDescriptor | undefined;
    } catch {
      throw new TypeError(
        `${label} must expose stable own data properties`,
      );
    }
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !('value' in descriptor)
    ) {
      throw new TypeError(
        `${label} ${field} must be an enumerable own data property`,
      );
    }
    defineEnumerableDataProperty(snapshot, field, descriptor.value);
  }
  return snapshot;
}

/**
 * Resolve and defensively capture the local trust anchor for one V4 load.
 * The callback is invoked exactly once. Undefined, malformed, or rejected
 * results abort the load rather than falling back to a peer-supplied tuple.
 */
export async function captureTrustedLoadSecurityCommitments(
  documentPath: string,
  resolver: LoadSecurityCommitmentsResolver | undefined,
): Promise<LoadSecurityCommitments> {
  if (resolver === undefined) {
    throw new TrustedLoadSecurityCommitmentsError(
      documentPath,
      'resolveLoadSecurityCommitments is not configured',
    );
  }

  let resolved: unknown;
  try {
    resolved = await resolver(documentPath);
  } catch (cause) {
    throw new TrustedLoadSecurityCommitmentsError(
      documentPath,
      'resolveLoadSecurityCommitments failed',
      cause,
    );
  }
  if (resolved === undefined) {
    throw new TrustedLoadSecurityCommitmentsError(
      documentPath,
      'resolveLoadSecurityCommitments returned undefined',
    );
  }

  try {
    return cloneLoadSecurityCommitments(
      resolved as LoadSecurityCommitments,
    );
  } catch (cause) {
    throw new TrustedLoadSecurityCommitmentsError(
      documentPath,
      'resolveLoadSecurityCommitments returned an invalid tuple',
      cause,
    );
  }
}

/**
 * Compare a remotely supplied V4 tuple with the locally captured trust
 * anchor. Group and epoch use exact equality. Every byte of every fixed-size
 * hash is visited before returning, so hash-content comparison does not
 * short-circuit on the first differing byte.
 */
export function loadSecurityCommitmentsEqual(
  trusted: LoadSecurityCommitments | undefined,
  candidate: LoadSecurityCommitments | undefined,
): boolean {
  if (trusted === undefined || candidate === undefined) return false;
  let trustedSnapshot: LoadSecurityCommitments;
  let candidateSnapshot: LoadSecurityCommitments;
  try {
    trustedSnapshot = validateAndCloneLoadSecurityCommitments(trusted);
    candidateSnapshot = validateAndCloneLoadSecurityCommitments(candidate);
  } catch {
    return false;
  }

  let difference = 0;
  difference |= Number(trustedSnapshot.version !== candidateSnapshot.version);
  difference |= Number(trustedSnapshot.groupId !== candidateSnapshot.groupId);
  difference |= Number(trustedSnapshot.epoch !== candidateSnapshot.epoch);
  for (let index = 0; index < LOAD_SECURITY_HASH_LENGTH; index++) {
    difference |=
      trustedSnapshot.controlHead[index] ^ candidateSnapshot.controlHead[index];
    difference |=
      trustedSnapshot.treeHash[index] ^ candidateSnapshot.treeHash[index];
    difference |=
      trustedSnapshot.confirmedTranscriptHash[index] ^
      candidateSnapshot.confirmedTranscriptHash[index];
  }
  return difference === 0;
}

function snapshotLoadSecurityFrontier(value: unknown): string[] {
  let isArray: boolean;
  let lengthDescriptor: PropertyDescriptor | undefined;
  try {
    isArray = reflectApply(arrayIsArray, Array, [value]) as boolean;
    lengthDescriptor = isArray
      ? (reflectApply(objectGetOwnPropertyDescriptor, Object, [
          value,
          'length',
        ]) as PropertyDescriptor | undefined)
      : undefined;
  } catch {
    throw new TypeError('frontier must be a stable array of CID strings');
  }
  const length =
    lengthDescriptor !== undefined && 'value' in lengthDescriptor
      ? lengthDescriptor.value
      : undefined;
  if (!isArray || !Number.isSafeInteger(length) || (length as number) < 0) {
    throw new TypeError('frontier must be an array of CID strings');
  }
  if ((length as number) > MAX_LOAD_SECURITY_FRONTIER_ENTRIES) {
    throw new RangeError(
      `frontier exceeds ${MAX_LOAD_SECURITY_FRONTIER_ENTRIES} entries`,
    );
  }

  const snapshot = new Array<string>(length as number);
  const seen = new Set<string>();
  for (let index = 0; index < snapshot.length; index++) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = reflectApply(objectGetOwnPropertyDescriptor, Object, [
        value,
        String(index),
      ]) as PropertyDescriptor | undefined;
    } catch {
      throw new TypeError('frontier must expose stable own data entries');
    }
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !('value' in descriptor)
    ) {
      throw new TypeError(
        'frontier must contain only enumerable own data entries',
      );
    }
    const entry = requirePlainString(
      'frontier entry',
      descriptor.value,
      MAX_LOAD_SECURITY_FRONTIER_ENTRY_BYTES,
    );
    if (seen.has(entry)) {
      throw new TypeError('frontier contains a duplicate entry');
    }
    seen.add(entry);
    defineEnumerableDataProperty(snapshot, String(index), entry);
  }
  return snapshot;
}

function validateAndCloneLoadSecurityState(value: unknown): LoadSecurityState {
  const fields = snapshotLoadSecurityOwnDataFields(
    value,
    LOAD_SECURITY_STATE_FIELDS,
    'load security state',
  );
  return {
    ...validateAndCloneCommitmentFields(fields),
    documentId: requirePlainString(
      'documentId',
      fields.documentId,
      MAX_LOAD_SECURITY_DOCUMENT_ID_BYTES,
    ),
    frontier: snapshotLoadSecurityFrontier(fields.frontier),
  };
}

export function validateLoadSecurityState(state: LoadSecurityState): void {
  validateAndCloneLoadSecurityState(state);
}

function uint32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function uint64(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
}

function lengthPrefixed(bytes: Uint8Array): Uint8Array[] {
  return [uint32(bytes.length), bytes];
}

function concatenate(parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Canonical, domain-separated encoding used for quorum advertisements. */
export function encodeLoadSecurityState(state: LoadSecurityState): Uint8Array {
  const snapshot = validateAndCloneLoadSecurityState(state);
  const frontier = [...snapshot.frontier].sort();
  const parts: Uint8Array[] = [encodeUtf8(LOAD_SECURITY_STATE_DOMAIN)];
  parts.push(...lengthPrefixed(encodeUtf8(snapshot.documentId)));
  parts.push(...lengthPrefixed(encodeUtf8(snapshot.groupId)));
  parts.push(uint64(snapshot.epoch));
  parts.push(
    snapshot.controlHead,
    snapshot.treeHash,
    snapshot.confirmedTranscriptHash,
  );
  parts.push(uint32(frontier.length));
  for (const entry of frontier) {
    parts.push(...lengthPrefixed(encodeUtf8(entry)));
  }
  return concatenate(parts);
}

export async function loadSecurityStateHash(
  state: LoadSecurityState,
): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    encodeLoadSecurityState(state) as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(digest);
}

export function loadSecurityStateHashToHex(hash: Uint8Array): string {
  const snapshot = requireHash('load security state hash', hash);
  return Array.from(snapshot, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}
