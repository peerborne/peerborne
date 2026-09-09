import { copyUnsharedUint8Array } from './utils.js';

const LOAD_SECURITY_STATE_DOMAIN = 'peerborne/load-security-state/v1\0';

export const LOAD_SECURITY_STATE_VERSION = 1 as const;
export const LOAD_SECURITY_HASH_LENGTH = 32;
export const MAX_LOAD_SECURITY_GROUP_ID_BYTES = 1024;
export const MAX_LOAD_SECURITY_DOCUMENT_ID_BYTES = 4096;
export const MAX_LOAD_SECURITY_FRONTIER_ENTRIES = 4096;
export const MAX_LOAD_SECURITY_FRONTIER_ENTRY_BYTES = 1024;
export const MAX_LOAD_SECURITY_EPOCH = (1n << 64n) - 1n;

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
  if (commitments === null || typeof commitments !== 'object') {
    throw new TypeError('load security commitments must be an object');
  }
  if (commitments.version !== LOAD_SECURITY_STATE_VERSION) {
    throw new RangeError(`unsupported load security version: ${String(commitments.version)}`);
  }
  requireHash('controlHead', commitments.controlHead);
  requirePlainString(
    'groupId',
    commitments.groupId,
    MAX_LOAD_SECURITY_GROUP_ID_BYTES,
  );
  if (
    typeof commitments.epoch !== 'bigint' ||
    commitments.epoch < 0n ||
    commitments.epoch > MAX_LOAD_SECURITY_EPOCH
  ) {
    throw new RangeError('epoch must be an unsigned 64-bit bigint');
  }
  requireHash('treeHash', commitments.treeHash);
  requireHash('confirmedTranscriptHash', commitments.confirmedTranscriptHash);
}

/** Return a defensive byte-for-byte copy of a validated commitment tuple. */
export function cloneLoadSecurityCommitments(
  commitments: LoadSecurityCommitments,
): LoadSecurityCommitments {
  validateLoadSecurityCommitments(commitments);
  return {
    ...commitments,
    controlHead: requireHash('controlHead', commitments.controlHead),
    treeHash: requireHash('treeHash', commitments.treeHash),
    confirmedTranscriptHash: requireHash(
      'confirmedTranscriptHash',
      commitments.confirmedTranscriptHash,
    ),
  };
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
  let trustedControlHead: Uint8Array;
  let trustedTreeHash: Uint8Array;
  let trustedTranscriptHash: Uint8Array;
  let candidateControlHead: Uint8Array;
  let candidateTreeHash: Uint8Array;
  let candidateTranscriptHash: Uint8Array;
  try {
    validateLoadSecurityCommitments(trusted);
    validateLoadSecurityCommitments(candidate);
    trustedControlHead = requireHash('controlHead', trusted.controlHead);
    trustedTreeHash = requireHash('treeHash', trusted.treeHash);
    trustedTranscriptHash = requireHash(
      'confirmedTranscriptHash',
      trusted.confirmedTranscriptHash,
    );
    candidateControlHead = requireHash('controlHead', candidate.controlHead);
    candidateTreeHash = requireHash('treeHash', candidate.treeHash);
    candidateTranscriptHash = requireHash(
      'confirmedTranscriptHash',
      candidate.confirmedTranscriptHash,
    );
  } catch {
    return false;
  }

  let difference = 0;
  difference |= Number(trusted.version !== candidate.version);
  difference |= Number(trusted.groupId !== candidate.groupId);
  difference |= Number(trusted.epoch !== candidate.epoch);
  for (let index = 0; index < LOAD_SECURITY_HASH_LENGTH; index++) {
    difference |= trustedControlHead[index] ^ candidateControlHead[index];
    difference |= trustedTreeHash[index] ^ candidateTreeHash[index];
    difference |=
      trustedTranscriptHash[index] ^ candidateTranscriptHash[index];
  }
  return difference === 0;
}

export function validateLoadSecurityState(state: LoadSecurityState): void {
  validateLoadSecurityCommitments(state);
  requirePlainString(
    'documentId',
    state.documentId,
    MAX_LOAD_SECURITY_DOCUMENT_ID_BYTES,
  );
  if (!Array.isArray(state.frontier)) {
    throw new TypeError('frontier must be an array of CID strings');
  }
  if (state.frontier.length > MAX_LOAD_SECURITY_FRONTIER_ENTRIES) {
    throw new RangeError(
      `frontier exceeds ${MAX_LOAD_SECURITY_FRONTIER_ENTRIES} entries`,
    );
  }
  const seen = new Set<string>();
  for (const entry of state.frontier) {
    requirePlainString(
      'frontier entry',
      entry,
      MAX_LOAD_SECURITY_FRONTIER_ENTRY_BYTES,
    );
    if (seen.has(entry)) {
      throw new Error(`frontier contains duplicate entry: ${entry}`);
    }
    seen.add(entry);
  }
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
  validateLoadSecurityState(state);
  const controlHead = requireHash('controlHead', state.controlHead);
  const treeHash = requireHash('treeHash', state.treeHash);
  const confirmedTranscriptHash = requireHash(
    'confirmedTranscriptHash',
    state.confirmedTranscriptHash,
  );
  const frontier = [...state.frontier].sort();
  const parts: Uint8Array[] = [encodeUtf8(LOAD_SECURITY_STATE_DOMAIN)];
  parts.push(...lengthPrefixed(encodeUtf8(state.documentId)));
  parts.push(...lengthPrefixed(encodeUtf8(state.groupId)));
  parts.push(uint64(state.epoch));
  parts.push(controlHead, treeHash, confirmedTranscriptHash);
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
