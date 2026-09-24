import { Base64 } from 'js-base64';
import { copyUnsharedUint8Array } from './utils.js';
import {
  computeKeychainStateCommitment,
  MAX_KEYCHAIN_EPOCHS,
} from './keychain.js';
import type { KeychainAppendIntent } from './keychain.js';

const KEY_ID_LENGTH_BYTES = 32;

/** @internal Detached canonical entries shared by the CRDT adapters. */
export type CanonicalKeychainEntry = readonly [string, string];

/** @internal Captured append intent shared by the CRDT adapters. */
export type CanonicalAppendIntent = {
  readonly previousKeyId: string;
  readonly newKeyId: string;
};

function toHex(bytes: Uint8Array): string {
  const hexChars: string[] = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    hexChars[i] = bytes[i].toString(16).padStart(2, '0');
  }
  return hexChars.join('');
}

function keyIdToCacheKey(keyIDBytes: Uint8Array): string {
  return toHex(
    copyUnsharedUint8Array(
      keyIDBytes,
      KEY_ID_LENGTH_BYTES,
      KEY_ID_LENGTH_BYTES,
      'Key ID',
    ),
  );
}

function cacheKeyToKeyId(cacheKey: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(cacheKey)) {
    throw new Error(
      'Invalid keychain key ID: expected 64 lowercase hex characters',
    );
  }
  const bytes = new Uint8Array(KEY_ID_LENGTH_BYTES);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cacheKey.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function assertAesGcmDocumentKey(key: CryptoKey): void {
  try {
    const algorithm = key.algorithm as AesKeyAlgorithm;
    if (
      key.type !== 'secret' ||
      algorithm.name !== 'AES-GCM' ||
      algorithm.length !== 256 ||
      !key.usages.includes('encrypt') ||
      !key.usages.includes('decrypt')
    ) {
      throw new Error();
    }
  } catch {
    throw new TypeError('Document key must be a 256-bit AES-GCM key');
  }
  if (!key.extractable) {
    throw new TypeError('Document key must be extractable for serialization');
  }
}

function assertSerializedDocumentKey(
  serialized: unknown,
): asserts serialized is string {
  if (
    typeof serialized !== 'string' ||
    !/^[A-Za-z0-9+/]{43}=$/.test(serialized)
  ) {
    throw new Error('Invalid serialized keychain key');
  }
  let raw: Uint8Array;
  try {
    raw = Base64.toUint8Array(serialized);
  } catch {
    throw new Error('Invalid serialized keychain key');
  }
  if (raw.byteLength !== 32 || Base64.fromUint8Array(raw) !== serialized) {
    throw new Error('Invalid serialized keychain key');
  }
}

function assertCanonicalKeychainEntry(
  entry: unknown,
): asserts entry is [string, string] {
  if (
    !Array.isArray(entry) ||
    entry.length !== 2 ||
    typeof entry[0] !== 'string' ||
    typeof entry[1] !== 'string' ||
    !/^[0-9a-f]{64}$/.test(entry[0])
  ) {
    throw new Error('Invalid keychain entry');
  }
  assertSerializedDocumentKey(entry[1]);
}

function validateCanonicalKeychainEntries(
  entries: readonly unknown[],
): CanonicalKeychainEntry[] {
  if (entries.length > MAX_KEYCHAIN_EPOCHS) {
    throw new Error('Keychain exceeds the supported epoch limit');
  }
  const result: CanonicalKeychainEntry[] = [];
  const ids = new Set<string>();
  for (const entry of entries) {
    assertCanonicalKeychainEntry(entry);
    if (ids.has(entry[0])) {
      throw new Error('Duplicate keychain key ID');
    }
    ids.add(entry[0]);
    result.push([entry[0], entry[1]]);
  }
  return result;
}

function sameKeychainEntry(
  left: CanonicalKeychainEntry,
  right: CanonicalKeychainEntry,
): boolean {
  return left[0] === right[0] && left[1] === right[1];
}

function assertAppendOnlyTransition(
  before: readonly CanonicalKeychainEntry[],
  after: readonly CanonicalKeychainEntry[],
): void {
  if (after.length < before.length) {
    throw new Error('Keychain merge must preserve existing entries');
  }
  for (let index = 0; index < before.length; index++) {
    if (!sameKeychainEntry(before[index], after[index])) {
      throw new Error('Keychain merge must append without rewriting entries');
    }
  }
}

function isKeychainPrefix(
  prefix: readonly CanonicalKeychainEntry[],
  entries: readonly CanonicalKeychainEntry[],
): boolean {
  return (
    prefix.length <= entries.length &&
    prefix.every((entry, index) => sameKeychainEntry(entry, entries[index]))
  );
}

function snapshotAppendIntent(
  intent: KeychainAppendIntent,
): CanonicalAppendIntent {
  if (typeof intent !== 'object' || intent === null) {
    throw new TypeError('Keychain append intent must be an object');
  }
  return {
    previousKeyId: keyIdToCacheKey(intent.expectedPreviousKeyId),
    newKeyId: keyIdToCacheKey(intent.expectedNewKeyId),
  };
}

function stateCommitment(
  entries: readonly CanonicalKeychainEntry[],
): Promise<Uint8Array> {
  return computeKeychainStateCommitment(
    entries.map(([keyId, serialized]) => [
      cacheKeyToKeyId(keyId),
      Base64.toUint8Array(serialized),
    ]),
  );
}

/** @internal Canonical validation shared by the CRDT adapters. */
export const canonicalKeychain = Object.freeze({
  toHex,
  keyIdToCacheKey,
  cacheKeyToKeyId,
  assertAesGcmDocumentKey,
  assertSerializedDocumentKey,
  assertCanonicalKeychainEntry,
  validateCanonicalKeychainEntries,
  sameKeychainEntry,
  assertAppendOnlyTransition,
  isKeychainPrefix,
  snapshotAppendIntent,
  stateCommitment,
});
