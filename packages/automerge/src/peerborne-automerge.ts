import {
  Doc,
  init,
  change,
  clone,
  decodeChange,
  getChanges,
  getConflicts,
  applyChanges,
  getMissingDeps,
  Change as BinaryChange,
  getAllChanges,
  save,
  load,
  merge,
} from '@automerge/automerge';

import {
  ACL,
  ACLProvider,
  PeerborneDocumentChangeHandler,
  CRDTChangeBlock,
  CRDTChangeNodeWire,
  CRDTProvider,
  CRDTSyncMessage,
  describeValue,
  deserializeChangeNodeFromJSON,
  deserializeInitialLoadChallengeFromWire,
  INITIAL_INVITATION_CAPACITY_PROFILE,
  deserializeLoadSecurityCommitmentsFromWire,
  JSONSerializer,
  Keychain,
  KeychainAppendIntent,
  PreparedKeychainAddition,
  PreparedKeychainEpoch,
  PreparedKeychainMerge,
  KeychainProvider,
  LRUCache,
  MAX_KEYCHAIN_EPOCHS,
  computeKeychainStateCommitment,
  copyUnsharedUint8Array,
  serializeChangeNodeForJSON,
  serializeInitialLoadChallengeForWire,
  serializeLoadSecurityCommitmentsForWire,
  TIPS_HASH_LENGTH,
} from '@peerborne/core';
import { validateChangeBlockMetadata } from '@peerborne/core';
import { Base64 } from 'js-base64';

export type AutomergeDocumentChangeHandler<T = any> =
  PeerborneDocumentChangeHandler<Doc<T>, CryptoKey>;

export class AutomergeProvider<T = any>
  implements CRDTProvider<Doc<T>, BinaryChange[], (doc: T) => void>
{
  readonly initialInvitationCapacityProfile =
    INITIAL_INVITATION_CAPACITY_PROFILE;

  newDocument(): Doc<T> {
    return init();
  }
  localChange(
    document: Doc<T>,
    message: string,
    changeFn: (doc: T) => void,
  ): [Doc<T>, BinaryChange[]] {
    const newDocument = message
      ? change(document, message, changeFn)
      : change(document, changeFn);
    const changes = getChanges(document, newDocument);
    return [newDocument, changes];
  }
  remoteChange(document: Doc<T>, changes: BinaryChange[]): Doc<T> {
    const [newDoc] = applyChanges(document, changes);
    return newDoc;
  }
  getHistory(document: Doc<T>): BinaryChange[] {
    return getAllChanges(document);
  }
  getSnapshot(document: Doc<T>): BinaryChange[] {
    // Automerge.save() produces a single compact binary blob containing
    // the full document state. This is much smaller than getAllChanges()
    // which returns every individual change. The save format is NOT
    // compatible with applyChanges(), so applySnapshot() must be used.
    return [save(document) as unknown as BinaryChange];
  }
  applySnapshot(document: Doc<T>, snapshot: BinaryChange[]): Doc<T> {
    // snapshot is [save(doc)] -- a single-element array containing a save buffer.
    // Load it into a new document and merge with the current one to preserve
    // any concurrent changes not included in the snapshot.
    const loaded = load<T>(snapshot[0] as unknown as Uint8Array);
    return merge(document, loaded);
  }
}

export async function serializeKey(publicKey: CryptoKey): Promise<string> {
  const buf = await crypto.subtle.exportKey('raw', publicKey);
  return Base64.fromUint8Array(new Uint8Array(buf));
}

export function deserializeKey(
  algorithm:
    | AlgorithmIdentifier
    | RsaHashedImportParams
    | EcKeyImportParams
    | HmacImportParams
    | AesKeyAlgorithm,
  keyUsages: KeyUsage[],
): (publicKey: string) => Promise<CryptoKey> {
  return (publicKey: string) => {
    const bytes = Base64.toUint8Array(publicKey);
    // Cast needed: Uint8Array<ArrayBufferLike> does not satisfy BufferSource (excludes SharedArrayBuffer)
    return crypto.subtle.importKey(
      'raw',
      bytes as Uint8Array<ArrayBuffer>,
      algorithm,
      true,
      keyUsages,
    );
  };
}

export type AutomergeACLDoc = Doc<{
  users?: { [hash: string]: true };
}>;

export class AutomergeACL implements ACL<BinaryChange[], CryptoKey> {
  // Start without a local `users` root. The first add creates the map and its
  // membership in one self-contained Automerge change, while complete ACL
  // histories produced by older random-seed releases apply without a
  // competing root assignment.
  private _acl: AutomergeACLDoc = init();
  private readonly _keyCache = new LRUCache<string, CryptoKey>(1000);

  private _assertComplete(operation: string): void {
    if (getMissingDeps(this._acl, []).length > 0) {
      throw new Error(
        `Cannot ${operation}: Automerge ACL has unresolved change ` +
          'dependencies. Replay the complete ACL history; legacy incremental ' +
          'ACL changes that omitted their random seed cannot be migrated safely.',
      );
    }
  }

  async add(publicKey: CryptoKey): Promise<BinaryChange[]> {
    this._assertComplete('add an ACL member');
    const hash = await serializeKey(publicKey);
    const aclNew = change(this._acl, (doc) => {
      if (!doc.users) {
        doc.users = {};
      }
      doc.users[hash] = true;
    });
    const aclChanges = getChanges(this._acl, aclNew);
    this._acl = aclNew;
    return aclChanges;
  }
  async remove(publicKey: CryptoKey): Promise<BinaryChange[]> {
    this._assertComplete('remove an ACL member');
    if (!this._acl.users) {
      return [];
    }
    const hash = await serializeKey(publicKey);
    const aclNew = change(this._acl, (doc) => {
      if (doc.users?.[hash] !== undefined) {
        delete doc.users[hash];
      }
    });
    const aclChanges = getChanges(this._acl, aclNew);
    this._acl = aclNew;
    return aclChanges;
  }
  current(): BinaryChange[] {
    this._assertComplete('read the current ACL history');
    return getAllChanges(this._acl);
  }
  merge(change: BinaryChange[]): void {
    const [doc] = applyChanges(this._acl, change);
    this._acl = doc;
  }
  // AutomergeACL uses binary access control (user is either in the list or not).
  // The capability parameter is accepted for interface compatibility but ignored here;
  // capability-based filtering is handled at the UCANACL wrapper level.
  async check(publicKey: CryptoKey, capability?: string): Promise<boolean> {
    this._assertComplete('check ACL membership');
    const hash = await serializeKey(publicKey);
    return this._acl.users?.[hash] !== undefined;
  }
  // The capability parameter is accepted for interface compatibility but ignored here;
  // capability-based filtering is handled at the UCANACL wrapper level.
  async users(capability?: string): Promise<CryptoKey[]> {
    this._assertComplete('list ACL members');
    // Parallel deserialization for cold cache performance.
    // Create importer once to avoid per-miss closure allocation.
    const importKey = deserializeKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      ['verify'],
    );
    const entries = Object.keys(this._acl.users ?? {});
    return Promise.all(
      entries.map(async (serializedKey) => {
        let key = this._keyCache.get(serializedKey);
        if (!key) {
          key = await importKey(serializedKey);
          this._keyCache.set(serializedKey, key);
        }
        return key;
      }),
    );
  }
}

export class AutomergeACLProvider
  implements ACLProvider<BinaryChange[], CryptoKey>
{
  readonly initialInvitationCapacityProfile =
    INITIAL_INVITATION_CAPACITY_PROFILE;

  initialize(): AutomergeACL {
    return new AutomergeACL();
  }
}

export type AutomergeKeychainDoc = Doc<{
  keys: [string, string][];
}>;

const KEY_ID_LENGTH_BYTES = 32;
const MAX_KEYCHAIN_CHANGE_BYTES = 10 * 1024 * 1024;

/**
 * Convert a Uint8Array to a lowercase hex string for use as a cache key.
 */
function toHex(bytes: Uint8Array): string {
  const hexChars: string[] = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    hexChars[i] = bytes[i].toString(16).padStart(2, '0');
  }
  return hexChars.join('');
}

/**
 * Convert any key ID (random or HKDF-derived, any byte length) to a cache
 * key string.
 *
 * Uniform lowercase-hex encoding regardless of byte length. Earlier
 * revisions special-cased 16-byte IDs through `uuid.stringify` (producing
 * a dashed-UUID string) on the assumption that 16-byte IDs were always
 * UUIDs. That assumption broke once BeeKEM epoch IDs (originally 32
 * bytes from `deriveEpochIdFromRootSecret`) were truncated to the
 * `keyIDLength` width for wire framing: the truncated 16-byte epoch
 * prefix would be stored under hex (via `addEpochKey`) but looked up
 * under the UUID format (via `getKey`), causing a deterministic cache
 * miss on every PathUpdate-derived key.
 *
 * Hex-only avoids the conflation entirely. The keychain's wire-format
 * key-ID width is now `keyIDLength = 32`, so both UUID-based `add()`
 * outputs and BeeKEM-derived epoch IDs share the same byte length and
 * round-trip through this function without any special casing.
 */
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

/**
 * Parse a cache key string back to a Uint8Array key ID. The keychain
 * stores cache keys exclusively in lowercase hex (see
 * {@link keyIdToCacheKey}), so this only needs to decode hex.
 *
 * @throws {Error} If the cache key is not a canonical lowercase 32-byte ID.
 */
function cacheKeyToKeyId(cacheKey: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(cacheKey)) {
    throw new Error('Invalid keychain key ID');
  }
  const bytes = new Uint8Array(KEY_ID_LENGTH_BYTES);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cacheKey.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Deterministic Automerge actor used only for the *seed* change that
 * initializes the empty `keys: []` array in every keychain document.
 *
 * Automerge resolves conflicting writes on a root array by actor ID; if
 * every keychain instance (source and receiver) seeds the empty array
 * with the same actor and timestamp, the seed op is byte-identical and
 * merges cleanly.
 * Subsequent per-instance writes happen under a fresh random actor (via
 * `clone()`) so two keychains can independently append keys without
 * colliding op IDs.
 *
 * The value here is arbitrary but must be a valid Automerge actor (hex
 * string, even length, 1..64 bytes). It is *not* a security boundary —
 * peers do not trust each other's actor IDs.
 */
const KEYCHAIN_SEED_ACTOR = 'ababababababababababababababababababababab';

/**
 * Build a fresh keychain document. The seed change (creating the empty
 * `keys` array) is written under {@link KEYCHAIN_SEED_ACTOR} so it is
 * identical across all keychain instances; the returned document then
 * uses a random per-instance actor for any subsequent changes. Shared seed
 * operations let actual keychain histories merge without a root-array actor
 * conflict; filtered exports must still preserve their existing operation IDs.
 */
function newKeychainDoc(): AutomergeKeychainDoc {
  const seeded = change(
    init<{ keys: [string, string][] }>(KEYCHAIN_SEED_ACTOR),
    { time: 0 },
    (doc) => {
      doc.keys = [];
    },
  );
  // clone() with no actor argument assigns a random per-instance actor.
  return clone(seeded);
}

type CanonicalKeychainEntry = readonly [string, string];

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
  if (
    raw.byteLength !== 32 ||
    Base64.fromUint8Array(raw) !== serialized
  ) {
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

type CanonicalAppendIntent = {
  readonly previousKeyId: string;
  readonly newKeyId: string;
};

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

function automergeKeychainStateCommitment(
  entries: readonly CanonicalKeychainEntry[],
): Promise<Uint8Array> {
  return computeKeychainStateCommitment(
    entries.map(([keyId, serialized]) => [
      cacheKeyToKeyId(keyId),
      Base64.toUint8Array(serialized),
    ]),
  );
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index++) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const sharedLength = Math.min(left.byteLength, right.byteLength);
  for (let index = 0; index < sharedLength; index++) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.byteLength - right.byteLength;
}

function compareAutomergeHistories(
  left: AutomergeKeychainDoc,
  right: AutomergeKeychainDoc,
): number {
  const leftHistory = getAllChanges(left);
  const rightHistory = getAllChanges(right);
  const sharedLength = Math.min(leftHistory.length, rightHistory.length);
  for (let index = 0; index < sharedLength; index++) {
    const comparison = compareBytes(leftHistory[index], rightHistory[index]);
    if (comparison !== 0) return comparison;
  }
  return leftHistory.length - rightHistory.length;
}

function sameAutomergeHistory(
  changes: readonly Uint8Array[],
  doc: AutomergeKeychainDoc,
): boolean {
  const history = getAllChanges(doc);
  return (
    changes.length === history.length &&
    changes.every((binaryChange, index) =>
      sameBytes(binaryChange, history[index]),
    )
  );
}

function assertNoAutomergeConflicts(
  doc: AutomergeKeychainDoc,
  entries: readonly CanonicalKeychainEntry[],
): void {
  if (getConflicts(doc, 'keys') !== undefined) {
    throw new Error('Keychain history contains conflicting operations');
  }
  for (let index = 0; index < entries.length; index++) {
    if (
      getConflicts(doc.keys, index) !== undefined ||
      getConflicts(doc.keys[index], 0) !== undefined ||
      getConflicts(doc.keys[index], 1) !== undefined
    ) {
      throw new Error('Keychain history contains conflicting operations');
    }
  }
}

type DecodedAutomergeChange = ReturnType<typeof decodeChange>;
type DecodedAutomergeSequenceOperation =
  DecodedAutomergeChange['ops'][number] & {
    readonly elemId?: unknown;
    readonly insert?: unknown;
  };

function automergeOperationId(
  decoded: DecodedAutomergeChange,
  operationIndex: number,
): string {
  return `${decoded.startOp + operationIndex}@${decoded.actor}`;
}

function decodeCanonicalAutomergeAppend(
  decoded: DecodedAutomergeChange,
  expectedPreviousElementId: string,
): { readonly entry: CanonicalKeychainEntry; readonly elementId: string } {
  if (decoded.message !== null || decoded.ops.length !== 111) {
    throw new Error(
      'Keychain history contains unrelated metadata or operations',
    );
  }
  const tuple = decoded.ops[0] as DecodedAutomergeSequenceOperation;
  const idText = decoded.ops[1] as DecodedAutomergeSequenceOperation;
  const keyText = decoded.ops[2] as DecodedAutomergeSequenceOperation;
  const tupleId = automergeOperationId(decoded, 0);
  const idTextId = automergeOperationId(decoded, 1);
  const keyTextId = automergeOperationId(decoded, 2);
  if (
    tuple.action !== 'makeList' ||
    tuple.obj !== `1@${KEYCHAIN_SEED_ACTOR}` ||
    tuple.elemId !== expectedPreviousElementId ||
    tuple.insert !== true ||
    tuple.pred.length !== 0 ||
    idText.action !== 'makeText' ||
    idText.obj !== tupleId ||
    idText.elemId !== '_head' ||
    idText.insert !== true ||
    idText.pred.length !== 0 ||
    keyText.action !== 'makeText' ||
    keyText.obj !== tupleId ||
    keyText.elemId !== idTextId ||
    keyText.insert !== true ||
    keyText.pred.length !== 0
  ) {
    throw new Error('Keychain history contains a non-append operation');
  }

  const readText = (startIndex: number, length: number, objectId: string) => {
    let result = '';
    let previousElementId = '_head';
    for (let offset = 0; offset < length; offset++) {
      const operationIndex = startIndex + offset;
      const operation = decoded.ops[
        operationIndex
      ] as DecodedAutomergeSequenceOperation;
      if (
        operation.action !== 'set' ||
        operation.obj !== objectId ||
        operation.elemId !== previousElementId ||
        operation.insert !== true ||
        operation.pred.length !== 0 ||
        typeof operation.value !== 'string' ||
        operation.value.length !== 1
      ) {
        throw new Error('Keychain history contains a non-append operation');
      }
      result += operation.value;
      previousElementId = automergeOperationId(decoded, operationIndex);
    }
    return result;
  };

  const entry: CanonicalKeychainEntry = [
    readText(3, 64, idTextId),
    readText(67, 44, keyTextId),
  ];
  assertCanonicalKeychainEntry(entry);
  return { entry, elementId: tupleId };
}

/**
 * Replay and validate the complete operation history. Visible-state checks
 * alone would permit tombstoned key material, concurrent/non-append branches,
 * or unrelated edits to escape in a later full-history projection.
 */
function validateAutomergeKeychain(
  doc: AutomergeKeychainDoc,
): CanonicalKeychainEntry[] {
  if (
    getMissingDeps(doc, []).length !== 0 ||
    Object.keys(doc).length !== 1 ||
    Object.keys(doc)[0] !== 'keys' ||
    !Array.isArray(doc.keys)
  ) {
    throw new Error('Invalid Automerge keychain document');
  }

  const visibleEntries = validateCanonicalKeychainEntries(doc.keys);
  assertNoAutomergeConflicts(doc, visibleEntries);
  const history = getAllChanges(doc);
  const expectedSeed = getAllChanges(newKeychainDoc())[0];
  if (history.length === 0 || !sameBytes(history[0], expectedSeed)) {
    throw new Error('Invalid Automerge keychain seed');
  }

  const retainedEntries: CanonicalKeychainEntry[] = [];
  let previousElementId = '_head';
  let previousChangeHash: string | undefined;
  for (let index = 0; index < history.length; index++) {
    const binaryChange = history[index];
    const decoded = decodeChange(binaryChange);
    if (index === 0) {
      if (decoded.ops.length !== 1 || decoded.ops[0].action !== 'makeList') {
        throw new Error('Invalid Automerge keychain seed');
      }
    } else {
      if (
        previousChangeHash === undefined ||
        decoded.deps.length !== 1 ||
        decoded.deps[0] !== previousChangeHash
      ) {
        throw new Error('Keychain history is not a linear append sequence');
      }
      const append = decodeCanonicalAutomergeAppend(
        decoded,
        previousElementId,
      );
      retainedEntries.push(append.entry);
      previousElementId = append.elementId;
    }
    previousChangeHash = decoded.hash;
  }

  validateCanonicalKeychainEntries(retainedEntries);
  if (
    visibleEntries.length !== retainedEntries.length ||
    visibleEntries.some(
      (entry, index) => !sameKeychainEntry(entry, retainedEntries[index]),
    )
  ) {
    throw new Error('Automerge keychain history does not match visible state');
  }
  return visibleEntries;
}

/**
 * BREAKING CHANGE: keychain key-ID width is unified to 32 bytes.
 *
 * The keychain now uses 32-byte IDs uniformly for BOTH locally-generated
 * keys (formerly 16-byte UUIDs via `uuid.v4`) and BeeKEM-derived epoch
 * keys (already 32 bytes via `deriveEpochIdFromRootSecret`). The wire-
 * format key-ID prefix, the BeeKEM `pathUpdateEpochId`, and the
 * keychain's storage key are all the same 32 bytes -- no truncation
 * step exists.
 *
 * This is an **intentional, on-disk-breaking change** from earlier
 * shipped revisions of this library, which used 16-byte UUIDs. The project
 * is alpha-only and no migration shim is provided. Any
 * document state persisted with the old 16-byte UUID format will fail
 * to load against this version because `cacheKeyToKeyId` only accepts
 * 64-character lowercase hex (no UUID/dashed format), and existing 16-byte
 * key IDs would be looked up under a different cache-key format than
 * they were stored under.
 *
 * Persisted deployments require a fresh document or a separately reviewed
 * migration; ordinary document load is not a keychain/ratchet migration
 * mechanism.
 */
export class AutomergeKeychain implements Keychain<BinaryChange[], CryptoKey> {
  private readonly _keyCache = new LRUCache<string, CryptoKey>(
    MAX_KEYCHAIN_EPOCHS,
  );
  private _keychain: AutomergeKeychainDoc = newKeychainDoc();
  private _revision = 0;

  async add(): Promise<[Uint8Array, CryptoKey, BinaryChange[]]> {
    const prepared = await this.prepareKey();
    prepared.commit();
    return [new Uint8Array(prepared.keyId), prepared.key, prepared.changes];
  }

  async prepareKey(): Promise<
    PreparedKeychainAddition<BinaryChange[], CryptoKey>
  > {
    if (
      validateAutomergeKeychain(this._keychain).length ===
      MAX_KEYCHAIN_EPOCHS
    ) {
      throw new Error('Keychain exceeds the supported epoch limit');
    }
    // 32 random bytes match the width used by BeeKEM-derived epoch IDs
    // (`deriveEpochIdFromRootSecret`), so the wire-format key-ID prefix
    // is a single fixed width regardless of how the key was provisioned.
    // Earlier revisions used a 16-byte UUID here, but that required the
    // PathUpdate handler to truncate 32-byte BeeKEM epoch IDs down to 16
    // bytes on install -- producing a deterministic cache-key-format
    // mismatch with `getKey` (stored under hex, looked up under UUID
    // format). Removing the size asymmetry removes the need for the
    // truncation in the first place.
    const keyIDBytes = crypto.getRandomValues(
      new Uint8Array(KEY_ID_LENGTH_BYTES),
    );
    const key = await crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256,
      },
      true,
      ['encrypt', 'decrypt'],
    );

    const prepared = await this.prepareEpochKey(keyIDBytes, key);
    return {
      ...prepared,
      keyId: new Uint8Array(keyIDBytes),
      key,
    };
  }

  /**
   * Add an epoch-based encryption key to the keychain.
   *
   * Epoch keys are used for key rotation: each epoch has a unique 32-byte ID
   * and an associated AES-GCM symmetric key. The key is cached locally and
   * appended to the Automerge keychain document for synchronization with peers.
   *
   * @param epochId - The 32-byte epoch identifier.
   * @param key - The AES-GCM CryptoKey for this epoch.
   * @returns The Automerge changes representing the keychain update for broadcasting.
   */
  async addEpochKey(
    epochId: Uint8Array,
    key: CryptoKey,
  ): Promise<BinaryChange[]> {
    const prepared = await this.prepareEpochKey(epochId, key);
    prepared.commit();
    return prepared.changes;
  }

  async prepareEpochKey(
    epochId: Uint8Array,
    key: CryptoKey,
  ): Promise<PreparedKeychainEpoch<BinaryChange[]>> {
    const stableEpochId = copyUnsharedUint8Array(
      epochId,
      KEY_ID_LENGTH_BYTES,
      KEY_ID_LENGTH_BYTES,
      'Epoch ID',
    );
    const epochIdHex = toHex(stableEpochId);
    assertAesGcmDocumentKey(key);
    const serialized = await serializeKey(key);
    assertSerializedDocumentKey(serialized);
    const base = this._keychain;
    const baseRevision = this._revision;
    const baseEntries = validateAutomergeKeychain(base);
    if (baseEntries.length === MAX_KEYCHAIN_EPOCHS) {
      throw new Error('Keychain exceeds the supported epoch limit');
    }
    if (baseEntries.some(([keyID]) => keyID === epochIdHex)) {
      throw new Error('Duplicate keychain key ID');
    }
    const keychainNew = change(clone(base), (doc) => {
      doc.keys.push([epochIdHex, serialized]);
    });
    const stagedEntries = validateAutomergeKeychain(keychainNew);
    assertAppendOnlyTransition(baseEntries, stagedEntries);
    const changes = getChanges(base, keychainNew);
    const history = getAllChanges(keychainNew);
    // This exact projection is safe to cache and replay because retries reuse
    // its existing actor operation. It must not be regenerated later from a
    // multi-key live history under a fresh actor.
    const projectionBase = newKeychainDoc();
    const projection = change(projectionBase, (doc) => {
      doc.keys.push([epochIdHex, serialized]);
    });
    validateAutomergeKeychain(projection);
    const currentKeyChange = getAllChanges(projection);
    let committed = false;
    return {
      changes: changes.map(
        (binaryChange) => new Uint8Array(binaryChange) as BinaryChange,
      ),
      history: history.map(
        (binaryChange) => new Uint8Array(binaryChange) as BinaryChange,
      ),
      currentKeyChange: currentKeyChange.map(
        (binaryChange) => new Uint8Array(binaryChange) as BinaryChange,
      ),
      commit: () => {
        if (committed) {
          throw new Error('Prepared epoch key was already committed');
        }
        if (this._keychain !== base || this._revision !== baseRevision) {
          throw new Error('Keychain changed while epoch key was staged');
        }
        this._keyCache.set(epochIdHex, key);
        this._keychain = keychainNew;
        this._revision++;
        committed = true;
      },
    };
  }

  history(): BinaryChange[] {
    validateAutomergeKeychain(this._keychain);
    return getAllChanges(this._keychain);
  }
  async stateCommitment(): Promise<Uint8Array> {
    return await automergeKeychainStateCommitment(
      validateAutomergeKeychain(this._keychain),
    );
  }
  merge(change: BinaryChange[]): void {
    this.prepareMerge(change).commit();
  }

  prepareMerge(
    changes: BinaryChange[],
  ): PreparedKeychainMerge<BinaryChange[], CryptoKey> {
    return this._prepareMerge(changes);
  }

  prepareAppend(
    changes: BinaryChange[],
    intent: KeychainAppendIntent,
  ): PreparedKeychainMerge<BinaryChange[], CryptoKey> {
    return this._prepareMerge(changes, snapshotAppendIntent(intent));
  }

  private _prepareMerge(
    changes: BinaryChange[],
    stableAppendIntent?: CanonicalAppendIntent,
  ): PreparedKeychainMerge<BinaryChange[], CryptoKey> {
    if (!Array.isArray(changes)) {
      throw new TypeError('Automerge keychain changes must be an array');
    }
    const changeCount = changes.length;
    if (!Number.isSafeInteger(changeCount) || changeCount < 0) {
      throw new TypeError('Invalid Automerge keychain change count');
    }
    if (changeCount > MAX_KEYCHAIN_EPOCHS + 1) {
      throw new Error('Too many Automerge keychain changes');
    }
    const base = this._keychain;
    const baseRevision = this._revision;
    const baseEntries = validateAutomergeKeychain(base);
    const stableChanges: BinaryChange[] = [];
    let totalChangeBytes = 0;
    for (let index = 0; index < changeCount; index++) {
      const binaryChange = changes[index];
      const stableChange = copyUnsharedUint8Array(
        binaryChange,
        1,
        MAX_KEYCHAIN_CHANGE_BYTES,
        'Automerge keychain change',
      );
      totalChangeBytes += stableChange.byteLength;
      if (totalChangeBytes > MAX_KEYCHAIN_CHANGE_BYTES) {
        throw new Error('Automerge keychain changes exceed the size limit');
      }
      stableChanges.push(stableChange as BinaryChange);
    }
    let merged: AutomergeKeychainDoc | undefined;
    let stagedEntries: CanonicalKeychainEntry[] | undefined;

    // Independently authored, byte-identical epoch tuples may have different
    // Automerge actor operations. Select one complete canonical lineage when
    // its logical history is an exact prefix/superset instead of retaining two
    // copies of the same key material.
    let incoming: AutomergeKeychainDoc | undefined;
    let incomingEntries: CanonicalKeychainEntry[] | undefined;
    try {
      [incoming] = applyChanges(newKeychainDoc(), stableChanges);
      incomingEntries = validateAutomergeKeychain(incoming);
    } catch {
      incoming = undefined;
      incomingEntries = undefined;
    }
    if (stableAppendIntent !== undefined) {
      if (
        !incoming ||
        !incomingEntries ||
        incomingEntries.length !== 1 ||
        !sameAutomergeHistory(stableChanges, incoming)
      ) {
        throw new Error(
          'Keychain append intent requires a canonical standalone single-key projection',
        );
      }
      const projected = incomingEntries[0];
      if (projected[0] !== stableAppendIntent.newKeyId) {
        throw new Error('Keychain projection does not match expected new key');
      }
      const current = baseEntries[baseEntries.length - 1];
      if (current?.[0] === stableAppendIntent.newKeyId) {
        const previous = baseEntries[baseEntries.length - 2];
        if (
          !sameKeychainEntry(current, projected) ||
          previous?.[0] !== stableAppendIntent.previousKeyId
        ) {
          throw new Error('Keychain append replay does not match live history');
        }
        merged = base;
        stagedEntries = baseEntries;
      } else {
        if (current?.[0] !== stableAppendIntent.previousKeyId) {
          throw new Error(
            'Keychain append predecessor does not match current key',
          );
        }
        if (baseEntries.some(([keyID]) => keyID === projected[0])) {
          throw new Error('Keychain append would replay an older key');
        }
        merged = change(clone(base), (doc) => {
          doc.keys.push([projected[0], projected[1]]);
        });
        stagedEntries = validateAutomergeKeychain(merged);
      }
    } else if (incoming && incomingEntries) {
      const current = baseEntries[baseEntries.length - 1];
      if (
        baseEntries.length > 1 &&
        incomingEntries.length === 1 &&
        current !== undefined &&
        sameKeychainEntry(current, incomingEntries[0])
      ) {
        merged = base;
        stagedEntries = baseEntries;
      } else if (
        baseEntries.length === incomingEntries.length &&
        isKeychainPrefix(baseEntries, incomingEntries)
      ) {
        if (compareAutomergeHistories(base, incoming) <= 0) {
          merged = base;
          stagedEntries = baseEntries;
        } else {
          merged = incoming;
          stagedEntries = incomingEntries;
        }
      } else if (isKeychainPrefix(baseEntries, incomingEntries)) {
        merged = incoming;
        stagedEntries = incomingEntries;
      } else if (isKeychainPrefix(incomingEntries, baseEntries)) {
        merged = base;
        stagedEntries = baseEntries;
      } else {
        throw new Error(
          'Standalone keychain history is not an append-only view',
        );
      }
    }

    if (!merged || !stagedEntries) {
      [merged] = applyChanges(clone(base), stableChanges);
      stagedEntries = validateAutomergeKeychain(merged);
    }
    assertAppendOnlyTransition(baseEntries, stagedEntries);
    const committedKeyIds = stagedEntries.map(([keyID]) =>
      cacheKeyToKeyId(keyID),
    );
    const returnedKeyIds = committedKeyIds.map((keyID) =>
      new Uint8Array(keyID),
    );
    const currentKeyId =
      committedKeyIds.length === 0
        ? undefined
        : new Uint8Array(committedKeyIds[committedKeyIds.length - 1]);
    const stagedKeyCache = new Map<string, CryptoKey>();
    let committed = false;
    return {
      changes: stableChanges.map(
        (binaryChange) => new Uint8Array(binaryChange) as BinaryChange,
      ),
      keyIds: returnedKeyIds,
      currentKeyId,
      hydrateKeys: async () => {
        const hydrated: [Uint8Array, CryptoKey][] = [];
        for (const [keyID, serialized] of stagedEntries) {
          let key = stagedKeyCache.get(keyID);
          if (!key) {
            key = await deserializeKey({ name: 'AES-GCM', length: 256 }, [
              'encrypt',
              'decrypt',
            ])(serialized);
            stagedKeyCache.set(keyID, key);
          }
          hydrated.push([cacheKeyToKeyId(keyID), key]);
        }
        return hydrated;
      },
      getKey: (keyID: Uint8Array) =>
        stagedKeyCache.get(keyIdToCacheKey(keyID)),
      stateCommitment: async () =>
        await automergeKeychainStateCommitment(stagedEntries),
      commit: () => {
        if (committed) {
          throw new Error('Prepared keychain merge was already committed');
        }
        if (this._keychain !== base || this._revision !== baseRevision) {
          throw new Error('Keychain changed while merge was staged');
        }
        const liveCache = this._keyCache;
        for (const [keyID, key] of stagedKeyCache) {
          liveCache.set(keyID, key);
        }
        this._keychain = merged;
        this._revision++;
        committed = true;
      },
    };
  }
  async keys(): Promise<[Uint8Array, CryptoKey][]> {
    validateAutomergeKeychain(this._keychain);
    return await Promise.all(
      this._keychain.keys.map(async ([keyID, serialized]) => {
        const keyIDBytes = cacheKeyToKeyId(keyID);
        let key = this._keyCache.get(keyID);
        if (!key) {
          key = await deserializeKey({ name: 'AES-GCM', length: 256 }, [
            'encrypt',
            'decrypt',
          ])(serialized);
          this._keyCache.set(keyID, key);
        }
        return [keyIDBytes, key] as [Uint8Array, CryptoKey];
      }),
    );
  }
  async current(): Promise<[Uint8Array, CryptoKey]> {
    validateAutomergeKeychain(this._keychain);
    if (this._keychain.keys.length === 0) {
      throw new Error("Can't get an empty keychain's current value");
    }

    const [keyID, serialized] =
      this._keychain.keys[this._keychain.keys.length - 1];
    const keyIDBytes = cacheKeyToKeyId(keyID);

    let key = this._keyCache.get(keyID);
    if (!key) {
      key = await deserializeKey({ name: 'AES-GCM', length: 256 }, [
        'encrypt',
        'decrypt',
      ])(serialized);
      this._keyCache.set(keyID, key);
    }
    return [keyIDBytes, key];
  }
  async currentKeyChange(): Promise<BinaryChange[]> {
    validateAutomergeKeychain(this._keychain);
    if (this._keychain.keys.length === 0) {
      throw new Error("Can't get current key change from an empty keychain");
    }

    if (this._keychain.keys.length !== 1) {
      throw new Error(
        'Automerge cannot export the current key replay-safely',
      );
    }
    return this.history();
  }

  /**
   * Return stable existing keychain operations when the requested boundary is
   * the first retained key.
   *
   * Automerge append operations after a later boundary depend on operations
   * that contain the preceding keys. Reconstructing a minimal suffix under a
   * fresh actor would merge once, but independently regenerated responses would
   * have distinct operation IDs and duplicate entries. Reject boundaries that
   * cannot be served from existing operation history without either that replay
   * ambiguity or disclosure of pre-boundary keys.
   */
  async historySince(keyID: Uint8Array): Promise<BinaryChange[]> {
    validateAutomergeKeychain(this._keychain);
    if (this._keychain.keys.length === 0) {
      throw new Error("Can't get history-since from an empty keychain");
    }
    const cacheKey = keyIdToCacheKey(keyID);
    let startIdx = -1;
    for (let i = 0; i < this._keychain.keys.length; i++) {
      if (this._keychain.keys[i][0] !== cacheKey) continue;
      if (startIdx !== -1) {
        throw new Error('Ambiguous keychain history boundary');
      }
      startIdx = i;
    }
    if (startIdx === -1) {
      throw new Error('Unknown keychain history boundary');
    }
    if (startIdx !== 0) {
      throw new Error(
        'Automerge cannot export this keychain suffix replay-safely',
      );
    }
    return this.history();
  }
  getKey(keyIDBytes: Uint8Array): CryptoKey | undefined {
    const cacheKey = keyIdToCacheKey(keyIDBytes);
    return this._keyCache.get(cacheKey);
  }
}

export class AutomergeKeychainProvider
  implements KeychainProvider<BinaryChange[], CryptoKey>
{
  readonly initialInvitationCapacityProfile =
    INITIAL_INVITATION_CAPACITY_PROFILE;

  initialize(): AutomergeKeychain {
    return new AutomergeKeychain();
  }

  // 32 bytes: matches both `add()`'s random key-ID output and the
  // BeeKEM-derived epoch ID width from `deriveEpochIdFromRootSecret`.
  // Using one fixed width across the keychain's two key-provisioning
  // paths means the on-wire key-ID prefix never needs to be truncated;
  // truncation would break post-rotation decryption.
  readonly keyIDLength = KEY_ID_LENGTH_BYTES;
}

/**
 * Intermediate wire type for Automerge Merkle-DAG nodes where each
 * BinaryChange[] is represented as base64-encoded strings.
 */
type iCRDTChangeNode = CRDTChangeNodeWire<string[]>;

function serializeBinaryChanges(changes: BinaryChange[]): string[] {
  return changes.map((c: Uint8Array) => Base64.fromUint8Array(c));
}

function deserializeBinaryChanges(changes: string[]): BinaryChange[] {
  return changes.map((c: string) => Base64.toUint8Array(c)) as BinaryChange[];
}

export class AutomergeJSONSerializer extends JSONSerializer<
  BinaryChange[],
  CryptoKey
> {
  readonly initialInvitationCapacityProfile =
    INITIAL_INVITATION_CAPACITY_PROFILE;
  serializeChanges(changes: BinaryChange[]): Uint8Array {
    return this.encode(this.serialize(serializeBinaryChanges(changes)));
  }

  deserializeChanges(changes: Uint8Array): BinaryChange[] {
    const raw = this.deserialize(this.decode(changes));
    if (!Array.isArray(raw)) {
      throw new Error('Invalid serialized changes: expected string[]');
    }
    return deserializeBinaryChanges(raw as string[]);
  }

  serializeChangeBlock(changes: CRDTChangeBlock<BinaryChange[]>): string {
    const obj: Record<string, unknown> = {
      changes: serializeBinaryChanges(changes.changes),
      nonce: Base64.fromUint8Array(changes.nonce),
    };
    if (changes.keyID !== undefined) obj.keyID = changes.keyID;
    if (
      changes.blindIndexTokens !== undefined &&
      changes.blindIndexTokens !== null
    )
      obj.blindIndexTokens = changes.blindIndexTokens;
    return this.serialize(obj);
  }

  deserializeChangeBlock(changes: string): CRDTChangeBlock<BinaryChange[]> {
    const raw = this.deserialize(changes);
    if (
      typeof raw !== 'object' ||
      raw === null ||
      !Array.isArray((raw as Record<string, unknown>).changes) ||
      typeof (raw as Record<string, unknown>).nonce !== 'string'
    ) {
      throw new Error(
        'Invalid change block: expected {changes: string[], nonce: string}',
      );
    }
    const deserialized = raw as {
      changes: string[];
      nonce: string;
      keyID?: string;
      blindIndexTokens?: Record<string, string>;
    };
    const result: CRDTChangeBlock<BinaryChange[]> = {
      changes: deserializeBinaryChanges(deserialized.changes),
      nonce: Base64.toUint8Array(deserialized.nonce),
    };
    validateChangeBlockMetadata(deserialized, result);
    return result;
  }

  serializeSyncMessage(
    message: CRDTSyncMessage<BinaryChange[], CryptoKey>,
  ): Uint8Array {
    let snapshotForWire: any;
    if (message.snapshot) {
      snapshotForWire = { ...message.snapshot };
      // Base64-encode each BinaryChange (Uint8Array) in state for JSON safety.
      if (Array.isArray(snapshotForWire.state)) {
        snapshotForWire.state = snapshotForWire.state.map((c: Uint8Array) =>
          Base64.fromUint8Array(c),
        );
      }
      if (snapshotForWire.signature instanceof Uint8Array) {
        snapshotForWire.signature = Base64.fromUint8Array(
          snapshotForWire.signature,
        );
      }
      // Drop publicKey -- CryptoKey is not JSON-serializable and
      // snapshot verification uses writer ACL keys, not the embedded key.
      delete snapshotForWire.publicKey;
    }
    return this.encode(
      this.serializeNormalizedSyncWireValue({
        ...message,
        // Mirror the deserializer: only `undefined` skips the
        // serialization path. Any defined value flows through
        // `serializeChangeNodeForJSON` so the wire shape matches what
        // the deserializer will validate on the receiving end.
        changes:
          message.changes === undefined
            ? undefined
            : serializeChangeNodeForJSON(
                message.changes,
                serializeBinaryChanges,
              ),
        keychainChanges:
          message.keychainChanges &&
          serializeBinaryChanges(message.keychainChanges),
        welcomeEpochId:
          message.welcomeEpochId &&
          Base64.fromUint8Array(message.welcomeEpochId),
        // `welcomeRecipient` is already a string (the serialized recipient
        // public key); pass through verbatim.
        welcomeRecipient: message.welcomeRecipient,
        welcomeRecipientKemPublicKey:
          message.welcomeRecipientKemPublicKey &&
          Base64.fromUint8Array(message.welcomeRecipientKemPublicKey),
        eciesSealed:
          message.eciesSealed && Base64.fromUint8Array(message.eciesSealed),
        // BeeKEM PathUpdate v1/v2 fields. `pathUpdate` is already the
        // negotiated version's JSON-safe serialized shape; pass through
        // verbatim.
        // `pathUpdateEpochId` is a `Uint8Array`; base64-encode it.
        pathUpdate: message.pathUpdate,
        pathUpdateEpochId:
          message.pathUpdateEpochId &&
          Base64.fromUint8Array(message.pathUpdateEpochId),
        // Initial-load quorum tip-set hash (#189 §5.4.2). Base64-encoded
        // for JSON-safe transport, mirrored on the deserialize path below.
        // Only populated on tip-advertise responses.
        tipsHash: message.tipsHash && Base64.fromUint8Array(message.tipsHash),
        // Explicit tip-set advertisement populated on load responses to
        // bind the served state to the responder's frontier (see
        // `CRDTSyncMessage.tips`). Plain string[] of CIDs; passes through
        // JSON verbatim.
        tips: message.tips,
        loadSecurityState:
          message.loadSecurityState === undefined
            ? undefined
            : serializeLoadSecurityCommitmentsForWire(
                message.loadSecurityState,
              ),
        loadChallenge:
          message.loadChallenge === undefined
            ? undefined
            : serializeInitialLoadChallengeForWire(message.loadChallenge),
        snapshot: snapshotForWire,
      }),
    );
  }

  deserializeSyncMessage(
    message: Uint8Array,
  ): CRDTSyncMessage<BinaryChange[], CryptoKey> {
    const decoded = this.deserialize(this.decode(message));
    // Wire input is untrusted: a malformed peer can send `null`, an array, or
    // a primitive in place of a sync-message object. Reading properties on
    // those values would throw a bare `TypeError` (`Cannot read properties of
    // null`) that is hard to attribute back to the peer; reject up front with
    // a descriptive error instead. This also denies a trivial DoS path where
    // a peer crashes the deserializer by sending e.g. JSON `null`. Mirrors
    // the equivalent guard in `YjsJSONSerializer.deserializeSyncMessage`.
    if (
      typeof decoded !== 'object' ||
      decoded === null ||
      Array.isArray(decoded)
    ) {
      throw new Error(
        `Invalid sync message: expected a plain object (got ${describeValue(
          decoded,
        )})`,
      );
    }
    const raw = decoded as {
      documentId?: unknown;
      changeId?: unknown;
      changes?: unknown;
      keychainChanges?: unknown;
      welcomeEpochId?: unknown;
      welcomeRecipient?: unknown;
      welcomeRecipientKemPublicKey?: unknown;
      eciesSealed?: unknown;
      pathUpdate?: unknown;
      pathUpdateEpochId?: unknown;
      tipsHash?: unknown;
      tips?: unknown;
      loadSecurityState?: unknown;
      loadChallenge?: unknown;
      snapshot?: unknown;
      signature?: unknown;
    };
    // `documentId` is a required field on the wire contract. A malformed peer
    // could omit it or send a non-string value (number, object, null), which
    // would otherwise propagate as `documentId: undefined`/non-string into
    // downstream consumers that key documents by string ID. Validate up front
    // and attribute the failure back to the peer with a descriptive error.
    if (typeof raw.documentId !== 'string') {
      throw new Error(
        `Invalid sync message: 'documentId' must be a string (got ${describeValue(
          raw.documentId,
        )})`,
      );
    }
    // Validate optional scalar fields that have a fixed expected type. Skipped
    // when omitted (`undefined`) so callers can send partial sync messages.
    if (raw.changeId !== undefined && typeof raw.changeId !== 'string') {
      throw new Error(
        `Invalid sync message: 'changeId' must be a string when present (got ${describeValue(
          raw.changeId,
        )})`,
      );
    }
    if (raw.signature !== undefined && typeof raw.signature !== 'string') {
      throw new Error(
        `Invalid sync message: 'signature' must be a string when present (got ${describeValue(
          raw.signature,
        )})`,
      );
    }
    let snapshot: any;
    // Any value other than `undefined` (including `null`, `0`, `""`, etc.)
    // must be routed through the validator -- using a truthy guard like
    // `raw.snapshot && ...` would let a malformed peer message bypass the
    // object/array shape check by sending e.g. `snapshot: null`, with the
    // falsy value flowing through and silently being dropped.
    if (raw.snapshot !== undefined) {
      // `raw.snapshot` is untrusted; reject anything that isn't a plain object
      // before spreading it (a peer-supplied array, null, or primitive would
      // otherwise be silently coerced via spread or dropped on the floor).
      if (
        raw.snapshot === null ||
        typeof raw.snapshot !== 'object' ||
        Array.isArray(raw.snapshot)
      ) {
        throw new Error(
          `Invalid sync message: 'snapshot' must be an object when present (got ${describeValue(
            raw.snapshot,
          )})`,
        );
      }
      snapshot = { ...(raw.snapshot as Record<string, unknown>) };
      // Decode base64-encoded BinaryChange[] back to Uint8Array[].
      if (Array.isArray(snapshot.state)) {
        snapshot.state = snapshot.state.map((c: string) =>
          Base64.toUint8Array(c),
        );
      }
      if (typeof snapshot.signature === 'string') {
        snapshot.signature = Base64.toUint8Array(snapshot.signature);
      }
    }
    let keychainChanges: BinaryChange[] | undefined;
    if (raw.keychainChanges !== undefined) {
      if (!Array.isArray(raw.keychainChanges)) {
        throw new Error(
          `Invalid sync message: 'keychainChanges' must be an array when present (got ${describeValue(
            raw.keychainChanges,
          )})`,
        );
      }
      keychainChanges = deserializeBinaryChanges(
        raw.keychainChanges as string[],
      );
    }
    let welcomeEpochId: Uint8Array | undefined;
    if (raw.welcomeEpochId !== undefined) {
      if (typeof raw.welcomeEpochId !== 'string') {
        throw new Error(
          `Invalid sync message: 'welcomeEpochId' must be a string when present (got ${describeValue(
            raw.welcomeEpochId,
          )})`,
        );
      }
      welcomeEpochId = Base64.toUint8Array(raw.welcomeEpochId);
    }
    let welcomeRecipient: string | undefined;
    if (raw.welcomeRecipient !== undefined) {
      if (typeof raw.welcomeRecipient !== 'string') {
        throw new Error(
          `Invalid sync message: 'welcomeRecipient' must be a string when present (got ${describeValue(
            raw.welcomeRecipient,
          )})`,
        );
      }
      welcomeRecipient = raw.welcomeRecipient;
    }
    let welcomeRecipientKemPublicKey: Uint8Array | undefined;
    if (raw.welcomeRecipientKemPublicKey !== undefined) {
      if (typeof raw.welcomeRecipientKemPublicKey !== 'string') {
        throw new Error(
          `Invalid sync message: 'welcomeRecipientKemPublicKey' must be a string when present (got ${describeValue(
            raw.welcomeRecipientKemPublicKey,
          )})`,
        );
      }
      welcomeRecipientKemPublicKey = Base64.toUint8Array(
        raw.welcomeRecipientKemPublicKey,
      );
    }
    let eciesSealed: Uint8Array | undefined;
    if (raw.eciesSealed !== undefined) {
      if (typeof raw.eciesSealed !== 'string') {
        throw new Error(
          `Invalid sync message: 'eciesSealed' must be a string when present (got ${describeValue(
            raw.eciesSealed,
          )})`,
        );
      }
      eciesSealed = Base64.toUint8Array(raw.eciesSealed);
    }
    // Loose top-level shape check for `pathUpdate`; the
    // per-field decode happens later in
    // `deserializePathUpdateFromWire`. Rejecting `null`/array/primitive
    // here keeps malformed peer payloads from propagating downstream.
    let pathUpdate: unknown;
    if (raw.pathUpdate !== undefined) {
      if (
        raw.pathUpdate === null ||
        typeof raw.pathUpdate !== 'object' ||
        Array.isArray(raw.pathUpdate)
      ) {
        throw new Error(
          `Invalid sync message: 'pathUpdate' must be an object when present (got ${describeValue(
            raw.pathUpdate,
          )})`,
        );
      }
      pathUpdate = raw.pathUpdate;
    }
    let pathUpdateEpochId: Uint8Array | undefined;
    if (raw.pathUpdateEpochId !== undefined) {
      if (typeof raw.pathUpdateEpochId !== 'string') {
        throw new Error(
          `Invalid sync message: 'pathUpdateEpochId' must be a string when present (got ${describeValue(
            raw.pathUpdateEpochId,
          )})`,
        );
      }
      pathUpdateEpochId = Base64.toUint8Array(raw.pathUpdateEpochId);
    }
    // Initial-load quorum tip-set hash (#189 §5.4.2). Decoded from base64
    // on the way back to Uint8Array; mirrors the serializer above.
    // Untrusted input -- reject anything that isn't a string AND enforce
    // the fixed-width SHA-256 digest length (32 bytes) at the wire
    // boundary so malformed values never reach the quorum decision
    // logic. `tipsHash` is used as a Map key in `decideLoadQuorum`; a
    // wrong-length value could either silently mis-bucket against
    // legitimate votes or produce a partial-hash collision under a
    // hostile peer. Reject on the way in.
    let tipsHash: Uint8Array | undefined;
    if (raw.tipsHash !== undefined) {
      if (typeof raw.tipsHash !== 'string') {
        throw new Error(
          `Invalid sync message: 'tipsHash' must be a string when present (got ${describeValue(
            raw.tipsHash,
          )})`,
        );
      }
      tipsHash = Base64.toUint8Array(raw.tipsHash);
      if (tipsHash.length !== TIPS_HASH_LENGTH) {
        throw new Error(
          `Invalid sync message: 'tipsHash' must decode to exactly ` +
            `${TIPS_HASH_LENGTH} bytes (SHA-256 digest); got ${tipsHash.length} bytes`,
        );
      }
    }
    // Initial-load quorum frontier binding (#186 / #189 §5.4.2). Untrusted
    // input -- reject non-arrays or arrays containing non-strings up front
    // so the loader's binding check never has to defensively coerce.
    let tips: string[] | undefined;
    if (raw.tips !== undefined) {
      if (!Array.isArray(raw.tips)) {
        throw new Error(
          `Invalid sync message: 'tips' must be an array when present (got ${describeValue(
            raw.tips,
          )})`,
        );
      }
      for (const entry of raw.tips) {
        if (typeof entry !== 'string') {
          throw new Error(
            `Invalid sync message: 'tips' entries must be strings (got ${describeValue(
              entry,
            )})`,
          );
        }
      }
      tips = raw.tips as string[];
    }
    const loadSecurityState =
      raw.loadSecurityState === undefined
        ? undefined
        : deserializeLoadSecurityCommitmentsFromWire(raw.loadSecurityState);
    const loadChallenge =
      raw.loadChallenge === undefined
        ? undefined
        : deserializeInitialLoadChallengeFromWire(raw.loadChallenge);
    // Copy only recognized fields, but retain their incoming insertion order.
    // Sync-message signatures cover the serialized JSON bytes. Rebuilding in a
    // fixed schema order moves `keychainChanges` ahead of the V4 `tips` /
    // security fields and makes an honest full-load signature unverifiable.
    // Iterating the parsed wire keys preserves shipped signed payloads while the
    // switch continues to drop peer-supplied junk properties.
    const result = {} as CRDTSyncMessage<BinaryChange[], CryptoKey>;
    for (const field of Object.keys(raw)) {
      switch (field) {
        case 'documentId':
          result.documentId = raw.documentId;
          break;
        case 'changeId':
          if (raw.changeId !== undefined)
            result.changeId = raw.changeId as string;
          break;
        case 'signature':
          if (raw.signature !== undefined)
            result.signature = raw.signature as string;
          break;
        case 'changes':
          // Any value other than `undefined` must pass through the untrusted
          // Merkle-DAG validator; do not use a truthiness guard here.
          if (raw.changes !== undefined) {
            result.changes = deserializeChangeNodeFromJSON(
              raw.changes as iCRDTChangeNode,
              deserializeBinaryChanges,
            );
          }
          break;
        case 'keychainChanges':
          if (keychainChanges !== undefined)
            result.keychainChanges = keychainChanges;
          break;
        case 'welcomeEpochId':
          if (welcomeEpochId !== undefined)
            result.welcomeEpochId = welcomeEpochId;
          break;
        case 'welcomeRecipient':
          if (welcomeRecipient !== undefined)
            result.welcomeRecipient = welcomeRecipient;
          break;
        case 'welcomeRecipientKemPublicKey':
          if (welcomeRecipientKemPublicKey !== undefined)
            result.welcomeRecipientKemPublicKey = welcomeRecipientKemPublicKey;
          break;
        case 'eciesSealed':
          if (eciesSealed !== undefined) result.eciesSealed = eciesSealed;
          break;
        case 'pathUpdate':
          if (pathUpdate !== undefined)
            result.pathUpdate = pathUpdate as CRDTSyncMessage<
              BinaryChange[],
              CryptoKey
            >['pathUpdate'];
          break;
        case 'pathUpdateEpochId':
          if (pathUpdateEpochId !== undefined)
            result.pathUpdateEpochId = pathUpdateEpochId;
          break;
        case 'tipsHash':
          if (tipsHash !== undefined) result.tipsHash = tipsHash;
          break;
        case 'tips':
          if (tips !== undefined) result.tips = tips;
          break;
        case 'loadSecurityState':
          if (loadSecurityState !== undefined)
            result.loadSecurityState = loadSecurityState;
          break;
        case 'loadChallenge':
          if (loadChallenge !== undefined) result.loadChallenge = loadChallenge;
          break;
        case 'snapshot':
          if (snapshot !== undefined) result.snapshot = snapshot;
          break;
      }
    }
    return result;
  }
}
