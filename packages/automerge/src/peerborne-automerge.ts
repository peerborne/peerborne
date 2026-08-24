import {
  Doc,
  init,
  change,
  clone,
  getChanges,
  applyChanges,
  Change as BinaryChange,
  getAllChanges,
  save,
  load,
  merge,
  from,
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
  JSONSerializer,
  Keychain,
  KeychainProvider,
  LRUCache,
  serializeChangeNodeForJSON,
  TIPS_HASH_LENGTH,
} from '@peerborne/core';
import { validateChangeBlockMetadata } from '@peerborne/core';
import { Base64 } from 'js-base64';

export type AutomergeDocumentChangeHandler<T = any> =
  PeerborneDocumentChangeHandler<Doc<T>, CryptoKey>;

export class AutomergeProvider<T = any>
  implements CRDTProvider<Doc<T>, BinaryChange[], (doc: T) => void>
{
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
    return crypto.subtle.importKey('raw', bytes as Uint8Array<ArrayBuffer>, algorithm, true, keyUsages);
  };
}



export type AutomergeACLDoc = Doc<{
  users: { [hash: string]: true };
}>;

export class AutomergeACL implements ACL<BinaryChange[], CryptoKey> {
  private _acl: AutomergeACLDoc = from({
    users: {},
  });
  private readonly _keyCache = new LRUCache<string, CryptoKey>(1000);

  async add(publicKey: CryptoKey): Promise<BinaryChange[]> {
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
    const hash = await serializeKey(publicKey);
    const aclNew = change(this._acl, (doc) => {
      if (!doc.users) {
        doc.users = {};
      } else {
        if (doc.users[hash] !== undefined) {
          delete doc.users[hash];
        }
      }
    });
    const aclChanges = getChanges(this._acl, aclNew);
    this._acl = aclNew;
    return aclChanges;
  }
  current(): BinaryChange[] {
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
    const hash = await serializeKey(publicKey);
    return this._acl.users && this._acl.users[hash] !== undefined;
  }
  // The capability parameter is accepted for interface compatibility but ignored here;
  // capability-based filtering is handled at the UCANACL wrapper level.
  async users(capability?: string): Promise<CryptoKey[]> {
    // Parallel deserialization for cold cache performance.
    // Create importer once to avoid per-miss closure allocation.
    const importKey = deserializeKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      ['verify'],
    );
    const entries = Object.keys(this._acl.users);
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
  initialize(): AutomergeACL {
    return new AutomergeACL();
  }
}

export type AutomergeKeychainDoc = Doc<{
  keys: [string, string][];
}>;

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
  return toHex(keyIDBytes);
}

/**
 * Parse a cache key string back to a Uint8Array key ID. The keychain
 * stores cache keys exclusively in lowercase hex (see
 * {@link keyIdToCacheKey}), so this only needs to decode hex.
 *
 * @throws {Error} If the cache key is not a valid even-length hex string.
 */
function cacheKeyToKeyId(cacheKey: string): Uint8Array {
  const hexRegex = /^[0-9a-fA-F]+$/;
  if (!hexRegex.test(cacheKey) || cacheKey.length % 2 !== 0) {
    throw new Error(`Invalid cache key format: expected even-length hex string, got "${cacheKey}"`);
  }
  const bytes = new Uint8Array(cacheKey.length / 2);
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
 * uses a random per-instance actor for any subsequent changes. This is
 * what makes {@link AutomergeKeychain.historySince} and
 * {@link AutomergeKeychain.currentKeyChange} mergeable into a fresh
 * receiver keychain without a root-array actor conflict.
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

/**
 * BREAKING CHANGE (PR #285): keychain key-ID width unified to 32 bytes.
 *
 * The keychain now uses 32-byte IDs uniformly for BOTH locally-generated
 * keys (formerly 16-byte UUIDs via `uuid.v4`) and BeeKEM-derived epoch
 * keys (already 32 bytes via `deriveEpochIdFromRootSecret`). The wire-
 * format key-ID prefix, the BeeKEM `pathUpdateEpochId`, and the
 * keychain's storage key are all the same 32 bytes -- no truncation
 * step exists.
 *
 * This is an **intentional, on-disk-breaking change** from earlier
 * shipped revisions of this library, which used 16-byte UUIDs. There
 * are NO live users at the time of this change (project doctrine:
 * see `CLAUDE.md`/`SPECS.md`), so no migration shim is provided. Any
 * document state persisted with the old 16-byte UUID format will fail
 * to load against this version because `cacheKeyToKeyId` only accepts
 * even-length hex strings (no UUID/dashed format), and existing 16-byte
 * key IDs would be looked up under a different cache-key format than
 * they were stored under.
 *
 * If a future deployment ever needs migration, the recovery path is a
 * fresh keychain via `add()` + a BeeKEM Welcome to redistribute
 * material under the new ID width.
 */
export class AutomergeKeychain implements Keychain<BinaryChange[], CryptoKey> {
  private readonly _keyCache = new LRUCache<string, CryptoKey>(1000);
  private _keychain: AutomergeKeychainDoc = newKeychainDoc();

  async add(): Promise<[Uint8Array, CryptoKey, BinaryChange[]]> {
    // 32 random bytes match the width used by BeeKEM-derived epoch IDs
    // (`deriveEpochIdFromRootSecret`), so the wire-format key-ID prefix
    // is a single fixed width regardless of how the key was provisioned.
    // Earlier revisions used a 16-byte UUID here, but that required the
    // PathUpdate handler to truncate 32-byte BeeKEM epoch IDs down to 16
    // bytes on install -- producing a deterministic cache-key-format
    // mismatch with `getKey` (stored under hex, looked up under UUID
    // format). Removing the size asymmetry removes the need for the
    // truncation in the first place.
    const keyIDBytes = crypto.getRandomValues(new Uint8Array(32));
    const keyIDHex = toHex(keyIDBytes);
    const key = await crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256,
      },
      true,
      ['encrypt', 'decrypt'],
    );

    const serialized = await serializeKey(key);
    this._keyCache.set(keyIDHex, key);
    const keychainNew = change(this._keychain, (doc) => {
      if (!doc.keys) {
        doc.keys = [];
      }
      doc.keys.push([keyIDHex, serialized]);
    });
    const keychainChanges = getChanges(this._keychain, keychainNew);
    this._keychain = keychainNew;
    return [keyIDBytes, key, keychainChanges];
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
  async addEpochKey(epochId: Uint8Array, key: CryptoKey): Promise<BinaryChange[]> {
    const epochIdHex = toHex(epochId);
    this._keyCache.set(epochIdHex, key);
    const serialized = await serializeKey(key);
    const keychainNew = change(this._keychain, (doc) => {
      if (!doc.keys) {
        doc.keys = [];
      }
      doc.keys.push([epochIdHex, serialized]);
    });
    const keychainChanges = getChanges(this._keychain, keychainNew);
    this._keychain = keychainNew;
    return keychainChanges;
  }

  history(): BinaryChange[] {
    return getAllChanges(this._keychain);
  }
  merge(change: BinaryChange[]): void {
    const [doc] = applyChanges(this._keychain, change);
    this._keychain = doc;
  }
  async keys(): Promise<[Uint8Array, CryptoKey][]> {
    if (!this._keychain.keys) {
      return [];
    }
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
    if (!this._keychain.keys || this._keychain.keys.length === 0) {
      throw new Error("Can't get an empty keychain's current value");
    }

    const [keyID, serialized] = this._keychain.keys[this._keychain.keys.length - 1];
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
    if (!this._keychain.keys || this._keychain.keys.length === 0) {
      throw new Error("Can't get current key change from an empty keychain");
    }

    // Build a minimal Automerge doc containing only the current (most recent) key.
    // The fresh doc is seeded with the deterministic keychain seed actor so the
    // initial empty `keys: []` op is identical to the one in any receiver
    // keychain, allowing the slice to merge cleanly without root-array
    // actor conflicts.
    const [keyID, serialized] = this._keychain.keys[this._keychain.keys.length - 1];
    const minimalDoc = change(newKeychainDoc(), (doc) => {
      doc.keys.push([keyID, serialized]);
    });
    return getAllChanges(minimalDoc);
  }

  /**
   * Build a keychain change list containing only the keys at or after the
   * specified key ID. The keys array preserves insertion order, so we
   * locate the boundary by ID and copy the suffix into a fresh doc.
   *
   * If the boundary key is not found in this keychain, the full history
   * is returned so the recipient can still decrypt past blocks rather
   * than be wedged at the load step.
   */
  async historySince(keyID: Uint8Array): Promise<BinaryChange[]> {
    if (!this._keychain.keys || this._keychain.keys.length === 0) {
      throw new Error("Can't get history-since from an empty keychain");
    }
    const cacheKey = keyIdToCacheKey(keyID);
    const startIdx = this._keychain.keys.findIndex(([id]) => id === cacheKey);
    if (startIdx === -1) {
      // Fall back to full history when the boundary key is unknown.
      return getAllChanges(this._keychain);
    }
    const tail = this._keychain.keys.slice(startIdx);
    // Use newKeychainDoc() so the slice's initial empty-array op is
    // identical to the receiver's, and the slice merges cleanly into a
    // fresh keychain without losing entries to a root-array actor
    // conflict on the empty seed.
    const minimalDoc = change(newKeychainDoc(), (doc) => {
      for (const [id, serialized] of tail) {
        doc.keys.push([id, serialized]);
      }
    });
    return getAllChanges(minimalDoc);
  }
  getKey(keyIDBytes: Uint8Array): CryptoKey | undefined {
    const cacheKey = keyIdToCacheKey(keyIDBytes);
    return this._keyCache.get(cacheKey);
  }
}

export class AutomergeKeychainProvider
  implements KeychainProvider<BinaryChange[], CryptoKey>
{
  initialize(): AutomergeKeychain {
    return new AutomergeKeychain();
  }

  // 32 bytes: matches both `add()`'s random key-ID output and the
  // BeeKEM-derived epoch ID width from `deriveEpochIdFromRootSecret`.
  // Using one fixed width across the keychain's two key-provisioning
  // paths means the on-wire key-ID prefix never needs to be truncated
  // -- which is the failure mode that caused the post-rotation
  // decryption regression fixed by PR #285 round 6.
  keyIDLength = 32;
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

export class AutomergeJSONSerializer extends JSONSerializer<BinaryChange[], CryptoKey> {
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
    if (changes.blindIndexTokens !== undefined && changes.blindIndexTokens !== null) obj.blindIndexTokens = changes.blindIndexTokens;
    return this.serialize(obj);
  }

  deserializeChangeBlock(changes: string): CRDTChangeBlock<BinaryChange[]> {
    const raw = this.deserialize(changes);
    if (
      typeof raw !== 'object' || raw === null ||
      !Array.isArray((raw as Record<string, unknown>).changes) ||
      typeof (raw as Record<string, unknown>).nonce !== 'string'
    ) {
      throw new Error('Invalid change block: expected {changes: string[], nonce: string}');
    }
    const deserialized = raw as { changes: string[]; nonce: string; keyID?: string; blindIndexTokens?: Record<string, string> };
    const result: CRDTChangeBlock<BinaryChange[]> = {
      changes: deserializeBinaryChanges(deserialized.changes),
      nonce: Base64.toUint8Array(deserialized.nonce),
    };
    validateChangeBlockMetadata(deserialized, result);
    return result;
  }

  serializeSyncMessage(message: CRDTSyncMessage<BinaryChange[], CryptoKey>): Uint8Array {
    let snapshotForWire: any;
    if (message.snapshot) {
      snapshotForWire = { ...message.snapshot };
      // Base64-encode each BinaryChange (Uint8Array) in state for JSON safety.
      if (Array.isArray(snapshotForWire.state)) {
        snapshotForWire.state = snapshotForWire.state.map(
          (c: Uint8Array) => Base64.fromUint8Array(c),
        );
      }
      if (snapshotForWire.signature instanceof Uint8Array) {
        snapshotForWire.signature = Base64.fromUint8Array(snapshotForWire.signature);
      }
      // Drop publicKey -- CryptoKey is not JSON-serializable and
      // snapshot verification uses writer ACL keys, not the embedded key.
      delete snapshotForWire.publicKey;
    }
    return this.encode(
      this.serialize({
        ...message,
        // Mirror the deserializer: only `undefined` skips the
        // serialization path. Any defined value flows through
        // `serializeChangeNodeForJSON` so the wire shape matches what
        // the deserializer will validate on the receiving end.
        changes:
          message.changes === undefined
            ? undefined
            : serializeChangeNodeForJSON(message.changes, serializeBinaryChanges),
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
        // BeeKEM PathUpdate v1 fields. `pathUpdate` is already a
        // JSON-safe `SerializedPathUpdate`; pass through verbatim.
        // `pathUpdateEpochId` is a `Uint8Array`; base64-encode it.
        pathUpdate: message.pathUpdate,
        pathUpdateEpochId:
          message.pathUpdateEpochId &&
          Base64.fromUint8Array(message.pathUpdateEpochId),
        // Initial-load quorum tip-set hash (#189 §5.4.2). Base64-encoded
        // for JSON-safe transport, mirrored on the deserialize path below.
        // Only populated on tip-advertise responses.
        tipsHash:
          message.tipsHash &&
          Base64.fromUint8Array(message.tipsHash),
        // Explicit tip-set advertisement populated on load responses to
        // bind the served state to the responder's frontier (see
        // `CRDTSyncMessage.tips`). Plain string[] of CIDs; passes through
        // JSON verbatim.
        tips: message.tips,
        snapshot: snapshotForWire,
      }),
    );
  }

  deserializeSyncMessage(message: Uint8Array): CRDTSyncMessage<BinaryChange[], CryptoKey> {
    const decoded = this.deserialize(this.decode(message));
    // Wire input is untrusted: a malformed peer can send `null`, an array, or
    // a primitive in place of a sync-message object. Reading properties on
    // those values would throw a bare `TypeError` (`Cannot read properties of
    // null`) that is hard to attribute back to the peer; reject up front with
    // a descriptive error instead. This also denies a trivial DoS path where
    // a peer crashes the deserializer by sending e.g. JSON `null`. Mirrors
    // the equivalent guard in `YjsJSONSerializer.deserializeSyncMessage`.
    if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) {
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
        snapshot.state = snapshot.state.map(
          (c: string) => Base64.toUint8Array(c),
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
      keychainChanges = deserializeBinaryChanges(raw.keychainChanges as string[]);
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
    // hostile peer. Reject on the way in. See PR #284 r24 Copilot review.
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
    // Build the returned object explicitly rather than spreading `...raw` so
    // that peer-supplied junk keys (e.g. `__proto__`, `constructor`, or any
    // unrecognized field) don't leak into the deserialized sync message. Only
    // fields declared on `CRDTSyncMessage` are propagated.
    const result: CRDTSyncMessage<BinaryChange[], CryptoKey> = {
      documentId: raw.documentId,
    };
    if (raw.changeId !== undefined) result.changeId = raw.changeId as string;
    if (raw.signature !== undefined) result.signature = raw.signature as string;
    // Any value other than `undefined` (including `null`, `0`, `""`, etc.)
    // must be routed through the validator -- using a truthy guard like
    // `raw.changes && ...` would let a malformed peer message bypass
    // `deserializeChangeNodeFromJSON`'s shape checks by sending e.g.
    // `changes: null`, with the falsy value flowing through to
    // downstream consumers.
    if (raw.changes !== undefined) {
      result.changes = deserializeChangeNodeFromJSON(
        raw.changes as iCRDTChangeNode,
        deserializeBinaryChanges,
      );
    }
    if (keychainChanges !== undefined) result.keychainChanges = keychainChanges;
    if (welcomeEpochId !== undefined) result.welcomeEpochId = welcomeEpochId;
    if (welcomeRecipient !== undefined) result.welcomeRecipient = welcomeRecipient;
    if (welcomeRecipientKemPublicKey !== undefined)
      result.welcomeRecipientKemPublicKey = welcomeRecipientKemPublicKey;
    if (eciesSealed !== undefined) result.eciesSealed = eciesSealed;
    if (pathUpdate !== undefined)
      result.pathUpdate = pathUpdate as CRDTSyncMessage<BinaryChange[], CryptoKey>['pathUpdate'];
    if (pathUpdateEpochId !== undefined) result.pathUpdateEpochId = pathUpdateEpochId;
    if (tipsHash !== undefined) result.tipsHash = tipsHash;
    if (tips !== undefined) result.tips = tips;
    if (snapshot !== undefined) result.snapshot = snapshot;
    return result;
  }
}
