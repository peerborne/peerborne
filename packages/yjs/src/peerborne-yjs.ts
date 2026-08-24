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
import { applyUpdateV2, Doc, encodeStateAsUpdateV2, encodeStateVector } from 'yjs';
import { Base64 } from 'js-base64';

// Binary data is stored as a base64 string for JSON serialization.
// Base64 has only ~33% payload expansion and is the standard encoding for
// binary data in JSON, so this is an acceptable trade-off.
type iCRDTChangeNode = CRDTChangeNodeWire<string>;

export class YjsJSONSerializer extends JSONSerializer<Uint8Array, CryptoKey> {
  serializeChanges(changes: Uint8Array): Uint8Array {
    return changes;
  }
  deserializeChanges(changes: Uint8Array): Uint8Array {
    return changes;
  }

  serializeChangeBlock(changes: CRDTChangeBlock<Uint8Array>): string {
    const obj: Record<string, unknown> = {
      changes: Base64.fromUint8Array(changes.changes),
      nonce: Base64.fromUint8Array(changes.nonce),
    };
    if (changes.keyID !== undefined) obj.keyID = changes.keyID;
    if (changes.blindIndexTokens !== undefined && changes.blindIndexTokens !== null) obj.blindIndexTokens = changes.blindIndexTokens;
    return this.serialize(obj);
  }
  deserializeChangeBlock(changes: string): CRDTChangeBlock<Uint8Array> {
    const raw = this.deserialize(changes);
    if (
      typeof raw !== 'object' || raw === null ||
      typeof (raw as Record<string, unknown>).changes !== 'string' ||
      typeof (raw as Record<string, unknown>).nonce !== 'string'
    ) {
      throw new Error('Invalid change block: expected {changes: string, nonce: string}');
    }
    const deserialized = raw as { changes: string; nonce: string; keyID?: string; blindIndexTokens?: Record<string, string> };
    const result: CRDTChangeBlock<Uint8Array> = {
      changes: Base64.toUint8Array(deserialized.changes),
      nonce: Base64.toUint8Array(deserialized.nonce),
    };
    validateChangeBlockMetadata(deserialized, result);
    return result;
  }
  serializeSyncMessage(message: CRDTSyncMessage<Uint8Array, CryptoKey>): Uint8Array {
    // Encode snapshot Uint8Array fields (state, signature) as base64 for JSON safety.
    let snapshotForWire: any;
    if (message.snapshot) {
      snapshotForWire = { ...message.snapshot };
      if (snapshotForWire.state instanceof Uint8Array) {
        snapshotForWire.state = Base64.fromUint8Array(snapshotForWire.state);
      }
      if (snapshotForWire.signature instanceof Uint8Array) {
        snapshotForWire.signature = Base64.fromUint8Array(snapshotForWire.signature);
      }
      // Drop publicKey from wire -- CryptoKey is not JSON-serializable and
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
            : serializeChangeNodeForJSON(message.changes, Base64.fromUint8Array),
        keychainChanges:
          message.keychainChanges &&
          Base64.fromUint8Array(message.keychainChanges),
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
        // JSON-safe `SerializedPathUpdate` (per-field base64) produced
        // by `serializePathUpdateForWire`, so pass it through verbatim.
        // `pathUpdateEpochId` is a `Uint8Array`; base64-encode it the
        // same way as `welcomeEpochId`.
        pathUpdate: message.pathUpdate,
        pathUpdateEpochId:
          message.pathUpdateEpochId &&
          Base64.fromUint8Array(message.pathUpdateEpochId),
        // Initial-load quorum tip-set hash (#189 §5.4.2). Base64-encoded for
        // JSON-safe transport, same pattern as `welcomeEpochId`. Only
        // populated on tip-advertise responses; absent on regular sync
        // traffic. The deserializer below mirrors this encoding.
        tipsHash:
          message.tipsHash &&
          Base64.fromUint8Array(message.tipsHash),
        // Explicit tip-set advertisement populated on load responses to
        // bind the served state to the responder's frontier (see
        // `CRDTSyncMessage.tips`). Plain string[] of CIDs; passes through
        // JSON verbatim. Absent on traffic that does not need binding.
        tips: message.tips,
        snapshot: snapshotForWire,
      }),
    );
  }
  deserializeSyncMessage(message: Uint8Array): CRDTSyncMessage<Uint8Array, CryptoKey> {
    const decoded = this.deserialize(this.decode(message));
    // Wire input is untrusted: reject non-object payloads up front with a
    // descriptive error so the malformed payload can be attributed back to
    // the peer instead of throwing a bare `TypeError`. Mirrors the guard in
    // `AutomergeJSONSerializer.deserializeSyncMessage`.
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
    // could omit it or send a non-string value, which would otherwise
    // propagate as `documentId: undefined`/non-string into downstream
    // consumers that key documents by string ID.
    if (typeof raw.documentId !== 'string') {
      throw new Error(
        `Invalid sync message: 'documentId' must be a string (got ${describeValue(
          raw.documentId,
        )})`,
      );
    }
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
    // Decode snapshot base64 fields back to Uint8Array.
    // Any value other than `undefined` (including `null`, `0`, `""`, etc.)
    // must be routed through the validator -- using a truthy guard like
    // `raw.snapshot && ...` would let a malformed peer message bypass the
    // object/array shape check by sending e.g. `snapshot: null`, with the
    // falsy value flowing through and silently being dropped.
    let snapshot: any;
    if (raw.snapshot !== undefined) {
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
      if (typeof snapshot.state === 'string') {
        snapshot.state = Base64.toUint8Array(snapshot.state);
      }
      if (typeof snapshot.signature === 'string') {
        snapshot.signature = Base64.toUint8Array(snapshot.signature);
      }
    }
    let keychainChanges: Uint8Array | undefined;
    if (raw.keychainChanges !== undefined) {
      if (typeof raw.keychainChanges !== 'string') {
        throw new Error(
          `Invalid sync message: 'keychainChanges' must be a string when present (got ${describeValue(
            raw.keychainChanges,
          )})`,
        );
      }
      keychainChanges = Base64.toUint8Array(raw.keychainChanges);
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
    // The `pathUpdate` field is a `SerializedPathUpdate` whose internal
    // shape is validated when the receive handler hands it to
    // `deserializePathUpdateFromWire`. Reject obviously malformed
    // top-level values (null / array / primitive) here so a peer who
    // sends e.g. `pathUpdate: 42` doesn't propagate that through to the
    // downstream consumer. The strict per-field decode happens later.
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
    // Initial-load quorum tip-set hash (#189 §5.4.2). Decoded base64 on the
    // way back to Uint8Array; mirrors the encoding in `serializeSyncMessage`
    // above. Untrusted input -- reject anything that isn't a string AND
    // enforce the fixed-width SHA-256 digest length (32 bytes) at the
    // wire boundary so malformed values never reach the quorum decision
    // logic. `tipsHash` is defined as `SHA-256(sorted CID list)` and is
    // used as a Map key in `decideLoadQuorum`; a wrong-length value could
    // either silently mis-bucket against legitimate votes or produce a
    // partial-hash collision under a hostile peer. Reject on the way in.
    // See PR #284 r24 Copilot review.
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
    // that peer-supplied junk keys don't leak into the deserialized sync
    // message. Only fields declared on `CRDTSyncMessage` are propagated.
    const result: CRDTSyncMessage<Uint8Array, CryptoKey> = {
      documentId: raw.documentId,
    };
    if (raw.changeId !== undefined) result.changeId = raw.changeId as string;
    if (raw.signature !== undefined) result.signature = raw.signature as string;
    // Any value other than `undefined` (including `null`, `0`, `""`, etc.)
    // must be routed through the validator -- using a truthy guard like
    // `raw.changes && ...` would let a malformed peer message bypass
    // `deserializeChangeNodeFromJSON`'s shape checks by sending e.g.
    // `changes: null`, with the falsy value flowing through.
    if (raw.changes !== undefined) {
      result.changes = deserializeChangeNodeFromJSON(
        raw.changes as iCRDTChangeNode,
        Base64.toUint8Array,
      );
    }
    if (keychainChanges !== undefined) result.keychainChanges = keychainChanges;
    if (welcomeEpochId !== undefined) result.welcomeEpochId = welcomeEpochId;
    if (welcomeRecipient !== undefined) result.welcomeRecipient = welcomeRecipient;
    if (welcomeRecipientKemPublicKey !== undefined)
      result.welcomeRecipientKemPublicKey = welcomeRecipientKemPublicKey;
    if (eciesSealed !== undefined) result.eciesSealed = eciesSealed;
    if (pathUpdate !== undefined)
      result.pathUpdate = pathUpdate as CRDTSyncMessage<Uint8Array, CryptoKey>['pathUpdate'];
    if (pathUpdateEpochId !== undefined) result.pathUpdateEpochId = pathUpdateEpochId;
    if (tipsHash !== undefined) result.tipsHash = tipsHash;
    if (tips !== undefined) result.tips = tips;
    if (snapshot !== undefined) result.snapshot = snapshot;
    return result;
  }
}

export type YjsDocumentChangeHandler = PeerborneDocumentChangeHandler<
  Doc,
  CryptoKey
>;

export class YjsProvider
  implements CRDTProvider<Doc, Uint8Array, (doc: Doc) => void>
{
  newDocument(): Doc {
    return new Doc();
  }
  localChange(
    document: Doc,
    message: string,
    changeFn: (doc: Doc) => void,
  ): [Doc, Uint8Array] {
    const beforeSV = encodeStateVector(document);
    changeFn(document);
    const changes = encodeStateAsUpdateV2(document, beforeSV);

    // Y.Doc is always mutated in-place -- returning the same reference is
    // correct Yjs behavior. Callers must not rely on reference equality to
    // detect changes.
    return [document, changes];
  }
  remoteChange(document: Doc, changes: Uint8Array): Doc {
    applyUpdateV2(document, changes);

    // Y.Doc is always mutated in-place -- returning the same reference is
    // correct Yjs behavior. Callers must not rely on reference equality to
    // detect changes.
    return document;
  }
  getHistory(document: Doc): Uint8Array {
    // This intentionally encodes the full document state. getHistory() is
    // used for initial sync with new peers, so the complete state is needed.
    // Incremental deltas are handled by localChange() which captures only
    // the changes made during a single mutation via
    // Y.encodeStateAsUpdate(doc, lastSyncState).
    return encodeStateAsUpdateV2(document);
  }
  getSnapshot(document: Doc): Uint8Array {
    return encodeStateAsUpdateV2(document);
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


export class YjsACLProvider implements ACLProvider<Uint8Array, CryptoKey> {
  initialize(): ACL<Uint8Array, CryptoKey> {
    return new YjsACL();
  }
}

export class YjsACL implements ACL<Uint8Array, CryptoKey> {
  private readonly _acl = new Doc();
  private readonly _keyCache = new LRUCache<string, CryptoKey>(1000);

  async add(publicKey: CryptoKey): Promise<Uint8Array> {
    const hash = await serializeKey(publicKey);
    const beforeSV = encodeStateVector(this._acl);
    this._acl.getMap('users').set(hash, true);
    return encodeStateAsUpdateV2(this._acl, beforeSV);
  }
  async remove(publicKey: CryptoKey): Promise<Uint8Array> {
    const hash = await serializeKey(publicKey);
    const beforeSV = encodeStateVector(this._acl);
    if (this._acl.getMap('users').has(hash)) {
      this._acl.getMap('users').delete(hash);
    }
    return encodeStateAsUpdateV2(this._acl, beforeSV);
  }
  current(): Uint8Array {
    return encodeStateAsUpdateV2(this._acl);
  }
  merge(change: Uint8Array): void {
    applyUpdateV2(this._acl, change);
  }
  async check(publicKey: CryptoKey): Promise<boolean> {
    const hash = await serializeKey(publicKey);
    return this._acl.getMap('users').has(hash);
  }
  async users(): Promise<CryptoKey[]> {
    // Parallel deserialization for cold cache performance.
    // Create importer once to avoid per-miss closure allocation.
    const importKey = deserializeKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      ['verify'],
    );
    const entries = [...this._acl.getMap('users').keys()];
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
export class YjsKeychain implements Keychain<Uint8Array, CryptoKey> {
  private readonly _keyCache = new LRUCache<string, CryptoKey>(1000);
  private readonly _keychain = new Doc();

  async add(): Promise<[Uint8Array, CryptoKey, Uint8Array]> {
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

    this._keyCache.set(keyIDHex, key);
    const serialized = await serializeKey(key);
    const beforeSV = encodeStateVector(this._keychain);
    this._keychain
      .getArray<[string, string]>('keys')
      .push([[keyIDHex, serialized]]);
    const keychainChanges = encodeStateAsUpdateV2(this._keychain, beforeSV);
    return [keyIDBytes, key, keychainChanges];
  }

  /**
   * Add an epoch-based encryption key to the keychain.
   *
   * Epoch keys are used for key rotation: each epoch has a unique 32-byte ID
   * and an associated AES-GCM symmetric key. The key is cached locally and
   * appended to the CRDT keychain for synchronization with peers.
   *
   * @param epochId - The 32-byte epoch identifier.
   * @param key - The AES-GCM CryptoKey for this epoch.
   * @returns The serialized keychain state as a Yjs update for broadcasting.
   */
  async addEpochKey(epochId: Uint8Array, key: CryptoKey): Promise<Uint8Array> {
    const epochIdHex = toHex(epochId);
    this._keyCache.set(epochIdHex, key);
    const serialized = await serializeKey(key);
    const beforeSV = encodeStateVector(this._keychain);
    this._keychain
      .getArray<[string, string]>('keys')
      .push([[epochIdHex, serialized]]);
    return encodeStateAsUpdateV2(this._keychain, beforeSV);
  }

  history(): Uint8Array {
    return encodeStateAsUpdateV2(this._keychain);
  }
  merge(change: Uint8Array): void {
    applyUpdateV2(this._keychain, change);
  }
  async keys(): Promise<[Uint8Array, CryptoKey][]> {
    const yarr = this._keychain.getArray<[string, string]>('keys');
    const promises: Promise<[Uint8Array, CryptoKey]>[] = [];
    for (let i = 0; i < yarr.length; i++) {
      const [keyID, serialized] = yarr.get(i);
      const keyIDBytes = cacheKeyToKeyId(keyID);
      promises.push(
        (async () => {
          let key = this._keyCache.get(keyID);
          if (!key) {
            key = await deserializeKey({ name: 'AES-GCM', length: 256 }, [
              'encrypt',
              'decrypt',
            ])(serialized);
            this._keyCache.set(keyID, key);
          }
          return [keyIDBytes, key] as [Uint8Array, CryptoKey];
        })(),
      );
    }

    return await Promise.all(promises);
  }
  async current(): Promise<[Uint8Array, CryptoKey]> {
    const yarr = this._keychain.getArray<string>('keys');
    if (yarr.length === 0) {
      throw new Error("Can't get an empty keychain's current value");
    }

    const [keyID, serialized] = yarr.get(yarr.length - 1);
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
  async currentKeyChange(): Promise<Uint8Array> {
    const yarr = this._keychain.getArray<[string, string]>('keys');
    if (yarr.length === 0) {
      throw new Error("Can't get current key change from an empty keychain");
    }

    // Build a minimal Y.Doc containing only the current (most recent) key.
    const minimalDoc = new Doc();
    const [keyID, serialized] = yarr.get(yarr.length - 1);
    minimalDoc.getArray<[string, string]>('keys').push([[keyID, serialized]]);
    return encodeStateAsUpdateV2(minimalDoc);
  }

  /**
   * Build a keychain update containing only the keys at or after the
   * specified key ID. The keys array preserves insertion order, so we walk
   * the array to find the boundary and copy the suffix into a fresh Y.Doc.
   *
   * If the boundary key is not found in this keychain, the full keychain
   * history is returned so the recipient can still decrypt past blocks
   * rather than be wedged at the load step.
   */
  async historySince(keyID: Uint8Array): Promise<Uint8Array> {
    const yarr = this._keychain.getArray<[string, string]>('keys');
    if (yarr.length === 0) {
      throw new Error("Can't get history-since from an empty keychain");
    }
    const cacheKey = keyIdToCacheKey(keyID);
    let startIdx = -1;
    for (let i = 0; i < yarr.length; i++) {
      if (yarr.get(i)[0] === cacheKey) {
        startIdx = i;
        break;
      }
    }
    if (startIdx === -1) {
      // Fall back to full history when the boundary key is unknown.
      return encodeStateAsUpdateV2(this._keychain);
    }
    const minimalDoc = new Doc();
    const minimalArr = minimalDoc.getArray<[string, string]>('keys');
    for (let i = startIdx; i < yarr.length; i++) {
      const entry = yarr.get(i);
      minimalArr.push([[entry[0], entry[1]]]);
    }
    return encodeStateAsUpdateV2(minimalDoc);
  }
  /**
   * Synchronous cache lookup for a key by its ID bytes.
   *
   * This is intentionally a pure cache lookup. Use keys() or current() to
   * ensure keys are imported and cached before calling getKey.
   */
  getKey(keyIDBytes: Uint8Array): CryptoKey | undefined {
    const cacheKey = keyIdToCacheKey(keyIDBytes);
    return this._keyCache.get(cacheKey);
  }
}

export class YjsKeychainProvider
  implements KeychainProvider<Uint8Array, CryptoKey>
{
  initialize(): YjsKeychain {
    return new YjsKeychain();
  }

  // 32 bytes: matches both `add()`'s random key-ID output and the
  // BeeKEM-derived epoch ID width from `deriveEpochIdFromRootSecret`.
  // Using one fixed width across the keychain's two key-provisioning
  // paths means the on-wire key-ID prefix never needs to be truncated
  // -- which is the failure mode that caused the post-rotation
  // decryption regression fixed by PR #285 round 6.
  keyIDLength = 32;
}
