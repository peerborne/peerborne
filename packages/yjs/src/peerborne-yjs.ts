import {
  ACL,
  ACLProvider,
  PeerborneDocumentChangeHandler,
  CRDTChangeBlock,
  CRDTChangeNodeWire,
  CRDTProvider,
  CRDTSyncMessage,
  isSyncMessageSignatureContext,
  copyUnsharedUint8Array,
  describeValue,
  deserializeInitialLoadChallengeFromWire,
  deserializeChangeNodeFromJSON,
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
  canonicalKeychain,
  CanonicalKeychainEntry,
  CanonicalAppendIntent,
  serializeChangeNodeForJSON,
  serializeInitialLoadChallengeForWire,
  serializeLoadSecurityCommitmentsForWire,
  TIPS_HASH_LENGTH,
} from '@peerborne/core';
import { validateChangeBlockMetadata } from '@peerborne/core';
import {
  applyUpdateV2,
  ContentAny,
  decodeUpdateV2,
  Doc,
  encodeStateAsUpdateV2,
  encodeStateVector,
  Item,
} from 'yjs';
import { Base64 } from 'js-base64';

const {
  toHex,
  keyIdToCacheKey,
  cacheKeyToKeyId,
  assertAesGcmDocumentKey,
  validateCanonicalKeychainEntries,
  sameKeychainEntry,
  assertAppendOnlyTransition,
  isKeychainPrefix,
  snapshotAppendIntent,
  stateCommitment: yjsKeychainStateCommitment,
}: typeof canonicalKeychain = canonicalKeychain;

const assertSerializedDocumentKey: typeof canonicalKeychain.assertSerializedDocumentKey = canonicalKeychain.assertSerializedDocumentKey;

const assertCanonicalKeychainEntry: typeof canonicalKeychain.assertCanonicalKeychainEntry = canonicalKeychain.assertCanonicalKeychainEntry;

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
    if (
      changes.blindIndexTokens !== undefined &&
      changes.blindIndexTokens !== null
    )
      obj.blindIndexTokens = changes.blindIndexTokens;
    return this.serialize(obj);
  }
  deserializeChangeBlock(changes: string): CRDTChangeBlock<Uint8Array> {
    const raw = this.deserialize(changes);
    if (
      typeof raw !== 'object' ||
      raw === null ||
      typeof (raw as Record<string, unknown>).changes !== 'string' ||
      typeof (raw as Record<string, unknown>).nonce !== 'string'
    ) {
      throw new Error(
        'Invalid change block: expected {changes: string, nonce: string}',
      );
    }
    const deserialized = raw as {
      changes: string;
      nonce: string;
      keyID?: string;
      blindIndexTokens?: Record<string, string>;
    };
    const result: CRDTChangeBlock<Uint8Array> = {
      changes: Base64.toUint8Array(deserialized.changes),
      nonce: Base64.toUint8Array(deserialized.nonce),
    };
    validateChangeBlockMetadata(deserialized, result);
    return result;
  }
  serializeSyncMessage(
    message: CRDTSyncMessage<Uint8Array, CryptoKey>,
  ): Uint8Array {
    // Encode snapshot Uint8Array fields (state, signature) as base64 for JSON safety.
    let snapshotForWire: any;
    if (message.snapshot) {
      snapshotForWire = { ...message.snapshot };
      if (snapshotForWire.state instanceof Uint8Array) {
        snapshotForWire.state = Base64.fromUint8Array(snapshotForWire.state);
      }
      if (snapshotForWire.signature instanceof Uint8Array) {
        snapshotForWire.signature = Base64.fromUint8Array(
          snapshotForWire.signature,
        );
      }
      // Drop publicKey from wire -- CryptoKey is not JSON-serializable and
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
                Base64.fromUint8Array,
              ),
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
        // BeeKEM PathUpdate v1/v2 fields. `pathUpdate` is already the
        // negotiated version's JSON-safe serialized shape, so pass it
        // through verbatim.
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
        tipsHash: message.tipsHash && Base64.fromUint8Array(message.tipsHash),
        // Explicit tip-set advertisement populated on load responses to
        // bind the served state to the responder's frontier (see
        // `CRDTSyncMessage.tips`). Plain string[] of CIDs; passes through
        // JSON verbatim. Absent on traffic that does not need binding.
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
  ): CRDTSyncMessage<Uint8Array, CryptoKey> {
    const decoded = this.deserialize(this.decode(message));
    // Wire input is untrusted: reject non-object payloads up front with a
    // descriptive error so the malformed payload can be attributed back to
    // the peer instead of throwing a bare `TypeError`. Mirrors the guard in
    // `AutomergeJSONSerializer.deserializeSyncMessage`.
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
      signatureContext?: unknown;
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
    if (
      raw.signatureContext !== undefined &&
      !isSyncMessageSignatureContext(raw.signatureContext)
    ) {
      throw new Error(
        `Invalid sync message: 'signatureContext' is not a supported exact tag (got ${describeValue(
          raw.signatureContext,
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
    // The `pathUpdate` field is the serialized v1|v2 union. Its internal
    // shape is validated by the decoder selected by protocol negotiation.
    // Reject obviously malformed
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
    return this.orderDecodedSyncFields(raw, {
      documentId: raw.documentId,
      signatureContext: raw.signatureContext,
      changeId: raw.changeId as string | undefined,
      signature: raw.signature as string | undefined,
      changes: raw.changes === undefined ? undefined : deserializeChangeNodeFromJSON(
        raw.changes as iCRDTChangeNode,
        Base64.toUint8Array,
      ),
      keychainChanges,
      welcomeEpochId,
      welcomeRecipient,
      welcomeRecipientKemPublicKey,
      eciesSealed,
      pathUpdate: pathUpdate as CRDTSyncMessage<Uint8Array, CryptoKey>['pathUpdate'],
      pathUpdateEpochId,
      tipsHash,
      tips,
      loadSecurityState,
      loadChallenge,
      snapshot,
    });
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
    return crypto.subtle.importKey(
      'raw',
      bytes as Uint8Array<ArrayBuffer>,
      algorithm,
      true,
      keyUsages,
    );
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
    const importKey = deserializeKey({ name: 'ECDSA', namedCurve: 'P-384' }, [
      'verify',
    ]);
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

const KEY_ID_LENGTH_BYTES = 32;
const KEYCHAIN_PROJECTION_CLIENT_DOMAIN =
  'peerborne:yjs-keychain-projection:v1\0';

// This independently rooted current-key view is reconciled by prepareMerge:
// a matching current tuple preserves the receiver's existing linear history
// without applying the projection's unrelated CRDT root operations.
let projectionTextEncoder: TextEncoder | undefined;

async function currentKeyProjectionClientID(
  entry: CanonicalKeychainEntry,
): Promise<number> {
  const identity = (projectionTextEncoder ??= new TextEncoder()).encode(
    `${KEYCHAIN_PROJECTION_CLIENT_DOMAIN}${JSON.stringify(entry)}`,
  );
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', identity),
  );
  // Five high bits plus six bytes yield a deterministic 53-bit safe integer.
  let clientID = digest[0] & 0x1f;
  for (let index = 1; index < 7; index++) {
    clientID = clientID * 256 + digest[index];
  }
  return clientID;
}

function currentKeyProjection(
  entry: CanonicalKeychainEntry,
  clientID: number,
): Uint8Array {
  const projection = new Doc();
  projection.clientID = clientID;
  projection
    .getArray<[string, string]>('keys')
    .push([[entry[0], entry[1]]]);
  validateYjsKeychain(projection);
  return new Uint8Array(encodeStateAsUpdateV2(projection));
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const sharedLength = Math.min(left.byteLength, right.byteLength);
  for (let index = 0; index < sharedLength; index++) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.byteLength - right.byteLength;
}

type YjsItemId = { readonly client: number; readonly clock: number };

function sameYjsItemId(
  left: YjsItemId | null,
  right: YjsItemId | null,
): boolean {
  return (
    left !== null &&
    right !== null &&
    left.client === right.client &&
    left.clock === right.clock
  );
}

function validateRawYjsKeychainUpdate(update: Uint8Array): void {
  const decoded = decodeUpdateV2(update);
  if (decoded.ds.clients.size !== 0) {
    throw new Error('Keychain history must not contain deletions');
  }
  const retainedEntries: unknown[] = [];
  for (const struct of decoded.structs) {
    if (
      !(struct instanceof Item) ||
      !(struct.content instanceof ContentAny) ||
      struct.length !== struct.content.arr.length ||
      struct.content.arr.length === 0
    ) {
      throw new Error('Keychain history contains an invalid operation');
    }
    if (struct.parentSub !== null) {
      throw new Error('Keychain history contains an unrelated operation');
    }
    retainedEntries.push(...struct.content.arr);
  }
  validateCanonicalKeychainEntries(retainedEntries);
}

/**
 * Validate both the visible keychain and its retained Yjs operations. Looking
 * only at the array would miss tombstoned keys, concurrent/non-append
 * branches, and unrelated hidden structs that a later full-history export
 * would disclose.
 */
// Y.Doc is mutable independently of the adapter's publication revision. Reads
// deliberately revalidate its bounded state; a revision-only cache would miss
// in-place edits and could authorize a keychain that was never validated.
function validateYjsKeychain(doc: Doc): CanonicalKeychainEntry[] {
  const entries = validateCanonicalKeychainEntries(
    doc.getArray<unknown>('keys').toArray(),
  );
  // Yjs 13.6 represents complete integration with null in both fields.
  // An absent/changed internal field is unsupported, not evidence of safety.
  if (doc.store.pendingStructs !== null || doc.store.pendingDs !== null) {
    throw new Error('Keychain history has unresolved update dependencies');
  }
  const decoded = decodeUpdateV2(encodeStateAsUpdateV2(doc));
  if (decoded.ds.clients.size !== 0) {
    throw new Error('Keychain history must not contain deletions');
  }

  const pending: Item[] = [];
  for (const struct of decoded.structs) {
    if (!(struct instanceof Item) || !(struct.content instanceof ContentAny)) {
      throw new Error('Keychain history contains an invalid operation');
    }
    if (
      struct.length !== struct.content.arr.length ||
      struct.content.arr.length === 0
    ) {
      throw new Error('Keychain history contains an invalid operation');
    }
    if (struct.parentSub !== null) {
      throw new Error('Keychain history contains an unrelated operation');
    }
    for (const entry of struct.content.arr) {
      assertCanonicalKeychainEntry(entry);
    }
    pending.push(struct);
  }

  const accepted: Item[] = [];
  let tailId: YjsItemId | null = null;
  let progressed = true;
  while (pending.length > 0 && progressed) {
    progressed = false;
    for (let index = pending.length - 1; index >= 0; index--) {
      const item = pending[index];
      const rootedAtKeys =
        accepted.length === 0 &&
        (item.parent as unknown) === 'keys' &&
        item.origin === null &&
        item.rightOrigin === null;
      const extendsKeys =
        accepted.length > 0 &&
        item.parent === null &&
        item.rightOrigin === null &&
        sameYjsItemId(item.origin, tailId);
      if (!rootedAtKeys && !extendsKeys) continue;
      accepted.push(item);
      tailId = {
        client: item.id.client,
        clock: item.id.clock + item.length - 1,
      };
      pending.splice(index, 1);
      progressed = true;
    }
  }
  if (pending.length !== 0) {
    throw new Error('Keychain history contains an unrelated operation');
  }
  const retained = validateCanonicalKeychainEntries(
    accepted.flatMap((item) => (item.content as ContentAny).arr),
  );
  if (
    retained.length !== entries.length ||
    entries.some(
      (entry, index) => !sameKeychainEntry(entry, retained[index]),
    )
  ) {
    throw new Error('Yjs keychain history does not match visible state');
  }
  return entries;
}

/** Append-only keychain with canonical 32-byte identifiers. */
export class YjsKeychain implements Keychain<Uint8Array, CryptoKey> {
  private readonly _keyCache = new LRUCache<string, CryptoKey>(
    MAX_KEYCHAIN_EPOCHS,
  );
  private _keychain = new Doc();
  private _revision = 0;

  async add(): Promise<[Uint8Array, CryptoKey, Uint8Array]> {
    const prepared = await this.prepareKey();
    prepared.commit();
    return [new Uint8Array(prepared.keyId), prepared.key, prepared.changes];
  }

  async prepareKey(): Promise<
    PreparedKeychainAddition<Uint8Array, CryptoKey>
  > {
    if (validateYjsKeychain(this._keychain).length === MAX_KEYCHAIN_EPOCHS) {
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
   * appended to the CRDT keychain for synchronization with peers.
   *
   * @param epochId - The 32-byte epoch identifier.
   * @param key - The AES-GCM CryptoKey for this epoch.
   * @returns The serialized keychain state as a Yjs update for broadcasting.
   */
  async addEpochKey(epochId: Uint8Array, key: CryptoKey): Promise<Uint8Array> {
    const prepared = await this.prepareEpochKey(epochId, key);
    prepared.commit();
    return prepared.changes;
  }

  async prepareEpochKey(
    epochId: Uint8Array,
    key: CryptoKey,
  ): Promise<PreparedKeychainEpoch<Uint8Array>> {
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
    const entry: CanonicalKeychainEntry = [epochIdHex, serialized];
    const projectionClientID = await currentKeyProjectionClientID(entry);
    const baseEntries = validateYjsKeychain(this._keychain);
    if (baseEntries.length === MAX_KEYCHAIN_EPOCHS) {
      throw new Error('Keychain exceeds the supported epoch limit');
    }
    if (baseEntries.some(([keyID]) => keyID === epochIdHex)) {
      throw new Error('Duplicate keychain key ID');
    }
    const baseRevision = this._revision;
    const staged = new Doc();
    // A first key is authored under its projection identity so the live
    // one-key history and every current-only export of it share one lineage.
    if (baseEntries.length === 0) staged.clientID = projectionClientID;
    applyUpdateV2(staged, encodeStateAsUpdateV2(this._keychain));
    const beforeSV = encodeStateVector(staged);
    staged.getArray<[string, string]>('keys').push([[epochIdHex, serialized]]);
    const stagedEntries = validateYjsKeychain(staged);
    assertAppendOnlyTransition(baseEntries, stagedEntries);
    const commitChanges = encodeStateAsUpdateV2(staged, beforeSV);
    const history = encodeStateAsUpdateV2(staged);
    const currentKeyChange =
      stagedEntries.length === 1
        ? new Uint8Array(history)
        : currentKeyProjection(entry, projectionClientID);
    let committed = false;
    return {
      changes: new Uint8Array(commitChanges),
      history: new Uint8Array(history),
      currentKeyChange,
      commit: () => {
        if (committed) {
          throw new Error('Prepared epoch key was already committed');
        }
        if (this._revision !== baseRevision) {
          throw new Error('Keychain changed while epoch key was staged');
        }
        this._keyCache.set(epochIdHex, key);
        this._keychain = staged;
        this._revision++;
        committed = true;
      },
    };
  }

  history(): Uint8Array {
    validateYjsKeychain(this._keychain);
    return encodeStateAsUpdateV2(this._keychain);
  }
  async stateCommitment(): Promise<Uint8Array> {
    return await yjsKeychainStateCommitment(
      validateYjsKeychain(this._keychain),
    );
  }
  merge(change: Uint8Array): void {
    this.prepareMerge(change).commit();
  }

  prepareMerge(
    changes: Uint8Array,
  ): PreparedKeychainMerge<Uint8Array, CryptoKey> {
    return this._prepareMerge(changes);
  }

  prepareAppend(
    changes: Uint8Array,
    intent: KeychainAppendIntent,
  ): PreparedKeychainMerge<Uint8Array, CryptoKey> {
    return this._prepareMerge(changes, snapshotAppendIntent(intent));
  }

  private _prepareMerge(
    changes: Uint8Array,
    stableAppendIntent?: CanonicalAppendIntent,
  ): PreparedKeychainMerge<Uint8Array, CryptoKey> {
    const commitChanges = copyUnsharedUint8Array(
      changes,
      1,
      10 * 1024 * 1024,
      'Yjs keychain change',
    );
    validateRawYjsKeychainUpdate(commitChanges);
    const baseEntries = validateYjsKeychain(this._keychain);
    const baseRevision = this._revision;
    let staged: Doc | undefined;
    let stagedEntries: CanonicalKeychainEntry[] | undefined;

    // A peer may independently author the same logical epoch entries under
    // different Yjs client IDs. Prefer one complete canonical lineage when
    // its logical history is an exact prefix/superset, avoiding duplicate
    // retained structs while preserving every existing tuple verbatim.
    let incoming: Doc | undefined;
    let incomingEntries: CanonicalKeychainEntry[] | undefined;
    try {
      incoming = new Doc();
      applyUpdateV2(incoming, commitChanges);
      incomingEntries = validateYjsKeychain(incoming);
    } catch {
      incoming = undefined;
      incomingEntries = undefined;
    }
    if (stableAppendIntent !== undefined) {
      if (!incoming || !incomingEntries || incomingEntries.length !== 1) {
        throw new Error(
          'Keychain append intent requires a standalone single-key projection',
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
        staged = new Doc();
        applyUpdateV2(staged, encodeStateAsUpdateV2(this._keychain));
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
        staged = new Doc();
        applyUpdateV2(staged, encodeStateAsUpdateV2(this._keychain));
        staged
          .getArray<[string, string]>('keys')
          .push([[projected[0], projected[1]]]);
        stagedEntries = validateYjsKeychain(staged);
      }
    } else if (incoming && incomingEntries) {
      const current = baseEntries[baseEntries.length - 1];
      if (
        baseEntries.length > 1 &&
        incomingEntries.length === 1 &&
        current !== undefined &&
        sameKeychainEntry(current, incomingEntries[0])
      ) {
        staged = new Doc();
        applyUpdateV2(staged, encodeStateAsUpdateV2(this._keychain));
        stagedEntries = baseEntries;
      } else if (
        baseEntries.length === incomingEntries.length &&
        isKeychainPrefix(baseEntries, incomingEntries)
      ) {
        const baseHistory = encodeStateAsUpdateV2(this._keychain);
        const incomingHistory = encodeStateAsUpdateV2(incoming);
        if (compareBytes(baseHistory, incomingHistory) <= 0) {
          staged = new Doc();
          applyUpdateV2(staged, baseHistory);
          stagedEntries = baseEntries;
        } else {
          staged = incoming;
          stagedEntries = incomingEntries;
        }
      } else if (isKeychainPrefix(baseEntries, incomingEntries)) {
        staged = incoming;
        stagedEntries = incomingEntries;
      } else if (isKeychainPrefix(incomingEntries, baseEntries)) {
        staged = new Doc();
        applyUpdateV2(staged, encodeStateAsUpdateV2(this._keychain));
        stagedEntries = baseEntries;
      } else {
        throw new Error(
          'Standalone keychain history is not an append-only view',
        );
      }
    }

    if (!staged || !stagedEntries) {
      staged = new Doc();
      applyUpdateV2(staged, encodeStateAsUpdateV2(this._keychain));
      applyUpdateV2(staged, commitChanges);
      stagedEntries = validateYjsKeychain(staged);
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
      changes: new Uint8Array(commitChanges),
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
        await yjsKeychainStateCommitment(stagedEntries),
      commit: () => {
        if (committed) {
          throw new Error('Prepared keychain merge was already committed');
        }
        if (this._revision !== baseRevision) {
          throw new Error('Keychain changed while merge was staged');
        }
        const liveCache = this._keyCache;
        for (const [keyID, key] of stagedKeyCache) {
          liveCache.set(keyID, key);
        }
        this._keychain = staged;
        this._revision++;
        committed = true;
      },
    };
  }
  async keys(): Promise<[Uint8Array, CryptoKey][]> {
    validateYjsKeychain(this._keychain);
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
    validateYjsKeychain(this._keychain);
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
    const entries = validateYjsKeychain(this._keychain);
    if (entries.length === 0) {
      throw new Error("Can't get current key change from an empty keychain");
    }

    if (entries.length === 1) {
      return encodeStateAsUpdateV2(this._keychain);
    }
    const current = entries[entries.length - 1];
    return currentKeyProjection(
      current,
      await currentKeyProjectionClientID(current),
    );
  }

  /**
   * Return stable existing keychain operations when the requested boundary is
   * the first retained key.
   *
   * A later Yjs array suffix depends on preceding client clocks/structs. A
   * fresh minimal Doc would merge once, but independently regenerated updates
   * use new client IDs and duplicate entries. Reject boundaries that cannot be
   * served from existing operation history without either that replay ambiguity
   * or disclosure of pre-boundary keys.
   */
  async historySince(keyID: Uint8Array): Promise<Uint8Array> {
    validateYjsKeychain(this._keychain);
    const yarr = this._keychain.getArray<[string, string]>('keys');
    if (yarr.length === 0) {
      throw new Error("Can't get history-since from an empty keychain");
    }
    const cacheKey = keyIdToCacheKey(keyID);
    let startIdx = -1;
    for (let i = 0; i < yarr.length; i++) {
      if (yarr.get(i)[0] === cacheKey) {
        if (startIdx !== -1) {
          throw new Error('Ambiguous keychain history boundary');
        }
        startIdx = i;
      }
    }
    if (startIdx === -1) {
      throw new Error('Unknown keychain history boundary');
    }
    if (startIdx !== 0) {
      throw new Error('Yjs cannot export this keychain suffix replay-safely');
    }
    return encodeStateAsUpdateV2(this._keychain);
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
  // paths means the on-wire key-ID prefix never needs to be truncated;
  // truncation would break post-rotation decryption.
  readonly keyIDLength = KEY_ID_LENGTH_BYTES;
}
