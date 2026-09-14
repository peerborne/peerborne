import { copyUnsharedUint8Array } from './utils.js';

/** Maximum retained epochs supported by the built-in keychain adapters. */
export const MAX_KEYCHAIN_EPOCHS = 1000;

const KEYCHAIN_STATE_COMMITMENT_DOMAIN = 'peerborne:keychain-state:v1\0';
const KEYCHAIN_COMMITMENT_VALUE_BYTES = 32;

/**
 * Hash a canonical ordered keychain sequence independently of its CRDT
 * operation identities. The committed encoding is the ASCII domain above,
 * followed by a big-endian u32 entry count and, for each entry, big-endian
 * u32 lengths plus the 32-byte key ID and 32 raw AES-key bytes.
 */
export async function computeKeychainStateCommitment(
  entries: readonly (readonly [Uint8Array, Uint8Array])[],
): Promise<Uint8Array> {
  if (!Array.isArray(entries)) {
    throw new TypeError('Keychain commitment entries must be an array');
  }
  const entryCount = entries.length;
  if (!Number.isSafeInteger(entryCount) || entryCount < 0) {
    throw new TypeError('Invalid keychain commitment entry count');
  }
  if (entryCount > MAX_KEYCHAIN_EPOCHS) {
    throw new Error('Keychain exceeds the supported epoch limit');
  }

  const domain = new TextEncoder().encode(KEYCHAIN_STATE_COMMITMENT_DOMAIN);
  const encoded = new Uint8Array(
    domain.byteLength +
      4 +
      entryCount *
        (4 +
          KEYCHAIN_COMMITMENT_VALUE_BYTES +
          4 +
          KEYCHAIN_COMMITMENT_VALUE_BYTES),
  );
  encoded.set(domain);
  const view = new DataView(encoded.buffer);
  let offset = domain.byteLength;
  view.setUint32(offset, entryCount, false);
  offset += 4;

  const keyIds = new Set<string>();
  for (let index = 0; index < entryCount; index++) {
    const entry = entries[index];
    if (!Array.isArray(entry) || entry.length !== 2) {
      throw new TypeError('Invalid keychain commitment entry');
    }
    const keyId = copyUnsharedUint8Array(
      entry[0],
      KEYCHAIN_COMMITMENT_VALUE_BYTES,
      KEYCHAIN_COMMITMENT_VALUE_BYTES,
      'Keychain commitment key ID',
    );
    const rawKey = copyUnsharedUint8Array(
      entry[1],
      KEYCHAIN_COMMITMENT_VALUE_BYTES,
      KEYCHAIN_COMMITMENT_VALUE_BYTES,
      'Keychain commitment raw key',
    );
    const keyIdHex = Array.from(keyId, (byte) =>
      byte.toString(16).padStart(2, '0'),
    ).join('');
    if (keyIds.has(keyIdHex)) {
      throw new Error('Duplicate keychain commitment key ID');
    }
    keyIds.add(keyIdHex);
    view.setUint32(offset, keyId.byteLength, false);
    offset += 4;
    encoded.set(keyId, offset);
    offset += keyId.byteLength;
    view.setUint32(offset, rawKey.byteLength, false);
    offset += 4;
    encoded.set(rawKey, offset);
    offset += rawKey.byteLength;
  }

  return new Uint8Array(await crypto.subtle.digest('SHA-256', encoded));
}

/**
 * A keychain contains a PeerborneDocument's encryption keys.
 *
 * Keys are identified by a fixed-width binary key ID. Both
 * provisioning paths (`add()`, which generates random per-key
 * identifiers, and `addEpochKey()`, which installs BeeKEM-derived
 * epoch IDs from `deriveEpochIdFromRootSecret`) use the SAME byte
 * width -- 32 bytes in the shipped Yjs / Automerge providers, surfaced
 * via `KeychainProvider.keyIDLength`. The matching width means the
 * wire-format encrypted-block key-ID prefix is a single fixed size for
 * any key the keychain has installed, regardless of how it was
 * provisioned: there is no truncation step, and `getKey()` never has to
 * disambiguate between key-ID encodings.
 *
 * @typeParam KeychainChange Type of a block of change(s) describing edits made to the document keychain.
 * @typeParam DocumentKey Type of a document encryption key.
 */
export interface Keychain<KeychainChange, DocumentKey> {
  /**
   * Generates and adds a new document encryption key to the keychain.
   *
   * @return The new document key ID, key, and a block of change(s) describing the keychain addition.
   */
  add(): Promise<[Uint8Array, DocumentKey, KeychainChange]>;

  /**
   * Stage generation and insertion of a random document key without mutating
   * live state. Callers can finish fallible wire preparation before invoking
   * the synchronous commit. Optional for backwards compatibility; workflows
   * that require it must feature-detect and fail closed when absent.
   */
  prepareKey?(): Promise<
    PreparedKeychainAddition<KeychainChange, DocumentKey>
  >;

  /**
   * Gets a block of change(s) describing the whole state of the keychain.
   *
   * @return A block of change(s) describing the keychain.
   */
  history(): KeychainChange;

  /**
   * Commit to the validated ordered logical key sequence independently of
   * provider-specific CRDT operation identities. Optional for backwards
   * compatibility; implementations MUST use
   * `computeKeychainStateCommitment`, and protocols that require this binding
   * must feature-detect it.
   */
  stateCommitment?(): Promise<Uint8Array>;

  /**
   * Merges in a block of change(s) to the keychain.
   *
   * @param change A block of change(s) to apply.
   */
  merge(change: KeychainChange): void;

  /**
   * Gets the all document encryption keys in the keychain.
   *
   * @return all document encryption keys.
   */
  keys(): Promise<[Uint8Array, DocumentKey][]>;

  /**
   * Gets the current encryption key that should be used to encrypt new changes.
   */
  current(): Promise<[Uint8Array, DocumentKey]>;

  /**
   * Looks up a document key by its ID.
   *
   * @param keyID An identifier for a document key. Provider implementations
   *   define the width via `KeychainProvider.keyIDLength` and both
   *   provisioning paths (`add()` and `addEpochKey()`) emit IDs of that
   *   exact width.
   * @return The requested document key.
   */
  getKey(keyID: Uint8Array): DocumentKey | undefined;

  /**
   * Gets a block of change(s) describing only the current (most recent) key.
   * Used for `current_only` key distribution where new members receive the
   * current encryption key, not the full key history. This does not itself
   * redact retained CRDT operations encrypted during that epoch.
   *
   * The returned value MUST be safe to regenerate and replay without creating
   * a second logical keychain entry. Implementations whose CRDT operation
   * history cannot represent the isolated current key replay-safely MUST
   * reject instead of synthesizing a fresh actor/client operation.
   *
   * @return A replay-safe block of change(s) containing only the current key.
   */
  currentKeyChange(): Promise<KeychainChange>;

  /**
   * Add an encryption key for a specific epoch. The epoch ID is the
   * full HKDF output from `deriveEpochIdFromRootSecret` -- the
   * `KeychainProvider.keyIDLength`-wide identifier (32 bytes in the
   * shipped providers) that also becomes the wire-format key-ID
   * prefix on subsequent encrypted blocks. No truncation: the byte
   * width is uniform across provisioning, storage, and the wire.
   *
   * @param epochId The epoch ID, exactly `KeychainProvider.keyIDLength`
   *   bytes wide. Implementations MUST reject a mismatched width instead of
   *   truncating or padding it. The shipped providers require exactly 32 bytes
   *   and store those validated bytes verbatim.
   * @param key The encryption key for this epoch.
   * @return A block of change(s) describing the keychain addition.
   */
  addEpochKey(epochId: Uint8Array, key: DocumentKey): Promise<KeychainChange>;

  /**
   * Stage an epoch-key insertion without mutating live keychain state.
   * Transactional BeeKEM membership transitions can use this optional
   * capability to finish all fallible signing, sealing, serialization, and
   * block preparation before a synchronous keychain/tree commit. Custom
   * keychains that omit it cannot be used for transactional BeeKEM add/remove
   * operations.
   *
   * `commit()` MUST either apply the staged state completely or throw before
   * mutation. It is called at most once, after every asynchronous preparation
   * step has succeeded.
   *
   * The `epochId` width contract is identical to `addEpochKey()`: it must equal
   * `KeychainProvider.keyIDLength`, exactly 32 bytes in the shipped providers,
   * and a mismatch must be rejected before any state is staged or mutated.
   *
   * @param epochId The full-width epoch identifier.
   * @param key The encryption key for this epoch.
   */
  prepareEpochKey?(
    epochId: Uint8Array,
    key: DocumentKey,
  ): Promise<PreparedKeychainEpoch<KeychainChange>>;

  /** Stage a remote keychain merge for an atomic Welcome state commit. */
  prepareMerge?(
    change: KeychainChange,
  ): PreparedKeychainMerge<KeychainChange, DocumentKey>;

  /**
   * Stage an authenticated, predecessor-bound standalone key append. This is
   * intentionally distinct from `prepareMerge()` so legacy implementations
   * cannot silently ignore append authority passed as an extra argument.
   * Implementations MUST require a canonical one-key projection matching
   * `expectedNewKeyId`. They may append only when the live current key matches
   * `expectedPreviousKeyId`, or return an unchanged exact replay when the live
   * sequence already ends with the expected previous/new pair and material.
   */
  prepareAppend?(
    change: KeychainChange,
    intent: KeychainAppendIntent,
  ): PreparedKeychainMerge<KeychainChange, DocumentKey>;

  /**
   * Gets a block of change(s) describing only the keys at or after the given
   * key ID. Used for the `since_invited` history visibility mode where a new
   * member receives every key from the moment they were invited onward, but
   * no earlier epoch keys. It does not itself redact retained CRDT operations.
   *
   * The returned value MUST be safe to regenerate and replay: repeated calls
   * for the same boundary and keychain state must not create fresh CRDT
   * actor/client operations that duplicate keys or change the visible window.
   * Implementations MUST reject when their CRDT cannot project the requested
   * suffix from stable existing operation history without including keys before
   * the boundary. In particular, an unknown, stale, or attacker-controlled
   * `keyID` MUST reject unless the implementation can derive a replay-safe
   * current-key-only change from existing operation history. Returning full
   * history would disclose every pre-invitation epoch.
   *
   * Optional for backwards compatibility with `Keychain` implementations
   * written before the `since_invited` history-visibility mode landed. When a
   * provider does not implement this method, `since_invited` rejects rather
   * than guessing that a newly synthesized `currentKeyChange()` is replay-safe.
   * Custom keychains that want efficient `since_invited` filtering SHOULD
   * implement this method directly; the next major version will make it
   * required.
   *
   * @param keyID The key ID marking the start of the visible window.
   * @return A block of change(s) containing only keys at or after `keyID`.
   */
  historySince?(keyID: Uint8Array): Promise<KeychainChange>;
}

/**
 * Keychain capability for staging BeeKEM membership transitions.
 *
 * Callers that require an atomic ratchet/keychain transition can use
 * `isTransactionalKeychain` to require both staging methods. A plain
 * `Keychain` remains source-compatible with implementations that omit them.
 */
export interface TransactionalKeychain<KeychainChange, DocumentKey>
  extends Keychain<KeychainChange, DocumentKey> {
  prepareEpochKey(
    epochId: Uint8Array,
    key: DocumentKey,
  ): Promise<PreparedKeychainEpoch<KeychainChange>>;

  prepareMerge(
    change: KeychainChange,
  ): PreparedKeychainMerge<KeychainChange, DocumentKey>;
}

/** Return whether a keychain supports atomic BeeKEM transition staging. */
export function isTransactionalKeychain<KeychainChange, DocumentKey>(
  keychain: Keychain<KeychainChange, DocumentKey>,
): keychain is TransactionalKeychain<KeychainChange, DocumentKey> {
  return (
    typeof keychain.prepareEpochKey === 'function' &&
    typeof keychain.prepareMerge === 'function'
  );
}

export interface PreparedKeychainEpoch<KeychainChange> {
  /** Delta suitable for an already-synchronized keychain. */
  readonly changes: KeychainChange;
  /** Standalone full staged keychain history. */
  readonly history: KeychainChange;
  /**
   * Standalone staged current-key-only state. Callers may cache and replay
   * these exact bytes, but MUST NOT regenerate an equivalent projection under
   * fresh CRDT operation IDs after the staged transition has committed.
   * `undefined` means callers that require current-only distribution must fail
   * closed.
   */
  readonly currentKeyChange?: KeychainChange;
  /** Synchronous, single-use, atomic live-state commit. */
  commit(): void;
}

export interface PreparedKeychainAddition<KeychainChange, DocumentKey>
  extends PreparedKeychainEpoch<KeychainChange> {
  /** Detached full-width ID of the staged random key. */
  readonly keyId: Uint8Array;
  /** Generated document key installed by `commit()`. */
  readonly key: DocumentKey;
}

/** Explicit protocol intent for a standalone single-key projection. */
export type KeychainAppendIntent = {
  /** Key that must immediately precede the appended key. */
  readonly expectedPreviousKeyId: Uint8Array;
  /** Key ID that the standalone projection must contain. */
  readonly expectedNewKeyId: Uint8Array;
};

export interface PreparedKeychainMerge<KeychainChange, DocumentKey> {
  /** Detached staged state, retained for diagnostics/tests. */
  readonly changes: KeychainChange;
  /** Detached key IDs in the staged provider's canonical history order. */
  readonly keyIds: readonly Uint8Array[];
  /** Detached ID of the staged current/final key, or undefined when empty. */
  readonly currentKeyId: Uint8Array | undefined;
  /** Validate, import, and hydrate the detached staged keychain. */
  hydrateKeys(): Promise<[Uint8Array, DocumentKey][]>;
  /** Look up a key hydrated by `hydrateKeys()` without mutating live state. */
  getKey(keyID: Uint8Array): DocumentKey | undefined;
  /**
   * Commit to the detached staged logical key sequence with
   * `computeKeychainStateCommitment`, when supported.
   */
  stateCommitment?(): Promise<Uint8Array>;
  /**
   * Synchronous, single-use, atomic live-state commit. Keys already hydrated
   * through this staged view MUST become immediately available from the live
   * keychain's `getKey()` when commit returns.
   */
  commit(): void;
}

/**
 * Returns a function that invokes `keychain.historySince` when the
 * implementation provides it, and returns a rejecting function otherwise.
 * The historical export name is retained for source compatibility. Rejecting
 * is deliberately fail-closed: core cannot know whether an arbitrary legacy
 * provider's newly generated `currentKeyChange()` is operation-idempotent.
 */
export function keychainHistorySinceOrFull<KeychainChange, DocumentKey>(
  keychain: Keychain<KeychainChange, DocumentKey>,
): (keyID: Uint8Array) => Promise<KeychainChange> {
  const impl = keychain.historySince;
  if (impl) {
    return (keyID) => impl.call(keychain, keyID);
  }
  return async () => {
    throw new Error('Keychain does not support replay-safe history slicing');
  };
}
