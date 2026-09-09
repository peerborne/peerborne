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
   * Gets a block of change(s) describing the whole state of the keychain.
   *
   * @return A block of change(s) describing the keychain.
   */
  history(): KeychainChange;

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
   * @return A block of change(s) containing only the current key.
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
  ): PreparedKeychainMerge<KeychainChange>;

  /**
   * Gets a block of change(s) describing only the keys at or after the given
   * key ID. Used for the `since_invited` history visibility mode where a new
   * member receives every key from the moment they were invited onward, but
   * no earlier epoch keys. It does not itself redact retained CRDT operations.
   *
   * If the supplied `keyID` is not present in the keychain, implementations
   * MUST return only the current-key change or reject. Returning full history
   * would disclose every pre-invitation epoch when the boundary is malformed,
   * stale, or attacker-controlled.
   *
   * Optional for backwards compatibility with `Keychain` implementations
   * written before the `since_invited` history-visibility mode landed. When a
   * provider does not implement this method, `since_invited` falls back to
   * `currentKeyChange()` so a missing capability cannot widen disclosure.
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
  ): PreparedKeychainMerge<KeychainChange>;
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
  /** Standalone staged current-key-only state. */
  readonly currentKeyChange: KeychainChange;
  /** Synchronous, single-use, atomic live-state commit. */
  commit(): void;
}

export interface PreparedKeychainMerge<KeychainChange> {
  /** Detached staged state, retained for diagnostics/tests. */
  readonly changes: KeychainChange;
  /** Key IDs in the staged provider's canonical history order. */
  readonly keyIds: readonly Uint8Array[];
  /** Synchronous, single-use, atomic live-state commit. */
  commit(): void;
}

/**
 * Returns a function that invokes `keychain.historySince` when the
 * implementation provides it, and falls back to `currentKeyChange()`
 * otherwise. The historical export name is retained for source compatibility;
 * its fallback is deliberately fail-closed. It lets callers compile against
 * the optional interface method without scattering null checks at every call
 * site.
 */
export function keychainHistorySinceOrFull<KeychainChange, DocumentKey>(
  keychain: Keychain<KeychainChange, DocumentKey>,
): (keyID: Uint8Array) => Promise<KeychainChange> {
  const impl = keychain.historySince;
  if (impl) {
    return (keyID) => impl.call(keychain, keyID);
  }
  return async () => keychain.currentKeyChange();
}
