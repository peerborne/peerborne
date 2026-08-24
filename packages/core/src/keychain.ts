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
   * Used for `current_only` history visibility where new members should only
   * receive the current encryption key, not the full key history.
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
   *   bytes wide. Implementations MAY throw on mismatched widths but
   *   the shipped providers store the supplied bytes verbatim.
   * @param key The encryption key for this epoch.
   * @return A block of change(s) describing the keychain addition.
   */
  addEpochKey(epochId: Uint8Array, key: DocumentKey): Promise<KeychainChange>;

  /**
   * Gets a block of change(s) describing only the keys at or after the given
   * key ID. Used for the `since_invited` history visibility mode where a new
   * member should receive every key from the moment they were invited onward,
   * but no earlier history.
   *
   * If the supplied `keyID` is not present in the keychain, the keychain is
   * not yet aware of that epoch -- the method returns the full history so the
   * recipient can still decrypt; this errs on the side of availability.
   *
   * Optional for backwards compatibility with `Keychain` implementations
   * written before the `since_invited` history-visibility mode landed. When a
   * provider does not implement this method, `since_invited` falls back to
   * `history()` (matching the documented "boundary unknown" recovery path).
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
 * Returns a function that invokes `keychain.historySince` when the
 * implementation provides it, and falls back to `keychain.history()`
 * otherwise. Lets callers (notably
 * `PeerborneDocument._keychainChangesForVisibility`) compile against
 * the optional interface method without scattering null checks at
 * every call site.
 */
export function keychainHistorySinceOrFull<KeychainChange, DocumentKey>(
  keychain: Keychain<KeychainChange, DocumentKey>,
): (keyID: Uint8Array) => Promise<KeychainChange> {
  const impl = keychain.historySince;
  if (impl) {
    return (keyID) => impl.call(keychain, keyID);
  }
  return async () => keychain.history();
}
