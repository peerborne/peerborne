import { Keychain } from './keychain.js';

/**
 * Factory for Keychain objects.
 *
 * @typeParam KeychainChange Type of a block of change(s) describing edits made to the document keychain.
 * @typeParam DocumentKey Type of a document encryption key.
 */
export interface KeychainProvider<KeychainChange, DocumentKey> {
  /**
   * Construct a new Keychain object.
   *
   * @return A new Keychain object.
   */
  initialize(): Keychain<KeychainChange, DocumentKey>;

  /**
   * Number of bytes reserved on the wire for the key ID prefix on every
   * encrypted block, and the byte width of all key IDs emitted by
   * `Keychain.add()` / `Keychain.addEpochKey()`. The two provisioning
   * paths use the SAME width so the wire-format key-ID prefix is a
   * single fixed size and no truncation step exists between
   * BeeKEM-derived epoch IDs and the keychain's storage key.
   */
  readonly keyIDLength: number;
}
