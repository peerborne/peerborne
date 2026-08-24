/**
 * Derive an AES-GCM `CryptoKey` from a BeeKEM root secret.
 *
 * Used by the BeeKEM-based reader-revocation flow
 * (`PeerborneDocument.removeReader` and the
 * `beekemPathUpdateV1` receive path): after a successful
 * `BeeKEM.removeMember` (which blanks the leaf AND re-derives the
 * writer's path to root in a single step -- no follow-up
 * `BeeKEM.update` is involved), the writer derives the
 * next document encryption key from the new root secret and
 * installs it via `Keychain.addEpochKey`. Surviving readers do the
 * same after `BeeKEM.processPathUpdate`. The removed reader cannot
 * recompute the root secret (their leaf is blanked and the path is
 * re-keyed), so they cannot derive the new document key.
 *
 * The derivation uses HKDF-SHA-256 with a fixed `info` string,
 * `"collabswarm-doc-key-v1"`, so all peers — writer and surviving
 * readers alike — converge on the same AES-GCM key given the same
 * root secret. The `salt` is left empty: BeeKEM's root secret is
 * already uniformly random and per-epoch, so additional salting
 * would only add entropy bookkeeping without changing the security
 * properties.
 *
 * The `info` string carries an explicit version suffix (`-v1`) so a
 * future scheme change (different KDF, different document-key
 * algorithm) can rev the info label and avoid silent collisions
 * with epoch keys derived under the old rule.
 */

/** HKDF `info` label that domain-separates the doc-key derivation. */
export const DOC_KEY_INFO = 'collabswarm-doc-key-v1';

/** AES-GCM key length in bits — must match the document-encryption setup. */
const AES_KEY_BITS = 256;

/**
 * Derive an AES-GCM 256-bit `CryptoKey` from a BeeKEM root secret.
 *
 * @param rootSecret The 32-byte root secret returned by
 *   `BeeKEM.getRootSecret` / `BeeKEM.update` / `BeeKEM.removeMember`.
 * @returns An extractable AES-GCM `CryptoKey` usable for both
 *   `encrypt` and `decrypt` so it can be stored in the document
 *   keychain via `Keychain.addEpochKey`.
 */
export async function deriveDocumentKeyFromRootSecret(
  rootSecret: Uint8Array,
): Promise<CryptoKey> {
  if (!(rootSecret instanceof Uint8Array)) {
    throw new TypeError(
      `deriveDocumentKeyFromRootSecret: rootSecret must be a Uint8Array (got ${typeof rootSecret})`,
    );
  }
  // BeeKEM's root secret width is fixed at 32 bytes (HKDF-SHA-256
  // output via `BeeKEM.getRootSecret` / `BeeKEM.removeMember`). Pin
  // the input width here so a caller that passes a wrong-buffer or a
  // partially-populated view fails fast with a precise error rather
  // than silently deriving a different key than every other peer.
  if (rootSecret.byteLength !== 32) {
    throw new Error(
      `deriveDocumentKeyFromRootSecret: rootSecret must be 32 bytes; got ${rootSecret.byteLength}`,
    );
  }

  // Slice into a fresh ArrayBuffer so WebCrypto sees a BufferSource
  // matching its strict typing (rejects SharedArrayBuffer-backed
  // views) regardless of how `rootSecret` was allocated.
  const ikm = new Uint8Array(rootSecret.byteLength);
  ikm.set(rootSecret);

  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    ikm,
    'HKDF',
    false,
    ['deriveKey'],
  );

  // Empty salt: BeeKEM's root secret is already uniformly random
  // and per-epoch. Domain separation comes from the `info` label.
  const emptySalt = new Uint8Array(0);
  const infoBytes = new TextEncoder().encode(DOC_KEY_INFO);

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: emptySalt,
      info: infoBytes,
    },
    hkdfKey,
    { name: 'AES-GCM', length: AES_KEY_BITS },
    // Extractable so the keychain CRDT can serialize it for
    // peer-to-peer state replication of the epoch keychain.
    true,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Derive a 32-byte epoch ID from a BeeKEM root secret.
 *
 * The epoch ID identifies the resulting document key inside the
 * keychain (it is the keychain's first-class key identifier for
 * messages encrypted under this epoch). Using a stable hash of the
 * root secret keeps every peer's epoch-ID computation in agreement
 * without an explicit ID round-trip.
 *
 * Uses a different HKDF `info` string than
 * `deriveDocumentKeyFromRootSecret` so the epoch ID and the
 * document key remain independent outputs even though both derive
 * from the same root secret.
 */
export async function deriveEpochIdFromRootSecret(
  rootSecret: Uint8Array,
): Promise<Uint8Array> {
  if (!(rootSecret instanceof Uint8Array)) {
    throw new TypeError(
      `deriveEpochIdFromRootSecret: rootSecret must be a Uint8Array (got ${typeof rootSecret})`,
    );
  }
  // Same 32-byte width pin as `deriveDocumentKeyFromRootSecret`. The
  // derived epoch ID is also 32 bytes; both functions consume the
  // same fixed-width BeeKEM root secret so a mismatch on input
  // typically means a wrong buffer was passed.
  if (rootSecret.byteLength !== 32) {
    throw new Error(
      `deriveEpochIdFromRootSecret: rootSecret must be 32 bytes; got ${rootSecret.byteLength}`,
    );
  }

  // Slice into a fresh ArrayBuffer for the same reason as above.
  const ikm = new Uint8Array(rootSecret.byteLength);
  ikm.set(rootSecret);

  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    ikm,
    'HKDF',
    false,
    ['deriveBits'],
  );

  const infoBytes = new TextEncoder().encode(`${DOC_KEY_INFO}/epoch-id`);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: infoBytes,
    },
    hkdfKey,
    32 * 8,
  );
  return new Uint8Array(bits);
}
