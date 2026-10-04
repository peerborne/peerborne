// Restrict access to those on ACL

/** Supported AES encryption algorithm names. */
export type AesAlgorithmName = 'AES-GCM' | 'AES-CTR' | 'AES-CBC';

export type EncryptionResult = {
  data: Uint8Array;
  nonce?: Uint8Array;
};

export interface AuthProvider<PrivateKey, PublicKey, DocumentKey = string> {
  sign(data: Uint8Array, privateKey: PrivateKey): Promise<Uint8Array>;
  verify(
    data: Uint8Array,
    publicKey: PublicKey,
    signature: Uint8Array,
  ): Promise<boolean>;
  encrypt(
    data: Uint8Array,
    documentKey: DocumentKey,
  ): Promise<EncryptionResult>;
  decrypt(
    data: Uint8Array,
    documentKey: DocumentKey,
    nonce?: Uint8Array,
  ): Promise<Uint8Array>;

  /**
   * Returns the nonce/IV size in bytes for the configured encryption algorithm.
   */
  readonly nonceBytes: number;

  /**
   * Serialize a `PublicKey` to a stable string representation. The
   * representation MUST be canonical and collision-free for the provider's
   * identity domain: two keys serialize equally if and only if the provider
   * treats them as the same identity. Two peers must therefore reach the same
   * identity decision from the serialized strings.
   *
   * Implementations MUST capture every caller-owned value needed for the
   * encoding synchronously, before their first asynchronous suspension, and
   * MUST NOT retain a mutable caller-owned object for later inspection. Role
   * transitions snapshot identities before waiting for the document mutation
   * queue; deferring the read until after an `await` would let the caller
   * change which identity the queued operation targets.
   *
   * This is used by the BeeKEM Welcome flow (recipient binding) and is
   * intentionally generic so non-CryptoKey providers (e.g.
   * opaque/hash-based identities) can supply their own canonical
   * encoding. Membership changes use it to snapshot the target identity
   * before they wait for the document mutation queue.
   */
  serializePublicKey(publicKey: PublicKey): Promise<string>;

  /**
   * Restore a public identity from the canonical representation produced by
   * `serializePublicKey`. The result MUST round-trip to the exact same
   * canonical string and MUST be detached from mutable objects owned by the
   * caller of `serializePublicKey` (including nested aliases). Network
   * invitation flows require this operation so the inviter can verify proof
   * of possession from a previously unknown recipient and the recipient can
   * pin the inviter named in the offer. Reader and writer membership changes
   * round-trip every target identity through this codec before queueing so the
   * queued target is detached from the caller.
   */
  deserializePublicKey(serialized: string): Promise<PublicKey>;
}

/**
 * Resolve the `serializePublicKey` method of an `AuthProvider`, rejecting a
 * missing or non-function member at the JavaScript runtime boundary.
 */
export function requireSerializePublicKey<PrivateKey, PublicKey, DocumentKey>(
  authProvider: AuthProvider<PrivateKey, PublicKey, DocumentKey>,
  featureName: string,
): (publicKey: PublicKey) => Promise<string> {
  const impl = authProvider.serializePublicKey;
  if (typeof impl !== 'function') {
    throw new TypeError(
      `${featureName} requires AuthProvider.serializePublicKey to be a function`,
    );
  }
  return impl.bind(authProvider);
}

/**
 * Resolve the `deserializePublicKey` method of an `AuthProvider`, rejecting a
 * missing or non-function member at the JavaScript runtime boundary.
 */
export function requireDeserializePublicKey<PrivateKey, PublicKey, DocumentKey>(
  authProvider: AuthProvider<PrivateKey, PublicKey, DocumentKey>,
  featureName: string,
): (serialized: string) => Promise<PublicKey> {
  const impl = authProvider.deserializePublicKey;
  if (typeof impl !== 'function') {
    throw new TypeError(
      `${featureName} requires AuthProvider.deserializePublicKey to be a function`,
    );
  }
  return impl.bind(authProvider);
}
