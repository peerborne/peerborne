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
   * encoding.
   */
  serializePublicKey(publicKey: PublicKey): Promise<string>;

  /**
   * Restore a public identity from the canonical representation produced by
   * `serializePublicKey`. The result MUST round-trip to the exact same
   * canonical string and MUST be detached from mutable objects owned by the
   * caller of `serializePublicKey` (including nested aliases). Network
   * invitation flows require this operation so the inviter can verify proof
   * of possession from a previously unknown recipient and the recipient can
   * pin the inviter named in the offer. Reader onboarding and role transitions round-trip every identity through
   * this codec before queueing so the target is detached from the caller.
   */
  deserializePublicKey(serialized: string): Promise<PublicKey>;
}

/**
 * Resolve the `serializePublicKey` method of an `AuthProvider`,
 * rejecting a missing or malformed method at the runtime boundary.
 * Callers that depend on the recipient-binding
 * semantics of the Welcome flow should invoke this once at the call
 * site so the failure mode is obvious to operators.
 */
export function requireSerializePublicKey<PrivateKey, PublicKey, DocumentKey>(
  authProvider: AuthProvider<PrivateKey, PublicKey, DocumentKey>,
  featureName: string,
): (publicKey: PublicKey) => Promise<string> {
  const impl = authProvider.serializePublicKey;
  if (typeof impl !== 'function') {
    throw new Error(
      `${featureName} requires AuthProvider.serializePublicKey; ` +
        `AuthProvider.serializePublicKey must be a function`,
    );
  }
  return impl.bind(authProvider);
}

/** Resolve `deserializePublicKey` or fail before starting an invitation. */
export function requireDeserializePublicKey<PrivateKey, PublicKey, DocumentKey>(
  authProvider: AuthProvider<PrivateKey, PublicKey, DocumentKey>,
  featureName: string,
): (serialized: string) => Promise<PublicKey> {
  const impl = authProvider.deserializePublicKey;
  if (typeof impl !== 'function') {
    throw new Error(
      `${featureName} requires AuthProvider.deserializePublicKey; ` +
        `AuthProvider.deserializePublicKey must be a function`,
    );
  }
  return impl.bind(authProvider);
}
