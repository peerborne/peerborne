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
   * Returns the nonce/IV size **in bytes** for the configured encryption
   * algorithm. The property name is a historical artifact — it represents
   * a byte count, not a bit count.
   */
  readonly nonceBits: number;

  /**
   * Serialize a `PublicKey` to a stable string representation. The
   * representation MUST be deterministic for a given key so two peers
   * can compare serialized strings for equality and reach the same
   * conclusion about whether a `PublicKey` is the same identity.
   *
   * This is used by the BeeKEM Welcome flow (recipient binding) and is
   * intentionally generic so non-CryptoKey providers (e.g.
   * opaque/hash-based identities) can supply their own canonical
   * encoding.
   *
   * Optional for backwards compatibility with `AuthProvider`
   * implementations written before the Welcome flow landed. When a
   * provider does not implement this method, features that require a
   * canonical public-key string (e.g. BeeKEM Welcome's recipient
   * binding gate) are unavailable and the caller will throw; see
   * `requireSerializePublicKey` in `auth-provider.ts` for the shared
   * helper that raises a clear error in that case. Custom providers
   * that want to participate in Welcome onboarding SHOULD implement
   * this method; the next major version will make it required.
   */
  serializePublicKey?(publicKey: PublicKey): Promise<string>;
}

/**
 * Resolve the `serializePublicKey` method of an `AuthProvider`,
 * throwing a clear error if the provider has not implemented this
 * optional method. Callers that depend on the recipient-binding
 * semantics of the Welcome flow should invoke this once at the call
 * site so the failure mode is obvious to operators.
 */
export function requireSerializePublicKey<PrivateKey, PublicKey, DocumentKey>(
  authProvider: AuthProvider<PrivateKey, PublicKey, DocumentKey>,
  featureName: string,
): (publicKey: PublicKey) => Promise<string> {
  const impl = authProvider.serializePublicKey;
  if (!impl) {
    throw new Error(
      `${featureName} requires AuthProvider.serializePublicKey, but the ` +
        `current AuthProvider does not implement it. Upgrade or provide a ` +
        `serializePublicKey method on your AuthProvider implementation.`,
    );
  }
  return impl.bind(authProvider);
}
