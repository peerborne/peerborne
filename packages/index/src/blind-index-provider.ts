/**
 * Provider interface for computing blind index tokens.
 * Blind indexes enable exact-match queries over encrypted data without exposing plaintext values.
 * Based on the CipherSweet approach: HMAC(field_key, normalize(value))
 */
export interface BlindIndexProvider {
  /**
   * Derive a field-specific key from a master key using the field path as context.
   * Uses HKDF or similar key derivation.
   */
  deriveFieldKey(masterKey: CryptoKey, fieldPath: string): Promise<CryptoKey>;

  /**
   * Derive a field-specific key from raw key material (Uint8Array) using the field path
   * as context. This allows the caller to avoid ever creating an extractable CryptoKey,
   * which strengthens key-handling guarantees.
   */
  deriveFieldKeyFromRaw(rawKeyMaterial: Uint8Array, fieldPath: string): Promise<CryptoKey>;

  /**
   * Compute a blind index token for a single field value.
   * The token is a deterministic, one-way transform of the value.
   */
  computeToken(fieldKey: CryptoKey, value: string | number): Promise<string>;

  /**
   * Compute a compound blind index token from multiple field values.
   * Useful for multi-field equality queries.
   */
  computeCompoundToken(fieldKey: CryptoKey, values: (string | number)[]): Promise<string>;
}
