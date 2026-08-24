import { BlindIndexProvider } from './blind-index-provider.js';

/**
 * WebCrypto-based BlindIndexProvider implementation.
 * - Key derivation: HKDF with SHA-256, field path as "info" parameter
 * - Token computation: HMAC-SHA-256 of normalized value, truncated and base64url-encoded
 * - Token truncation: First 16 bytes of HMAC output (128 bits) -- balances collision resistance vs leakage
 */
export class SubtleBlindIndexProvider implements BlindIndexProvider {
  private _tokenLengthBytes: number;

  /**
   * @param tokenLengthBytes Number of bytes to use from HMAC output (default: 16 = 128 bits).
   *   Shorter tokens increase false positives but reduce information leakage.
   */
  constructor(tokenLengthBytes: number = 16) {
    if (!Number.isInteger(tokenLengthBytes) || tokenLengthBytes <= 0 || tokenLengthBytes > 32) {
      throw new RangeError(`tokenLengthBytes must be an integer between 1 and 32, got ${tokenLengthBytes}`);
    }
    this._tokenLengthBytes = tokenLengthBytes;
  }

  /**
   * Derive a field-specific HMAC key from a master key using HKDF with the field path as context.
   * Each unique field path produces a distinct key, ensuring index tokens for different fields
   * are cryptographically isolated.
   *
   * The master key must be a raw-exportable secret key (e.g., AES-GCM/HMAC),
   * so its bytes can be fed into HKDF via `exportKey('raw', ...)`. Keys whose
   * type only supports JWK or PKCS#8 export (asymmetric keys, or symmetric
   * keys generated with raw export disabled) will not work here even if
   * `extractable: true` was set. Prefer `deriveFieldKeyFromRaw` when possible
   * to avoid requiring an extractable master key at all.
   *
   * @param masterKey A raw-exportable secret CryptoKey used as the root secret.
   * @param fieldPath Dot-notation path identifying the field (e.g., "title", "metadata.author").
   *   Must be a non-empty string.
   * @returns A non-extractable CryptoKey usable with `computeToken` and `computeCompoundToken`.
   * @throws If fieldPath is empty/blank or if masterKey cannot be exported as raw bytes.
   */
  async deriveFieldKey(masterKey: CryptoKey, fieldPath: string): Promise<CryptoKey> {
    if (!fieldPath || fieldPath.trim().length === 0) {
      throw new Error('fieldPath must be a non-empty string');
    }
    let rawMaster: ArrayBuffer;
    try {
      rawMaster = await crypto.subtle.exportKey('raw', masterKey);
    } catch {
      throw new Error(
        'Master key must be a raw-exportable secret key (extractable, with raw export supported by the key type).',
      );
    }
    return this._deriveFromRawBytes(new Uint8Array(rawMaster), fieldPath);
  }

  /**
   * Derive a field-specific HMAC key from raw key material (Uint8Array).
   * This avoids the need for an extractable CryptoKey, strengthening key-handling
   * guarantees. The raw bytes are imported as a non-extractable HKDF key internally.
   *
   * @param rawKeyMaterial Raw secret bytes (e.g., 32 bytes of randomness).
   *   Must be at least 16 bytes.
   * @param fieldPath Dot-notation path identifying the field (e.g., "title").
   *   Must be a non-empty string.
   * @returns A non-extractable CryptoKey usable with `computeToken` and `computeCompoundToken`.
   */
  async deriveFieldKeyFromRaw(rawKeyMaterial: Uint8Array, fieldPath: string): Promise<CryptoKey> {
    if (!fieldPath || fieldPath.trim().length === 0) {
      throw new Error('fieldPath must be a non-empty string');
    }
    if (rawKeyMaterial.length < 16) {
      throw new RangeError(`rawKeyMaterial must be at least 16 bytes, got ${rawKeyMaterial.length}`);
    }
    return this._deriveFromRawBytes(rawKeyMaterial, fieldPath);
  }

  /**
   * Shared HKDF derivation logic used by both `deriveFieldKey` and `deriveFieldKeyFromRaw`.
   */
  private async _deriveFromRawBytes(raw: Uint8Array, fieldPath: string): Promise<CryptoKey> {
    // Copy into a fresh Uint8Array backed by a non-shared ArrayBuffer. Calling
    // `.buffer.slice()` on `raw` is not reliable: if `raw` is backed by a
    // `SharedArrayBuffer`, `slice()` returns another `SharedArrayBuffer` which
    // is not a valid `BufferSource` for WebCrypto in many runtimes. The
    // `new Uint8Array(ArrayLike)` constructor allocates a fresh ArrayBuffer
    // and copies the bytes, yielding a `Uint8Array<ArrayBuffer>` that
    // satisfies `importKey`'s BufferSource typing under this tsconfig.
    const copy = new Uint8Array(raw);
    const hkdfKey = await crypto.subtle.importKey('raw', copy, 'HKDF', false, ['deriveKey']);
    const encoder = new TextEncoder();
    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: encoder.encode(fieldPath),
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      false,
      ['sign'],
    );
  }

  /**
   * Compute a blind index token for a single field value.
   * The value is normalized (lowercased/trimmed for strings, prefixed for type disambiguation)
   * then HMAC'd with the field key and truncated.
   *
   * @param fieldKey A field-specific CryptoKey obtained from `deriveFieldKey`.
   * @param value The plaintext field value to tokenize.
   * @returns A base64url-encoded token string suitable for storage and equality comparison.
   */
  async computeToken(fieldKey: CryptoKey, value: string | number): Promise<string> {
    const normalized = this._normalize(value);
    const encoder = new TextEncoder();
    const signature = await crypto.subtle.sign('HMAC', fieldKey, encoder.encode(normalized));
    return this._truncateAndEncode(new Uint8Array(signature));
  }

  /**
   * Compute a compound blind index token from multiple field values.
   * Values are individually normalized and joined with a null separator before HMAC.
   * Useful for multi-field equality queries (e.g., matching on both author and category).
   *
   * @param fieldKey A field-specific CryptoKey obtained from `deriveFieldKey`.
   * @param values Array of plaintext field values to combine into a single token.
   * @returns A base64url-encoded compound token string.
   */
  async computeCompoundToken(fieldKey: CryptoKey, values: (string | number)[]): Promise<string> {
    const normalized = values.map(v => this._normalize(v)).join('\x00');
    const encoder = new TextEncoder();
    const signature = await crypto.subtle.sign('HMAC', fieldKey, encoder.encode(normalized));
    return this._truncateAndEncode(new Uint8Array(signature));
  }

  private _normalize(value: string | number): string {
    if (typeof value === 'number') {
      return `n:${value}`;
    }
    return `s:${value.toLowerCase().trim()}`;
  }

  private _truncateAndEncode(bytes: Uint8Array): string {
    const truncated = bytes.slice(0, this._tokenLengthBytes);
    let binary = '';
    for (let i = 0; i < truncated.length; i++) {
      binary += String.fromCharCode(truncated[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
}
