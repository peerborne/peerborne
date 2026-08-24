import { AuthProvider, AesAlgorithmName } from './auth-provider.js';
import { concatUint8Arrays } from './utils.js';
import { Base64 } from 'js-base64';

/** HMAC-SHA256 tag length in bytes. */
const HMAC_TAG_LENGTH = 32;

/**
 * Used to wrap CryptoKey so that initialized vector used in encryption
 * can be stored for decryption.
 *
 * @param data: encrypted data
 * @param nonce: unique value used for encryption and needed for decryption
 */
export type SubtleCryptoEncryptionResult = {
  data: Uint8Array;
  nonce: Uint8Array;
};

/**
 * SubtleCrypto implements `AuthProvider` using WebCrypto's Subtle API.
 *
 * Supports AES-GCM (default, AEAD), AES-CTR, and AES-CBC. For non-AEAD
 * modes (CTR, CBC) an encrypt-then-MAC (HMAC-SHA256) construction is
 * used automatically to provide ciphertext authentication.
 *
 * The base keytype is `CryptoKey`.
 */
export class SubtleCrypto
  implements AuthProvider<CryptoKey, CryptoKey, CryptoKey>
{
  /** Cache derived HMAC keys to avoid re-deriving per call. */
  private _hmacKeyCache = new WeakMap<CryptoKey, CryptoKey>();

  /**
   * @remarks The `nonceBits` constructor parameter was removed in the
   * AES-CTR/CBC support update. Nonce size is now derived automatically
   * from the configured encryption algorithm (12 bytes for GCM, 16 bytes
   * for CTR/CBC) via the `nonceBits` getter. No migration is needed as
   * there are no live consumers of the previous constructor signature.
   */
  constructor(
    /**
     * The type of algorithm used for signature and verification keys.
     *
     * @remarks https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign
     */
    public readonly signingAlgorithm:
      | AlgorithmIdentifier
      | RsaPssParams
      | EcdsaParams
      | AesCbcParams = {
      name: 'ECDSA',
      hash: { name: 'SHA-384' },
    },

    /**
     * The encryption algorithm to use for encrypt/decrypt.
     *
     * AES-GCM provides built-in AEAD. AES-CTR and AES-CBC use an
     * encrypt-then-MAC (HMAC-SHA256) construction for authentication.
     */
    public readonly _encryptionAlgorithmName: AesAlgorithmName = 'AES-GCM',
  ) {}

  /**
   * Returns the nonce/IV size **in bytes** for the configured encryption
   * algorithm. The property name is a historical artifact.
   *
   * - AES-GCM: 12 bytes (96-bit IV, standard)
   * - AES-CTR: 16 bytes (128-bit counter block)
   * - AES-CBC: 16 bytes (128-bit IV)
   *
   * **Breaking change:** GCM nonce was previously 96 *bytes* (a bug).
   * It is now 12 bytes (96 bits) per the NIST recommendation. Blocks
   * encrypted with the old 96-byte nonce cannot be decrypted with this
   * version. There are no known live users, so no migration is provided.
   */
  get nonceBits(): number {
    switch (this._encryptionAlgorithmName) {
      case 'AES-GCM':
        return 12;
      case 'AES-CTR':
      case 'AES-CBC':
        return 16;
      default:
        throw new Error(`Unsupported encryption algorithm: ${this._encryptionAlgorithmName}`);
    }
  }

  /**
   * Extract the nonce/IV/counter from encryption algorithm parameters.
   * Supports AES-GCM (iv), AES-CTR (counter), and AES-CBC (iv).
   * Normalizes BufferSource values to Uint8Array.
   */
  private _extractNonce(params: AesGcmParams | AesCtrParams | AesCbcParams): Uint8Array {
    let raw: BufferSource | undefined;
    if ('iv' in params) {
      raw = params.iv;
    } else if ('counter' in params) {
      raw = params.counter;
    }
    if (!raw) {
      throw new Error(`Cannot extract nonce from algorithm: ${(params as any).name}`);
    }
    // Normalize BufferSource to Uint8Array, respecting byteOffset/byteLength for views.
    if (raw instanceof Uint8Array) return raw;
    if (raw instanceof ArrayBuffer) return new Uint8Array(raw);
    // ArrayBufferView -- respect offset and length to avoid reading unrelated bytes.
    return new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
  }

  /**
   * Generate algorithm parameters for the configured encryption algorithm.
   *
   * @param nonce - If provided, used as the IV/counter. Otherwise a random one is generated.
   */
  _encryptionAlgorithmParams(nonce?: Uint8Array): AesGcmParams | AesCtrParams | AesCbcParams {
    switch (this._encryptionAlgorithmName) {
      case 'AES-GCM': {
        if (nonce && nonce.length !== 12) {
          throw new Error(`AES-GCM nonce must be 12 bytes, got ${nonce.length}`);
        }
        const iv = nonce ?? crypto.getRandomValues(new Uint8Array(12));
        return { name: 'AES-GCM', iv: iv as Uint8Array<ArrayBuffer> };
      }
      case 'AES-CTR': {
        if (nonce && nonce.length !== 16) {
          throw new Error(`AES-CTR counter must be 16 bytes, got ${nonce.length}`);
        }
        // length: 32 splits the 128-bit counter block into a 96-bit per-message
        // nonce (upper bits) and a 32-bit counter (lower bits). When we
        // generate the counter ourselves, randomize the upper 96 bits as the
        // nonce and zero the lower 32 counter bits. This matches NIST SP 800-38A
        // guidance and keeps collision risk negligible up to ~2^48 messages
        // (birthday bound on a 96-bit random nonce). An externally supplied
        // `nonce` is used as-is; the caller is responsible for choosing a safe
        // initial counter value.
        let counter: Uint8Array;
        if (nonce) {
          counter = nonce;
        } else {
          counter = new Uint8Array(16);
          crypto.getRandomValues(counter.subarray(0, 12));
        }
        return { name: 'AES-CTR', counter: counter as Uint8Array<ArrayBuffer>, length: 32 };
      }
      case 'AES-CBC': {
        if (nonce && nonce.length !== 16) {
          throw new Error(`AES-CBC IV must be 16 bytes, got ${nonce.length}`);
        }
        const iv = nonce ?? crypto.getRandomValues(new Uint8Array(16));
        return { name: 'AES-CBC', iv: iv as Uint8Array<ArrayBuffer> };
      }
      default:
        throw new Error(`Unsupported encryption algorithm: ${this._encryptionAlgorithmName}`);
    }
  }

  /**
   * Derive an HMAC-SHA256 key from a document encryption key via HKDF.
   * Used for encrypt-then-MAC with AES-CTR and AES-CBC.
   * Results are cached per CryptoKey instance.
   */
  private async _deriveHmacKey(documentKey: CryptoKey): Promise<CryptoKey> {
    const cached = this._hmacKeyCache.get(documentKey);
    if (cached) return cached;

    if (!documentKey.extractable) {
      throw new Error(
        'Cannot derive HMAC key: the document encryption key must be extractable. ' +
        'Ensure the key was created with extractable: true.',
      );
    }
    const rawBytes = await crypto.subtle.exportKey('raw', documentKey);
    const hkdfKey = await crypto.subtle.importKey(
      'raw',
      rawBytes,
      'HKDF',
      false,
      ['deriveKey'],
    );
    const hmacKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new ArrayBuffer(0),
        info: new TextEncoder().encode(`hmac-auth-${this._encryptionAlgorithmName.toLowerCase()}`),
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      false,
      ['sign', 'verify'],
    );
    this._hmacKeyCache.set(documentKey, hmacKey);
    return hmacKey;
  }

  /**
   * Given encrypted changes and a private key, returns a signature.
   *
   * @param data encrypted data to be signed
   * @param privateKey - part of key pair used to sign and verify
   * @returns signature for use in a CRDTChangeBlock
   */
  public async sign(
    data: Uint8Array,
    privateKey: CryptoKey,
  ): Promise<Uint8Array> {
    return new Uint8Array(
      await crypto.subtle.sign(this.signingAlgorithm, privateKey, data as Uint8Array<ArrayBuffer>),
    );
  }

  /**
   * Given a signature and data (from a CRDTChangeBlock), a Promise that fulfills with true if the signature is valid, false otherwise
   *
   * @param data data that was signed
   * @param publicKey part of key pair used to sign and verify
   * @param signature signature to verify
   * @returns a Promise that fulfills with true if the signature is valid, false otherwise
   */
  public async verify(
    data: Uint8Array,
    publicKey: CryptoKey,
    signature: Uint8Array,
  ): Promise<boolean> {
    return await crypto.subtle.verify(
      this.signingAlgorithm,
      publicKey,
      signature as Uint8Array<ArrayBuffer>,
      data as Uint8Array<ArrayBuffer>,
    );
  }

  /**
   * Serialize a public `CryptoKey` to a stable base64-encoded string.
   *
   * The encoding matches the one used by ACLs and keychain entries in
   * the yjs and automerge providers (`exportKey('raw', ...)` +
   * Base64), so a `welcomeRecipient` value attached by one peer is
   * directly comparable to another peer's serialized public key.
   *
   * The key must be extractable; this is satisfied for all keys
   * imported or generated by the SubtleCrypto provider in this
   * codebase.
   */
  public async serializePublicKey(publicKey: CryptoKey): Promise<string> {
    if (!publicKey.extractable) {
      throw new Error(
        'BeeKEM Welcome recipient binding requires an extractable public key, ' +
          'but the provided CryptoKey has extractable=false. When generating ' +
          'keys via crypto.subtle.generateKey, pass extractable=true (or use a ' +
          'separately-generated extractable verifying key).',
      );
    }
    const raw = await crypto.subtle.exportKey('raw', publicKey);
    return Base64.fromUint8Array(new Uint8Array(raw));
  }

  /**
   * Decrypt data using the configured encryption algorithm.
   *
   * For AES-GCM, authentication is built-in (AEAD). For AES-CTR and
   * AES-CBC, the HMAC-SHA256 tag appended by `encrypt()` is verified
   * **before** decryption to prevent padding oracle attacks (CBC) and
   * ciphertext tampering (CTR).
   */
  public async decrypt(
    data: Uint8Array,
    documentKey: CryptoKey,
    nonce?: Uint8Array,
  ): Promise<Uint8Array> {
    if (!nonce) {
      throw new Error('Nonce is required for decryption');
    }

    if (this._encryptionAlgorithmName !== 'AES-GCM') {
      // Split ciphertext and HMAC tag
      if (data.length < HMAC_TAG_LENGTH) {
        throw new Error('Ciphertext too short to contain HMAC tag');
      }
      const ciphertext = data.slice(0, data.length - HMAC_TAG_LENGTH);
      const receivedTag = data.slice(data.length - HMAC_TAG_LENGTH);

      // Verify HMAC before decrypting (encrypt-then-MAC)
      const hmacKey = await this._deriveHmacKey(documentKey);
      const macInput = concatUint8Arrays(nonce!, ciphertext);
      const valid = await crypto.subtle.verify(
        'HMAC',
        hmacKey,
        receivedTag as Uint8Array<ArrayBuffer>,
        macInput as Uint8Array<ArrayBuffer>,
      );
      if (!valid) {
        throw new Error('HMAC verification failed — ciphertext may be tampered');
      }

      return new Uint8Array(
        await crypto.subtle.decrypt(
          this._encryptionAlgorithmParams(nonce),
          documentKey,
          ciphertext as Uint8Array<ArrayBuffer>,
        ),
      );
    }

    // AES-GCM path — authentication is built into the algorithm.
    try {
      return new Uint8Array(
        await crypto.subtle.decrypt(
          this._encryptionAlgorithmParams(nonce),
          documentKey,
          data as Uint8Array<ArrayBuffer>,
        ),
      );
    } catch (err) {
      console.error('Failed to decrypt data:', err);
      throw err;
    }
  }

  /**
   * Encrypt data using the configured encryption algorithm.
   *
   * For AES-CTR and AES-CBC, an HMAC-SHA256 tag over (nonce || ciphertext)
   * is appended to the returned data for authentication. The document layer
   * treats this as opaque ciphertext — the wire format is unchanged.
   */
  public async encrypt(
    data: Uint8Array,
    documentKey: CryptoKey,
  ): Promise<SubtleCryptoEncryptionResult> {
    const algorithmParams = this._encryptionAlgorithmParams();
    // Note: WebCrypto's AES-CBC implementation applies PKCS#7 padding automatically
    // per the W3C WebCrypto spec, so plaintext of any length is accepted here.
    // See: https://www.w3.org/TR/WebCryptoAPI/#aes-cbc-operations
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        algorithmParams,
        documentKey,
        data as Uint8Array<ArrayBuffer>,
      ),
    );

    if (this._encryptionAlgorithmName !== 'AES-GCM') {
      // Encrypt-then-MAC: HMAC-SHA256(nonce || ciphertext)
      const hmacKey = await this._deriveHmacKey(documentKey);
      const nonce = this._extractNonce(algorithmParams);
      const macInput = concatUint8Arrays(nonce, ciphertext);
      const tag = new Uint8Array(
        await crypto.subtle.sign('HMAC', hmacKey, macInput as Uint8Array<ArrayBuffer>),
      );
      return {
        data: concatUint8Arrays(ciphertext, tag),
        nonce,
      };
    }

    return {
      data: ciphertext,
      nonce: this._extractNonce(algorithmParams),
    };
  }
}
