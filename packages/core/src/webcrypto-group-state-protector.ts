import {
  GroupStateCiphertext,
  GroupStateProtector,
} from './group-security-provider.js';
import { copyUnsharedUint8Array } from './utils.js';

export const WEBCRYPTO_GROUP_STATE_ALGORITHM = 'AES-256-GCM';
export const WEBCRYPTO_GROUP_STATE_NONCE_LENGTH = 12;

/** AES-256-GCM implementation of the encrypted provider-state boundary. */
export class WebCryptoGroupStateProtector implements GroupStateProtector {
  readonly algorithm = WEBCRYPTO_GROUP_STATE_ALGORITHM;

  constructor(
    readonly keyId: string,
    private readonly key: CryptoKey,
    private readonly cryptoProvider: Crypto = globalThis.crypto,
  ) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,255}$/.test(keyId)) {
      throw new Error('invalid group-state protector keyId');
    }
    const algorithm = key.algorithm as AesKeyAlgorithm;
    if (
      key.type !== 'secret' ||
      algorithm.name !== 'AES-GCM' ||
      algorithm.length !== 256 ||
      !key.usages.includes('encrypt') ||
      !key.usages.includes('decrypt')
    ) {
      throw new Error(
        'group-state protector requires a 256-bit AES-GCM encrypt/decrypt key',
      );
    }
    if (cryptoProvider?.subtle === undefined) {
      throw new Error('Web Crypto is unavailable');
    }
  }

  static async generate(
    keyId: string,
    cryptoProvider: Crypto = globalThis.crypto,
  ): Promise<WebCryptoGroupStateProtector> {
    const subtle = cryptoProvider?.subtle;
    if (subtle === undefined) {
      throw new Error('Web Crypto is unavailable');
    }
    const key = await subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    return new WebCryptoGroupStateProtector(keyId, key, cryptoProvider);
  }

  async seal(
    plaintext: Uint8Array,
    associatedData: Uint8Array,
  ): Promise<GroupStateCiphertext> {
    const plaintextSnapshot = snapshotBytes(plaintext, 'plaintext', 1);
    const associatedDataSnapshot = snapshotBytes(
      associatedData,
      'associatedData',
      1,
    );
    const nonce = snapshotBytes(
      this.cryptoProvider.getRandomValues(
        new Uint8Array(WEBCRYPTO_GROUP_STATE_NONCE_LENGTH),
      ),
      'nonce',
      WEBCRYPTO_GROUP_STATE_NONCE_LENGTH,
      WEBCRYPTO_GROUP_STATE_NONCE_LENGTH,
    );
    const ciphertext = await this.cryptoProvider.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce as BufferSource,
        additionalData: associatedDataSnapshot as BufferSource,
        tagLength: 128,
      },
      this.key,
      plaintextSnapshot as BufferSource,
    );
    return { nonce, ciphertext: new Uint8Array(ciphertext) };
  }

  async open(
    sealed: GroupStateCiphertext,
    associatedData: Uint8Array,
  ): Promise<Uint8Array> {
    const nonceSnapshot = snapshotBytes(
      sealed.nonce,
      'nonce',
      WEBCRYPTO_GROUP_STATE_NONCE_LENGTH,
      WEBCRYPTO_GROUP_STATE_NONCE_LENGTH,
    );
    const ciphertextSnapshot = snapshotBytes(
      sealed.ciphertext,
      'ciphertext',
      17,
    );
    const associatedDataSnapshot = snapshotBytes(
      associatedData,
      'associatedData',
      1,
    );
    const plaintext = await this.cryptoProvider.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonceSnapshot as BufferSource,
        additionalData: associatedDataSnapshot as BufferSource,
        tagLength: 128,
      },
      this.key,
      ciphertextSnapshot as BufferSource,
    );
    return new Uint8Array(plaintext);
  }
}

function snapshotBytes(
  value: unknown,
  field: string,
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER,
): Uint8Array {
  return copyUnsharedUint8Array(value, minimum, maximum, field);
}
