import {
  GroupStateCiphertext,
  GroupStateProtector,
} from './group-security-provider.js';
import { copyUnsharedUint8Array } from './utils.js';

export const WEBCRYPTO_GROUP_STATE_ALGORITHM = 'AES-256-GCM';
export const WEBCRYPTO_GROUP_STATE_NONCE_LENGTH = 12;
const WEBCRYPTO_GROUP_STATE_TAG_LENGTH = 16;

const arrayBufferByteLengthGetter = Object.getOwnPropertyDescriptor(
  ArrayBuffer.prototype,
  'byteLength',
)?.get;

if (arrayBufferByteLengthGetter === undefined) {
  throw new Error('ArrayBuffer intrinsic accessors are unavailable');
}
const intrinsicArrayBufferByteLengthGetter = arrayBufferByteLengthGetter;

const cryptoKeyAccessors =
  typeof CryptoKey === 'undefined'
    ? undefined
    : {
        type: Object.getOwnPropertyDescriptor(CryptoKey.prototype, 'type')?.get,
        extractable: Object.getOwnPropertyDescriptor(
          CryptoKey.prototype,
          'extractable',
        )?.get,
        algorithm: Object.getOwnPropertyDescriptor(
          CryptoKey.prototype,
          'algorithm',
        )?.get,
        usages: Object.getOwnPropertyDescriptor(CryptoKey.prototype, 'usages')
          ?.get,
      };
const intrinsicStructuredClone = globalThis.structuredClone;

interface CapturedProtectorCrypto {
  readonly cryptoReceiver: Crypto;
  readonly subtleReceiver: SubtleCrypto;
  readonly getRandomValues: Function;
  readonly encrypt: Function;
  readonly decrypt: Function;
}

interface CapturedGenerationCrypto extends CapturedProtectorCrypto {
  readonly generateKey: Function;
}

/** AES-256-GCM implementation of the encrypted provider-state boundary. */
export class WebCryptoGroupStateProtector implements GroupStateProtector {
  readonly algorithm = WEBCRYPTO_GROUP_STATE_ALGORITHM;
  readonly keyId: string;
  readonly #key: CryptoKey;
  readonly #crypto: CapturedProtectorCrypto;

  constructor(
    keyId: string,
    key: CryptoKey,
    cryptoProvider?: Crypto,
  ) {
    validateKeyId(keyId);
    const keySnapshot = snapshotProtectorKey(key);
    this.keyId = keyId;
    this.#key = keySnapshot;
    this.#crypto = captureProtectorCrypto(
      resolveCryptoProvider(cryptoProvider),
    );
  }

  static async generate(
    keyId: string,
    cryptoProvider?: Crypto,
  ): Promise<WebCryptoGroupStateProtector> {
    validateKeyId(keyId);
    const captured = captureGenerationCrypto(
      resolveCryptoProvider(cryptoProvider),
    );
    const key = (await Reflect.apply(
      captured.generateKey,
      captured.subtleReceiver,
      [
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
      ],
    )) as CryptoKey;
    return new WebCryptoGroupStateProtector(
      keyId,
      key,
      providerFromCapturedCrypto(captured),
    );
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
      Reflect.apply(
        this.#crypto.getRandomValues,
        this.#crypto.cryptoReceiver,
        [new Uint8Array(WEBCRYPTO_GROUP_STATE_NONCE_LENGTH)],
      ),
      'nonce',
      WEBCRYPTO_GROUP_STATE_NONCE_LENGTH,
      WEBCRYPTO_GROUP_STATE_NONCE_LENGTH,
    );
    const ciphertext = await Reflect.apply(
      this.#crypto.encrypt,
      this.#crypto.subtleReceiver,
      [
        {
          name: 'AES-GCM',
          iv: nonce as BufferSource,
          additionalData: associatedDataSnapshot as BufferSource,
          tagLength: 128,
        },
        this.#key,
        plaintextSnapshot as BufferSource,
      ],
    );
    return {
      nonce,
      ciphertext: snapshotCryptoOutput(
        ciphertext,
        'ciphertext',
        plaintextSnapshot.byteLength + WEBCRYPTO_GROUP_STATE_TAG_LENGTH,
      ),
    };
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
      WEBCRYPTO_GROUP_STATE_TAG_LENGTH + 1,
    );
    const associatedDataSnapshot = snapshotBytes(
      associatedData,
      'associatedData',
      1,
    );
    const plaintext = await Reflect.apply(
      this.#crypto.decrypt,
      this.#crypto.subtleReceiver,
      [
        {
          name: 'AES-GCM',
          iv: nonceSnapshot as BufferSource,
          additionalData: associatedDataSnapshot as BufferSource,
          tagLength: 128,
        },
        this.#key,
        ciphertextSnapshot as BufferSource,
      ],
    );
    return snapshotCryptoOutput(
      plaintext,
      'plaintext',
      ciphertextSnapshot.byteLength - WEBCRYPTO_GROUP_STATE_TAG_LENGTH,
    );
  }
}

function validateKeyId(keyId: unknown): asserts keyId is string {
  if (
    typeof keyId !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,255}$/.test(keyId)
  ) {
    throw new Error('invalid group-state protector keyId');
  }
}

function resolveCryptoProvider(cryptoProvider: Crypto | undefined): Crypto {
  return cryptoProvider === undefined
    ? (readCryptoProperty(globalThis, 'crypto') as Crypto)
    : cryptoProvider;
}

function snapshotProtectorKey(key: unknown): CryptoKey {
  try {
    if (
      key === null ||
      typeof key !== 'object' ||
      cryptoKeyAccessors === undefined ||
      cryptoKeyAccessors.type === undefined ||
      cryptoKeyAccessors.extractable === undefined ||
      cryptoKeyAccessors.algorithm === undefined ||
      cryptoKeyAccessors.usages === undefined ||
      intrinsicStructuredClone === undefined
    ) {
      throw invalidProtectorKey();
    }

    // Brand-check before cloning so lookalikes cannot make structuredClone
    // consult attacker-controlled enumerable accessors. Native CryptoKey
    // serialization ignores shadowing expandos and detaches the stored key
    // from subsequent mutation through the caller's reference.
    Reflect.apply(cryptoKeyAccessors.type, key, []);
    const snapshot = Reflect.apply(intrinsicStructuredClone, globalThis, [
      key,
    ]) as unknown;
    if (snapshot === key) throw invalidProtectorKey();
    const type = Reflect.apply(cryptoKeyAccessors.type, snapshot, []);
    const extractable = Reflect.apply(
      cryptoKeyAccessors.extractable,
      snapshot,
      [],
    );
    const algorithm = Reflect.apply(
      cryptoKeyAccessors.algorithm,
      snapshot,
      [],
    ) as unknown;
    const usages = Reflect.apply(
      cryptoKeyAccessors.usages,
      snapshot,
      [],
    ) as unknown;
    if (
      type !== 'secret' ||
      extractable !== false ||
      algorithm === null ||
      typeof algorithm !== 'object'
    ) {
      throw invalidProtectorKey();
    }
    const name = Reflect.get(algorithm, 'name');
    const length = Reflect.get(algorithm, 'length');
    if (!Array.isArray(usages)) throw invalidProtectorKey();
    const usageCount = Reflect.get(usages, 'length');
    const firstUsage = Reflect.get(usages, '0');
    const secondUsage = Reflect.get(usages, '1');
    if (
      name !== 'AES-GCM' ||
      length !== 256 ||
      usageCount !== 2 ||
      !(
        (firstUsage === 'encrypt' && secondUsage === 'decrypt') ||
        (firstUsage === 'decrypt' && secondUsage === 'encrypt')
      )
    ) {
      throw invalidProtectorKey();
    }
    return snapshot as CryptoKey;
  } catch {
    throw invalidProtectorKey();
  }
}

function invalidProtectorKey(): Error {
  return new Error(
    'group-state protector requires a non-extractable 256-bit AES-GCM key with exactly encrypt/decrypt usages',
  );
}

function captureGenerationCrypto(
  cryptoProvider: Crypto,
): CapturedGenerationCrypto {
  const subtleReceiver = requireSubtleCrypto(cryptoProvider);
  const generateKey = requireCryptoMethod(subtleReceiver, 'generateKey');
  return Object.freeze({
    ...captureProtectorCryptoWithSubtle(cryptoProvider, subtleReceiver),
    generateKey,
  });
}

function captureProtectorCrypto(
  cryptoProvider: Crypto,
): CapturedProtectorCrypto {
  return captureProtectorCryptoWithSubtle(
    cryptoProvider,
    requireSubtleCrypto(cryptoProvider),
  );
}

function captureProtectorCryptoWithSubtle(
  cryptoProvider: Crypto,
  subtleReceiver: SubtleCrypto,
): CapturedProtectorCrypto {
  return Object.freeze({
    cryptoReceiver: cryptoProvider,
    subtleReceiver,
    getRandomValues: requireCryptoMethod(cryptoProvider, 'getRandomValues'),
    encrypt: requireCryptoMethod(subtleReceiver, 'encrypt'),
    decrypt: requireCryptoMethod(subtleReceiver, 'decrypt'),
  });
}

function requireSubtleCrypto(cryptoProvider: unknown): SubtleCrypto {
  const subtle = readCryptoProperty(cryptoProvider, 'subtle');
  if (
    subtle === null ||
    (typeof subtle !== 'object' && typeof subtle !== 'function')
  ) {
    throw webCryptoUnavailable();
  }
  return subtle as SubtleCrypto;
}

function providerFromCapturedCrypto(
  captured: CapturedProtectorCrypto,
): Crypto {
  const {
    cryptoReceiver,
    subtleReceiver,
    getRandomValues,
    encrypt,
    decrypt,
  } = captured;
  const subtle = Object.freeze({
    encrypt: (...args: unknown[]) =>
      Reflect.apply(encrypt, subtleReceiver, args),
    decrypt: (...args: unknown[]) =>
      Reflect.apply(decrypt, subtleReceiver, args),
  });
  return Object.freeze({
    subtle,
    getRandomValues: (...args: unknown[]) =>
      Reflect.apply(getRandomValues, cryptoReceiver, args),
  }) as unknown as Crypto;
}

function requireCryptoMethod(receiver: unknown, name: string): Function {
  const method = readCryptoProperty(receiver, name);
  if (typeof method !== 'function') {
    throw webCryptoUnavailable();
  }
  return method;
}

function readCryptoProperty(receiver: unknown, name: string): unknown {
  if (
    receiver === null ||
    (typeof receiver !== 'object' && typeof receiver !== 'function')
  ) {
    throw webCryptoUnavailable();
  }
  try {
    return Reflect.get(receiver, name);
  } catch {
    throw webCryptoUnavailable();
  }
}

function webCryptoUnavailable(): Error {
  return new Error('Web Crypto is unavailable');
}

function snapshotBytes(
  value: unknown,
  field: string,
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER,
): Uint8Array {
  return copyUnsharedUint8Array(value, minimum, maximum, field);
}

function snapshotCryptoOutput(
  value: unknown,
  field: 'ciphertext' | 'plaintext',
  expectedLength: number,
): Uint8Array {
  try {
    const byteLength = Reflect.apply(
      intrinsicArrayBufferByteLengthGetter,
      value,
      [],
    );
    if (byteLength !== expectedLength) throw invalidCryptoOutput(field);
    const view = new Uint8Array(value as ArrayBuffer);
    return copyUnsharedUint8Array(
      view,
      expectedLength,
      expectedLength,
      field,
    );
  } catch {
    throw invalidCryptoOutput(field);
  }
}

function invalidCryptoOutput(field: 'ciphertext' | 'plaintext'): Error {
  return new Error(`Web Crypto returned invalid AES-GCM ${field}`);
}
