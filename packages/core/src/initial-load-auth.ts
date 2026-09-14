import { MAX_INITIAL_LOAD_SIGNER_AUTHORITIES } from './initial-load-trust.js';

const arrayIsArray = Array.isArray;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const reflectApply = Reflect.apply;

export interface InitialLoadAuthenticationOptions<PublicKey> {
  strict: boolean;
  signingEnabled: boolean;
  payload: Uint8Array;
  signature?: Uint8Array;
  existingWriterKeys: readonly PublicKey[];
  trustedBootstrapWriterKeys: readonly PublicKey[];
  verify: (
    payload: Uint8Array,
    publicKey: PublicKey,
    signature: Uint8Array,
  ) => Promise<boolean>;
}

export interface IdentifiedInitialLoadSigner<PublicKey> {
  readonly publicKey: PublicKey;
  readonly keyIndex: number;
}

function selectedTrustKeys<PublicKey>(
  options: InitialLoadAuthenticationOptions<PublicKey>,
): readonly PublicKey[] {
  const existingWriterKeys = snapshotTrustKeys(
    options.existingWriterKeys,
    'existing writer keys',
  );
  return existingWriterKeys.length > 0
    ? existingWriterKeys
    : snapshotTrustKeys(
        options.trustedBootstrapWriterKeys,
        'trusted bootstrap writer keys',
      );
}

function snapshotTrustKeys<PublicKey>(
  value: readonly PublicKey[],
  field: string,
): readonly PublicKey[] {
  let isArray: boolean;
  let lengthDescriptor: PropertyDescriptor | undefined;
  try {
    isArray = reflectApply(arrayIsArray, Array, [value]) as boolean;
    lengthDescriptor = isArray
      ? (reflectApply(objectGetOwnPropertyDescriptor, Object, [
          value,
          'length',
        ]) as PropertyDescriptor | undefined)
      : undefined;
  } catch {
    throw new TypeError(`${field} must be a stable array`);
  }
  const length =
    lengthDescriptor !== undefined && 'value' in lengthDescriptor
      ? lengthDescriptor.value
      : undefined;
  if (!isArray || !Number.isSafeInteger(length) || (length as number) < 0) {
    throw new TypeError(`${field} must be a stable array`);
  }
  if ((length as number) > MAX_INITIAL_LOAD_SIGNER_AUTHORITIES) {
    throw new RangeError(
      `${field} exceeds ${MAX_INITIAL_LOAD_SIGNER_AUTHORITIES} entries`,
    );
  }

  const snapshot = new Array<PublicKey>(length as number);
  for (let index = 0; index < snapshot.length; index++) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = reflectApply(objectGetOwnPropertyDescriptor, Object, [
        value,
        String(index),
      ]) as PropertyDescriptor | undefined;
    } catch {
      throw new TypeError(`${field} must expose stable own data entries`);
    }
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !('value' in descriptor)
    ) {
      throw new TypeError(`${field} must contain only own data entries`);
    }
    reflectApply(objectDefineProperty, Object, [
      snapshot,
      String(index),
      {
        configurable: true,
        enumerable: true,
        value: descriptor.value,
        writable: true,
      },
    ]);
  }
  return reflectApply(objectFreeze, Object, [snapshot]) as readonly PublicKey[];
}

async function verifiedSignerIndexes<PublicKey>(
  options: InitialLoadAuthenticationOptions<PublicKey>,
  keys: readonly PublicKey[],
): Promise<number[]> {
  if (
    !options.signingEnabled ||
    !(options.signature instanceof Uint8Array)
  ) {
    return [];
  }
  const results = await Promise.allSettled(
    keys.map((key) =>
      Promise.resolve().then(() =>
        options.verify(options.payload, key, options.signature!),
      ),
    ),
  );
  const indexes: number[] = [];
  for (let index = 0; index < results.length; index++) {
    const result = results[index];
    if (result.status === 'fulfilled' && result.value === true) {
      indexes.push(index);
    }
  }
  return indexes;
}

/**
 * Identify the unique trusted signing key that authenticated an envelope.
 * Ambiguous signatures that verify under more than one distinct trust entry
 * fail closed; callers cannot safely attribute such a vote to one authority.
 */
export async function identifyInitialLoadSigner<PublicKey>(
  options: InitialLoadAuthenticationOptions<PublicKey>,
): Promise<IdentifiedInitialLoadSigner<PublicKey> | null> {
  const keys = selectedTrustKeys(options);
  const indexes = await verifiedSignerIndexes(options, keys);
  if (indexes.length !== 1) return null;
  const keyIndex = indexes[0];
  return { publicKey: keys[keyIndex], keyIndex };
}

/**
 * Authenticate a first-load envelope without trusting writer keys carried by
 * that same envelope. Existing ACL writers take precedence; an empty ACL can
 * only bootstrap from application-pinned writer keys in strict mode.
 */
export async function verifyInitialLoadAuthentication<PublicKey>(
  options: InitialLoadAuthenticationOptions<PublicKey>,
): Promise<boolean> {
  if (!options.signingEnabled) {
    return !options.strict;
  }
  const keys = selectedTrustKeys(options);
  if (keys.length === 0) {
    return !options.strict;
  }
  if (!(options.signature instanceof Uint8Array)) {
    return false;
  }
  return (await verifiedSignerIndexes(options, keys)).length > 0;
}
