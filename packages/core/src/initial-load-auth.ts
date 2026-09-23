import { snapshotTrustKeys } from './initial-load-trust.js';
import { copyUnsharedUint8Array } from './utils.js';

export const MAX_INITIAL_LOAD_AUTHENTICATION_PAYLOAD_BYTES = 64 * 1024 * 1024;
export const MAX_INITIAL_LOAD_AUTHENTICATION_SIGNATURE_BYTES = 8192;

const reflectApply = Reflect.apply;

export interface InitialLoadAuthenticationOptions<PublicKey> {
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
  existingWriterKeysValue: readonly PublicKey[],
  trustedBootstrapWriterKeysValue: readonly PublicKey[],
): readonly PublicKey[] {
  const existingWriterKeys = snapshotTrustKeys(
    existingWriterKeysValue,
    'existing writer keys',
  );
  return existingWriterKeys.length > 0
    ? existingWriterKeys
    : snapshotTrustKeys(
        trustedBootstrapWriterKeysValue,
        'trusted bootstrap writer keys',
      );
}

interface InitialLoadVerificationInputs<PublicKey> {
  readonly payload: Uint8Array;
  readonly signature: Uint8Array;
  readonly verify: InitialLoadAuthenticationOptions<PublicKey>['verify'];
}

function captureVerificationInputs<PublicKey>(
  payloadValue: unknown,
  signatureValue: unknown,
  verifyValue: unknown,
): InitialLoadVerificationInputs<PublicKey> | undefined {
  if (typeof verifyValue !== 'function') return undefined;
  try {
    return {
      payload: copyUnsharedUint8Array(
        payloadValue,
        1,
        MAX_INITIAL_LOAD_AUTHENTICATION_PAYLOAD_BYTES,
        'initial-load authentication payload',
      ),
      signature: copyUnsharedUint8Array(
        signatureValue,
        1,
        MAX_INITIAL_LOAD_AUTHENTICATION_SIGNATURE_BYTES,
        'initial-load authentication signature',
      ),
      verify: verifyValue as InitialLoadAuthenticationOptions<PublicKey>['verify'],
    };
  } catch {
    return undefined;
  }
}

async function verifiedSignerIndexes<PublicKey>(
  keys: readonly PublicKey[],
  inputs: InitialLoadVerificationInputs<PublicKey>,
): Promise<number[]> {
  const indexes: number[] = [];
  // Verify sequentially with disposable copies. A custom verifier may retain
  // and later mutate its arguments, so checking for immediate mutation cannot
  // make shared payload buffers safe for the next authority.
  for (let index = 0; index < keys.length; index++) {
    try {
      const payload = copyUnsharedUint8Array(
        inputs.payload,
        inputs.payload.byteLength,
        inputs.payload.byteLength,
        'initial-load authentication payload',
      );
      const signature = copyUnsharedUint8Array(
        inputs.signature,
        inputs.signature.byteLength,
        inputs.signature.byteLength,
        'initial-load authentication signature',
      );
      const verified = await reflectApply(inputs.verify, undefined, [
        payload,
        keys[index],
        signature,
      ]);
      if (verified === true) indexes.push(index);
    } catch {
      // One malformed key or verifier failure is not evidence about the rest.
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
  const signingEnabled = options.signingEnabled;
  const existingWriterKeys = options.existingWriterKeys;
  const trustedBootstrapWriterKeys = options.trustedBootstrapWriterKeys;
  const keys = selectedTrustKeys(
    existingWriterKeys,
    trustedBootstrapWriterKeys,
  );
  if (!signingEnabled) return null;
  const payload = options.payload;
  const signature = options.signature;
  const verify = options.verify;
  const inputs = captureVerificationInputs<PublicKey>(
    payload,
    signature,
    verify,
  );
  if (inputs === undefined) return null;
  const indexes = await verifiedSignerIndexes(keys, inputs);
  if (indexes.length !== 1) return null;
  const keyIndex = indexes[0];
  return { publicKey: keys[keyIndex], keyIndex };
}

/**
 * Authenticate a first-load envelope without trusting writer keys carried by
 * that same envelope. Existing ACL writers take precedence; an empty ACL can
 * only bootstrap from application-pinned writer keys.
 */
export async function verifyInitialLoadAuthentication<PublicKey>(
  options: InitialLoadAuthenticationOptions<PublicKey>,
): Promise<boolean> {
  const signingEnabled = options.signingEnabled;
  if (!signingEnabled) {
    return false;
  }
  const existingWriterKeys = options.existingWriterKeys;
  const trustedBootstrapWriterKeys = options.trustedBootstrapWriterKeys;
  const keys = selectedTrustKeys(
    existingWriterKeys,
    trustedBootstrapWriterKeys,
  );
  if (keys.length === 0) {
    return false;
  }
  const payload = options.payload;
  const signature = options.signature;
  const verify = options.verify;
  const inputs = captureVerificationInputs<PublicKey>(
    payload,
    signature,
    verify,
  );
  if (inputs === undefined) return false;
  return (await verifiedSignerIndexes(keys, inputs)).length > 0;
}
