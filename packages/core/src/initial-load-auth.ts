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
  return options.existingWriterKeys.length > 0
    ? options.existingWriterKeys
    : options.trustedBootstrapWriterKeys;
}

async function verifiedSignerIndexes<PublicKey>(
  options: InitialLoadAuthenticationOptions<PublicKey>,
): Promise<number[]> {
  if (
    !options.signingEnabled ||
    !(options.signature instanceof Uint8Array)
  ) {
    return [];
  }
  const keys = selectedTrustKeys(options);
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
  const indexes = await verifiedSignerIndexes(options);
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
  return (await verifiedSignerIndexes(options)).length > 0;
}
