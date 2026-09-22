export const MAX_INITIAL_LOAD_SIGNER_AUTHORITIES = 256;
export const MAX_INITIAL_LOAD_SIGNER_AUTHORITY_ID_BYTES = 1024;

const arrayIsArray = Array.isArray;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const reflectApply = Reflect.apply;

export function snapshotTrustKeys<PublicKey>(
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

function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

export interface InitialLoadSignerAuthority<PublicKey> {
  readonly authorityId: string;
  readonly publicKey: PublicKey;
}

export interface CaptureInitialLoadSignerAuthoritiesOptions<PublicKey> {
  documentPath: string;
  existingWriterKeys: readonly PublicKey[];
  resolveTrustedDocumentWriters?: (
    documentPath: string,
  ) => readonly PublicKey[] | Promise<readonly PublicKey[]>;
  serializePublicKey: (publicKey: PublicKey) => Promise<string>;
}

function validateAuthorityId(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(
      'AuthProvider.serializePublicKey must return a non-empty string',
    );
  }
  for (let index = 0; index < value.length; index++) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError(
          'AuthProvider.serializePublicKey must return well-formed UTF-16',
        );
      }
      index++;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new TypeError(
        'AuthProvider.serializePublicKey must return well-formed UTF-16',
      );
    }
  }
  if (utf8ByteLength(value) > MAX_INITIAL_LOAD_SIGNER_AUTHORITY_ID_BYTES) {
    throw new RangeError(
      `serialized writer authority exceeds ${MAX_INITIAL_LOAD_SIGNER_AUTHORITY_ID_BYTES} UTF-8 bytes`,
    );
  }
}

/**
 * Capture the signer trust set used for one security-aware initial load.
 * Existing ACL writers take precedence. The bootstrap resolver is invoked at
 * most once, and only when there are no already-trusted writers.
 *
 * Authority IDs are canonical serialized public keys rather than libp2p
 * PeerIds. Duplicate IDs are collapsed so one trusted signing credential can
 * cast at most one quorum vote even when it is presented through many network
 * identities.
 */
export async function captureInitialLoadSignerAuthorities<PublicKey>(
  options: CaptureInitialLoadSignerAuthoritiesOptions<PublicKey>,
): Promise<readonly InitialLoadSignerAuthority<PublicKey>[]> {
  let sourceKeys = snapshotTrustKeys(
    options.existingWriterKeys,
    'existing writer keys',
  );
  if (sourceKeys.length === 0) {
    const resolver = options.resolveTrustedDocumentWriters;
    if (resolver === undefined) {
      throw new Error(
        `Cannot start security-aware load for ${options.documentPath}: ` +
          'resolveTrustedDocumentWriters is not configured',
      );
    }
    let resolved: readonly PublicKey[];
    try {
      resolved = await resolver(options.documentPath);
    } catch (cause) {
      throw new Error(
        `Cannot start security-aware load for ${options.documentPath}: ` +
          'resolveTrustedDocumentWriters failed',
        { cause },
      );
    }
    if (!Array.isArray(resolved)) {
      throw new TypeError(
        `Cannot start security-aware load for ${options.documentPath}: ` +
          'resolveTrustedDocumentWriters must return an array of public keys',
      );
    }
    sourceKeys = snapshotTrustKeys(resolved, 'trusted bootstrap writer keys');
  }

  if (sourceKeys.length === 0) {
    throw new Error(
      `Cannot start security-aware load for ${options.documentPath}: ` +
        'no trusted writer authorities are available',
    );
  }

  const authorities: InitialLoadSignerAuthority<PublicKey>[] = [];
  const seen = new Set<string>();
  for (const publicKey of sourceKeys) {
    let authorityId: string;
    try {
      authorityId = await options.serializePublicKey(publicKey);
    } catch (cause) {
      throw new Error(
        `Cannot start security-aware load for ${options.documentPath}: ` +
          'failed to serialize a trusted writer authority',
        { cause },
      );
    }
    try {
      validateAuthorityId(authorityId);
    } catch (cause) {
      throw new TypeError(
        `Cannot start security-aware load for ${options.documentPath}: ` +
          (cause instanceof Error ? cause.message : String(cause)),
        { cause },
      );
    }
    if (seen.has(authorityId)) continue;
    seen.add(authorityId);
    authorities.push(Object.freeze({ authorityId, publicKey }));
  }
  return Object.freeze(authorities);
}
