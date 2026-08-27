export const IDENTITY_DATABASE_NAME = 'peerborne-note-identity';
export const IDENTITY_STORE_NAME = 'identities';
export const CURRENT_IDENTITY_KEY = 'current';

const IDENTITY_DATABASE_VERSION = 1;
const IDENTITY_RECORD_VERSION = 1;

interface StoredIdentityRecord {
  readonly version: typeof IDENTITY_RECORD_VERSION;
  readonly createdAtMs: number;
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed'));
  });
}

function openIdentityDatabase(): Promise<IDBDatabase> {
  if (typeof indexedDB === 'undefined') {
    return Promise.reject(new Error('IndexedDB is unavailable'));
  }
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(
      IDENTITY_DATABASE_NAME,
      IDENTITY_DATABASE_VERSION,
    );
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(IDENTITY_STORE_NAME)) {
        database.createObjectStore(IDENTITY_STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('Identity database failed to open'));
    request.onblocked = () => reject(new Error('Identity database upgrade is blocked by another tab'));
  });
}

async function readIdentityRecord(): Promise<unknown> {
  const database = await openIdentityDatabase();
  try {
    const transaction = database.transaction(IDENTITY_STORE_NAME, 'readonly');
    return await requestResult(
      transaction.objectStore(IDENTITY_STORE_NAME).get(CURRENT_IDENTITY_KEY),
    );
  } finally {
    database.close();
  }
}

async function addIdentityRecord(record: StoredIdentityRecord): Promise<void> {
  const database = await openIdentityDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(IDENTITY_STORE_NAME, 'readwrite');
      const request = transaction
        .objectStore(IDENTITY_STORE_NAME)
        .add(record, CURRENT_IDENTITY_KEY);
      transaction.oncomplete = () => resolve();
      transaction.onabort = () => reject(
        transaction.error ?? request.error ?? new Error('Identity record was not stored'),
      );
      transaction.onerror = () => undefined;
    });
  } finally {
    database.close();
  }
}

function algorithmIsP384(key: CryptoKey): boolean {
  const algorithm = key.algorithm as EcKeyAlgorithm;
  return algorithm.name === 'ECDSA' && algorithm.namedCurve === 'P-384';
}

function hasExactlyUsage(key: CryptoKey, usage: KeyUsage): boolean {
  return key.usages.length === 1 && key.usages[0] === usage;
}

function isCryptoKey(value: unknown): value is CryptoKey {
  return Object.prototype.toString.call(value) === '[object CryptoKey]';
}

export async function validateStoredIdentity(
  value: unknown,
): Promise<CryptoKeyPair> {
  if (!value || typeof value !== 'object') {
    throw new Error('Stored Peerborne Note identity is malformed');
  }
  const record = value as Partial<StoredIdentityRecord>;
  if (
    record.version !== IDENTITY_RECORD_VERSION ||
    !isCryptoKey(record.privateKey) ||
    !isCryptoKey(record.publicKey) ||
    typeof record.createdAtMs !== 'number' ||
    !Number.isSafeInteger(record.createdAtMs) ||
    record.createdAtMs < 0
  ) {
    throw new Error('Stored Peerborne Note identity is malformed');
  }
  const { privateKey, publicKey } = record as StoredIdentityRecord;
  if (
    privateKey.type !== 'private' ||
    privateKey.extractable ||
    !algorithmIsP384(privateKey) ||
    !hasExactlyUsage(privateKey, 'sign') ||
    publicKey.type !== 'public' ||
    !publicKey.extractable ||
    !algorithmIsP384(publicKey) ||
    !hasExactlyUsage(publicKey, 'verify')
  ) {
    throw new Error('Stored Peerborne Note identity has an unsafe key profile');
  }
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-384' },
    privateKey,
    challenge,
  );
  const matches = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-384' },
    publicKey,
    signature,
    challenge,
  );
  if (!matches) {
    throw new Error('Stored Peerborne Note identity key pair does not match');
  }
  return Object.freeze({ privateKey, publicKey });
}

async function generateIdentityRecord(): Promise<StoredIdentityRecord> {
  const pair = (await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  return {
    version: IDENTITY_RECORD_VERSION,
    createdAtMs: Date.now(),
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
  };
}

function isConstraintError(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'ConstraintError';
}

export async function getOrCreateIdentity(): Promise<CryptoKeyPair> {
  const existing = await readIdentityRecord();
  if (existing !== undefined) {
    return validateStoredIdentity(existing);
  }

  const candidate = await generateIdentityRecord();
  try {
    await addIdentityRecord(candidate);
    return validateStoredIdentity(candidate);
  } catch (error) {
    if (!isConstraintError(error)) throw error;
    const winner = await readIdentityRecord();
    if (winner === undefined) {
      throw new Error('Identity creation raced but no stored identity was found');
    }
    return validateStoredIdentity(winner);
  }
}

export async function identityFingerprint(publicKey: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', publicKey);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', raw));
  return Array.from(digest.slice(0, 10), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join(':');
}
