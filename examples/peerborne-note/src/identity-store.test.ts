import {
  CURRENT_IDENTITY_KEY,
  getOrCreateIdentity,
  IDENTITY_DATABASE_NAME,
  IDENTITY_STORE_NAME,
  identityFingerprint,
  validateStoredIdentity,
} from './identity-store.js';

function deleteIdentityDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(IDENTITY_DATABASE_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error('Identity test database is blocked'));
  });
}

function openIdentityDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(IDENTITY_DATABASE_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(IDENTITY_STORE_NAME)) {
        request.result.createObjectStore(IDENTITY_STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function writeRawIdentity(value: unknown): Promise<void> {
  const database = await openIdentityDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(IDENTITY_STORE_NAME, 'readwrite');
      transaction.objectStore(IDENTITY_STORE_NAME).put(
        value,
        CURRENT_IDENTITY_KEY,
      );
      transaction.oncomplete = () => resolve();
      transaction.onabort = () => reject(transaction.error);
      transaction.onerror = () => undefined;
    });
  } finally {
    database.close();
  }
}

async function rawPublicKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

describe('Peerborne Note identity storage', () => {
  beforeEach(async () => {
    await deleteIdentityDatabase();
  });

  afterAll(async () => {
    await deleteIdentityDatabase();
  });

  test('persists one non-extractable P-384 signing identity', async () => {
    const created = await getOrCreateIdentity();
    const restored = await getOrCreateIdentity();

    expect(created.privateKey.extractable).toBe(false);
    expect(created.privateKey.usages).toEqual(['sign']);
    expect(created.publicKey.extractable).toBe(true);
    expect(created.publicKey.usages).toEqual(['verify']);
    expect(created.privateKey.algorithm).toMatchObject({
      name: 'ECDSA',
      namedCurve: 'P-384',
    });
    expect(await rawPublicKey(restored.publicKey)).toEqual(
      await rawPublicKey(created.publicKey),
    );
    expect(await identityFingerprint(restored.publicKey)).toMatch(
      /^(?:[0-9a-f]{2}:){9}[0-9a-f]{2}$/u,
    );
  });

  test('uses the same fingerprint after canonical public-key round-trip', async () => {
    const identity = await getOrCreateIdentity();
    const raw = await crypto.subtle.exportKey('raw', identity.publicKey);
    const imported = await crypto.subtle.importKey(
      'raw',
      raw,
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['verify'],
    );

    expect(await identityFingerprint(imported)).toBe(
      await identityFingerprint(identity.publicKey),
    );
  });

  test('concurrent first writers converge on the atomically stored identity', async () => {
    const identities = await Promise.all(
      Array.from({ length: 8 }, () => getOrCreateIdentity()),
    );
    const encoded = await Promise.all(
      identities.map(async ({ publicKey }) =>
        Buffer.from(await rawPublicKey(publicKey)).toString('hex'),
      ),
    );
    expect(new Set(encoded).size).toBe(1);
  });

  test('rejects a mismatched signing pair', async () => {
    const first = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const second = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['sign', 'verify'],
    )) as CryptoKeyPair;

    await expect(validateStoredIdentity({
      version: 1,
      createdAtMs: Date.now(),
      privateKey: first.privateKey,
      publicKey: second.publicKey,
    })).rejects.toThrow(/does not match/u);
  });

  test('fails closed instead of silently replacing malformed stored state', async () => {
    const malformed = { version: 1, createdAtMs: Date.now() };
    await writeRawIdentity(malformed);

    await expect(getOrCreateIdentity()).rejects.toThrow(/malformed/u);
    await expect(getOrCreateIdentity()).rejects.toThrow(/malformed/u);
  });

  test('rejects an extractable private signing key', async () => {
    const unsafe = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;

    await expect(validateStoredIdentity({
      version: 1,
      createdAtMs: Date.now(),
      privateKey: unsafe.privateKey,
      publicKey: unsafe.publicKey,
    })).rejects.toThrow(/unsafe key profile/u);
  });
});
