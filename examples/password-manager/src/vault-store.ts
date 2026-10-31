import {
  MAX_DOCUMENT_CHECKPOINT_BYTES,
  type DocumentCheckpoint,
} from '@peerborne/core';

export const VAULT_DATABASE = 'peerborne-password-manager';
const VERSION = 1;
const MAX_CIPHERTEXT_BYTES = MAX_DOCUMENT_CHECKPOINT_BYTES + 8192 + 20;

export interface BrowserIdentity {
  version: 1;
  signing: CryptoKeyPair;
  kem: CryptoKeyPair;
  storageKey: CryptoKey;
}

interface StoredDocument {
  version: 1;
  owner: string;
  path: string;
  revision: number;
  isVault: boolean;
  nonce: Uint8Array<ArrayBuffer>;
  ciphertext: ArrayBuffer;
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(VAULT_DATABASE, VERSION);
    request.onupgradeneeded = () => {
      request.result.createObjectStore('identity');
      request.result.createObjectStore('documents');
      request.result.createObjectStore('vaults');
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(new Error('Could not open browser vault storage'));
    request.onblocked = () =>
      reject(new Error('Close other password-manager tabs and try again'));
  });
}

async function transaction<T>(
  store: string | string[],
  mode: IDBTransactionMode,
  operation: (store: IDBObjectStore, setResult: (value: T) => void) => void,
): Promise<T> {
  const database = await openDatabase();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = database.transaction(store, mode);
      let result: T;
      tx.oncomplete = () => resolve(result);
      tx.onabort = () =>
        reject(tx.error ?? new Error('Browser vault storage failed'));
      tx.onerror = () => undefined;
      try {
        operation(
          tx.objectStore(typeof store === 'string' ? store : store[0]),
          (value) => {
            result = value;
          },
        );
      } catch (error) {
        tx.abort();
        reject(error);
      }
    });
  } finally {
    database.close();
  }
}

function read<T>(store: string, key: IDBValidKey): Promise<T | undefined> {
  return transaction<T | undefined>(store, 'readonly', (objects, result) => {
    const request = objects.get(key);
    request.onsuccess = () => result(request.result);
  });
}

function keyProfile(
  key: CryptoKey,
  type: KeyType,
  name: string,
  usages: string[],
  curve?: string,
): boolean {
  return (
    Object.prototype.toString.call(key) === '[object CryptoKey]' &&
    key.type === type &&
    key.algorithm.name === name &&
    (curve === undefined ||
      (key.algorithm as EcKeyAlgorithm).namedCurve === curve) &&
    key.extractable === (type === 'public') &&
    [...key.usages].sort().join() === [...usages].sort().join()
  );
}

export async function validateBrowserIdentity(
  value: unknown,
): Promise<BrowserIdentity> {
  const identity = value as BrowserIdentity | undefined;
  if (
    !identity ||
    identity.version !== 1 ||
    !keyProfile(
      identity.signing?.privateKey,
      'private',
      'ECDSA',
      ['sign'],
      'P-384',
    ) ||
    !keyProfile(
      identity.signing?.publicKey,
      'public',
      'ECDSA',
      ['verify'],
      'P-384',
    ) ||
    !keyProfile(
      identity.kem?.privateKey,
      'private',
      'ECDH',
      ['deriveBits'],
      'P-256',
    ) ||
    !keyProfile(identity.kem?.publicKey, 'public', 'ECDH', [], 'P-256') ||
    !keyProfile(identity.storageKey, 'secret', 'AES-GCM', [
      'encrypt',
      'decrypt',
    ]) ||
    (identity.storageKey.algorithm as AesKeyAlgorithm).length !== 256
  ) {
    throw new Error(
      'Stored browser identity is invalid; existing vaults were left unchanged',
    );
  }
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-384' },
    identity.signing.privateKey,
    challenge,
  );
  if (
    !(await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-384' },
      identity.signing.publicKey,
      signature,
      challenge,
    ))
  ) {
    throw new Error('Stored signing identity does not match');
  }
  const probe = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const a = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'ECDH', public: probe.publicKey },
      identity.kem.privateKey,
      256,
    ),
  );
  const b = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'ECDH', public: identity.kem.publicKey },
      probe.privateKey,
      256,
    ),
  );
  try {
    if (!a.every((byte, index) => byte === b[index]))
      throw new Error('Stored KEM identity does not match');
  } finally {
    a.fill(0);
    b.fill(0);
  }
  return identity;
}

export async function getBrowserIdentity(): Promise<BrowserIdentity> {
  const stored = await read<unknown>('identity', 'current');
  if (stored !== undefined) return validateBrowserIdentity(stored);
  const savedDocuments = await transaction<number>(
    'documents',
    'readonly',
    (objects, result) => {
      const request = objects.count();
      request.onsuccess = () => result(request.result);
    },
  );
  if (savedDocuments > 0)
    throw new Error(
      'The browser identity is missing; existing vaults were left unchanged',
    );
  const [signing, kem, storageKey] = await Promise.all([
    crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, false, [
      'sign',
      'verify',
    ]),
    crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
      'deriveBits',
    ]),
    crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
      'encrypt',
      'decrypt',
    ]),
  ]);
  const identity: BrowserIdentity = { version: 1, signing, kem, storageKey };
  try {
    await transaction<void>('identity', 'readwrite', (objects) => {
      objects.add(identity, 'current');
    });
    return identity;
  } catch (error) {
    if (!(error instanceof DOMException) || error.name !== 'ConstraintError')
      throw error;
    return validateBrowserIdentity(await read('identity', 'current'));
  }
}

function aad(
  record: Pick<StoredDocument, 'owner' | 'path' | 'revision' | 'isVault'>,
): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(
    JSON.stringify([
      'peerborne/password-manager/checkpoint/1',
      record.owner,
      record.path,
      record.revision,
      record.isVault,
    ]),
  );
}

export class VaultStore {
  constructor(
    private readonly identity: BrowserIdentity,
    readonly owner: string,
  ) {}

  async listVaults(): Promise<string[]> {
    const records = await transaction<{ owner: string; path: string }[]>(
      'vaults',
      'readonly',
      (objects, result) => {
        const request = objects.getAll();
        request.onsuccess = () => result(request.result);
      },
    );
    return records
      .filter(
        (record) =>
          record?.owner === this.owner && typeof record.path === 'string',
      )
      .map((record) => record.path)
      .sort();
  }

  async load(
    path: string,
  ): Promise<
    | { checkpoint: DocumentCheckpoint; revision: number; isVault: boolean }
    | undefined
  > {
    const record = await read<StoredDocument>('documents', path);
    if (record === undefined) return undefined;
    if (
      !record ||
      record.version !== 1 ||
      record.path !== path ||
      record.owner !== this.owner ||
      !Number.isSafeInteger(record.revision) ||
      record.revision < 1 ||
      typeof record.isVault !== 'boolean' ||
      !(record.nonce instanceof Uint8Array) ||
      record.nonce.length !== 12 ||
      !(record.ciphertext instanceof ArrayBuffer) ||
      record.ciphertext.byteLength > MAX_CIPHERTEXT_BYTES
    ) {
      throw new Error('Saved vault data is invalid; it was left unchanged');
    }
    let cleartext: Uint8Array<ArrayBuffer>;
    try {
      cleartext = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: record.nonce, additionalData: aad(record) },
          this.identity.storageKey,
          record.ciphertext,
        ),
      );
    } catch {
      throw new Error(
        'Saved vault data could not be authenticated; it was left unchanged',
      );
    }
    try {
      if (cleartext.length < 6)
        throw new Error('Saved vault data is incomplete');
      const length = new DataView(cleartext.buffer).getUint32(0);
      if (
        length === 0 ||
        length > MAX_DOCUMENT_CHECKPOINT_BYTES ||
        cleartext.length - length - 4 < 1 ||
        cleartext.length - length - 4 > 8192
      )
        throw new Error('Saved vault data is incomplete');
      return {
        checkpoint: {
          payload: cleartext.slice(4, 4 + length),
          signature: cleartext.slice(4 + length),
        },
        revision: record.revision,
        isVault: record.isVault,
      };
    } finally {
      cleartext.fill(0);
    }
  }

  async save(
    path: string,
    isVault: boolean,
    checkpoint: DocumentCheckpoint,
    expectedRevision: number,
  ): Promise<number> {
    if (
      checkpoint.payload.length < 1 ||
      checkpoint.payload.length > MAX_DOCUMENT_CHECKPOINT_BYTES ||
      checkpoint.signature.length < 1 ||
      checkpoint.signature.length > 8192 ||
      !Number.isSafeInteger(expectedRevision) ||
      expectedRevision < 0 ||
      expectedRevision === Number.MAX_SAFE_INTEGER
    )
      throw new Error('Invalid vault checkpoint');
    const cleartext = new Uint8Array(
      4 + checkpoint.payload.length + checkpoint.signature.length,
    );
    new DataView(cleartext.buffer).setUint32(0, checkpoint.payload.length);
    cleartext.set(checkpoint.payload, 4);
    cleartext.set(checkpoint.signature, 4 + checkpoint.payload.length);
    const metadata = {
      owner: this.owner,
      path,
      revision: expectedRevision + 1,
      isVault,
    };
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    let ciphertext: ArrayBuffer;
    try {
      ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad(metadata) },
        this.identity.storageKey,
        cleartext,
      );
    } finally {
      cleartext.fill(0);
    }
    await transaction<void>(['documents', 'vaults'], 'readwrite', (objects) => {
      const request = objects.get(path);
      request.onsuccess = () => {
        try {
          const previous = request.result as StoredDocument | undefined;
          if (
            (previous === undefined ? 0 : previous.revision) !==
              expectedRevision ||
            (previous !== undefined &&
              (previous.owner !== this.owner ||
                previous.path !== path ||
                previous.isVault !== isVault))
          ) {
            request.transaction!.abort();
            return;
          }
          objects.put(
            {
              version: 1,
              ...metadata,
              nonce,
              ciphertext,
            } satisfies StoredDocument,
            path,
          );
          if (isVault)
            objects.transaction
              .objectStore('vaults')
              .put({ owner: this.owner, path }, path);
        } catch {
          try {
            request.transaction!.abort();
          } catch {}
        }
      };
    });
    return metadata.revision;
  }
}
