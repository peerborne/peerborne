import 'fake-indexeddb/auto';
import { webcrypto } from 'node:crypto';
import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import {
  getBrowserIdentity,
  validateBrowserIdentity,
  VAULT_DATABASE,
  VaultStore,
} from './vault-store';

Object.defineProperty(globalThis, 'crypto', {
  value: webcrypto,
  configurable: true,
});

beforeEach(async () => {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(VAULT_DATABASE);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
});

async function editRecord(
  store: string,
  key: string,
  edit: (value: any) => any,
): Promise<void> {
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(VAULT_DATABASE, 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = database.transaction(store, 'readwrite');
      const objects = tx.objectStore(store);
      const request = objects.get(key);
      request.onsuccess = () => objects.put(edit(request.result), key);
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    database.close();
  }
}

const checkpoint = {
  payload: new TextEncoder().encode('opaque checkpoint fixture'),
  signature: new Uint8Array([1, 2, 3]),
};

test('retains non-extractable signing, KEM, and storage keys across reconstruction', async () => {
  const first = await getBrowserIdentity();
  const second = await getBrowserIdentity();
  for (const key of [
    second.signing.privateKey,
    second.kem.privateKey,
    second.storageKey,
  ])
    assert.equal(key.extractable, false);
  const raw = (key: CryptoKey) => crypto.subtle.exportKey('raw', key);
  assert.equal(
    Buffer.from(await raw(first.signing.publicKey)).equals(
      Buffer.from(await raw(second.signing.publicKey)),
    ),
    true,
  );
  assert.equal(
    Buffer.from(await raw(first.kem.publicKey)).equals(
      Buffer.from(await raw(second.kem.publicKey)),
    ),
    true,
  );
  const original = new VaultStore(first, 'owner');
  await original.save('/vaults/fixture', true, checkpoint, 0);
  const restored = await new VaultStore(second, 'owner').load(
    '/vaults/fixture',
  );
  assert.equal(restored?.checkpoint.payload.length, checkpoint.payload.length);
});

test('concurrent initial identity creation converges on one stored key pair', async () => {
  const identities = await Promise.all(
    Array.from({ length: 5 }, () => getBrowserIdentity()),
  );
  const encoded = await Promise.all(
    identities.map(async (identity) =>
      Buffer.from(
        await crypto.subtle.exportKey('raw', identity.signing.publicKey),
      ).toString('hex'),
    ),
  );
  assert.equal(new Set(encoded).size, 1);
});

test('rejects mismatched KEM keys and malformed stored identities without replacing them', async () => {
  const identity = await getBrowserIdentity();
  const other = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  await assert.rejects(
    validateBrowserIdentity({
      ...identity,
      kem: { privateKey: identity.kem.privateKey, publicKey: other.publicKey },
    }),
    /KEM identity does not match/,
  );
  await editRecord('identity', 'current', () => ({ version: 999 }));
  await assert.rejects(getBrowserIdentity(), /identity is invalid/);
  await assert.rejects(getBrowserIdentity(), /identity is invalid/);
});

test('encrypts checkpoint contents and rejects ciphertext damage', async () => {
  const store = new VaultStore(await getBrowserIdentity(), 'owner');
  await store.save('/vaults/fixture', true, checkpoint, 0);
  let containsCleartext = true;
  await editRecord('documents', '/vaults/fixture', (record) => {
    containsCleartext = Buffer.from(record.ciphertext).includes(
      Buffer.from(checkpoint.payload),
    );
    new Uint8Array(record.ciphertext)[0] ^= 1;
    return record;
  });
  assert.equal(containsCleartext, false);
  await assert.rejects(
    store.load('/vaults/fixture'),
    /could not be authenticated/,
  );
});

test('does not generate a replacement identity when saved documents still exist', async () => {
  const store = new VaultStore(await getBrowserIdentity(), 'owner');
  await store.save('/vaults/fixture', true, checkpoint, 0);
  await editRecord('identity', 'current', () => undefined);
  await assert.rejects(getBrowserIdentity(), /identity is missing/);
  await assert.rejects(getBrowserIdentity(), /identity is missing/);
});

test('authenticates the path, owner, revision, and vault role', async () => {
  const store = new VaultStore(await getBrowserIdentity(), 'owner');
  for (const field of ['path', 'owner', 'revision', 'isVault']) {
    const path = `/vaults/${field}`;
    await store.save(path, true, checkpoint, 0);
    await editRecord('documents', path, (record) => ({
      ...record,
      [field]:
        field === 'revision' ? 2 : field === 'isVault' ? false : 'substituted',
    }));
    await assert.rejects(store.load(path));
  }
});

test('stale saves cannot overwrite a newer committed checkpoint', async () => {
  const store = new VaultStore(await getBrowserIdentity(), 'owner');
  assert.equal(await store.save('/vaults/fixture', true, checkpoint, 0), 1);
  await assert.rejects(
    store.save(
      '/vaults/fixture',
      true,
      { payload: new Uint8Array([9]), signature: new Uint8Array([8]) },
      0,
    ),
  );
  assert.equal((await store.load('/vaults/fixture'))?.revision, 1);
  assert.equal(
    (await store.load('/vaults/fixture'))?.checkpoint.payload.length,
    checkpoint.payload.length,
  );
});
