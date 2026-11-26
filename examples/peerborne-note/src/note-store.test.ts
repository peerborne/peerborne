import { getNoteIdentity, NOTE_DATABASE, NoteStore } from './note-store.js';
import { getOrCreateIdentity, identityFingerprint } from './identity-store.js';
import { createBrowserCheckpointStorage } from '../../shared/browser-checkpoint-store.js';

jest.mock('@peerborne/core', () => ({
  MAX_DOCUMENT_CHECKPOINT_BYTES: 16 * 1024 * 1024,
}));

async function removeDatabase(name: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

beforeEach(async () => {
  await removeDatabase(NOTE_DATABASE);
});
afterAll(async () => {
  await removeDatabase(NOTE_DATABASE);
});

test('retains the original signing identity and stable non-extractable recovery keys', async () => {
  const signing = await getOrCreateIdentity();
  const first = await getNoteIdentity(signing);
  const second = await getNoteIdentity(signing);
  expect(await identityFingerprint(first.signing.publicKey)).toBe(
    await identityFingerprint(signing.publicKey),
  );
  expect(await identityFingerprint(second.signing.publicKey)).toBe(
    await identityFingerprint(signing.publicKey),
  );
  expect(first.kem.privateKey.extractable).toBe(false);
  expect(second.storageKey.extractable).toBe(false);
  const firstKem = Buffer.from(
    await crypto.subtle.exportKey('raw', first.kem.publicKey),
  );
  const secondKem = Buffer.from(
    await crypto.subtle.exportKey('raw', second.kem.publicKey),
  );
  expect(firstKem.equals(secondKem)).toBe(true);
});

test('rejects another signing identity without replacing the retained keys', async () => {
  const signing = await getOrCreateIdentity();
  await getNoteIdentity(signing);
  const other = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  );
  await expect(getNoteIdentity(other)).rejects.toThrow(
    /another browser identity/,
  );
  expect(
    await identityFingerprint(
      (await getNoteIdentity(signing)).signing.publicKey,
    ),
  ).toBe(await identityFingerprint(signing.publicKey));
});

test('lists and restores accepted notes as well as notes created in this browser', async () => {
  const identity = await getNoteIdentity(await getOrCreateIdentity());
  const store = new NoteStore(identity, 'owner');
  const checkpoint = {
    payload: new Uint8Array([1, 2]),
    signature: new Uint8Array([3]),
  };
  const now = jest.spyOn(Date, 'now');
  try {
    now.mockReturnValue(2_000);
    await store.save('/notes/founder', true, checkpoint, 0);
    now.mockReturnValue(1_000);
    await store.save('/notes/accepted', true, checkpoint, 0);
  } finally {
    now.mockRestore();
  }
  expect(await store.listDocuments()).toEqual([
    { path: '/notes/accepted', createdAtMs: 1_000 },
    { path: '/notes/founder', createdAtMs: 2_000 },
  ]);
  expect((await store.load('/notes/accepted'))?.isVault).toBe(true);
  expect((await store.load('/notes/founder'))?.isVault).toBe(true);
});

test('keeps a note in creation order after later saves', async () => {
  const identity = await getNoteIdentity(await getOrCreateIdentity());
  const store = new NoteStore(identity, 'owner');
  const checkpoint = {
    payload: new Uint8Array([1, 2]),
    signature: new Uint8Array([3]),
  };
  const now = jest.spyOn(Date, 'now');
  try {
    now.mockReturnValue(1_000);
    const revision = await store.save('/notes/first', true, checkpoint, 0);
    now.mockReturnValue(2_000);
    await store.save('/notes/second', true, checkpoint, 0);
    now.mockReturnValue(3_000);
    await store.save('/notes/first', true, checkpoint, revision);
  } finally {
    now.mockRestore();
  }
  expect(await store.listDocuments()).toEqual([
    { path: '/notes/first', createdAtMs: 1_000 },
    { path: '/notes/second', createdAtMs: 2_000 },
  ]);
});

test('lists a note whose creation time is malformed and records one on the next save', async () => {
  const identity = await getNoteIdentity(await getOrCreateIdentity());
  const store = new NoteStore(identity, 'owner');
  const checkpoint = {
    payload: new Uint8Array([1, 2]),
    signature: new Uint8Array([3]),
  };
  const revision = await store.save('/notes/fixture', true, checkpoint, 0);
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.open(NOTE_DATABASE, 1);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const database = request.result;
      const tx = database.transaction('vaults', 'readwrite');
      tx.objectStore('vaults').put(
        { owner: 'owner', path: '/notes/fixture', createdAtMs: -1 },
        '/notes/fixture',
      );
      tx.oncomplete = () => {
        database.close();
        resolve();
      };
      tx.onabort = () => reject(tx.error);
    };
  });
  expect(await store.listDocuments()).toEqual([
    { path: '/notes/fixture', createdAtMs: undefined },
  ]);
  const now = jest.spyOn(Date, 'now').mockReturnValue(4_000);
  try {
    await store.save('/notes/fixture', true, checkpoint, revision);
  } finally {
    now.mockRestore();
  }
  expect(await store.listDocuments()).toEqual([
    { path: '/notes/fixture', createdAtMs: 4_000 },
  ]);
});

test('the application authentication domain is bound to the ciphertext', async () => {
  const identity = await getNoteIdentity(await getOrCreateIdentity());
  const store = new NoteStore(identity, 'owner');
  await store.save(
    '/notes/fixture',
    true,
    { payload: new Uint8Array([1]), signature: new Uint8Array([2]) },
    0,
  );
  const otherDomain = createBrowserCheckpointStorage(
    NOTE_DATABASE,
    'another-app/checkpoint/1',
  );
  await expect(
    new otherDomain.Store(identity, 'owner').load('/notes/fixture'),
  ).rejects.toThrow(/could not be authenticated/);
});
