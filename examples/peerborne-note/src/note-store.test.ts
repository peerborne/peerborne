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
  await store.save('/notes/founder', true, checkpoint, 0);
  await store.save('/notes/accepted', true, checkpoint, 0);
  expect(await store.listDocuments()).toEqual([
    '/notes/accepted',
    '/notes/founder',
  ]);
  expect((await store.load('/notes/accepted'))?.isVault).toBe(true);
  expect((await store.load('/notes/founder'))?.isVault).toBe(true);
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
