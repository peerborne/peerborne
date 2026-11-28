import assert from 'node:assert/strict';
import test from 'node:test';
import { MemoryBlockstore } from 'blockstore-core/memory';
import { MemoryDatastore } from 'datastore-core/memory';
import { documentCheckpointCommitment } from '@peerborne/core';
import {
  documentFixture,
  project,
  signingIdentity,
} from '../../../verification/fixtures.mjs';

const path = '/encrypted-checkpoint';
const secret = 'restored value';
const storageKey = () =>
  crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);

function edit(target, adapter, value) {
  return target.document.change(
    adapter === 'automerge'
      ? (doc) => {
          doc.value = value;
        }
      : (doc) => doc.getMap('root').set('value', value),
  );
}

function valueOf(target, adapter) {
  return adapter === 'automerge'
    ? project(target).value
    : target.document.document.getMap('root').get('value');
}

const contains = (haystack, needle) =>
  Buffer.from(haystack).includes(Buffer.from(needle));

for (const adapter of ['automerge', 'yjs', 'loro']) {
  test(`${adapter}: an encrypted checkpoint restores the document before open`, async () => {
    const options = {
      adapter,
      path,
      identity: await signingIdentity(),
      blockstore: new MemoryBlockstore(),
      datastore: new MemoryDatastore(),
    };
    const writer = await documentFixture(options);
    await edit(writer, adapter, secret);
    const key = await storageKey();
    const sealed = await writer.document.exportEncryptedCheckpoint(key);
    const plaintext = await writer.document.exportPlaintextCheckpoint();
    for (const marker of [
      'peerborne/local-document-checkpoint',
      '"keychain"',
    ]) {
      assert.equal(contains(plaintext.payload, marker), true);
      assert.equal(contains(sealed, marker), false);
    }
    await writer.close();

    const restored = await documentFixture({ ...options, open: false });
    await restored.document.restoreEncryptedCheckpoint(sealed, key);
    await restored.document.open();
    assert.equal(valueOf(restored, adapter), secret);
    await restored.close();
  });
}

test('an encrypted checkpoint is refused under another key, path, commitment or identity, leaving the instance fresh', async () => {
  const options = {
    adapter: 'yjs',
    path,
    identity: await signingIdentity(),
    blockstore: new MemoryBlockstore(),
    datastore: new MemoryDatastore(),
  };
  const writer = await documentFixture(options);
  await edit(writer, 'yjs', 'first');
  const key = await storageKey();
  const older = await writer.document.exportEncryptedCheckpoint(key);
  await edit(writer, 'yjs', 'second');
  const sealed = await writer.document.exportEncryptedCheckpoint(key);
  const pin = await documentCheckpointCommitment(sealed);
  await assert.rejects(
    writer.document.exportEncryptedCheckpoint(
      await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
        'decrypt',
      ]),
    ),
    /256-bit AES-GCM key that can encrypt/,
  );
  await writer.close();

  const candidate = await documentFixture({ ...options, open: false });
  await assert.rejects(
    candidate.document.restoreEncryptedCheckpoint(sealed, await storageKey()),
    /could not be authenticated/,
  );
  const other = await documentFixture({
    ...options,
    path: '/another',
    open: false,
  });
  await assert.rejects(
    other.document.restoreEncryptedCheckpoint(sealed, key),
    /could not be authenticated/,
  );
  await other.close();
  await assert.rejects(
    candidate.document.restoreEncryptedCheckpoint(older, key, pin),
    /commitment mismatch/,
  );
  const stranger = await documentFixture({
    ...options,
    identity: await signingIdentity(),
    open: false,
  });
  await assert.rejects(
    stranger.document.restoreEncryptedCheckpoint(sealed, key),
    /authentication failed/,
  );
  await stranger.close();

  await candidate.document.restoreEncryptedCheckpoint(sealed, key, pin);
  await candidate.document.open();
  assert.equal(valueOf(candidate, 'yjs'), 'second');
  await assert.rejects(
    candidate.document.restoreEncryptedCheckpoint(sealed, key),
    /requires a fresh document/,
  );
  await candidate.close();
});
