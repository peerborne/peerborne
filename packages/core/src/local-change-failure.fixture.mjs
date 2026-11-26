import assert from 'node:assert/strict';
import test from 'node:test';
import { MemoryBlockstore } from 'blockstore-core/memory';
import { MemoryDatastore } from 'datastore-core/memory';
import {
  documentFixture,
  project,
  receiveEncrypted,
  replicaOf,
} from '../../../verification/fixtures.mjs';

const path = '/local-change-failure';

async function fixture(adapter, options) {
  const datastore = options.datastore ?? new MemoryDatastore();
  const created = await documentFixture({
    adapter,
    path,
    blockstore: new MemoryBlockstore(),
    ...options,
    datastore,
  });
  return { ...created, datastore };
}

// A Yjs or Loro document reopened by an application gets a new client or
// peer ID, as a fresh instance does by default.
async function reopen(previous, adapter, checkpoint, index) {
  const next = await fixture(adapter, {
    index,
    identity: previous.identity,
    blockstore: previous.blockstore,
    datastore: previous.datastore,
    open: false,
  });
  await next.document.restoreCheckpoint(checkpoint);
  await next.document.open();
  return next;
}

function setter(adapter, key, value) {
  return adapter === 'automerge'
    ? (doc) => {
        doc.root ??= {};
        doc.root[key] = value;
      }
    : (doc) => doc.getMap('root').set(key, value);
}

async function edit(target, adapter, key, value, entry = 'change') {
  const change = setter(adapter, key, value);
  if (entry === 'change') return target.document.change(change);
  target.document.startChange();
  target.document.addChange(change);
  return target.document.endChange();
}

function rootOf(target, adapter) {
  return adapter === 'automerge'
    ? (project(target).root ?? {})
    : target.document.document.getMap('root').toJSON();
}

const steps = {
  'storing the block'(target, failure) {
    const put = target.helia.blockstore.put.bind(target.helia.blockstore);
    let failed = false;
    target.helia.blockstore.put = async (...args) => {
      if (failed) return put(...args);
      failed = true;
      throw failure;
    };
  },
  'publishing the frame'(target, failure) {
    let failed = false;
    target.setPublish(async () => {
      if (failed) return;
      failed = true;
      throw failure;
    });
  },
};

for (const adapter of ['automerge', 'yjs', 'loro']) {
  for (const entry of ['change', 'endChange']) {
    for (const step of Object.keys(steps)) {
      test(`${adapter}: after ${entry}() fails while ${step}, the writer and a replica converge`, async () => {
        const writer = await fixture(adapter, { index: 1 });
        await edit(writer, adapter, 'a', 1);
        const replica = await replicaOf(writer, 2, { adapter });
        const accepted = await writer.document.exportCheckpoint();
        const failure = new Error('QuotaExceededError');
        steps[step](writer, failure);

        const error = await edit(writer, adapter, 'b', 2, entry).then(
          () => assert.fail('the failed change resolved'),
          (reason) => reason,
        );
        let author = writer;
        if (adapter === 'automerge') {
          assert.equal(error, failure);
          assert.deepEqual(rootOf(writer, adapter), { a: 1 });
        } else {
          // An in-place edit cannot be undone, so the instance retires.
          assert.match(error.message, /could not be rolled back/);
          assert.equal(error.cause, failure);
          await assert.rejects(edit(writer, adapter, 'c', 3), /retired/);
          await assert.rejects(writer.document.exportCheckpoint(), /retired/);
          await writer.close();
          author = await reopen(writer, adapter, accepted, 3);
          assert.deepEqual(rootOf(author, adapter), { a: 1 });
        }

        for (const [key, value] of [
          ['c', 3],
          ['d', 4],
        ]) {
          await edit(author, adapter, key, value, entry);
          assert.equal(
            await receiveEncrypted(replica, author.stats.lastFrame),
            true,
          );
        }
        const expected = { a: 1, c: 3, d: 4 };
        assert.deepEqual(rootOf(author, adapter), expected);
        assert.deepEqual(rootOf(replica, adapter), expected);

        const checkpoint = await author.document.exportCheckpoint();
        await author.close();
        const restored = await reopen(author, adapter, checkpoint, 4);
        assert.deepEqual(rootOf(restored, adapter), expected);
        await edit(restored, adapter, 'e', 5);
        assert.equal(
          await receiveEncrypted(replica, restored.stats.lastFrame),
          true,
        );
        assert.deepEqual(rootOf(replica, adapter), { ...expected, e: 5 });
        await Promise.all([restored.close(), replica.close()]);
      });
    }
  }
}
