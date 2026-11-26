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
  // Nothing is stored, so the change never reaches the retained tree.
  'storing the block': {
    kept: false,
    failure: () => new Error('QuotaExceededError'),
    inject(target, failure) {
      const put = target.helia.blockstore.put.bind(target.helia.blockstore);
      let failed = false;
      target.helia.blockstore.put = async (...args) => {
        if (failed) return put(...args);
        failed = true;
        throw failure;
      };
    },
  },
  // GossipSub rejects a publication without topic peers by default. The
  // change is already stored and in the retained tree.
  'publishing the frame': {
    kept: true,
    failure: () => new Error('PublishError.NoPeersSubscribedToTopic'),
    inject(target, failure) {
      let failed = false;
      target.setPublish(async () => {
        if (failed) return;
        failed = true;
        throw failure;
      });
    },
  },
};

for (const adapter of ['automerge', 'yjs', 'loro']) {
  for (const entry of ['change', 'endChange']) {
    for (const [step, { kept, failure: failureFor, inject }] of Object.entries(
      steps,
    )) {
      const outcome = kept
        ? 'the writer keeps the change and the next frame delivers it'
        : 'the change is discarded';
      test(`${adapter}: after ${entry}() fails while ${step}, ${outcome}, and the writer and a replica converge`, async () => {
        const writer = await fixture(adapter, { index: 1 });
        await edit(writer, adapter, 'a', 1);
        const replica = await replicaOf(writer, 2, { adapter });
        const accepted = await writer.document.exportCheckpoint();
        const failure = failureFor();
        inject(writer, failure);

        const error = await edit(writer, adapter, 'b', 2, entry).then(
          () => assert.fail('the failed change resolved'),
          (reason) => reason,
        );
        let author = writer;
        if (kept || adapter === 'automerge') {
          assert.equal(error, failure);
          assert.deepEqual(
            rootOf(writer, adapter),
            kept ? { a: 1, b: 2 } : { a: 1 },
          );
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
          assert.deepEqual(rootOf(replica, adapter), rootOf(author, adapter));
        }
        const expected = kept
          ? { a: 1, b: 2, c: 3, d: 4 }
          : { a: 1, c: 3, d: 4 };
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
