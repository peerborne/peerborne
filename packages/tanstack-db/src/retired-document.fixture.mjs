import assert from 'node:assert/strict';
import test from 'node:test';
import { createCollection } from '@tanstack/db';
import { createDocumentStore } from '@peerborne/store';
import { peerborneCollectionOptions } from '@peerborne/tanstack-db';
import { documentFixture } from '../../../verification/fixtures.mjs';

const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

for (const adapter of ['automerge', 'yjs', 'loro']) {
  const getTitle =
    adapter === 'automerge'
      ? (doc) => doc.title
      : (doc) => doc.getMap('data').get('title');
  const setTitle =
    adapter === 'automerge'
      ? (title) => (doc) => {
          doc.title = title;
        }
      : (title) => (doc) => doc.getMap('data').set('title', title);
  const retires = adapter !== 'automerge';

  test(`${adapter}: a change that fails to store its block ${retires ? 'retires the store and fails the collection' : 'is rolled back'}, and the collection never shows it`, async () => {
    const fixture = await documentFixture({
      adapter,
      path: '/tanstack-retire',
    });
    const { document } = fixture;
    await document.change(setTitle('Initial'));
    const store = createDocumentStore(document, { manageLifecycle: false });
    const collection = createCollection(
      peerborneCollectionOptions({
        id: `retire-${adapter}`,
        store,
        getKey: (row) => row.id,
        select: (doc) => [
          { id: 'workspace', title: String(getTitle(doc) ?? 'Untitled') },
        ],
        mutate: (mutations) => (doc) => {
          for (const mutation of mutations)
            if (mutation.changes.title !== undefined)
              setTitle(mutation.changes.title)(doc);
        },
      }),
    );
    await collection.preload();
    const statuses = [];
    store.subscribe(() => statuses.push(store.getSnapshot().status));

    const quota = new Error('QuotaExceededError');
    const put = fixture.helia.blockstore.put.bind(fixture.helia.blockstore);
    fixture.helia.blockstore.put = async () => {
      throw quota;
    };
    const transaction = collection.update('workspace', (row) => {
      row.title = 'Discarded edit';
    });
    const error = await transaction.when('settled').then(
      () => assert.fail('the failed change settled'),
      (reason) => reason,
    );
    fixture.helia.blockstore.put = put;
    await settle();

    assert.equal(collection.get('workspace')?.title, 'Initial');
    assert.equal(document.retired, retires);
    if (retires) {
      assert.match(error.message, /could not be rolled back/);
      assert.equal(error.cause, quota);
      assert.deepEqual(statuses, ['retired', 'closed']);
      assert.equal(collection.health.hasErrors, true);
      await store.start();
      assert.equal(store.getSnapshot().status, 'retired');
      assert.equal(store.getSnapshot().data, undefined);
      await assert.rejects(store.change(setTitle('Next')), /retired/);
      assert.equal(collection.get('workspace')?.title, 'Initial');
    } else {
      assert.equal(error, quota);
      assert.equal(store.getSnapshot().status, 'ready');
      assert.equal(getTitle(store.getSnapshot().data), 'Initial');
      assert.equal(collection.health.hasErrors, false);
      await store.change(setTitle('Next'));
      assert.equal(collection.get('workspace')?.title, 'Next');
    }

    await collection.cleanup();
    await store.stop();
    await fixture.close();
  });
}
