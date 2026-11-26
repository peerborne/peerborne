import assert from 'node:assert/strict';
import test from 'node:test';
import { createDocumentStore } from '@peerborne/store';
import { documentFixture } from '../../../verification/fixtures.mjs';

const path = '/managed-remount';
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

for (const adapter of ['automerge', 'yjs']) {
  const setTitle =
    adapter === 'automerge'
      ? (title) => (doc) => {
          doc.title = title;
        }
      : (title) => (doc) => doc.getMap('data').set('title', title);
  const titleOf = (doc) =>
    adapter === 'automerge' ? doc.title : doc.getMap('data').get('title');

  test(`${adapter}: a managed remount keeps an undelivered offline edit and its handle`, async () => {
    const founder = await documentFixture({ adapter, path });
    const swarm = founder.document.swarm;
    await founder.document.change(setTitle('Founded'));
    const checkpoint = await founder.document.exportCheckpoint();
    await founder.document.close();

    const handles = [];
    const store = createDocumentStore(async () => {
      const handle = swarm.doc(path);
      await handle.restoreCheckpoint(checkpoint);
      handles.push(handle);
      return handle;
    });
    const release = store.connect();
    while (store.getSnapshot().status === 'opening') await settle();
    assert.equal(titleOf(store.getSnapshot().data), 'Founded');

    const offline = new Error('PublishError.NoPeersSubscribedToTopic');
    founder.setPublish(async () => {
      throw offline;
    });
    await store.change(setTitle('Typed offline'));
    assert.equal(store.getSnapshot().deliveryFailure.error, offline);
    release();
    await settle();
    assert.equal(store.getSnapshot().status, 'ready');
    assert.equal(swarm._documentRegistry.get(path), handles[0]);

    const remount = store.connect();
    await settle();
    assert.equal(handles.length, 1);
    assert.equal(titleOf(store.getSnapshot().data), 'Typed offline');
    assert.equal(store.getSnapshot().deliveryFailure.error, offline);

    founder.setPublish(async () => {});
    await handles[0].change(setTitle('Delivered'));
    assert.equal(handles[0].deliveryFailure, undefined);
    assert.equal(store.getSnapshot().deliveryFailure, undefined);
    remount();
    await settle();
    assert.equal(store.getSnapshot().status, 'closed');
    await assert.rejects(
      store.change(setTitle('Late')),
      /Document store is closed/,
    );
    assert.equal(handles.length, 1);
    await founder.helia.stop();
  });
}
