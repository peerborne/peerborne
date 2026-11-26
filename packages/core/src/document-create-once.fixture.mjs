import assert from 'node:assert/strict';
import test from 'node:test';
import { documentFixture } from '../../../verification/fixtures.mjs';

const path = '/document-create-once';
const alreadyCreated =
  /already created or is open on this node; open it instead/;

for (const adapter of ['automerge', 'yjs']) {
  const setTitle =
    adapter === 'automerge'
      ? (title) => (doc) => {
          doc.title = title;
        }
      : (title) => (doc) => doc.getMap('root').set('title', title);
  const titleOf = (document) =>
    adapter === 'automerge'
      ? document.document.title
      : document.document.getMap('root').get('title');

  test(`${adapter}: a node rejects creating a path it created, while open and after close`, async () => {
    const founder = await documentFixture({ adapter, path });
    const swarm = founder.document.swarm;
    await founder.document.change(setTitle('Founded'));

    const whileOpen = swarm.doc(path);
    await assert.rejects(whileOpen.create(), alreadyCreated);
    assert.equal(whileOpen.historySize(), 0);

    const checkpoint = await founder.document.exportCheckpoint();
    await founder.document.close();
    const afterClose = swarm.doc(path);
    await assert.rejects(afterClose.create(), alreadyCreated);
    assert.equal(afterClose.historySize(), 0);

    const restored = swarm.doc(path);
    await restored.restoreCheckpoint(checkpoint);
    await assert.rejects(restored.create(), /existing local state/);
    await restored.open();
    assert.equal(titleOf(restored), 'Founded');

    const other = swarm.doc('/document-create-once/other');
    await other.create();
    await Promise.all([restored.close(), other.close()]);
    await founder.helia.stop();
  });

  test(`${adapter}: a create that fails before founding the path does not reserve it`, async () => {
    const first = await documentFixture({ adapter, path, open: false });
    const swarm = first.document.swarm;
    const offline = new Error('PublishError.NoPeersSubscribedToTopic');
    first.setPublish(async () => {
      throw offline;
    });
    await assert.rejects(first.document.create(), (error) => error === offline);

    first.setPublish(async () => {});
    const retry = swarm.doc(path);
    await retry.create();
    await retry.change(setTitle('Retried'));
    assert.equal(titleOf(retry), 'Retried');
    await retry.close();
    await assert.rejects(swarm.doc(path).create(), alreadyCreated);
    await first.helia.stop();
  });
}
