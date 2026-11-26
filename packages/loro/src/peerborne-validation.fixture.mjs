import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { LoroDoc, LoroMap } from 'loro-crdt';
import {
  documentFixture,
  project,
  publishedMessage,
  replicaOf,
  signedMessage,
} from '../../../verification/fixtures.mjs';

// The crafted payloads are written under fixed peer IDs, so these scenarios
// check Loro byte validation without binding actors to change signers.
const options = { adapter: 'loro', actorBinding: false };

function fixture(name) {
  return new Uint8Array(
    readFileSync(new URL(`./fixtures/${name}.bin`, import.meta.url)),
  );
}

// The crafted updates in ./fixtures extend this history.
function baseSnapshot() {
  const doc = new LoroDoc();
  doc.setPeerId('1');
  doc.getText('t').insert(0, 'hello world');
  doc.getMap('m').set('k', 1);
  doc.getList('l').push('a');
  doc.getList('l').push('b');
  doc.getMap('m').setContainer('sub', new LoroMap()).set('x', 'y');
  doc.getMovableList('ml').push(1);
  doc.getMovableList('ml').push(2);
  const node = doc.getTree('tr').createNode();
  node.data.set('name', 'root');
  doc.getTree('tr').createNode(node.id);
  doc.getCounter('c').increment(3);
  doc.getText('rt').insert(0, 'rich text');
  doc.getText('rt').mark({ start: 0, end: 4 }, 'bold', true);
  doc.commit();
  return doc.export({ mode: 'snapshot' });
}

function recorded(fixture) {
  return {
    state: project(fixture),
    hashes: [...fixture.document._hashes].sort(),
    history: fixture.document.historySize(),
  };
}

async function restore(fixture, index) {
  const checkpoint = await fixture.document.exportCheckpoint();
  const restored = await documentFixture({
    ...options,
    index,
    identity: fixture.identity,
    path: fixture.document.documentPath,
    open: false,
  });
  await restored.document.restoreCheckpoint(checkpoint);
  return restored;
}

test('replicas reject crafted Loro payloads from an authorized writer and stay in sync', async (t) => {
  const base = baseSnapshot();
  const alice = await documentFixture({ ...options, index: 11 });
  await alice.document.change((doc) => {
    doc.import(base);
  });
  const bob = await replicaOf(alice, 12, options);
  const mallory = await replicaOf(alice, 13, options);
  t.after(() => Promise.all([alice, bob, mallory].map((f) => f.close())));

  const honestLocalChange = mallory.provider.localChange.bind(mallory.provider);
  for (const name of ['unknown-tree-container', 'unknown-list-container']) {
    const crafted = fixture(name);
    mallory.provider.localChange = (doc) => [doc, crafted];
    await mallory.document.change(() => {});
    const frame = await publishedMessage(mallory);
    for (const replica of [alice, bob]) {
      const before = recorded(replica);
      await assert.rejects(
        replica.document.sync(frame),
        /unsupported container/,
      );
      assert.deepEqual(recorded(replica), before);
      assert.equal(replica.document._hashes.has(frame.changeId), false);
    }
  }
  mallory.provider.localChange = honestLocalChange;

  await bob.document.change((doc) => {
    doc.getMap('m').set('bob', 1);
  });
  assert.equal(await alice.document.sync(await publishedMessage(bob)), true);
  await alice.document.change((doc) => {
    doc.getText('rt').insert(0, '> ');
  });
  assert.equal(await bob.document.sync(await publishedMessage(alice)), true);
  assert.deepEqual(project(bob), project(alice));

  const restored = await restore(bob, 22);
  t.after(() => restored.close());
  assert.deepEqual(project(restored), project(bob));

  mallory.document.document.import(fixture('unknown-list-container'));
  await mallory.document.snapshot();
  const snapshot = await signedMessage(mallory, {
    snapshot: mallory.document.latestSnapshot,
  });
  const before = recorded(alice);
  await assert.rejects(alice.document.sync(snapshot), /unsupported container/);
  assert.deepEqual(recorded(alice), before);
  assert.equal(alice.document.latestSnapshot, undefined);

  await alice.document.snapshot();
  const carol = await replicaOf(alice, 14, options);
  t.after(() => carol.close());
  assert.deepEqual(project(carol), project(alice));
  await carol.document.change((doc) => {
    doc.getMap('m').set('carol', 1);
  });
  assert.equal(await alice.document.sync(await publishedMessage(carol)), true);
  assert.deepEqual(project(carol), project(alice));
});

test('a crafted change that waited for a dependency stops waiting once it is discarded', async (t) => {
  const complete = new LoroDoc();
  complete.import(baseSnapshot());
  const partial = complete.forkAt([{ peer: '1', counter: 31 }]);
  const missing = complete.export({
    mode: 'update',
    from: partial.oplogVersion(),
  });
  const alice = await documentFixture({ ...options, index: 11 });
  await alice.document.change((doc) => {
    doc.import(partial.export({ mode: 'update' }));
  });
  const bob = await replicaOf(alice, 12, options);
  const mallory = await replicaOf(alice, 13, options);
  t.after(() => Promise.all([alice, bob, mallory].map((f) => f.close())));

  const crafted = fixture('unknown-tree-container');
  mallory.provider.localChange = (doc) => [doc, crafted];
  await mallory.document.change(() => {});
  const poisoned = await publishedMessage(mallory);
  assert.equal(await alice.document.sync(poisoned), true);
  assert.equal(alice.document._isWaiting(poisoned.changeId), true);
  assert.equal(alice.document._hashes.has(poisoned.changeId), false);

  await bob.document.change((doc) => {
    doc.import(missing);
  });
  const dependency = bob.document._lastSyncMessage.changeId;
  await bob.document.change((doc) => {
    doc.getMap('m').set('bob', 1);
  });
  const dependent = bob.document._lastSyncMessage.changeId;
  const notified = [];
  alice.document.subscribe(
    'remote-updates',
    (_document, _readers, _writers, hashes) => notified.push(...hashes),
    'remote',
  );
  assert.equal(await alice.document.sync(await publishedMessage(bob)), true);
  for (const cid of [dependency, dependent]) {
    assert.equal(alice.document._hashes.has(cid), true);
    assert.ok(notified.includes(cid));
  }
  assert.equal(alice.document._isWaiting(poisoned.changeId), false);
  assert.equal(alice.document._hashes.has(poisoned.changeId), false);
  assert.deepEqual(project(alice), project(bob));

  await assert.rejects(alice.document.sync(poisoned), /unsupported container/);
  assert.equal(alice.document._isWaiting(poisoned.changeId), false);
  assert.equal(alice.document._hashes.has(poisoned.changeId), false);
  assert.deepEqual(project(alice), project(bob));
});
