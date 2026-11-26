import assert from 'node:assert/strict';
import test from 'node:test';
import {
  A,
  documentFixture,
  receiveEncrypted,
  replicaOf,
} from '../../../verification/fixtures.mjs';

const adapters = {
  automerge: {
    init: (doc) => {
      doc.log = [];
    },
    append: (entry) => (doc) => {
      doc.log.push(entry);
    },
    log: (fixture) => [...fixture.document.document.log],
    waiting: (fixture) =>
      A.getMissingDeps(fixture.document.document, []).length > 0,
  },
  yjs: {
    init: (doc) => {
      doc.getArray('log').push(['r']);
    },
    // Inserting after an item makes the Yjs update depend on that item.
    append: (entry, after) => (doc) => {
      const log = doc.getArray('log');
      const index =
        after === undefined ? log.length : log.toJSON().indexOf(after) + 1;
      log.insert(index, [entry]);
    },
    log: (fixture) => fixture.document.document.getArray('log').toJSON(),
    waiting: (fixture) =>
      fixture.document.document.store.pendingStructs !== null ||
      fixture.document.document.store.pendingDs !== null,
  },
  loro: {
    init: (doc) => {
      doc.getList('log').push('r');
    },
    append: (entry) => (doc) => {
      doc.getList('log').push(entry);
    },
    log: (fixture) => fixture.document.document.getList('log').toJSON(),
    waiting: (fixture) =>
      fixture.document.document.exportPendingUpdates() !== undefined,
  },
};

async function deliver(frame, ...targets) {
  for (const target of targets) {
    assert.equal(await receiveEncrypted(target, frame), true);
  }
}

async function change(fixture, changeFn) {
  await fixture.document.change(changeFn);
  return {
    cid: fixture.document._lastSyncMessage.changeId,
    frame: fixture.stats.lastFrame,
  };
}

function referencedCids(node, cids = new Set()) {
  for (const [cid, child] of Object.entries(node.children ?? {})) {
    cids.add(cid);
    referencedCids(child, cids);
  }
  return cids;
}

// G misses b1. A applies b1, then four changes from G evict b1 from A's recent
// tips, so A's next change a2 depends on b1 without referencing it. G's CRDT
// buffers a2 until b1 arrives.
async function replicasWithBufferedChange(t, adapter) {
  const { init, append } = adapters[adapter];
  const options = { adapter };
  const a = await documentFixture({ ...options, index: 1 });
  await change(a, init);
  const b = await replicaOf(a, 2, options);
  const g = await replicaOf(a, 3, options);
  const fixtures = [a, b, g];
  t.after(() => Promise.all(fixtures.map((fixture) => fixture.close())));

  await deliver((await change(a, append('a1'))).frame, g);
  const b1 = await change(b, append('b1'));
  await deliver(b1.frame, a);
  for (let index = 1; index <= 4; index++) {
    await deliver((await change(g, append(`g${index}`))).frame, a);
  }
  const a2 = await change(a, append('a2', 'b1'));
  assert.equal(
    referencedCids(a.document._lastSyncMessage.changes).has(b1.cid),
    false,
  );
  const notified = [];
  g.document.subscribe(
    'remote-updates',
    (_document, _readers, _writers, hashes) => notified.push(...hashes),
    'remote',
  );
  await deliver(a2.frame, g);
  assert.equal(adapters[adapter].waiting(g), true);
  assert.equal(adapters[adapter].log(g).includes('a2'), false);
  return { a, b, g, b1, a2, fixtures, notified };
}

for (const adapter of Object.keys(adapters)) {
  test(`a restored ${adapter} replica recovers a change that was waiting for a dependency`, async (t) => {
    const { append, log, waiting } = adapters[adapter];
    const { a, b, g, fixtures } = await replicasWithBufferedChange(t, adapter);

    const restored = await documentFixture({
      adapter,
      index: 4,
      identity: g.identity,
      path: g.document.documentPath,
      open: false,
    });
    fixtures.push(restored);
    await restored.document.restoreCheckpoint(
      await g.document.exportCheckpoint(),
    );
    await restored.document.open();
    assert.deepEqual(log(restored), log(g));

    await deliver((await change(b, append('b2'))).frame, restored, a);
    await deliver((await change(a, append('a3'))).frame, restored, b);

    assert.deepEqual(log(restored), log(a));
    assert.deepEqual(log(b), log(a));
    assert.equal(waiting(restored), false);
  });
}

test('an Automerge change waiting for a dependency is recorded when its dependency arrives', async (t) => {
  const { append, log } = adapters.automerge;
  const { a, b, g, b1, a2, notified } = await replicasWithBufferedChange(
    t,
    'automerge',
  );
  assert.deepEqual(notified, []);
  assert.equal(g.document.hasChange(a2.cid), false);
  assert.notEqual(g.document._lastSyncMessage.changeId, a2.cid);

  const b2 = await change(b, append('b2'));
  await deliver(b2.frame, g, a);
  assert.deepEqual(log(g), log(a));
  assert.equal(g.document.hasChange(a2.cid), true);
  assert.deepEqual(notified.sort(), [b1.cid, b2.cid, a2.cid].sort());

  const a3 = await change(a, append('a3'));
  await deliver(a3.frame, g);
  assert.deepEqual(log(g), log(a));
  assert.equal(g.document._lastSyncMessage.changeId, a3.cid);
  assert.deepEqual(notified.sort(), [b1.cid, b2.cid, a2.cid, a3.cid].sort());
});

test('a new Automerge replica keeps a restorable checkpoint when its first tree waits for a dependency', async (t) => {
  const { append, log, waiting } = adapters.automerge;
  const { a, b, a2, fixtures } = await replicasWithBufferedChange(
    t,
    'automerge',
  );
  const joined = await replicaOf(a, 5, { adapter: 'automerge' });
  fixtures.push(joined);
  assert.equal(waiting(joined), true);
  assert.equal(joined.document.hasChange(a2.cid), false);
  assert.notEqual(joined.document._lastSyncMessage.changeId, a2.cid);

  const restored = await documentFixture({
    adapter: 'automerge',
    index: 6,
    identity: joined.identity,
    path: joined.document.documentPath,
    open: false,
  });
  fixtures.push(restored);
  await restored.document.restoreCheckpoint(
    await joined.document.exportCheckpoint(),
  );
  await restored.document.open();

  await deliver((await change(b, append('b2'))).frame, restored, a);
  await deliver((await change(a, append('a3'))).frame, restored);

  assert.deepEqual(log(restored), log(a));
  assert.equal(waiting(restored), false);
});
