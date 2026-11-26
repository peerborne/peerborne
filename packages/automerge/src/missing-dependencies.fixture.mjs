import assert from 'node:assert/strict';
import test from 'node:test';
import {
  A,
  documentFixture,
  project,
  receiveEncrypted,
  replicaOf,
} from '../../../verification/fixtures.mjs';

const options = { adapter: 'automerge' };

async function deliver(frame, ...targets) {
  for (const target of targets) {
    assert.equal(await receiveEncrypted(target, frame), true);
  }
}

async function append(fixture, entry) {
  await fixture.document.change((doc) => {
    doc.log.push(entry);
  });
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
// tips, so A's next change a2 depends on b1 without referencing it. G buffers
// a2 until b1 arrives.
async function replicasWithBufferedChange(t) {
  const a = await documentFixture({ ...options, index: 1 });
  await a.document.change((doc) => {
    doc.log = [];
  });
  const b = await replicaOf(a, 2, options);
  const g = await replicaOf(a, 3, options);
  const fixtures = [a, b, g];
  t.after(() => Promise.all(fixtures.map((fixture) => fixture.close())));

  await deliver((await append(a, 'a1')).frame, g);
  const b1 = await append(b, 'b1');
  await deliver(b1.frame, a);
  for (let index = 1; index <= 4; index++) {
    await deliver((await append(g, `g${index}`)).frame, a);
  }
  const a2 = await append(a, 'a2');
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
  assert.equal(A.getMissingDeps(g.document.document, []).length, 1);
  assert.equal(project(g).log.includes('a2'), false);
  return { a, b, g, b1, a2, fixtures, notified };
}

test('a restored replica recovers a change that was waiting for a dependency', async (t) => {
  const { a, b, g, a2, fixtures } = await replicasWithBufferedChange(t);

  const restored = await documentFixture({
    ...options,
    index: 3,
    identity: g.identity,
    path: g.document.documentPath,
    open: false,
  });
  fixtures.push(restored);
  await restored.document.restoreCheckpoint(
    await g.document.exportCheckpoint(),
  );
  await restored.document.open();
  assert.deepEqual(project(restored), project(g));

  await deliver((await append(b, 'b2')).frame, restored, a);
  await deliver((await append(a, 'a3')).frame, restored, b);

  assert.deepEqual(project(restored), project(a));
  assert.deepEqual(project(b), project(a));
  assert.deepEqual(A.getMissingDeps(restored.document.document, []), []);
  assert.equal(restored.document.hasChange(a2.cid), true);
});

test('a late dependency integrates and records the buffered change', async (t) => {
  const { a, b, g, b1, a2, notified } = await replicasWithBufferedChange(t);
  assert.deepEqual(notified, []);
  assert.equal(g.document.hasChange(a2.cid), false);
  assert.notEqual(g.document._lastSyncMessage.changeId, a2.cid);

  const b2 = await append(b, 'b2');
  await deliver(b2.frame, g, a);

  assert.deepEqual(project(g), project(a));
  assert.deepEqual(A.getMissingDeps(g.document.document, []), []);
  assert.equal(g.document.hasChange(a2.cid), true);
  assert.deepEqual(notified.sort(), [b1.cid, a2.cid, b2.cid].sort());
});
