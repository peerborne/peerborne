import assert from 'node:assert/strict';
import test from 'node:test';
import { MemoryBlockstore } from 'blockstore-core/memory';
import { MemoryDatastore } from 'datastore-core/memory';
import { CID } from 'multiformats/cid';
import {
  documentFixture,
  signingIdentity,
} from '../../../verification/fixtures.mjs';

const compaction = {
  enabled: true,
  snapshotInterval: 10,
  minChangesBeforeSnapshot: 10,
  pruneAfterSnapshot: true,
  keepRecentNodes: 2,
  gcAfterPrune: true,
};

test('a restored checkpoint deletes blocks pruned before it was exported', async (t) => {
  t.mock.method(console, 'error', () => {});
  const options = {
    adapter: 'yjs',
    identity: await signingIdentity(),
    path: '/checkpoint-gc',
    compaction,
    blockstore: new MemoryBlockstore(),
    datastore: new MemoryDatastore(),
  };
  const writer = await documentFixture(options);
  // Deletion does not finish before the instance closes.
  writer.helia.blockstore.delete = async () => {
    throw new Error('closing');
  };
  for (let index = 0; index < 10; index++)
    await writer.document.change((doc) =>
      doc.getMap('root').set(`k${index}`, index),
    );
  await writer.document.collectGarbage();
  const pruned = [...writer.document._gcCandidates];
  assert.ok(pruned.length > 0);
  for (const cid of pruned)
    assert.equal(await options.blockstore.has(CID.parse(cid)), true);
  const checkpoint = await writer.document.exportPlaintextCheckpoint();
  await writer.close();

  const restored = await documentFixture({ ...options, open: false });
  await restored.document.restorePlaintextCheckpoint(checkpoint);
  await restored.document.open();
  assert.deepEqual([...restored.document._gcCandidates], pruned);
  await restored.document.collectGarbage();
  const deleted = [];
  for (const cid of pruned) {
    const present = await options.blockstore.has(CID.parse(cid));
    assert.equal(present, restored.document._gcCandidates.has(cid));
    if (!present) deleted.push(cid);
  }
  assert.ok(deleted.length > 0);
  await restored.close();
});
