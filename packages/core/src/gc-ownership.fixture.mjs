import assert from 'node:assert/strict';
import test from 'node:test';
import { unixfs } from '@helia/unixfs';
import { MemoryBlockstore } from 'blockstore-core/memory';
import { CID } from 'multiformats/cid';
import {
  documentFixture,
  publishedMessage,
  receiveEncrypted,
  signedMessage,
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

const present = (blockstore, cid) => blockstore.has(CID.parse(cid));

// One node: the victim's documents and the application share a blockstore.
async function sharedNode() {
  const blockstore = new MemoryBlockstore();
  const identity = await signingIdentity();
  const other = await documentFixture({
    index: 2,
    identity,
    path: '/other',
    blockstore,
  });
  await other.document.change((doc) => doc.getMap('root').set('b', 1));
  const application = (
    await unixfs(other.helia).addBytes(
      new TextEncoder().encode('application file'),
    )
  ).toString();
  return {
    blockstore,
    identity,
    other,
    targets: {
      document: other.document._lastSyncMessage.changeId,
      application,
    },
  };
}

async function victimWithMallory(node, options = {}) {
  const victim = await documentFixture({
    index: 1,
    identity: node.identity,
    path: '/shared',
    blockstore: node.blockstore,
    compaction,
  });
  const pruned = new Set();
  const collect = victim.document._gcPrunedBlocks.bind(victim.document);
  victim.document._gcPrunedBlocks = (cids, ...rest) => {
    for (const cid of cids) pruned.add(cid);
    return collect(cids, ...rest);
  };
  options.beforeChanges?.(victim);
  const mallory = await signingIdentity();
  await victim.document._writers.add(mallory.publicKey);
  const own = [];
  const edit = async (key) => {
    await victim.document.change((doc) => doc.getMap('root').set(key, 1));
    own.push(victim.document._lastSyncMessage.changeId);
  };
  await edit('a0');
  const attacker = await documentFixture({
    index: 3,
    identity: mallory,
    path: '/shared',
    open: false,
  });
  attacker.document._writers.merge(victim.document._writers.current());
  attacker.document._keychain.merge(victim.document._keychain.history());
  await attacker.document._keychain.keys();
  assert.equal(
    await attacker.document.sync(await publishedMessage(victim)),
    true,
  );
  await attacker.document.open();
  return { victim, attacker, pruned, own, edit };
}

async function attack({ victim, attacker }, mode, target) {
  if (mode === 'deferred') {
    attacker.document._trackTip(target, 'document');
    await attacker.document.change((doc) => doc.getMap('root').set('m', 1));
    return receiveEncrypted(victim, attacker.stats.lastFrame);
  }
  await attacker.document.change((doc) => doc.getMap('root').set('m', 1));
  const message = await publishedMessage(attacker);
  return victim.document.sync(
    await signedMessage(attacker, {
      changeId: target,
      changes: message.changes,
    }),
  );
}

function treeNames(document, cid) {
  const message = document._lastSyncMessage;
  return (
    message.changeId === cid ||
    Object.hasOwn(message.changes.children ?? {}, cid)
  );
}

const references = {
  deferred: 'a deferred cross-link to',
  inline: 'an inline change that claims the CID of',
};
const targets = {
  document: "another document's block",
  application: 'application UnixFS data',
};

for (const mode of ['deferred', 'inline'])
  for (const target of ['document', 'application'])
    test(`${references[mode]} ${targets[target]} cannot make GC delete it`, async (t) => {
      t.mock.method(console, 'log', () => {});
      t.mock.method(console, 'error', () => {});
      const node = await sharedNode();
      const cid = node.targets[target];
      const run = await victimWithMallory(node);
      try {
        assert.equal(await attack(run, mode, cid), true);
        assert.equal(treeNames(run.victim.document, cid), true);
        for (let index = 1; index <= 12; index++) await run.edit(`a${index}`);
        await run.victim.document.collectGarbage();

        assert.equal(run.pruned.has(cid), true);
        assert.equal(await present(node.blockstore, cid), true);
        assert.equal(run.victim.document._ownBlocks.has(cid), false);
        assert.equal(run.victim.document._gcCandidates.has(cid), false);
        if (target === 'document')
          assert.notEqual(
            await node.other.document.loadChangeBlock(cid),
            undefined,
          );
        const deleted = [];
        for (const own of run.own)
          if (!(await present(node.blockstore, own))) deleted.push(own);
        assert.ok(deleted.length > 0);
        for (const own of deleted) assert.equal(run.pruned.has(own), true);
      } finally {
        await run.victim.close();
        await run.attacker.close();
        await node.other.close();
      }
    });

test('a restored checkpoint keeps the ownership check on waiting candidates', async (t) => {
  t.mock.method(console, 'log', () => {});
  t.mock.method(console, 'error', () => {});
  const node = await sharedNode();
  const cid = node.targets.document;
  const run = await victimWithMallory(node, {
    beforeChanges(victim) {
      victim.helia.blockstore.delete = async () => {
        throw new Error('closing');
      };
    },
  });
  let restored;
  let forged;
  let victimOpen = true;
  try {
    assert.equal(await attack(run, 'deferred', cid), true);
    for (let index = 1; index <= 12; index++) await run.edit(`a${index}`);
    await run.victim.document.collectGarbage();
    assert.equal(run.pruned.has(cid), true);

    const checkpoint = await run.victim.document.exportCheckpoint();
    const state = JSON.parse(new TextDecoder().decode(checkpoint.payload));
    assert.ok(state.gcCandidates.length > 0);
    assert.equal(state.ownBlocks.includes(cid), false);
    assert.equal(state.gcCandidates.includes(cid), false);
    for (const candidate of state.gcCandidates)
      assert.equal(state.ownBlocks.includes(candidate), true);
    await run.victim.close();
    victimOpen = false;

    const payload = new TextEncoder().encode(
      JSON.stringify({ ...state, gcCandidates: [...state.gcCandidates, cid] }),
    );
    forged = await documentFixture({
      index: 1,
      identity: node.identity,
      path: '/shared',
      blockstore: node.blockstore,
      compaction,
      open: false,
    });
    await assert.rejects(
      forged.document.restoreCheckpoint({
        payload,
        signature: await forged.auth.sign(payload, node.identity.privateKey),
      }),
      /garbage collection candidate/,
    );

    restored = await documentFixture({
      index: 1,
      identity: node.identity,
      path: '/shared',
      blockstore: node.blockstore,
      compaction,
      open: false,
    });
    await restored.document.restoreCheckpoint(checkpoint);
    await restored.document.open();
    assert.deepEqual([...restored.document._gcCandidates], state.gcCandidates);
    await restored.document.collectGarbage();
    assert.equal(await present(node.blockstore, cid), true);
    let deleted = 0;
    for (const candidate of state.gcCandidates)
      if (!(await present(node.blockstore, candidate))) deleted++;
    assert.ok(deleted > 0);
  } finally {
    if (victimOpen) await run.victim.close();
    await restored?.close();
    await forged?.close();
    await run.attacker.close();
    await node.other.close();
  }
});
