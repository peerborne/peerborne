import assert from 'node:assert/strict';
import test from 'node:test';
import {
  documentFixture,
  receiveEncrypted,
  replicaOf,
} from '../../../verification/fixtures.mjs';

const options = { adapter: 'yjs' };
// Below the 10 s overall fetch deadline for one message.
const PROMPT_MS = 5_000;
const DEADLINE_BOUND_MS = 20_000;

async function within(promise, ms, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new Error(`${label} did not settle within ${ms} ms`)),
          ms,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function until(predicate, ms, label) {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started > ms) throw new Error(`${label} within ${ms} ms`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

async function append(fixture, key) {
  await fixture.document.change((doc) => doc.getMap('root').set(key, true));
  const message = fixture.document._lastSyncMessage;
  return {
    cid: message.changeId,
    tree: message.changes,
    frame: fixture.stats.lastFrame,
  };
}

async function deliver(frame, ...targets) {
  for (const target of targets) {
    assert.equal(await receiveEncrypted(target, frame), true);
  }
}

// Deliver through the document's own GossipSub receive path.
function gossip(fixture, frame) {
  fixture.helia.libp2p.services.pubsub.dispatchEvent(
    new CustomEvent('message', {
      detail: { topic: fixture.document._topic, data: frame },
    }),
  );
}

function crossLinks(tree, cid) {
  const child = tree.children?.[cid];
  return child !== undefined && child.change === undefined;
}

// Bitswap's wantBlock waits for a block no connected peer holds until the
// read is aborted. Stored blocks are read as before.
function bitswapLike(blockstore) {
  const wants = [];
  const store = new Proxy(blockstore, {
    get(target, property) {
      if (property === 'get') {
        return async function* (cid, settings = {}) {
          if (await target.has(cid)) {
            yield* target.get(cid, settings);
            return;
          }
          const want = { cid: cid.toString(), aborted: false };
          wants.push(want);
          await new Promise((_resolve, reject) => {
            const abort = () => {
              want.aborted = true;
              reject(settings.signal.reason);
            };
            if (settings.signal?.aborted) abort();
            else settings.signal?.addEventListener('abort', abort, { once: true });
          });
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  return { store, wants };
}

test('a replica missing a block whose author is offline keeps working', async (t) => {
  const a = await documentFixture({ ...options, index: 1 });
  await a.document.change((doc) => doc.getMap('root').set('created', true));
  const b = await replicaOf(a, 2, options);
  const g = await replicaOf(a, 3, options);
  t.after(async () => {
    await Promise.all([a.close(), b.close()]);
    await g.helia.stop();
  });
  const bitswap = bitswapLike(g.helia.blockstore);
  g.helia.blockstore = bitswap.store;

  // A and B write concurrently. B1 reaches only A, inline, and B goes
  // offline, so no peer stores B1 as a block. A's next change cross-links it.
  await deliver((await append(a, 'a1')).frame, g);
  const b1 = await append(b, 'b1');
  await deliver(b1.frame, a);
  const a2 = await append(a, 'a2');
  assert.equal(crossLinks(a2.tree, b1.cid), true);

  gossip(g, a2.frame);
  await until(
    () => bitswap.wants.some(({ cid }) => cid === b1.cid),
    PROMPT_MS,
    'G did not ask for B1',
  );

  // While G waits for B1, its state queue stays free.
  await within(
    g.document.change((doc) => doc.getMap('root').set('g1', true)),
    PROMPT_MS,
    'change()',
  );
  await within(g.document.exportCheckpoint(), PROMPT_MS, 'exportCheckpoint()');
  await within(g.document.requestSync(), PROMPT_MS, 'requestSync()');

  // At the deadline G gives up on B1 and applies A2 without it.
  await until(
    () => g.document.hasChange(a2.cid),
    DEADLINE_BOUND_MS,
    'G did not apply A2',
  );
  assert.equal(g.document.document.getMap('root').get('a2'), true);
  assert.equal(g.document.hasChange(b1.cid), false);
  assert.equal(bitswap.wants.find(({ cid }) => cid === b1.cid).aborted, true);

  // A later frame citing B1 again does not wait for it while it backs off.
  const a3 = await append(a, 'a3');
  assert.equal(crossLinks(a3.tree, b1.cid), true);
  gossip(g, a3.frame);
  await until(() => g.document.hasChange(a3.cid), PROMPT_MS, 'G did not apply A3');
  assert.equal(bitswap.wants.filter(({ cid }) => cid === b1.cid).length, 1);

  // close() aborts a fetch in progress at once.
  const b2 = await append(b, 'b2');
  await deliver(b2.frame, a);
  const a4 = await append(a, 'a4');
  assert.equal(crossLinks(a4.tree, b2.cid), true);
  gossip(g, a4.frame);
  await until(
    () => bitswap.wants.some(({ cid }) => cid === b2.cid),
    PROMPT_MS,
    'G did not ask for B2',
  );
  await within(g.document.close(), PROMPT_MS, 'close()');
  await until(
    () => bitswap.wants.find(({ cid }) => cid === b2.cid).aborted,
    PROMPT_MS,
    'close() did not abort the fetch of B2',
  );
  assert.equal(g.document.hasChange(a4.cid), false);
});
