import assert from 'node:assert/strict';
import test from 'node:test';
import { CID } from 'multiformats/cid';
import {
  documentFixture,
  receiveEncrypted,
  replicaOf,
  signedMessage,
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

// `to` stores the block of `cid`, as a replica that fetched it would.
async function share(from, to, cid) {
  const parsed = CID.parse(cid);
  const chunks = await Array.fromAsync(from.helia.blockstore.get(parsed));
  await to.helia.blockstore.put(parsed, Buffer.concat(chunks));
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

  // A and B write concurrently. B1 reaches only A, which stores its block
  // as a replica that fetched it would, so A's next change cites it without
  // its change. No peer G reaches stores B1.
  await deliver((await append(a, 'a1')).frame, g);
  const b1 = await append(b, 'b1');
  await deliver(b1.frame, a);
  await share(b, a, b1.cid);
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

  // At the deadline G gives up on B1 and applies A2's change without it. B1
  // is missing, not held, so A2 waits for it and catch-up keeps asking.
  const root = g.document.document.getMap('root');
  await until(
    () => root.get('a2') === true,
    DEADLINE_BOUND_MS,
    'G did not apply A2',
  );
  assert.equal(g.document.hasChange(a2.cid), false);
  assert.equal(g.document.hasChange(b1.cid), false);
  assert.equal(g.document._holdsChange(b1.cid), false);
  assert.equal(bitswap.wants.find(({ cid }) => cid === b1.cid).aborted, true);

  // A later frame citing B1 again does not wait for it while it backs off.
  const a3 = await append(a, 'a3');
  assert.equal(crossLinks(a3.tree, b1.cid), true);
  gossip(g, a3.frame);
  await until(() => root.get('a3') === true, PROMPT_MS, 'G did not apply A3');
  assert.equal(g.document.hasChange(a3.cid), false);
  assert.equal(bitswap.wants.filter(({ cid }) => cid === b1.cid).length, 1);

  // Once B1 arrives, the next frame that carries A2 and A3 settles them.
  await deliver(b1.frame, g);
  assert.equal(root.get('b1'), true);
  const a4 = await append(a, 'a4');
  gossip(g, a4.frame);
  await until(
    () => g.document.hasChange(a4.cid),
    PROMPT_MS,
    'G did not hold A4',
  );
  assert.equal(g.document.hasChange(a2.cid), true);
  assert.equal(g.document.hasChange(a3.cid), true);

  // close() aborts a fetch in progress at once.
  const b2 = await append(b, 'b2');
  await deliver(b2.frame, a);
  await share(b, a, b2.cid);
  const a5 = await append(a, 'a5');
  assert.equal(crossLinks(a5.tree, b2.cid), true);
  gossip(g, a5.frame);
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
  assert.equal(g.document.hasChange(a5.cid), false);
});

test('a snapshot that covers a missing change releases what waited for it', async (t) => {
  const a = await documentFixture({ ...options, index: 1 });
  await a.document.change((doc) => doc.getMap('root').set('created', true));
  const b = await replicaOf(a, 2, options);
  const g = await replicaOf(a, 3, options);
  t.after(async () => {
    await Promise.all([a.close(), b.close(), g.close()]);
  });

  // G cannot fetch B1, which only B and A store, so A2 waits for it.
  await deliver((await append(a, 'a1')).frame, g);
  const b1 = await append(b, 'b1');
  await deliver(b1.frame, a);
  await share(b, a, b1.cid);
  const a2 = await append(a, 'a2');
  assert.equal(crossLinks(a2.tree, b1.cid), true);
  await deliver(a2.frame, g);
  const root = g.document.document.getMap('root');
  assert.equal(root.get('a2'), true);
  assert.equal(g.document.hasChange(a2.cid), false);
  assert.equal(g.document._holdsChange(b1.cid), false);
  assert.notEqual(g.document._lastSyncMessage.changeId, a2.cid);

  // A's snapshot covers B1. G applies it, stops waiting and serves A's tree.
  await a.document.snapshot();
  assert.equal(
    await g.document.sync(
      await signedMessage(a, {
        changeId: a2.cid,
        changes: a2.tree,
        snapshot: a.document._latestSnapshot,
      }),
    ),
    true,
  );
  assert.equal(root.get('b1'), true);
  assert.equal(g.document._holdsChange(b1.cid), true);
  assert.equal(g.document._isWaiting(a2.cid), false);
  assert.equal(g.document._lastSyncMessage.changeId, a2.cid);

  // A later change that cites B1 again is held without fetching it.
  const a3 = await append(a, 'a3');
  assert.equal(crossLinks(a3.tree, b1.cid), true);
  await deliver(a3.frame, g);
  assert.equal(g.document.hasChange(a3.cid), true);
  assert.equal(g.document._lastSyncMessage.changeId, a3.cid);
});
