import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { tcp } from '@libp2p/tcp';
import { identify } from '@libp2p/identify';
import { ping } from '@libp2p/ping';
import { kadDHT } from '@libp2p/kad-dht';
import { gossipsub } from '@libp2p/gossipsub';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { MemoryBlockstore } from 'blockstore-core/memory';
import { MemoryDatastore } from 'datastore-core/memory';
import { Peerborne, SubtleCrypto } from '@peerborne/core';
import {
  YjsACLProvider,
  YjsJSONSerializer,
  YjsKeychainProvider,
  YjsProvider,
} from '@peerborne/yjs';
import { signingIdentity } from '../../../verification/fixtures.mjs';

const commitments = () => ({
  version: 1,
  controlHead: new Uint8Array(32).fill(1),
  groupId: 'document-tcp',
  epoch: 1n,
  treeHash: new Uint8Array(32).fill(2),
  confirmedTranscriptHash: new Uint8Array(32).fill(3),
});

async function until(description, predicate, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await predicate();
    if (value) return value;
    if (Date.now() > deadline)
      throw new Error(`Timed out waiting for ${description}`);
    await delay(20);
  }
}

async function within(description, promise, timeoutMs = 15_000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new Error(`Timed out waiting for ${description}`)),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

// Plain replacements: a mock records each call's stack, whose call sites keep
// their receivers, such as a closed document, alive.
function quiet(t) {
  const errors = [];
  const original = { ...console };
  for (const method of ['log', 'info', 'warn']) console[method] = () => {};
  console.error = (...args) => errors.push(args.join(' '));
  t.after(() => Object.assign(console, original));
  return errors;
}

function countListeners(target) {
  const live = new Map();
  const add = target.addEventListener.bind(target);
  const remove = target.removeEventListener.bind(target);
  target.addEventListener = (type, listener, options) => {
    live.set(type, (live.get(type) ?? new Set()).add(listener));
    return add(type, listener, options);
  };
  target.removeEventListener = (type, listener, options) => {
    live.get(type)?.delete(listener);
    return remove(type, listener, options);
  };
  return (type) => live.get(type)?.size ?? 0;
}

// Real libp2p TCP nodes on loopback: GossipSub, the shared protocol handlers,
// load streams and Helia's blockstore are production code.
async function startNode(
  t,
  { identity, writers, config = {}, dht = false } = {},
) {
  identity ??= await signingIdentity();
  const serializer = new YjsJSONSerializer();
  const swarm = new Peerborne(
    identity.privateKey,
    identity.publicKey,
    new YjsProvider(),
    serializer,
    serializer,
    serializer,
    new SubtleCrypto(),
    new YjsACLProvider(),
    new YjsKeychainProvider(),
  );
  const trusted = writers ?? [identity.publicKey];
  await swarm.initialize({
    helia: {
      blockstore: new MemoryBlockstore(),
      datastore: new MemoryDatastore(),
      libp2p: {
        addresses: { listen: ['/ip4/127.0.0.1/tcp/0'] },
        transports: [tcp()],
        connectionEncrypters: [noise()],
        streamMuxers: [yamux()],
        services: {
          identify: identify(),
          ping: ping(),
          ...(dht ? { dht: kadDHT({ clientMode: true }) } : {}),
          pubsub: gossipsub({
            allowPublishToZeroTopicPeers: true,
            emitSelf: false,
            globalSignaturePolicy: 'StrictSign',
          }),
        },
        connectionGater: { denyDialMultiaddr: async () => false },
      },
    },
    resolveTrustedDocumentWriters: () => trusted,
    ...config,
  });
  t.after(() => swarm.heliaNode.stop());
  return {
    swarm,
    identity,
    writers: trusted,
    libp2p: swarm.heliaNode.libp2p,
    listeners: countListeners(swarm.heliaNode.libp2p.services.pubsub),
  };
}

function document(node, path) {
  const doc = node.swarm.doc(path);
  doc.document.getMap('root');
  return doc;
}

async function replica(node, founder) {
  const doc = document(node, founder.documentPath);
  doc._keychain.merge(founder._keychain.history());
  await doc._keychain.keys();
  return doc;
}

function assertNothingRunning(node, doc) {
  assert.equal(node.swarm._documentRegistry.has(doc.documentPath), false);
  assert.equal(
    node.libp2p.services.pubsub.getTopics().includes(doc._topic),
    false,
  );
  assert.equal(doc._subscribed, false);
  assert.equal(doc._antiEntropy, undefined);
  assert.equal(doc._gossipReceiveAdmission, undefined);
}

// WeakRef.deref() would keep a live target until the job ends, so collection
// is observed through finalization instead.
function finalization() {
  let watched = 0;
  const collected = new Set();
  const registry = new FinalizationRegistry((token) => collected.add(token));
  return {
    watch(object) {
      registry.register(object, watched++);
    },
    async assertCollected() {
      assert.equal(typeof globalThis.gc, 'function', 'run with --expose-gc');
      await until('closed documents to be collected', async () => {
        globalThis.gc();
        await delay(10);
        return collected.size === watched;
      });
    },
  };
}

test('a replica closed while open() loads it rejects, leaves nothing running and can be opened again', async (t) => {
  quiet(t);
  const config = { resolveLoadSecurityCommitments: commitments };
  const founder = await startNode(t, { config });
  const peer = await startNode(t, {
    identity: founder.identity,
    writers: founder.writers,
    config,
  });
  await peer.libp2p.dial(founder.libp2p.getMultiaddrs()[0]);

  const sources = [];
  // A helper frame, so the test's own frame does not keep the last instance.
  const closeWhileLoading = async (source, wait) => {
    const closing = await replica(peer, source);
    const opening = closing.open();
    if (wait > 0) await delay(wait);
    await closing.close();
    await assert.rejects(opening, {
      message: `Document ${source.documentPath} was closed while opening`,
    });
    assertNothingRunning(peer, closing);
    closed.watch(closing);
  };
  const closed = finalization();
  for (const [index, wait] of [0, 0, 1, 2, 3].entries()) {
    const source = document(founder, `/tcp/load/${index}`);
    await source.create();
    await source.change((doc) => doc.getMap('root').set('index', index));
    sources.push(source);
    await closeWhileLoading(source, wait);
  }
  assert.equal(peer.swarm._documentRegistry.size, 0);
  assert.equal(peer.listeners('message'), 0);
  assert.equal(peer.listeners('subscription-change'), 0);
  await closed.assertCollected();

  const reopened = await replica(peer, sources[0]);
  assert.equal(await reopened.open(), true);
  assert.equal(reopened.document.getMap('root').get('index'), 0);
  assert.notEqual(reopened._antiEntropy, undefined);
  await reopened.close();
  for (const source of sources) await source.close();
});

test('close() rejects open() at once while the load it started has not returned', async (t) => {
  quiet(t);
  let entered, release;
  const loading = new Promise((resolve) => (entered = resolve));
  const held = new Promise((resolve) => (release = resolve));
  const founder = await startNode(t, {
    config: { resolveLoadSecurityCommitments: commitments },
  });
  const peer = await startNode(t, {
    identity: founder.identity,
    writers: founder.writers,
    config: {
      resolveLoadSecurityCommitments: async () => {
        entered();
        await held;
        return commitments();
      },
    },
  });
  await peer.libp2p.dial(founder.libp2p.getMultiaddrs()[0]);
  const source = document(founder, '/tcp/held-load');
  await source.create();
  const closing = await replica(peer, source);
  const opening = closing.open();
  await within('the load to start', loading);
  await closing.close();
  await within(
    'open() to reject',
    assert.rejects(opening, /was closed while opening/),
    1_000,
  );
  assertNothingRunning(peer, closing);
  release();
  await delay(100);
  assertNothingRunning(peer, closing);
  await source.close();
});

test('create() closed while validating its path or founding rejects and a later create() succeeds', async (t) => {
  quiet(t);
  let gate = Promise.resolve();
  const node = await startNode(t, {
    config: {
      validateDocumentPath: async () => {
        await gate;
        return true;
      },
    },
  });
  const closeWhileCreating = async (path, stage) => {
    let release = () => {};
    gate =
      stage === 'validation'
        ? new Promise((resolve) => (release = resolve))
        : Promise.resolve();
    const closing = document(node, path);
    const creating = closing.create();
    if (stage === 'founding')
      for (let turn = 0; !closing._subscribed && turn < 1_000; turn++)
        await Promise.resolve();
    await closing.close();
    release();
    await assert.rejects(creating, {
      message: `Document ${path} was closed while opening`,
    });
    assertNothingRunning(node, closing);
    closed.watch(closing);
  };
  const closed = finalization();
  for (const [index, stage] of ['validation', 'founding'].entries()) {
    const path = `/tcp/create/${index}`;
    await closeWhileCreating(path, stage);

    const created = document(node, path);
    assert.equal(await created.create(), false);
    await created.change((doc) => doc.getMap('root').set('stage', stage));
    assert.equal(node.swarm._documentRegistry.get(path), created);
    assert.notEqual(created._antiEntropy, undefined);
    await created.close();
    assertNothingRunning(node, created);
  }
  assert.equal(node.listeners('message'), 0);
  assert.equal(node.listeners('subscription-change'), 0);
  await closed.assertCollected();
});

const compaction = {
  enabled: true,
  snapshotInterval: 50,
  minChangesBeforeSnapshot: 50,
  pruneAfterSnapshot: true,
  keepRecentNodes: 5,
  gcAfterPrune: true,
};
const EDITS = 320;

for (const contentRouter of [false, true]) {
  test(`garbage collection keeps up with continuous edits ${contentRouter ? 'with' : 'without'} a content router`, async (t) => {
    const errors = quiet(t);
    const node = await startNode(t, {
      dht: contentRouter,
      config: { compaction },
    });
    const doc = document(node, '/tcp/gc');
    await doc.create();
    for (let edit = 0; edit < EDITS; edit++)
      await doc.change((value) =>
        value.getMap('root').set(`k${edit % 20}`, edit),
      );
    await until('collection to finish', () => doc._gcInProgress === undefined);
    let stored = 0;
    for await (const _ of node.swarm.heliaNode.blockstore.getAll()) stored++;
    assert.deepEqual(errors, []);
    assert.ok(
      stored <= compaction.snapshotInterval + compaction.keepRecentNodes + 10,
      `${stored} of ${EDITS + 1} blocks remain`,
    );
    assert.ok(doc._gcCandidates.size <= compaction.keepRecentNodes + 10);
    await doc.close();
  });
}
