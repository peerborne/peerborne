import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { createLibp2p } from 'libp2p';
import { webSockets } from '@libp2p/websockets';
import {
  circuitRelayServer,
  circuitRelayTransport,
} from '@libp2p/circuit-relay-v2';
import { identify } from '@libp2p/identify';
import { ping } from '@libp2p/ping';
import { gossipsub } from '@libp2p/gossipsub';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { MemoryBlockstore } from 'blockstore-core/memory';
import { MemoryDatastore } from 'datastore-core/memory';
import { CID } from 'multiformats/cid';
import {
  DEFAULT_DOCUMENT_TOPIC_PREFIX,
  LOAD_SECURITY_STATE_VERSION,
  Peerborne,
  SubtleCrypto,
  documentTopic,
} from '@peerborne/core';
import {
  AutomergeACLProvider,
  AutomergeJSONSerializer,
  AutomergeKeychainProvider,
  AutomergeProvider,
} from '@peerborne/automerge';
import {
  YjsACLProvider,
  YjsJSONSerializer,
  YjsKeychainProvider,
  YjsProvider,
} from '@peerborne/yjs';
import {
  documentFixture,
  project,
  replicaOf,
  signedMessage,
} from '../../../verification/fixtures.mjs';

for (const method of ['log', 'info', 'debug', 'warn', 'error'])
  console[method] = () => {};

const adapters = ['automerge', 'yjs'];
// Catch-up runs on a short cycle so a repair is observed within seconds.
const antiEntropy = {
  intervalMs: 6_000,
  minRequestIntervalMs: 2_000,
  loadAfterMs: 3_000,
  loadIntervalMs: 5_000,
};

async function until(label, predicate, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (!(await predicate())) {
    if (Date.now() > deadline)
      throw new Error(`Timed out waiting for ${label}`);
    await delay(100);
  }
}

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

const commitments = () => ({
  version: LOAD_SECURITY_STATE_VERSION,
  controlHead: new Uint8Array(32).fill(1),
  groupId: 'deferred-cross-links',
  epoch: 0n,
  treeHash: new Uint8Array(32).fill(2),
  confirmedTranscriptHash: new Uint8Array(32).fill(3),
});

async function network(t, path) {
  const relay = await createLibp2p({
    addresses: { listen: ['/ip4/127.0.0.1/tcp/0/ws'] },
    transports: [webSockets()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    connectionGater: { denyDialMultiaddr: async () => false },
    services: {
      identify: identify(),
      relay: circuitRelayServer({
        reservations: {
          applyDefaultLimit: true,
          defaultDataLimit: 64n * 1024n * 1024n,
          defaultDurationLimit: 10 * 60 * 1000,
        },
      }),
      pubsub: gossipsub({
        allowPublishToZeroTopicPeers: true,
        canRelayMessage: true,
        floodPublish: true,
        scoreParams: { IPColocationFactorWhitelist: new Set(['127.0.0.1']) },
      }),
    },
  });
  relay.services.pubsub.subscribe(
    documentTopic(path, DEFAULT_DOCUMENT_TOPIC_PREFIX),
  );
  const peers = [];
  t.after(async () => {
    for (const joined of peers.reverse()) await joined.stop();
    await relay.stop().catch(() => {});
  });
  const relayAddress = String(relay.getMultiaddrs()[0]);
  return async (adapter, options = {}) => {
    const joined = await peer(relayAddress, adapter, options);
    peers.push(joined);
    return joined;
  };
}

function stack(adapter) {
  if (adapter === 'automerge') {
    const serializer = new AutomergeJSONSerializer();
    return [
      new AutomergeProvider(),
      serializer,
      new AutomergeACLProvider(),
      new AutomergeKeychainProvider(),
    ];
  }
  return [
    new YjsProvider(),
    new YjsJSONSerializer(),
    new YjsACLProvider(),
    new YjsKeychainProvider(),
  ];
}

async function peer(
  relayAddress,
  adapter,
  { identity, kem, config = {} } = {},
) {
  identity ??= await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  );
  kem ??= await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const [provider, serializer, acl, keychain] = stack(adapter);
  const swarm = new Peerborne(
    identity.privateKey,
    identity.publicKey,
    provider,
    serializer,
    serializer,
    serializer,
    new SubtleCrypto(),
    acl,
    keychain,
  );
  const gate = { offline: false };
  const blockstore = new MemoryBlockstore();
  await swarm.initialize({
    helia: {
      blockstore,
      datastore: new MemoryDatastore(),
      libp2p: {
        addresses: { listen: ['/p2p-circuit'] },
        transports: [
          circuitRelayTransport({ reservationConcurrency: 1 }),
          webSockets(),
        ],
        connectionEncrypters: [noise()],
        streamMuxers: [yamux()],
        services: {
          identify: identify(),
          ping: ping(),
          pubsub: gossipsub({
            allowPublishToZeroTopicPeers: true,
            runOnLimitedConnection: true,
            emitSelf: false,
            canRelayMessage: true,
            globalSignaturePolicy: 'StrictSign',
          }),
        },
        connectionGater: {
          denyDialMultiaddr: async () => gate.offline,
          denyInboundConnection: async () => gate.offline,
        },
      },
    },
    pubsubDocumentPrefix: DEFAULT_DOCUMENT_TOPIC_PREFIX,
    enableTopicValidators: true,
    resolveLoadSecurityCommitments: commitments,
    ...config,
  });
  await swarm.connect([relayAddress]);
  let circuit;
  await until('circuit reservation', () => {
    circuit = swarm.libp2p
      .getMultiaddrs()
      .map(String)
      .find((address) => address.includes('/p2p-circuit'));
    return circuit !== undefined;
  });
  let stopped = false;
  return {
    adapter,
    swarm,
    identity,
    kem,
    circuit,
    blockstore,
    doc(path) {
      const document = swarm.doc(path);
      if (adapter === 'yjs') document.document.getMap('root');
      return document;
    },
    async offline() {
      gate.offline = true;
      await Promise.all(
        swarm.libp2p.getConnections().map((c) => c.close().catch(() => {})),
      );
      await until(
        'disconnected',
        () => swarm.libp2p.getConnections().length === 0,
      );
    },
    async online() {
      gate.offline = false;
      await swarm.connect([relayAddress]);
    },
    async stop() {
      if (stopped) return;
      stopped = true;
      await swarm.heliaNode.stop().catch(() => {});
    },
  };
}

const isYjs = (document) => typeof document.document?.getMap === 'function';

const set = (document, key, value) =>
  isYjs(document)
    ? document.change((draft) => draft.getMap('root').set(key, value))
    : document.change((draft) => {
        draft[key] = value;
      });

const get = (document, key) =>
  isYjs(document)
    ? document.document.getMap('root').get(key)
    : document.document?.[key];

const holds = (document, keys) =>
  Object.entries(keys).every(([key, value]) => get(document, key) === value);

// A device of the same identity that opens `path` from `source`'s replica.
async function device(join, source, sourceDocument, path, config) {
  const joined = await join(source.adapter, {
    identity: source.identity,
    config,
  });
  const document = joined.doc(path);
  document._keychain.merge(sourceDocument._keychain.history());
  await document._keychain.keys();
  await joined.swarm.connect([source.circuit]);
  return [joined, document];
}

async function invite(founder, document) {
  return document.createInvitation({
    role: 'editor',
    rendezvous: [founder.circuit],
    beforeAcceptance: async () => {},
  });
}

// `writer` and `other` edit concurrently, or `other` while disconnected,
// until both hold every edit.
async function editConcurrently(edits, writer, wd, other, od) {
  const expected = {};
  if (edits === 'concurrent') {
    for (let i = 0; i < 10; i++) {
      await Promise.all([set(wd, `w${i}`, i), set(od, `o${i}`, i)]);
      expected[`w${i}`] = i;
      expected[`o${i}`] = i;
    }
  } else {
    await other.offline();
    for (let i = 0; i < 5; i++) {
      await set(wd, `w${i}`, i);
      await set(od, `o${i}`, i);
      expected[`w${i}`] = i;
      expected[`o${i}`] = i;
    }
    await other.online();
  }
  await until(
    'both converge',
    () => holds(wd, expected) && holds(od, expected),
  );
  return expected;
}

// Invitations support only the attested Automerge profile.
for (const restore of [false, true])
  for (const edits of ['concurrent', 'offline']) {
    const restored = restore ? ' after the founder restored a checkpoint' : '';
    test(`automerge: re-sharing after removing a collaborator whose ${edits} edits only it stored${restored}`, async (t) => {
      const adapter = 'automerge';
      const path = `/deferred-cross-links/reshare-${edits}-${restore}-${crypto.randomUUID()}`;
      const join = await network(t, path);
      let founder = await join(adapter);
      const collaborator = await join(adapter);
      let fd = founder.doc(path);
      await fd.setKemKeyPair(founder.kem);
      await fd.create();
      fd.historyVisibility = 'full_history';
      await set(fd, 'body', 'v0');
      const cd = await collaborator.swarm.acceptInvitation(
        await invite(founder, fd),
        collaborator.kem,
      );
      await until('collaborator sees v0', () => get(cd, 'body') === 'v0');
      const expected = await editConcurrently(
        edits,
        founder,
        fd,
        collaborator,
        cd,
      );

      if (restore) {
        // The restored founder no longer has the delivered history of the
        // collaborator's branch, which its next change would have carried.
        const saved = await fd.exportCheckpoint();
        await founder.stop();
        founder = await join(adapter, {
          identity: founder.identity,
          kem: founder.kem,
        });
        fd = founder.doc(path);
        await fd.setKemKeyPair(founder.kem);
        await fd.restoreCheckpoint(saved);
        await fd.open();
        fd.historyVisibility = 'full_history';
        await set(fd, 'body', 'v1');
        expected.body = 'v1';
        await until('collaborator sees v1', () => get(cd, 'body') === 'v1');
      }

      await fd.removeWriter(collaborator.identity.publicKey);
      await fd.removeReader(collaborator.identity.publicKey);
      await collaborator.stop();
      await set(fd, 'afterRemoval', 1);
      expected.afterRemoval = 1;

      const replacement = await join(adapter);
      const rd = await within(
        replacement.swarm.acceptInvitation(
          await invite(founder, fd),
          replacement.kem,
        ),
        10_000,
        'acceptInvitation',
      );
      await until(
        'replacement holds every edit',
        () => holds(rd, expected),
        10_000,
      );
      assert.equal(rd._crdtProvider.hasPendingChanges(rd._document), false);
      await set(fd, 'later', 1);
      await until('replacement keeps up', () => get(rd, 'later') === 1, 10_000);
    });
  }

test('automerge: an invitation is served from a snapshot when the founder lost a block its tree cites', async (t) => {
  const adapter = 'automerge';
  const path = `/deferred-cross-links/snapshot-first-${crypto.randomUUID()}`;
  const join = await network(t, path);
  const founder = await join(adapter);
  const collaborator = await join(adapter);
  const fd = founder.doc(path);
  await fd.setKemKeyPair(founder.kem);
  await fd.create();
  fd.historyVisibility = 'full_history';
  await set(fd, 'body', 'v0');
  const cd = await collaborator.swarm.acceptInvitation(
    await invite(founder, fd),
    collaborator.kem,
  );
  await until('collaborator sees v0', () => get(cd, 'body') === 'v0');

  await collaborator.offline();
  await set(fd, 'f', 1);
  await set(cd, 'c', 1);
  const cited = cd._lastSyncMessage.changeId;
  await collaborator.online();
  await until('founder has c', () => get(fd, 'c') === 1);
  const block = CID.parse(cited);
  await founder.blockstore.put(
    block,
    Buffer.concat(await Array.fromAsync(collaborator.blockstore.get(block))),
  );
  await set(fd, 'afterMerge', 1);
  assert.equal(fd._lastSyncMessage.changes.children[cited]?.change, undefined);
  // Later edits retire C's change from the recent tips, so only the retained
  // tree still cites it when the founder loses its block.
  for (let i = 0; i < 4; i++) await set(fd, `g${i}`, i);
  await founder.blockstore.delete(block);
  await fd.removeWriter(collaborator.identity.publicKey);
  await fd.removeReader(collaborator.identity.publicKey);
  await collaborator.stop();
  assert.equal(fd._latestSnapshot, undefined);

  const replacement = await join(adapter);
  const rd = await within(
    replacement.swarm.acceptInvitation(
      await invite(founder, fd),
      replacement.kem,
    ),
    10_000,
    'acceptInvitation',
  );
  assert.notEqual(fd._latestSnapshot, undefined);
  await until(
    'replacement holds every edit',
    () => holds(rd, { body: 'v0', f: 1, c: 1, afterMerge: 1, g3: 3 }),
    10_000,
  );
});

for (const adapter of adapters) {
  for (const edits of ['concurrent', 'offline']) {
    test(`${adapter}: a new device loads ${edits} edits whose only other holder left`, async (t) => {
      const path = `/deferred-cross-links/load-${adapter}-${edits}-${crypto.randomUUID()}`;
      const join = await network(t, path);
      const writers = [];
      const config = { resolveTrustedDocumentWriters: () => writers };
      const a = await join(adapter, { config });
      writers.push(a.identity.publicKey);
      const ad = a.doc(path);
      await ad.create();
      await set(ad, 'body', 'v0');
      const [c, cd] = await device(join, a, ad, path, config);
      await cd.open();
      await until('C sees v0', () => get(cd, 'body') === 'v0');
      const expected = await editConcurrently(edits, a, ad, c, cd);
      await c.stop();
      await set(ad, 'afterwards', 1);
      expected.afterwards = 1;

      const [, dd] = await device(join, a, ad, path, {
        ...config,
        loadQuorumEnabled: false,
      });
      await within(dd.open(), 10_000, 'open()');
      await until(
        'the new device holds every edit',
        () => holds(dd, expected),
        10_000,
      );
    });
  }
}

for (const adapter of adapters) {
  test(`${adapter}: catch-up repairs a concurrent branch whose author left for good`, async (t) => {
    const path = `/deferred-cross-links/catch-up-${adapter}-${crypto.randomUUID()}`;
    const join = await network(t, path);
    const writers = [];
    const config = {
      resolveTrustedDocumentWriters: () => writers,
      antiEntropy,
    };
    const a = await join(adapter, { config });
    writers.push(a.identity.publicKey);
    const ad = a.doc(path);
    await ad.create();
    await set(ad, 'body', 'v0');
    const [b, bd] = await device(join, a, ad, path, config);
    await bd.open();
    const [c, cd] = await device(join, a, ad, path, config);
    await cd.open();
    await until(
      'devices see v0',
      () => get(bd, 'body') === 'v0' && get(cd, 'body') === 'v0',
    );

    // C misses everything below. A and B edit concurrently, B several times,
    // and A's next change merges B's branch, which only B stored as blocks.
    await c.offline();
    await b.offline();
    await set(ad, 'a', 1);
    for (let i = 0; i < 3; i++) await set(bd, `b${i}`, i);
    await b.online();
    await until("A has B's branch", () => get(ad, 'b2') === 2);
    await set(ad, 'afterMerge', 1);
    await b.stop();

    await c.online();
    const expected = { a: 1, b0: 0, b1: 1, b2: 2, afterMerge: 1 };
    await until('C repairs the branch', () => holds(cd, expected), 20_000);
    await set(ad, 'later', 1);
    await until('C keeps up', () => get(cd, 'later') === 1, 15_000);
    await until(
      'C closes the gap',
      () => cd.antiEntropyStatus.gap === false,
      15_000,
    );
  });

  test(`${adapter}: a fresh device settles while the only holder of a cited block is offline`, async (t) => {
    const path = `/deferred-cross-links/open-${adapter}-${crypto.randomUUID()}`;
    const join = await network(t, path);
    const writers = [];
    const config = { resolveTrustedDocumentWriters: () => writers };
    const a = await join(adapter, { config });
    writers.push(a.identity.publicKey);
    const ad = a.doc(path);
    await ad.create();
    await set(ad, 'body', 'v0');
    const [b, bd] = await device(join, a, ad, path, config);
    await bd.open();
    await until('B sees v0', () => get(bd, 'body') === 'v0');

    // A cites B's concurrent change by CID, as a replica that fetched its
    // block does, and then loses that block. Only B stores it, and B leaves.
    await b.offline();
    await set(ad, 'a', 1);
    await set(bd, 'b', 1);
    const cited = bd._lastSyncMessage.changeId;
    await b.online();
    await until('A has b', () => get(ad, 'b') === 1);
    const block = CID.parse(cited);
    await a.blockstore.put(
      block,
      Buffer.concat(await Array.fromAsync(b.blockstore.get(block))),
    );
    await set(ad, 'afterMerge', 1);
    const tree = ad._lastSyncMessage.changes;
    assert.equal(tree.children[cited]?.change, undefined);
    await a.blockstore.delete(block);
    await b.stop();

    const [, quorum] = await device(join, a, ad, path, config);
    await within(
      quorum.open().catch(() => false),
      30_000,
      'open() with the load quorum',
    );

    const [, single] = await device(join, a, ad, path, {
      ...config,
      loadQuorumEnabled: false,
    });
    await within(single.open(), 30_000, 'open() without the load quorum');
    assert.equal(
      holds(single, { body: 'v0', a: 1, b: 1, afterMerge: 1 }),
      true,
    );
  });
}

test('automerge: a change recorded once its dependency arrives is covered by a snapshot', async (t) => {
  const options = { adapter: 'automerge' };
  const a = await documentFixture({ ...options, index: 1 });
  await a.document.change((doc) => {
    doc.created = 1;
  });
  const b = await replicaOf(a, 2, options);
  const f = await replicaOf(a, 3, options);
  const g = await documentFixture({
    ...options,
    index: 4,
    identity: a.identity,
    path: a.document.documentPath,
    open: false,
  });
  t.after(async () => {
    for (const fixture of [a, b, f]) await fixture.close();
    await g.helia.stop();
  });
  const append = async (key) => {
    await b.document.change((doc) => {
      doc[key] = 1;
    });
    const { changeId, changes } = b.document._lastSyncMessage;
    return { cid: changeId, change: changes.change };
  };
  const b1 = await append('b1');
  const b2 = await append('b2');

  // F receives B2 citing B1, which it cannot fetch, so B2 waits. B1 then
  // arrives in a tree without B2, and B2 is recorded only afterwards.
  const node = (change, children) => ({ kind: 'document', change, children });
  assert.equal(
    await f.document.sync(
      await signedMessage(b, {
        changeId: b2.cid,
        changes: node(b2.change, { [b1.cid]: { kind: 'document' } }),
      }),
    ),
    true,
  );
  assert.equal(f.document.hasChange(b2.cid), false);
  assert.equal(
    await f.document.sync(
      await signedMessage(b, { changeId: b1.cid, changes: node(b1.change) }),
    ),
    true,
  );
  assert.equal(f.document.hasChange(b2.cid), true);

  // F's next change cannot carry B2, so F covers it with a snapshot.
  assert.equal(f.document._latestSnapshot, undefined);
  await f.document.change((doc) => {
    doc.f1 = 1;
  });
  assert.notEqual(f.document._latestSnapshot, undefined);
  assert.equal(await f.document._unservableChanges(true), 0);

  g.document._writers.merge(f.document._writers.current());
  g.document._keychain.merge(f.document._keychain.history());
  await g.document._keychain.keys();
  const { changeId, changes } = f.document._lastSyncMessage;
  assert.equal(
    await g.document.sync(
      await signedMessage(f, {
        changeId,
        changes,
        snapshot: f.document._latestSnapshot,
      }),
    ),
    true,
  );
  assert.deepEqual(
    { b1: project(g).b1, b2: project(g).b2, f1: project(g).f1 },
    { b1: 1, b2: 1, f1: 1 },
  );
  assert.equal(g.provider.hasPendingChanges(g.document._document), false);
});
