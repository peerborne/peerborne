import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { createLibp2p } from 'libp2p';
import { webSockets } from '@libp2p/websockets';
import {
  circuitRelayServer,
  circuitRelayTransport,
} from '@libp2p/circuit-relay-v2';
import { identify } from '@libp2p/identify';
import { ping } from '@libp2p/ping';
import { gossipsub } from '@libp2p/gossipsub';
import { bootstrap } from '@libp2p/bootstrap';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { MemoryBlockstore } from 'blockstore-core/memory';
import { MemoryDatastore } from 'datastore-core/memory';
import {
  DEFAULT_DOCUMENT_TOPIC_PREFIX,
  NoDeliveryPeersError,
  Peerborne,
  SubtleCrypto,
  documentTopic,
} from '@peerborne/core';
import {
  YjsACLProvider,
  YjsJSONSerializer,
  YjsKeychainProvider,
  YjsProvider,
} from '@peerborne/yjs';
import { createDocumentStore } from '@peerborne/store';

for (const method of ['log', 'info', 'debug', 'warn'])
  console[method] = () => {};

const TIMEOUT_MS = 20_000;
const commitments = () => ({
  version: 1,
  controlHead: new Uint8Array(32).fill(1),
  groupId: 'relay-delivery',
  epoch: 1n,
  treeHash: new Uint8Array(32).fill(2),
  confirmedTranscriptHash: new Uint8Array(32).fill(3),
});
const stops = [];
after(async () => {
  for (const stop of stops.reverse()) await stop().catch(() => {});
});

async function until(description, predicate, timeoutMs = TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await predicate();
    if (value) return value;
    if (Date.now() > deadline)
      throw new Error(`Timed out waiting for ${description}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

// Subscribes to every document topic a peer joins, as relay-server does.
async function startRelay({ autoSubscribe }) {
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
          maxReservations: 128,
          applyDefaultLimit: true,
          defaultDurationLimit: 30 * 60 * 1000,
          defaultDataLimit: 16n * 1024n * 1024n,
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
  if (autoSubscribe) {
    relay.services.pubsub.addEventListener('subscription-change', (event) => {
      for (const subscription of event.detail.subscriptions)
        if (
          subscription.subscribe &&
          subscription.topic.startsWith(DEFAULT_DOCUMENT_TOPIC_PREFIX)
        )
          relay.services.pubsub.subscribe(subscription.topic);
    });
  }
  stops.push(() => relay.stop());
  return { relay, address: relay.getMultiaddrs()[0].toString() };
}

async function startPeer(relayAddress, trustedWriters, identity) {
  identity ??= await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  );
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
  await swarm.initialize({
    helia: {
      blockstore: new MemoryBlockstore(),
      datastore: new MemoryDatastore(),
      libp2p: {
        addresses: { listen: ['/p2p-circuit'] },
        transports: [
          circuitRelayTransport({ reservationConcurrency: 1 }),
          webSockets(),
        ],
        connectionEncrypters: [noise()],
        streamMuxers: [yamux()],
        peerDiscovery: [bootstrap({ list: [relayAddress] })],
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
        connectionGater: { denyDialMultiaddr: async () => false },
      },
    },
    pubsubDocumentPrefix: DEFAULT_DOCUMENT_TOPIC_PREFIX,
    antiEntropy: { enabled: false },
    resolveTrustedDocumentWriters: () => trustedWriters,
    resolveLoadSecurityCommitments: commitments,
  });
  stops.push(() => swarm.heliaNode.stop());
  const libp2p = swarm.heliaNode.libp2p;
  const circuit = await until('a relay reservation', () =>
    libp2p
      .getMultiaddrs()
      .map(String)
      .find((address) => address.includes('/p2p-circuit')),
  );
  return { swarm, identity, circuit, libp2p };
}

const undelivered = (document) =>
  document.deliveryFailure?.error instanceof NoDeliveryPeersError;
const set = (key, value) => (doc) => doc.getMap('root').set(key, value);
const valueOf = (document, key) => document.document.getMap('root').get(key);

test('a relay subscribed to the topic is not a delivery, so a managed store keeps an offline edit across a remount', async () => {
  const path = '/relay-delivery/relay';
  const topic = documentTopic(path, DEFAULT_DOCUMENT_TOPIC_PREFIX);
  const { relay, address } = await startRelay({ autoSubscribe: true });
  const writers = [];
  const a = await startPeer(address, writers);
  writers.push(a.identity.publicKey);
  const founding = a.swarm.doc(path);
  await founding.create();
  assert.ok(undelivered(founding));
  await until('the relay to subscribe to the topic', () =>
    a.libp2p.services.pubsub
      .getSubscribers(topic)
      .some((peer) => peer.equals(relay.peerId)),
  );
  await founding.change(set('x', 1));
  assert.ok(undelivered(founding));
  const checkpoint = await founding.exportCheckpoint();
  await founding.close();

  const handles = [];
  const store = createDocumentStore(async () => {
    const handle = a.swarm.doc(path);
    await handle.restoreCheckpoint(checkpoint);
    handles.push(handle);
    return handle;
  });
  const release = store.connect();
  await until(
    'the store to open',
    () => store.getSnapshot().status === 'ready',
  );
  await until('the relay to subscribe again', () =>
    a.libp2p.services.pubsub
      .getSubscribers(topic)
      .some((peer) => peer.equals(relay.peerId)),
  );
  await store.change(set('y', 2));
  assert.ok(
    store.getSnapshot().deliveryFailure.error instanceof NoDeliveryPeersError,
  );
  release();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(store.getSnapshot().status, 'ready');
  const remount = store.connect();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(handles.length, 1);
  assert.equal(valueOf(handles[0], 'y'), 2);
  remount();
  await store.stop();
});

async function memberPair(path) {
  const { address } = await startRelay({ autoSubscribe: false });
  const writers = [];
  const a = await startPeer(address, writers);
  writers.push(a.identity.publicKey);
  const document = a.swarm.doc(path);
  await document.create();
  await document.change(set('x', 1));
  assert.ok(undelivered(document));

  const b = await startPeer(address, writers, a.identity);
  const replica = b.swarm.doc(path);
  replica._keychain.merge(document._keychain.history());
  await replica._keychain.keys();
  await b.swarm.connect([a.circuit]);
  assert.equal(await replica.open(), true);
  assert.equal(valueOf(replica, 'x'), 1);
  await until(
    'serving the load to clear the failure',
    () => document.deliveryFailure === undefined,
  );
  const topic = documentTopic(path, DEFAULT_DOCUMENT_TOPIC_PREFIX);
  await until('A to see B on the topic', () =>
    a.libp2p.services.pubsub
      .getSubscribers(topic)
      .some((peer) => peer.equals(b.libp2p.peerId)),
  );
  await document.change(set('y', 2));
  assert.ok(undelivered(document));
  await until('B to receive y', () => valueOf(replica, 'y') === 2);
  return { document, replica };
}

test('serving a member a load, then its sync request, clears the failure, and later frames reach it', async () => {
  const { document, replica } = await memberPair('/relay-delivery/sync');
  await replica.requestSync();
  await until(
    'the member sync request to clear the failure',
    () => document.deliveryFailure === undefined,
  );
  await document.change(set('z', 3));
  assert.equal(document.deliveryFailure, undefined);
  await until('B to receive z', () => valueOf(replica, 'z') === 3);
});

test('a member frame that builds on the undelivered change clears it', async () => {
  const { document, replica } = await memberPair('/relay-delivery/frame');
  await replica.change(set('w', 4));
  await until('A to receive w', () => valueOf(document, 'w') === 4);
  assert.equal(document.deliveryFailure, undefined);
  await document.change(set('z', 3));
  assert.equal(document.deliveryFailure, undefined);
});
