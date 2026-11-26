import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { createLibp2p } from 'libp2p';
import { webSockets } from '@libp2p/websockets';
import { identify } from '@libp2p/identify';
import { ping } from '@libp2p/ping';
import { gossipsub } from '@libp2p/gossipsub';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { MemoryBlockstore } from 'blockstore-core/memory';
import { MemoryDatastore } from 'datastore-core/memory';
import { NoDeliveryPeersError, Peerborne, SubtleCrypto } from '@peerborne/core';
import {
  YjsACLProvider,
  YjsJSONSerializer,
  YjsKeychainProvider,
  YjsProvider,
} from '@peerborne/yjs';
import { createDocumentStore } from '@peerborne/store';

for (const method of ['log', 'info', 'debug', 'warn'])
  console[method] = () => {};

const path = '/offline-remount';
const listen = { listen: ['/ip4/127.0.0.1/tcp/0/ws'] };
const transport = {
  transports: [webSockets()],
  connectionEncrypters: [noise()],
  streamMuxers: [yamux()],
  connectionGater: { denyDialMultiaddr: async () => false },
};

// The GossipSub options of the default browser and Node configurations.
const defaultPubsub = () =>
  gossipsub({
    allowPublishToZeroTopicPeers: true,
    runOnLimitedConnection: true,
    emitSelf: false,
    canRelayMessage: true,
    globalSignaturePolicy: 'StrictSign',
  });

async function until(label, predicate, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (!(await predicate())) {
    if (Date.now() > deadline)
      throw new Error(`Timed out waiting for ${label}`);
    await delay(50);
  }
}

async function node() {
  const identity = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
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
        addresses: listen,
        ...transport,
        services: {
          identify: identify(),
          ping: ping(),
          pubsub: defaultPubsub(),
        },
      },
    },
    loadQuorumEnabled: false,
    antiEntropy: { enabled: false },
  });
  return swarm;
}

test('with the default GossipSub options, a managed store keeps an edit made with no member peer across a remount', async (t) => {
  const swarm = await node();
  t.after(() => swarm.heliaNode.stop().catch(() => {}));
  const founding = swarm.doc(path);
  await founding.create();
  assert.ok(founding.deliveryFailure.error instanceof NoDeliveryPeersError);
  const unmanaged = createDocumentStore(founding, { manageLifecycle: false });
  await unmanaged.start();
  assert.equal(
    unmanaged.getSnapshot().deliveryFailure,
    founding.deliveryFailure,
  );
  await unmanaged.stop();
  const checkpoint = await founding.exportPlaintextCheckpoint();
  await founding.close();

  const handles = [];
  const store = createDocumentStore(async () => {
    const handle = swarm.doc(path);
    await handle.restorePlaintextCheckpoint(checkpoint);
    handles.push(handle);
    return handle;
  });
  const title = (snapshot) => snapshot.data?.getMap('data').get('title');
  const release = store.connect();
  await until(
    'the store to open',
    () => store.getSnapshot().status === 'ready',
  );

  await store.change((doc) => doc.getMap('data').set('title', 'Typed offline'));
  const offline = store.getSnapshot().deliveryFailure;
  assert.ok(offline.error instanceof NoDeliveryPeersError);
  release();
  await delay(20);
  assert.equal(store.getSnapshot().status, 'ready');

  const remount = store.connect();
  await delay(20);
  assert.equal(handles.length, 1);
  assert.equal(title(store.getSnapshot()), 'Typed offline');
  assert.equal(store.getSnapshot().deliveryFailure, offline);

  const subscriber = await createLibp2p({
    addresses: listen,
    ...transport,
    services: { identify: identify(), pubsub: defaultPubsub() },
  });
  t.after(() => subscriber.stop().catch(() => {}));
  const topic = handles[0]._topic;
  const received = [];
  subscriber.services.pubsub.addEventListener('message', (event) => {
    if (event.detail.topic === topic) received.push(event.detail.data);
  });
  subscriber.services.pubsub.subscribe(topic);
  await subscriber.dial(swarm.heliaNode.libp2p.getMultiaddrs()[0]);
  await until('the subscription to reach the writer', () =>
    swarm.heliaNode.libp2p.services.pubsub
      .getSubscribers(topic)
      .some((peer) => peer.equals(subscriber.peerId)),
  );

  await store.change((doc) => doc.getMap('data').set('title', 'Sent'));
  await until('the subscriber to receive the frame', () => received.length > 0);
  const unproven = store.getSnapshot().deliveryFailure;
  assert.ok(unproven.error instanceof NoDeliveryPeersError);
  assert.notEqual(unproven, offline);
  remount();
  await delay(20);
  assert.equal(store.getSnapshot().status, 'ready');
  await store.stop();
  assert.equal(store.getSnapshot().status, 'closed');
  assert.equal(handles.length, 1);
});
