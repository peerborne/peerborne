import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import 'fake-indexeddb/auto';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { gossipsub } from '@libp2p/gossipsub';
import { identify } from '@libp2p/identify';
import { tcp } from '@libp2p/tcp';
import { createLibp2p } from 'libp2p';
import { defaultBootstrapConfig, defaultConfig } from './peerborne-config.ts';
import { defaultNodeConfig } from './peerborne-node.ts';

const TOPIC = '/peerborne/document/v3/colocation';
const PEERS = 16;

async function until(description, predicate, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline)
      throw new Error(`Timed out waiting for ${description}`);
    await delay(10);
  }
}

function node(pubsub, options = {}) {
  return createLibp2p({
    ...options,
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    services: { identify: identify(), pubsub },
  });
}

test('browser and Node defaults disable GossipSub IP colocation scoring', async () => {
  const bootstrap = defaultBootstrapConfig([]);
  for (const config of [
    defaultConfig(bootstrap),
    defaultNodeConfig(bootstrap),
  ]) {
    const libp2p = await node(config.helia.libp2p.services.pubsub);
    try {
      assert.equal(
        libp2p.services.pubsub.score.params.IPColocationFactorWeight,
        0,
      );
    } finally {
      await libp2p.stop();
    }
  }
});

// Every peer connects from 127.0.0.1 and leaves before the next one joins,
// like browsers behind one NAT or relay. GossipSub keeps a departed peer's
// score for an hour, and its default penalty graylisted the 14th.
test('a default node keeps delivering frames to new peers that share an IP after churn', async () => {
  const { connectionManager, services } = defaultNodeConfig(
    defaultBootstrapConfig([]),
  ).helia.libp2p;
  const hub = await node(services.pubsub, {
    addresses: { listen: ['/ip4/127.0.0.1/tcp/0'] },
    connectionManager,
  });
  try {
    hub.services.pubsub.subscribe(TOPIC);
    for (let index = 1; index <= PEERS; index++) {
      const peer = await node(
        gossipsub({ emitSelf: false, globalSignaturePolicy: 'StrictSign' }),
      );
      try {
        const received = [];
        peer.services.pubsub.addEventListener('message', (event) =>
          received.push(new TextDecoder().decode(event.detail.data)),
        );
        peer.services.pubsub.subscribe(TOPIC);
        await peer.dial(hub.getMultiaddrs()[0]);
        await until(`peer ${index} to be subscribed`, () =>
          hub.services.pubsub
            .getSubscribers(TOPIC)
            .some((subscriber) => subscriber.equals(peer.peerId)),
        );
        await hub.services.pubsub.publish(
          TOPIC,
          new TextEncoder().encode(`frame ${index}`),
        );
        await until(`peer ${index} to receive its frame`, () =>
          received.includes(`frame ${index}`),
        );
        assert.ok(
          hub.services.pubsub.score.score(peer.peerId.toString()) >=
            hub.services.pubsub.opts.scoreThresholds.graylistThreshold,
        );
      } finally {
        await peer.stop();
      }
    }
  } finally {
    await hub.stop();
  }
});
