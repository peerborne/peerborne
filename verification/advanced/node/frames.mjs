import assert from 'node:assert/strict';
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
import {
  DEFAULT_DOCUMENT_TOPIC_PREFIX,
  MAX_GOSSIP_SYNC_MESSAGE_BYTES,
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
import { syntheticText } from '../../fixtures.mjs';

async function until(predicate, timeout = 90_000) {
  const end = performance.now() + timeout;
  while (!(await predicate())) {
    if (performance.now() >= end)
      throw new Error('Bounded convergence deadline exceeded');
    await delay(100);
  }
  return performance.now() - (end - timeout);
}

async function relayNode(path) {
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
  return relay;
}

async function peer(relayAddress, config = {}) {
  const identity = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  );
  const kem = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const serializer = new AutomergeJSONSerializer();
  const swarm = new Peerborne(
    identity.privateKey,
    identity.publicKey,
    new AutomergeProvider(),
    serializer,
    serializer,
    serializer,
    new SubtleCrypto(),
    new AutomergeACLProvider(),
    new AutomergeKeychainProvider(),
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
    enableTopicValidators: true,
    ...config,
  });
  await swarm.connect([relayAddress]);
  await until(() =>
    swarm.libp2p
      .getMultiaddrs()
      .some((a) => String(a).includes('/p2p-circuit')),
  );
  const circuit = swarm.libp2p
    .getMultiaddrs()
    .map(String)
    .find((a) => a.includes('/p2p-circuit'));
  return { swarm, kem, circuit };
}

const text = (doc, key) =>
  typeof doc.document[key] === 'string' ? doc.document[key] : undefined;

export async function oversizedFrames({ full }) {
  const path = `/advanced/oversized-${crypto.randomUUID()}`;
  const stops = [];
  try {
    const relay = await relayNode(path);
    stops.push(() => relay.stop());
    const relayAddress = String(relay.getMultiaddrs()[0]);
    const founder = await peer(relayAddress, {
      compaction: {
        enabled: true,
        snapshotInterval: 3,
        minChangesBeforeSnapshot: 3,
      },
    });
    stops.push(() => founder.swarm.heliaNode.stop());
    const reader = await peer(relayAddress);
    stops.push(() => reader.swarm.heliaNode.stop());
    const source = founder.swarm.doc(path);
    await source.setKemKeyPair(founder.kem);
    await source.create();
    source.historyVisibility = 'full_history';
    await source.change((draft) => {
      draft.body = 'joined';
    });
    const offer = await source.createInvitation({
      role: 'reader',
      rendezvous: [founder.circuit],
    });
    const target = await reader.swarm.acceptInvitation(offer, reader.kem);
    await until(() => text(target, 'body') === 'joined');

    const frames = [];
    const pubsub = founder.swarm.libp2p.services.pubsub;
    const publish = pubsub.publish.bind(pubsub);
    pubsub.publish = async (topic, data, options) => {
      const result = await publish(topic, data, options);
      frames.push({
        bytes: data.byteLength,
        recipients: result.recipients.length,
      });
      return result;
    };

    // One change larger than a GossipSub frame travels by CID over Bitswap.
    const big = syntheticText(MAX_GOSSIP_SYNC_MESSAGE_BYTES + 512 * 1024, 7);
    await source.change((draft) => {
      draft.big = big;
    });
    for (let i = 0; i < 3; i++)
      await source.change((draft) => {
        draft.body = `after big ${i}`;
      });
    const bigEditMs = await until(
      () =>
        text(target, 'big') === big && text(target, 'body') === 'after big 2',
    );
    assert(frames.every(({ recipients }) => recipients > 0));
    assert(frames.every(({ bytes }) => bytes < 4 * 1024 * 1024));

    // A typing burst beyond the per-document receive limit converges.
    const burst = full ? 60 : 30;
    await Promise.all(
      Array.from({ length: burst }, (_, i) =>
        source.change((draft) => {
          draft.body = `burst ${i}`;
        }),
      ),
    );
    const burstMs = await until(
      () => text(target, 'body') === `burst ${burst - 1}`,
    );

    // A reader that missed large edits catches up through a direct response.
    const readerPubsub = reader.swarm.libp2p.services.pubsub;
    readerPubsub.removeEventListener('message', target._pubsubHandler);
    for (let i = 0; i < 3; i++)
      await source.change((draft) => {
        draft[`missed${i}`] = syntheticText(1_000_000, 20 + i);
      });
    await source.change((draft) => {
      draft.body = 'missed final';
    });
    // Let in-flight frames drain while the reader still drops them.
    await delay(2000);
    readerPubsub.addEventListener('message', target._pubsubHandler);
    assert(source.latestSnapshot !== undefined);
    let directFrames = 0;
    const receiveDirect = target.handleSyncFrameData.bind(target);
    target.handleSyncFrameData = (...args) => {
      directFrames++;
      return receiveDirect(...args);
    };
    await delay(2100);
    const beforeCatchUp = frames.length;
    await target.requestSync();
    const catchUpMs = await until(
      () =>
        text(target, 'body') === 'missed final' &&
        [0, 1, 2].every((i) => text(target, `missed${i}`) !== undefined),
    );
    assert.equal(
      frames.length,
      beforeCatchUp,
      'the oversized response must not be published on GossipSub',
    );
    assert.equal(directFrames, 1, 'the response must arrive as one sync frame');
    return {
      scope:
        'A WebSocket relay and two real Peerborne nodes joined by invitation over Circuit Relay, with production GossipSub, topic validators, Bitswap and the sync-frame protocol.',
      metrics: {
        bigChangeBytes: big.length,
        largestFrame: Math.max(...frames.map(({ bytes }) => bytes)),
        bigEditMs,
        burst,
        burstMs,
        catchUpMs,
        directFrames,
        converged: true,
      },
      gaps: [
        'Loopback only. Real relay data limits, browser transports, slow links and an unreachable block holder are not exercised.',
      ],
    };
  } finally {
    for (const stop of stops.reverse()) await stop().catch(() => {});
  }
}
