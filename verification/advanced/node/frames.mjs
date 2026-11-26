import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { createLibp2p } from 'libp2p';
import { webSockets } from '@libp2p/websockets';
import { tcp } from '@libp2p/tcp';
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
  GossipFrameLimitError,
  MAX_CHANGE_FRAME_BYTES,
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
import { documentFixture, replicaOf, syntheticText } from '../../fixtures.mjs';

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
  return { swarm, kem, circuit, identity };
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
    const founder = await peer(relayAddress);
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

    // History larger than one GossipSub frame: every frame still fits and
    // carries every retained change inline.
    const edits = full ? 24 : 12;
    const historyStarted = performance.now();
    for (let i = 0; i < edits; i++)
      await source.change((draft) => {
        draft[`value${i}`] = syntheticText(300_000, 10 + i);
      });
    await until(() => text(target, `value${edits - 1}`) !== undefined);
    const historyMs = performance.now() - historyStarted;
    assert(source.latestSnapshot !== undefined, 'the writer must compact');
    for (let i = 0; i < edits; i++)
      assert.equal(text(target, `value${i}`), text(source, `value${i}`));

    // A membership change right after a large edit is not blocked.
    await source.change((draft) => {
      draft.large = syntheticText(1_200_000, 8);
    });
    await until(() => text(target, 'large') !== undefined);
    const removalStarted = performance.now();
    await source.removeReader(reader.identity.publicKey);
    const removalMs = performance.now() - removalStarted;
    const framesBeforeRefusal = frames.length;

    // One change too large for a frame is refused with a typed error before
    // it reaches history, and the instance is retired.
    let refused;
    try {
      await source.change((draft) => {
        draft.big = syntheticText(MAX_CHANGE_FRAME_BYTES, 7);
      });
    } catch (error) {
      refused = error;
    }
    assert(refused instanceof GossipFrameLimitError);
    assert.equal(frames.length, framesBeforeRefusal);
    await assert.rejects(
      source.change((draft) => {
        draft.body = 'after refusal';
      }),
      /retired after an oversized edit/,
    );
    assert(frames.every(({ recipients }) => recipients > 0));
    assert(frames.every(({ bytes }) => bytes < 4 * 1024 * 1024));
    return {
      scope:
        'A WebSocket relay and two real Peerborne nodes joined by invitation over Circuit Relay, with production GossipSub, topic validators and Bitswap.',
      metrics: {
        edits,
        historyMs,
        largestFrame: Math.max(...frames.map(({ bytes }) => bytes)),
        refusedLimit: refused.limit,
        removalMs,
        converged: true,
      },
      gaps: [
        'Loopback only. Real relay data limits, browser transports and slow links are not exercised. A requestSync() reply over the limit is not sent; the requester must load.',
      ],
    };
  } finally {
    for (const stop of stops.reverse()) await stop().catch(() => {});
  }
}

async function gossipNode() {
  return createLibp2p({
    addresses: { listen: ['/ip4/127.0.0.1/tcp/0'] },
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    services: {
      identify: identify(),
      pubsub: gossipsub({
        allowPublishToZeroTopicPeers: true,
        emitSelf: false,
        canRelayMessage: true,
        globalSignaturePolicy: 'StrictSign',
        heartbeatInterval: 200,
      }),
    },
  });
}

async function authorOffline(values) {
  const nodes = [];
  const replicas = [];
  try {
    for (let i = 0; i < 3; i++) nodes.push(await gossipNode());
    const topic = '/advanced/author-offline';
    for (const node of nodes) node.services.pubsub.subscribe(topic);
    await nodes[0].dial(nodes[1].getMultiaddrs()[0]);
    await nodes[1].dial(nodes[2].getMultiaddrs()[0]);
    await nodes[0].dial(nodes[2].getMultiaddrs()[0]);
    await until(() =>
      nodes.every(
        (node) => node.services.pubsub.getSubscribers(topic).length >= 2,
      ),
    );
    const a = await documentFixture({ adapter: 'yjs', index: 1 });
    replicas.push(a);
    await a.document.change((doc) => doc.getMap('root').set('start', 0));
    const b = await replicaOf(a, 2, { adapter: 'yjs' });
    const c = await replicaOf(a, 3, { adapter: 'yjs' });
    replicas.push(b, c);
    let cOnline = false;
    for (const [index, fixture] of replicas.entries()) {
      const node = nodes[index];
      fixture.setPublish(async (_topic, bytes) => {
        await node.services.pubsub.publish(topic, bytes);
      });
      node.services.pubsub.addEventListener('message', (event) => {
        if (fixture === c && !cOnline) return;
        fixture.helia.libp2p.services.pubsub.dispatchEvent(
          new CustomEvent('message', {
            detail: { topic: fixture.document._topic, data: event.detail.data },
          }),
        );
      });
    }
    let blockReads = 0;
    const readBlock = c.document._readBlock.bind(c.document);
    c.document._readBlock = (...args) => {
      blockReads++;
      return readBlock(...args);
    };
    let slowestSyncMs = 0;
    const sync = c.document._syncUnlocked.bind(c.document);
    c.document._syncUnlocked = async (...args) => {
      const started = performance.now();
      try {
        return await sync(...args);
      } finally {
        slowestSyncMs = Math.max(slowestSyncMs, performance.now() - started);
      }
    };
    const root = (fixture) => fixture.document.document.getMap('root');
    for (const [i, value] of values.entries())
      await a.document.change((doc) =>
        doc.getMap('root').set(`big${i}`, value),
      );
    for (let i = 0; i < 10; i++)
      await a.document.change((doc) => doc.getMap('root').set(`a${i}`, i));
    await until(() => root(b).get('a9') === 9);
    const authorCompacted = a.document.latestSnapshot !== undefined;

    await a.close();
    replicas.shift();
    await nodes[0].stop();
    nodes.shift();
    cOnline = true;

    let slowestApplyMs = 0;
    for (let i = 0; i < 5; i++) {
      const before = performance.now();
      await b.document.change((doc) => doc.getMap('root').set(`b${i}`, i));
      await until(() => root(c).get(`b${i}`) === i, 30_000);
      slowestApplyMs = Math.max(slowestApplyMs, performance.now() - before);
    }
    await delay(500);
    const valuesApplied = values.filter(
      (value, i) => root(c).get(`big${i}`) === value,
    ).length;
    assert(slowestApplyMs < 5_000, 'no frame may wait on the offline author');
    assert(slowestSyncMs < 5_000, 'no sync may hold the state queue');
    return {
      largeValues: values.length,
      largeValueBytes: values[0].length,
      authorCompacted,
      valuesApplied,
      editsApplied: root(c).get('a9') === 9,
      slowestApplyMs,
      slowestSyncMs,
      blockReads,
    };
  } finally {
    for (const fixture of replicas) await fixture.close().catch(() => {});
    await Promise.allSettled(nodes.map((node) => node.stop()));
  }
}

/**
 * Three replicas of one writer identity over real GossipSub. A writes large
 * values while C drops its traffic, then A goes offline and C must take B's
 * frames without waiting on A. Fixture replicas have no Bitswap, so any
 * block a frame names by CID is unreachable.
 */
export async function authorOfflineFrames() {
  // Within one compaction window every change travels inline in B's frames.
  const withinWindow = await authorOffline(
    Array.from({ length: 2 }, (_, i) => syntheticText(500_000, 40 + i)),
  );
  assert.equal(withinWindow.authorCompacted, false);
  assert.equal(withinWindow.blockReads, 0, 'no change may be sent by CID');
  assert.equal(withinWindow.valuesApplied, 2);
  assert.equal(withinWindow.editsApplied, true);
  // Beyond it A prunes, so C lacks A's older changes, yet B's frames still
  // apply without stalling.
  const beyondWindow = await authorOffline(
    Array.from({ length: 3 }, (_, i) => syntheticText(900_000, 50 + i)),
  );
  assert.equal(beyondWindow.authorCompacted, true);
  return {
    scope:
      'Three replicas of one writer identity over real libp2p TCP/Noise/Yamux/GossipSub with production document ciphertext and ingress. The author stops before the lagging replica reconnects; replicas cannot fetch blocks from one another.',
    metrics: { withinWindow, beyondWindow, converged: true },
    gaps: [
      "Beyond one compaction window the lagging Yjs replica cannot apply the author's retained changes until it receives the pruned ones, which needs a requestSync() reply or a load from a replica holding a snapshot.",
      "Cross-links to the offline author's tips are still fetched inside the state queue, as before; fixture replicas fail those reads at once, while a networked peer waits for Bitswap.",
    ],
  };
}
