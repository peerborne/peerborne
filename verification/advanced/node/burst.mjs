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

async function invitedPair(path) {
  const stops = [];
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
  return { founder, source, target, stops };
}

async function burstOnce(path, burst, authorStops) {
  const { founder, source, target, stops } = await invitedPair(path);
  try {
    let kept = 0;
    const receive = target._gossipReceiveAdmission;
    const keep = receive.keep.bind(receive);
    receive.keep = (...args) => {
      kept++;
      return keep(...args);
    };
    // The reader is busy while the burst arrives, so its validators wait in
    // the state queue and the burst outruns the receive limit.
    const busy = Promise.withResolvers();
    const queued = target._mutationQueue.run(() => busy.promise);
    const started = performance.now();
    await Promise.all(
      Array.from({ length: burst }, (_, i) =>
        source.change((draft) => {
          draft.body = `burst ${i}`;
        }),
      ),
    );
    await delay(1000);
    if (authorStops) await founder.swarm.heliaNode.stop();
    busy.resolve();
    await queued;
    await until(() => text(target, 'body') === `burst ${burst - 1}`, 30_000);
    assert(kept > 0, 'the burst must exceed the receive limit');
    return { burst, kept, convergeMs: performance.now() - started };
  } finally {
    for (const stop of stops.reverse()) await stop().catch(() => {});
  }
}

export async function typingBurst({ full }) {
  const burst = full ? 60 : 30;
  const authorOnline = await burstOnce(
    `/advanced/burst-${crypto.randomUUID()}`,
    burst,
    false,
  );
  // The author stops as soon as its last edit is published, so the reader
  // can only converge from frames it already received or kept.
  const authorOffline = await burstOnce(
    `/advanced/burst-${crypto.randomUUID()}`,
    burst,
    true,
  );
  return {
    scope:
      'A WebSocket relay and two real Peerborne nodes joined by invitation over Circuit Relay, with production GossipSub and topic validators. A founder publishes a burst of concurrent edits; in the second run it stops right after the last publish.',
    metrics: { authorOnline, authorOffline, converged: true },
    gaps: [
      'Loopback only. Browser transports, slow links and several concurrent writers are not exercised.',
    ],
  };
}
