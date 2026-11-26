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
  YjsACLProvider,
  YjsJSONSerializer,
  YjsKeychainProvider,
  YjsProvider,
} from '@peerborne/yjs';

const DEADLINE_MS = 30_000;

async function bounded(description, promise) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`Bounded ${description} deadline exceeded`)),
          DEADLINE_MS,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function until(description, predicate) {
  const end = performance.now() + DEADLINE_MS;
  while (!(await predicate())) {
    if (performance.now() >= end)
      throw new Error(`Bounded ${description} deadline exceeded`);
    await delay(100);
  }
}

// The relay server's default circuit limits make every relayed connection a
// limited one.
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
          defaultDataLimit: 16n * 1024n * 1024n,
          defaultDurationLimit: 30 * 60 * 1000,
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

async function device(path, relayAddress, writers, founder) {
  const identity =
    founder?.identity ??
    (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['sign', 'verify'],
    ));
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
    resolveTrustedDocumentWriters: () => writers,
    resolveLoadSecurityCommitments: () => ({
      version: 1,
      controlHead: new Uint8Array(32).fill(1),
      groupId: path,
      epoch: 1n,
      treeHash: new Uint8Array(32).fill(2),
      confirmedTranscriptHash: new Uint8Array(32).fill(3),
    }),
    loadQuorumAllowSinglePeer: true,
  });
  const circuits = new Map();
  swarm.libp2p.addEventListener('connection:open', ({ detail }) => {
    if (detail.limits == null) return;
    const peer = detail.remotePeer.toString();
    circuits.set(peer, (circuits.get(peer) ?? 0) + 1);
  });
  await swarm.connect([relayAddress]);
  await until('relay reservation', () =>
    swarm.libp2p
      .getMultiaddrs()
      .some((address) => String(address).includes('/p2p-circuit')),
  );
  const circuit = swarm.libp2p
    .getMultiaddrs()
    .map(String)
    .find((address) => address.includes('/p2p-circuit'));
  const document = swarm.doc(path);
  document.document.getMap('root');
  if (founder) {
    document._keychain.merge(founder.document._keychain.history());
    await document._keychain.keys();
  }
  return { swarm, identity, document, circuit, circuits };
}

const entries = (peer) => peer.document.document.getMap('root').size;

async function write(peer, from, count) {
  for (let index = from; index < from + count; index++)
    await peer.document.change((doc) =>
      doc.getMap('root').set(`entry-${index}`, index),
    );
}

async function load(loader, source) {
  const started = performance.now();
  await loader.swarm.connect([source.circuit]);
  assert.equal(await bounded('load', loader.document.open()), true);
  assert.equal(entries(loader), 135);
  const circuits = loader.circuits.get(source.swarm.libp2p.peerId.toString());
  assert.equal(circuits, 1, 'one relayed connection per peer pair');
  return performance.now() - started;
}

async function fetchRound(path) {
  const stops = [];
  try {
    const relay = await relayNode(path);
    stops.push(() => relay.stop());
    const relayAddress = String(relay.getMultiaddrs()[0]);
    const writers = [];
    const founder = await device(path, relayAddress, writers);
    stops.push(() => founder.swarm.heliaNode.stop());
    writers.push(founder.identity.publicKey);
    await founder.document.create();
    await write(founder, 0, 120);
    assert.notEqual(await founder.document.snapshot(), undefined);
    await write(founder, 120, 15);

    const holder = await device(path, relayAddress, writers, founder);
    stops.push(() => holder.swarm.heliaNode.stop());
    const fromFounderMs = await load(holder, founder);
    const replica = await device(path, relayAddress, writers, founder);
    stops.push(() => replica.swarm.heliaNode.stop());
    const fromHolderMs = await load(replica, holder);

    await write(founder, 135, 1);
    await until(
      'live sync',
      () => entries(holder) === 136 && entries(replica) === 136,
    );
    return { fromFounderMs, fromHolderMs };
  } finally {
    for (const stop of stops.reverse()) await stop().catch(() => {});
  }
}

export async function relayBlockFetch({ full, progress }) {
  const rounds = full ? 10 : 3;
  const loads = [];
  for (let round = 1; round <= rounds; round++) {
    const result = await fetchRound(
      `/advanced/relay-fetch-${crypto.randomUUID()}`,
    );
    loads.push(result.fromFounderMs, result.fromHolderMs);
    progress?.(`round ${round}/${rounds} loaded`);
  }
  loads.sort((a, b) => a - b);
  return {
    scope:
      'A WebSocket Circuit Relay with the relay server default 16 MiB and 30 minute circuit limits, and real Peerborne nodes that listen only on /p2p-circuit. In each round a fresh device of the only writer loads a snapshot and the change blocks after it over Bitswap from the founder, a second fresh device loads from that holder, and a new edit reaches both.',
    metrics: {
      rounds,
      loads: loads.length,
      loadMs: { p50: loads[Math.floor(loads.length / 2)], max: loads.at(-1) },
      relayedConnectionsPerPair: 1,
    },
    gaps: [
      'Loopback only. Browser transports, WebRTC upgrades, relay failover and circuit limit exhaustion are not exercised.',
    ],
  };
}
