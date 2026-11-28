import assert from 'node:assert/strict';
import { createServer } from 'node:net';
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
  DEFAULT_INBOUND_CONNECTION_THRESHOLD,
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

const connectionManager = {
  inboundConnectionThreshold: DEFAULT_INBOUND_CONNECTION_THRESHOLD,
};

// The relay server's default circuit limits make every relayed connection a
// limited one. Every peer reaches the relay from the loopback host.
async function relayNode(path) {
  const relay = await createLibp2p({
    addresses: { listen: ['/ip4/127.0.0.1/tcp/0/ws'] },
    transports: [webSockets()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    connectionManager,
    connectionGater: { denyDialMultiaddr: async () => false },
    services: {
      identify: identify(),
      relay: circuitRelayServer({
        reservations: {
          maxReservations: 128,
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

// A direct address that accepts TCP and then resets, so an upgrade dial to it
// fails at once. It counts how many upgrade dials reach it.
async function unreachableDirectAddress(stops) {
  const dials = { count: 0 };
  const server = createServer((socket) => {
    dials.count++;
    socket.destroy();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  stops.push(() => new Promise((resolve) => server.close(resolve)));
  return {
    address: `/ip4/127.0.0.1/tcp/${server.address().port}/ws`,
    dials,
  };
}

async function device(path, relayAddress, writers, founder, announce = []) {
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
        addresses: { listen: ['/p2p-circuit'], appendAnnounce: announce },
        transports: [
          circuitRelayTransport({ reservationConcurrency: 1 }),
          webSockets(),
        ],
        connectionEncrypters: [noise()],
        streamMuxers: [yamux()],
        connectionManager,
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
    allowLocalNetworkDials: true,
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
  const circuitsTo = (peer) =>
    circuits.get(peer.swarm.libp2p.peerId.toString()) ?? 0;
  return { swarm, identity, document, circuit, circuitsTo };
}

const entries = (peer) => peer.document.document.getMap('root').size;

async function write(peer, from, count) {
  for (let index = from; index < from + count; index++)
    await peer.document.change((doc) =>
      doc.getMap('root').set(`entry-${index}`, index),
    );
}

// Only circuits opened while the document loads are counted, so a retried
// connect cannot change the result. One upgrade dial to a direct address that
// fails may add one circuit.
async function load(loader, source, upgradeCircuits = 0) {
  const started = performance.now();
  await loader.swarm.connect([source.circuit]);
  const connected = loader.circuitsTo(source);
  assert.ok(connected >= 1);
  assert.equal(await bounded('load', loader.document.open()), true);
  assert.equal(entries(loader), 135);
  assert.ok(
    loader.circuitsTo(source) - connected <= upgradeCircuits,
    'loads reuse the relayed connection',
  );
  return performance.now() - started;
}

async function founderWithHistory(path, stops, announce) {
  const relay = await relayNode(path);
  stops.push(() => relay.stop());
  const relayAddress = String(relay.getMultiaddrs()[0]);
  const writers = [];
  const founder = await device(
    path,
    relayAddress,
    writers,
    undefined,
    announce,
  );
  stops.push(() => founder.swarm.heliaNode.stop());
  writers.push(founder.identity.publicKey);
  await founder.document.create();
  await write(founder, 0, 120);
  assert.notEqual(await founder.document.snapshot(), undefined);
  await write(founder, 120, 15);
  const join = async () => {
    const joiner = await device(path, relayAddress, writers, founder);
    stops.push(() => joiner.swarm.heliaNode.stop());
    return joiner;
  };
  return { founder, join };
}

async function fetchRound(path) {
  const stops = [];
  try {
    const direct = await unreachableDirectAddress(stops);
    const { founder, join } = await founderWithHistory(path, stops, [
      direct.address,
    ]);
    const holder = await join();
    const fromFounderMs = await load(holder, founder, 1);
    const replica = await join();
    const fromHolderMs = await load(replica, holder);

    await write(founder, 135, 1);
    await until(
      'live sync',
      () => entries(holder) === 136 && entries(replica) === 136,
    );
    assert.equal(
      direct.dials.count,
      1,
      'one upgrade dial per relayed connection',
    );
    return { fromFounderMs, fromHolderMs };
  } finally {
    for (const stop of stops.reverse()) await stop().catch(() => {});
  }
}

// More peers than libp2p's default of five inbound connections per second
// per host reach the founder through one relay at once. libp2p still refuses
// handshakes beyond its ten pending inbound upgrades.
async function burstJoin(path, peers) {
  const stops = [];
  try {
    const { founder, join } = await founderWithHistory(path, stops);
    const joiners = [];
    for (let index = 0; index < peers; index++) joiners.push(await join());
    const started = performance.now();
    await Promise.all(joiners.map((joiner) => load(joiner, founder)));
    return performance.now() - started;
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
  const burstPeers = full ? 10 : 8;
  const burstMs = await burstJoin(
    `/advanced/relay-fetch-${crypto.randomUUID()}`,
    burstPeers,
  );
  progress?.(`${burstPeers} peers loaded at once`);
  return {
    scope:
      'A WebSocket Circuit Relay with the relay server default 16 MiB and 30 minute circuit limits, and real Peerborne nodes that listen only on /p2p-circuit. In each round a fresh device of the only writer loads a snapshot and the change blocks after it over Bitswap from the founder, which also advertises a direct address that fails, a second fresh device loads from that holder, and a new edit reaches both. Then a burst of fresh devices connects to the founder through the relay at once and loads.',
    metrics: {
      rounds,
      loads: loads.length,
      loadMs: { p50: loads[Math.floor(loads.length / 2)], max: loads.at(-1) },
      upgradeDialsPerRelayedConnection: 1,
      burst: { peers: burstPeers, ms: burstMs },
    },
    gaps: [
      'Loopback only. The failing upgrade address is a WebSocket one; browser transports, real WebRTC upgrades, relay failover and circuit limit exhaustion are not exercised.',
    ],
  };
}
