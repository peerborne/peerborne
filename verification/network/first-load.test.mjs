import { after, test } from 'node:test';
import assert from 'node:assert/strict';
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
  LoadQuorumFailedError,
  Peerborne,
  SubtleCrypto,
  documentTopic,
  loadAdvertisementHash,
  loadAdvertisementHashToHex,
} from '@peerborne/core';
import {
  YjsACLProvider,
  YjsJSONSerializer,
  YjsKeychainProvider,
  YjsProvider,
} from '@peerborne/yjs';

const PATH = '/network-first-load';
const TIMEOUT_MS = 30_000;
const commitments = () => ({
  version: 1,
  controlHead: new Uint8Array(32).fill(1),
  groupId: 'network-first-load',
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
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

async function startRelay() {
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
        scoreParams: {
          IPColocationFactorWhitelist: new Set(['127.0.0.1']),
        },
      }),
    },
  });
  relay.services.pubsub.subscribe(
    documentTopic(PATH, DEFAULT_DOCUMENT_TOPIC_PREFIX),
  );
  stops.push(() => relay.stop());
  return {
    relay,
    address: relay.getMultiaddrs()[0].toString(),
  };
}

async function signingIdentity() {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  );
}

async function startPeer(
  relayAddress,
  trustedWriters,
  { identity, keysFrom, ...overrides } = {},
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
    resolveTrustedDocumentWriters: () => trustedWriters,
    resolveLoadSecurityCommitments: commitments,
    ...overrides,
  });
  stops.push(() => swarm.heliaNode.stop());
  const libp2p = swarm.heliaNode.libp2p;
  const circuit = await until('a relay reservation', () =>
    libp2p
      .getMultiaddrs()
      .map(String)
      .find((address) => address.includes('/p2p-circuit')),
  );
  const document = swarm.doc(PATH);
  document.document.getMap('root');
  if (keysFrom) {
    document._keychain.merge(keysFrom.document._keychain.history());
    await document._keychain.keys();
  }
  return { swarm, identity, document, circuit, libp2p };
}

const device = (founder, overrides = {}) => ({
  identity: founder.identity,
  keysFrom: founder,
  ...overrides,
});

const entries = (peer) => peer.document.document.getMap('root').size;

async function write(peer, from, count) {
  for (let index = from; index < from + count; index++) {
    await peer.document.change((doc) =>
      doc.getMap('root').set(`entry-${index}`, index),
    );
  }
}

async function founderWithHistory(relayAddress) {
  const placeholder = [];
  const founder = await startPeer(relayAddress, placeholder);
  placeholder.push(founder.identity.publicKey);
  await founder.document.create();
  await write(founder, 0, 120);
  assert.notEqual(await founder.document.snapshot(), undefined);
  await write(founder, 120, 15);
  return { founder, writers: placeholder };
}

const topic = documentTopic(PATH, DEFAULT_DOCUMENT_TOPIC_PREFIX);

async function advertisedDigest(peer) {
  const plan = await peer.document._createLoadResponsePlan(
    { loadChallenge: crypto.getRandomValues(new Uint8Array(32)) },
    'load-response-v4',
  );
  return loadAdvertisementHashToHex(
    await loadAdvertisementHash(
      PATH,
      plan.tips,
      plan.loadSecurityState,
      await peer.document._loadResponseManifestHash(plan),
    ),
  );
}

async function holderOf(address, founder, writers) {
  const holder = await startPeer(address, writers, device(founder));
  await holder.swarm.connect([founder.circuit]);
  assert.equal(await holder.document.open(), true);
  assert.equal(entries(holder), 135);
  return holder;
}

test('a fresh device of the only writer loads from one holder behind a relay by default', async () => {
  const { address } = await startRelay();
  const { founder, writers } = await founderWithHistory(address);
  const replica = await startPeer(address, writers, device(founder));
  await replica.swarm.connect([founder.circuit]);
  assert.equal(await replica.document.open(), true);
  assert.equal(entries(replica), 135);

  await write(founder, 135, 1);
  await until('live sync to the replica', () => entries(replica) === 136);
});

test('a fresh device loads full snapshot history from two devices of the only writer', async () => {
  const { address } = await startRelay();
  const { founder, writers } = await founderWithHistory(address);
  const holder = await holderOf(address, founder, writers);
  assert.equal(await advertisedDigest(holder), await advertisedDigest(founder));

  const replica = await startPeer(address, writers, device(founder));
  await replica.swarm.connect([founder.circuit, holder.circuit]);
  assert.equal(await replica.document.open(), true);
  assert.equal(entries(replica), 135);

  await write(founder, 135, 1);
  await until(
    'live sync to both replicas',
    () => entries(holder) === 136 && entries(replica) === 136,
  );
});

test('devices that signed their own snapshot of one state advertise one digest', async () => {
  const { address } = await startRelay();
  const { founder, writers } = await founderWithHistory(address);
  const holder = await holderOf(address, founder, writers);
  await write(founder, 135, 1);
  await until('live sync to the holder', () => entries(holder) === 136);

  const authored = await founder.document.snapshot();
  const resigned = await holder.document.snapshot();
  assert.equal(resigned.lastChangeNodeCID, authored.lastChangeNodeCID);
  assert.notDeepEqual(resigned.signature, authored.signature);
  assert.equal(await advertisedDigest(holder), await advertisedDigest(founder));

  const replica = await startPeer(address, writers, device(founder));
  await replica.swarm.connect([founder.circuit, holder.circuit]);
  assert.equal(await replica.document.open(), true);
  assert.equal(entries(replica), 136);
});

test("a fresh device loads when the only writer's devices are out of sync", async () => {
  const { address } = await startRelay();
  const { founder, writers } = await founderWithHistory(address);
  const holder = await holderOf(address, founder, writers);
  holder.libp2p.services.pubsub.unsubscribe(topic);
  await write(founder, 135, 1);
  assert.equal(entries(holder), 135);
  assert.notEqual(
    await advertisedDigest(holder),
    await advertisedDigest(founder),
  );

  const replica = await startPeer(address, writers, device(founder));
  await replica.swarm.connect([founder.circuit, holder.circuit]);
  assert.equal(await replica.document.open(), true);
  assert.ok([135, 136].includes(entries(replica)), String(entries(replica)));

  await write(founder, 136, 1);
  await until(
    'the replica to converge on the newest state',
    () => entries(replica) === 137,
  );
});

test('a fresh device fails closed when no device of the only writer answers', async () => {
  const { address } = await startRelay();
  const { founder, writers } = await founderWithHistory(address);
  const replica = await startPeer(address, writers, device(founder));
  await replica.swarm.connect([founder.circuit]);
  await founder.document.close();
  await assert.rejects(replica.document.open(), (error) => {
    assert.ok(error instanceof LoadQuorumFailedError, String(error));
    assert.equal(error.reason, 'insufficient-responses', error.message);
    assert.equal(error.requiredQ, 1, error.message);
    return true;
  });
  assert.equal(entries(replica), 0);
});
