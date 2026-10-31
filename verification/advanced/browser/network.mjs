import {
  documentFixture,
  publishedMessage,
  receiveEncrypted,
} from '../../fixtures.mjs';
import { assert, until, deadline } from './support.mjs';

const peers = new Map();
const connections = new Map();
const counters = () => ({
  sentFrames: 0,
  receivedFrames: 0,
  probeReceipts: 0,
  sentBytes: 0,
  maxBufferedBytes: 0,
  receiveFailures: 0,
  codecCalls: 0,
  codecMs: 0,
  maxCodecMs: 0,
  completedAt: null,
});
let expected = 0;

export async function seed(configuration) {
  const source = await documentFixture({
    index: 100000,
    path: `/advanced/network-${configuration.seed}`,
  });
  try {
    return {
      path: source.document.documentPath,
      privateKey: await crypto.subtle.exportKey(
        'jwk',
        source.identity.privateKey,
      ),
      publicKey: await crypto.subtle.exportKey(
        'jwk',
        source.identity.publicKey,
      ),
      writers: Array.from(source.document._writers.current()),
      keychain: Array.from(source.document._keychain.history()),
      message: Array.from(
        source.serializer.serializeSyncMessage(await publishedMessage(source)),
      ),
    };
  } finally {
    await source.close();
  }
}

export async function reset(bootstrap, ids, totalExpected) {
  expected = totalExpected;
  const identity = {
    privateKey: await crypto.subtle.importKey(
      'jwk',
      bootstrap.privateKey,
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign'],
    ),
    publicKey: await crypto.subtle.importKey(
      'jwk',
      bootstrap.publicKey,
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['verify'],
    ),
  };
  for (const id of ids) {
    let node = peers.get(id);
    if (!node) {
      node = { id, channels: new Map(), tail: Promise.resolve() };
      peers.set(id, node);
    }
    await node.tail;
    await node.fixture?.close();
    node.fixture = await documentFixture({
      identity,
      index: id + 1,
      path: bootstrap.path,
      open: false,
    });
    const fixture = node.fixture;
    fixture.document._writers.merge(new Uint8Array(bootstrap.writers));
    fixture.document._keychain.merge(new Uint8Array(bootstrap.keychain));
    await fixture.document._keychain.keys();
    assert(
      await fixture.document.sync(
        fixture.serializer.deserializeSyncMessage(
          new Uint8Array(bootstrap.message),
        ),
      ),
      'scaling bootstrap must authenticate',
    );
    await fixture.document.open();
    node.stats = counters();
    const decode = fixture.serializer.deserializeSyncMessage.bind(
      fixture.serializer,
    );
    fixture.serializer.deserializeSyncMessage = (...args) => {
      const start = performance.now();
      try {
        return decode(...args);
      } finally {
        const elapsed = performance.now() - start;
        node.stats.codecCalls++;
        node.stats.codecMs += elapsed;
        node.stats.maxCodecMs = Math.max(node.stats.maxCodecMs, elapsed);
      }
    };
    fixture.setPublish(async (_topic, frame) => {
      for (const channel of node.channels.values()) {
        node.stats.maxBufferedBytes = Math.max(
          node.stats.maxBufferedBytes,
          channel.bufferedAmount,
        );
        assert(
          channel.readyState === 'open',
          'active peer channel must remain open',
        );
        channel.send(frame);
        node.stats.sentFrames++;
        node.stats.sentBytes += frame.length;
      }
      complete(node);
    });
  }
}

function complete(node) {
  if (
    node.fixture.document.document.getMap('ops').size === expected &&
    node.stats.completedAt === null
  )
    node.stats.completedAt = performance.timeOrigin + performance.now();
}
function bind(local, remote, channel) {
  const node = peers.get(local);
  channel.binaryType = 'arraybuffer';
  node.channels.set(remote, channel);
  channel.onmessage = ({ data }) => {
    if (typeof data === 'string') {
      node.stats.probeReceipts++;
      return;
    }
    const frame = new Uint8Array(data);
    node.tail = node.tail
      .then(async () => {
        assert(
          await receiveEncrypted(node.fixture, frame),
          'scaling ciphertext must authenticate',
        );
        node.stats.receivedFrames++;
        complete(node);
      })
      .catch(() => {
        node.stats.receiveFailures++;
      });
  };
}
async function gathered(pc) {
  await until(
    () => pc.iceGatheringState === 'complete',
    15000,
    'scaling ICE gathering exceeded its bound',
  );
  return pc.localDescription.toJSON();
}
function connection(local, remote) {
  const pc = new RTCPeerConnection({ iceServers: [] });
  connections.set(`${local}:${remote}`, pc);
  return pc;
}
export async function offer(local, remote) {
  const pc = connection(local, remote);
  bind(
    local,
    remote,
    pc.createDataChannel('peerborne-scaling', { ordered: true }),
  );
  await pc.setLocalDescription(await pc.createOffer());
  return gathered(pc);
}
export async function answer(local, remote, description) {
  const pc = connection(local, remote);
  pc.ondatachannel = ({ channel }) => bind(local, remote, channel);
  await pc.setRemoteDescription(description);
  await pc.setLocalDescription(await pc.createAnswer());
  return gathered(pc);
}
export async function accept(local, remote, description) {
  await connections.get(`${local}:${remote}`).setRemoteDescription(description);
}
export async function opened(local, remote) {
  await until(
    () => peers.get(local).channels.get(remote)?.readyState === 'open',
    15000,
    'native scaling channel did not open',
  );
}
export async function mutate(rounds, ids) {
  await Promise.all(
    ids.map(async (id) => {
      const node = peers.get(id);
      for (let round = 0; round < rounds; round++)
        await node.fixture.document.change((doc) =>
          doc.getMap('ops').set(`${id}:${round}`, true),
        );
      complete(node);
    }),
  );
}
export function status() {
  return [...peers.values()].map((node) => ({
    id: node.id,
    operations: node.fixture.document.document.getMap('ops').size,
    ...node.stats,
  }));
}
export function probe(local, remote, count) {
  for (let i = 0; i < count; i++)
    peers.get(local).channels.get(remote).send('synthetic-loss-control');
}
export async function candidatePorts() {
  const ports = new Set();
  for (const pc of connections.values())
    for (const value of (await pc.getStats()).values()) {
      if (
        value.type === 'local-candidate' &&
        value.protocol === 'udp' &&
        Number.isInteger(value.port) &&
        value.port > 0 &&
        value.port < 65536
      )
        ports.add(value.port);
    }
  return [...ports];
}
export async function stats() {
  const iceStates = {};
  const candidateKinds = { mdns: 0, loopback: 0, syntheticIPv4: 0, other: 0 };
  let udpCandidateEntries = 0,
    selectedCandidatePairs = 0,
    nativeDataChannelsOpened = 0,
    maxBufferedBytes = 0;
  for (const pc of connections.values()) {
    iceStates[pc.iceConnectionState] =
      (iceStates[pc.iceConnectionState] ?? 0) + 1;
    const report = await pc.getStats();
    for (const value of report.values()) {
      if (value.type === 'local-candidate' && value.protocol === 'udp') {
        udpCandidateEntries++;
        const address = value.address ?? value.ip ?? '';
        candidateKinds[
          address.endsWith('.local')
            ? 'mdns'
            : address.startsWith('127.') || address === '::1'
              ? 'loopback'
              : address.startsWith('198.18.')
                ? 'syntheticIPv4'
                : 'other'
        ]++;
      }
      if (value.type === 'transport' && value.selectedCandidatePairId)
        selectedCandidatePairs++;
      if (value.type === 'peer-connection')
        nativeDataChannelsOpened += value.dataChannelsOpened ?? 0;
    }
  }
  for (const node of peers.values())
    for (const channel of node.channels.values())
      maxBufferedBytes = Math.max(maxBufferedBytes, channel.bufferedAmount);
  return {
    nativePeerConnectionEndpoints: connections.size,
    iceStates,
    candidateKinds,
    udpCandidateEntries,
    selectedCandidatePairs,
    nativeDataChannelsOpened,
    currentMaxBufferedBytes: maxBufferedBytes,
    peers: status(),
  };
}
export async function close() {
  for (const pc of connections.values()) pc.close();
  for (const node of peers.values()) {
    await deadline(node.tail, 15000);
    await node.fixture?.close();
  }
  peers.clear();
  connections.clear();
}
