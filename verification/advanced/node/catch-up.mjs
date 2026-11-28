import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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
  LOAD_SECURITY_STATE_VERSION,
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

async function until(predicate, timeout = 60_000) {
  const started = performance.now();
  while (!(await predicate())) {
    if (performance.now() - started >= timeout)
      throw new Error('Bounded convergence deadline exceeded');
    await delay(50);
  }
  return Math.round(performance.now() - started);
}

// Both replicas resolve the same locally trusted tuple, as an application
// that pins its security commitments would.
const commitments = () => ({
  version: LOAD_SECURITY_STATE_VERSION,
  controlHead: new Uint8Array(32).fill(1),
  groupId: 'anti-entropy-verification',
  epoch: 0n,
  treeHash: new Uint8Array(32).fill(2),
  confirmedTranscriptHash: new Uint8Array(32).fill(3),
});

async function relayNode(topic) {
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
          defaultDataLimit: 256n * 1024n * 1024n,
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
  relay.services.pubsub.subscribe(topic);
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
  const gate = { offline: false };
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
        connectionGater: {
          denyDialMultiaddr: async () => gate.offline,
          denyInboundConnection: async () => gate.offline,
        },
      },
    },
    pubsubDocumentPrefix: DEFAULT_DOCUMENT_TOPIC_PREFIX,
    enableTopicValidators: true,
    resolveLoadSecurityCommitments: commitments,
    ...config,
  });
  await swarm.connect([relayAddress]);
  await until(() =>
    swarm.libp2p
      .getMultiaddrs()
      .some((address) => String(address).includes('/p2p-circuit')),
  );
  const circuit = swarm.libp2p
    .getMultiaddrs()
    .map(String)
    .find((address) => address.includes('/p2p-circuit'));
  return { swarm, kem, circuit, gate };
}

/**
 * A WebSocket relay, a founding writer and a reader joined by invitation over
 * Circuit Relay. `inbound.drop` selects reader frames to discard after
 * GossipSub and topic validation accepted them, before the document applies
 * them; the listener is registered before the document's own.
 */
async function pair({ founder: founderConfig, reader: readerConfig }) {
  const path = `/advanced/catch-up-${crypto.randomUUID()}`;
  const topic = documentTopic(path, DEFAULT_DOCUMENT_TOPIC_PREFIX);
  const stops = [];
  try {
    const relay = await relayNode(topic);
    stops.push(() => relay.stop());
    const relayAddress = String(relay.getMultiaddrs()[0]);
    const founder = await peer(relayAddress, founderConfig);
    stops.push(() => founder.swarm.heliaNode.stop());
    const reader = await peer(relayAddress, readerConfig);
    stops.push(() => reader.swarm.heliaNode.stop());
    const founderPeer = founder.swarm.libp2p.peerId.toString();
    const inbound = {
      dropped: 0,
      drop: () => false,
      fromFounder: (event) => event.detail.from?.toString() === founderPeer,
    };
    reader.swarm.libp2p.services.pubsub.addEventListener('message', (event) => {
      if (event.detail.topic === topic && inbound.drop(event)) {
        inbound.dropped++;
        event.stopImmediatePropagation();
      }
    });
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
      beforeAcceptance: async () => {},
    });
    const target = await reader.swarm.acceptInvitation(offer, reader.kem);
    await until(() => target.document.body === 'joined');
    let manualRequests = 0;
    const requestSync = target.requestSync.bind(target);
    target.requestSync = () => {
      manualRequests++;
      return requestSync();
    };
    const events = [];
    const clock = { since: performance.now() };
    target.subscribeToAntiEntropy('verification', (event) =>
      events.push({
        name:
          event.type === 'request' ? `request:${event.triggers}` : event.type,
        at: performance.now(),
      }),
    );
    return {
      relay,
      relayAddress,
      founder,
      reader,
      source,
      target,
      inbound,
      events,
      clock,
      manualRequests: () => manualRequests,
      async close() {
        for (const stop of stops.reverse()) await stop().catch(() => {});
      },
    };
  } catch (error) {
    for (const stop of stops.reverse()) await stop().catch(() => {});
    throw error;
  }
}

// A repaired gap closes when the document next checks it, so allow a short
// settle before reading the final status.
const summary = async (session) => {
  await until(() => !session.target.antiEntropyStatus.gap, 5_000).catch(
    () => {},
  );
  const status = session.target.antiEntropyStatus;
  return {
    requests: status.requests,
    loads: status.loads,
    suppressed: status.suppressed,
    gapOpen: status.gap,
    // Events after the last reset, with ms since that reset.
    events: session.events
      .filter(({ at }) => at >= session.clock.since)
      .map(({ name, at }) => `${name}@${Math.round(at - session.clock.since)}`),
    manualRequests: session.manualRequests(),
  };
};

/**
 * The reader drops every frame while the writer makes more changes than the
 * depth bound retains, then receives one later frame whose inline tree no
 * longer reaches its own head. The CRDT queues those changes; catch-up asks,
 * and the writer's reply carries the snapshot.
 */
export async function prunedGapCatchUp({ full }) {
  const edits = full ? 600 : 300;
  const run = async (antiEntropy) => {
    const session = await pair({ reader: { antiEntropy } });
    try {
      session.inbound.drop = session.inbound.fromFounder;
      for (let i = 0; i < edits; i++)
        await session.source.change((draft) => {
          draft.counter = i;
        });
      assert(session.source.latestSnapshot, 'the writer must prune by depth');
      session.inbound.drop = () => false;
      session.clock.since = performance.now();
      await session.source.change((draft) => {
        draft.after = 'gap';
      });
      const converged = until(
        () =>
          session.target.document.counter === edits - 1 &&
          session.target.document.after === 'gap',
        antiEntropy.enabled === false ? 10_000 : 60_000,
      );
      return {
        dropped: session.inbound.dropped,
        convergedMs: await converged.catch(() => undefined),
        afterApplied: session.target.document.after === 'gap',
        ...(await summary(session)),
      };
    } finally {
      await session.close();
    }
  };
  const control = await run({ enabled: false });
  const automatic = await run({});
  assert.equal(control.convergedMs, undefined, 'the gap must be real');
  assert.notEqual(automatic.convergedMs, undefined);
  assert.equal(automatic.manualRequests, 0);
  assert(
    ['gap@', 'repaired@'].every((name) =>
      automatic.events.some((event) => event.startsWith(name)),
    ),
  );
  return {
    scope:
      'A WebSocket relay and two real Peerborne nodes (founding writer and invited reader) over Circuit Relay with production GossipSub, topic validators, Bitswap and Automerge. The reader drops its inbound document frames during the burst.',
    metrics: { edits, control, automatic, converged: true },
    gaps: [],
  };
}

/**
 * The writer leaves the relay, makes 400 changes while unreachable (pruning
 * by depth), and reconnects. Its request on reconnect advertises a head the
 * reader lacks; the reader asks and applies the reply.
 */
export async function offlineWriterCatchUp() {
  const edits = 400;
  const session = await pair({});
  try {
    const { founder } = session;
    founder.gate.offline = true;
    await Promise.all(
      founder.swarm.libp2p
        .getConnections()
        .map((connection) => connection.close().catch(() => {})),
    );
    await until(() => founder.swarm.libp2p.getConnections().length === 0);
    for (let i = 0; i < edits; i++)
      await session.source.change((draft) => {
        draft.offline = i;
      });
    assert(session.source.latestSnapshot, 'the writer must prune by depth');
    await delay(1_000);
    assert.equal(session.target.document.offline, undefined);
    founder.gate.offline = false;
    const reconnected = performance.now();
    session.clock.since = reconnected;
    await founder.swarm.connect([session.relayAddress]);
    await until(() => session.target.document.offline === edits - 1);
    const reconnectToConvergedMs = Math.round(performance.now() - reconnected);
    // The reply names changes below the writer's snapshot that no connected
    // peer serves over Bitswap; a later frame must still apply.
    await session.source.change((draft) => {
      draft.after = 'reconnect';
    });
    const followUpMs = await until(
      () => session.target.document.after === 'reconnect',
      30_000,
    );
    const metrics = {
      edits,
      reconnectToConvergedMs,
      followUpMs,
      ...(await summary(session)),
    };
    assert.equal(metrics.manualRequests, 0);
    assert(metrics.events.some((event) => event.startsWith('repaired@')));
    return {
      scope:
        'A WebSocket relay and two real Peerborne nodes over Circuit Relay. The writer closes every connection, a connection gater refuses redials during 400 edits, and the writer then reconnects to the relay only.',
      metrics: { ...metrics, converged: true },
      gaps: [],
    };
  } finally {
    await session.close();
  }
}

/**
 * The reader drops only the frame of a burst's final change, and nothing is
 * edited afterwards. Only the periodic request can reveal the gap.
 */
export async function droppedFinalFrameCatchUp({ full }) {
  const intervalMs = full ? 45_000 : 6_000;
  const session = await pair({
    reader: {
      antiEntropy: { intervalMs, minRequestIntervalMs: 2_000 },
    },
  });
  try {
    const burst = 30;
    // Start right after the reader's own request settles, so no reply from
    // the writer interleaves with the final change.
    await until(() => session.target.antiEntropyStatus.requests > 0);
    await delay(1_000);
    const founderPubsub = session.founder.swarm.libp2p.services.pubsub;
    const publish = founderPubsub.publish.bind(founderPubsub);
    let mark = false;
    let marked;
    founderPubsub.publish = (topic, data, options) => {
      if (mark) {
        mark = false;
        marked = data.slice();
      }
      return publish(topic, data, options);
    };
    session.inbound.drop = (event) => {
      const { data } = event.detail;
      if (
        marked === undefined ||
        data.byteLength !== marked.byteLength ||
        !data.every((byte, index) => byte === marked[index])
      )
        return false;
      marked = undefined;
      return true;
    };
    for (let i = 0; i < burst - 1; i++)
      await session.source.change((draft) => {
        draft.burst = i;
      });
    mark = true;
    session.clock.since = performance.now();
    await session.source.change((draft) => {
      draft.burst = burst - 1;
    });
    await delay(1_500);
    assert.equal(session.inbound.dropped, 1, 'the final frame must be dropped');
    assert.equal(session.target.document.burst, burst - 2);
    const convergedMs = await until(
      () => session.target.document.burst === burst - 1,
      intervalMs * 2 + 10_000,
    );
    const metrics = {
      burst,
      intervalMs,
      convergedMs,
      ...(await summary(session)),
    };
    assert.equal(metrics.manualRequests, 0);
    return {
      scope:
        'A WebSocket relay and two real Peerborne nodes over Circuit Relay. The reader drops exactly the frame that carries the final change of a 30-edit burst, after GossipSub accepted it.',
      metrics: { ...metrics, converged: true },
      gaps: full
        ? []
        : [
            'Smoke uses a 6 s periodic interval; the default is 30-60 s, which the full profile runs.',
          ],
    };
  } finally {
    await session.close();
  }
}

/**
 * The reader misses an entire burst that does not fit in a gossip reply.
 * The sole writer's periodic advertisement must trigger authenticated V4
 * catch-up even if there is no later edit to reveal the missing dependencies.
 */
export async function largeCatchUpLoad({ progress }) {
  const session = await pair({
    founder: {
      antiEntropy: { intervalMs: 5_000, minRequestIntervalMs: 2_000 },
      loadQuorumTimeoutMs: 30_000,
    },
    reader: {
      antiEntropy: {
        intervalMs: 10_000,
        minRequestIntervalMs: 2_000,
        loadAfterMs: 4_000,
        loadIntervalMs: 10_000,
      },
      // Allow headroom for signing and serializing on a loaded CI runner.
      loadQuorumTimeoutMs: 30_000,
    },
  });
  try {
    // Each change fits one frame; together they exceed any gossip reply.
    const values = Array.from({ length: 12 }, (_, i) =>
      syntheticText(400_000, 70 + i),
    );
    const pubsub = session.founder.swarm.libp2p.services.pubsub;
    const publish = pubsub.publish;
    const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
    const missed = new Set();
    pubsub.publish = function (topic, data, options) {
      missed.add(digest(data));
      return publish.call(this, topic, data, options);
    };
    session.inbound.drop = (event) =>
      session.inbound.fromFounder(event) &&
      missed.has(digest(event.detail.data));
    try {
      for (const [i, value] of values.entries())
        await session.source.change((draft) => {
          draft[`large${i}`] = value;
        });
    } finally {
      pubsub.publish = publish;
    }
    assert(missed.size >= values.length, 'the writer must publish the burst');
    assert(
      values.every(
        (_, i) => session.target.document[`large${i}`] === undefined,
      ),
    );
    assert.equal(session.target.antiEntropyStatus.loads, 0);
    session.clock.since = performance.now();
    progress(
      `waiting for advertised recovery of ${values.length} missed edits`,
    );
    session.target.subscribeToAntiEntropy(
      'large-catch-up-progress',
      (event) => {
        if (event.type === 'gap') progress(`gap: ${event.trigger}`);
        if (event.type === 'load') progress(`load: ${event.outcome}`);
      },
    );
    const convergedMs = await until(
      () =>
        session.target.antiEntropyStatus.lastLoad?.outcome === 'loaded' &&
        values.every(
          (value, i) => session.target.document[`large${i}`] === value,
        ),
      120_000,
    );
    await session.source.change((draft) => {
      draft.after = 'large';
    });
    const followUpMs = await until(
      () => session.target.document.after === 'large',
      30_000,
    );
    const metrics = {
      values: values.length,
      valueBytes: values[0].length,
      convergedMs,
      followUpMs,
      lastLoad: session.target.antiEntropyStatus.lastLoad?.outcome,
      droppedFrames: session.inbound.dropped,
      ...(await summary(session)),
    };
    assert(metrics.loads >= 1, 'the repair must use the load path');
    assert(metrics.droppedFrames > 0, 'the reader must miss document frames');
    assert.equal(metrics.lastLoad, 'loaded');
    assert.equal(metrics.gapOpen, false);
    assert.equal(metrics.manualRequests, 0);
    return {
      scope:
        'A WebSocket relay and two real Peerborne nodes over Circuit Relay with locally pinned load security commitments. The reader misses twelve 400 KB changes and uses the authenticated V4 load from the sole writer before any further edit. Multi-writer quorum is outside this case.',
      metrics: { ...metrics, converged: true },
      gaps: [],
    };
  } finally {
    await session.close();
  }
}
