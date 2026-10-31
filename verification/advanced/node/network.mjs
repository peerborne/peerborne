import assert from 'node:assert/strict';
import { createLibp2p } from 'libp2p';
import { tcp } from '@libp2p/tcp';
import { identify } from '@libp2p/identify';
import { gossipsub } from '@libp2p/gossipsub';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { setTimeout as delay } from 'node:timers/promises';
import { documentFixture, replicaOf } from '../../fixtures.mjs';
import { measure, measuredOnly } from '../../measure.mjs';

async function until(predicate, timeout = 15000) {
  const end = performance.now() + timeout;
  while (!predicate()) {
    if (performance.now() >= end)
      throw new Error('Bounded gossip readiness/delivery deadline exceeded');
    await delay(5);
  }
}

export async function echoStorm({ full }) {
  const nodes = [];
  const source = await documentFixture({ path: '/advanced/gossip-diamond' });
  let target;
  try {
    target = await replicaOf(source, 2);
    for (let i = 0; i < 4; i++)
      nodes.push(
        await createLibp2p({
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
              doPX: false,
              heartbeatInitialDelay: 20,
              heartbeatInterval: 100,
              D: 2,
              Dlo: 2,
              Dhi: 4,
              Dout: 1,
            }),
          },
        }),
      );
    const pubs = nodes.map((node) => node.services.pubsub);
    const topic = source.document._topic;
    pubs.forEach((pub) => pub.subscribe(topic));
    for (const [a, b] of [
      [0, 1],
      [0, 2],
      [1, 3],
      [2, 3],
    ])
      await nodes[a].dial(nodes[b].getMultiaddrs()[0]);
    await until(() =>
      pubs.every(
        (pub) =>
          pub.getSubscribers(topic).length >= 2 &&
          (pub.mesh.get(topic)?.size ?? 0) >= 2,
      ),
    );
    let rawReceipts = 0,
      deliveries = 0,
      decryptions = 0,
      syncCalls = 0,
      outgoingMessages = 0;
    const receive = pubs[3].handleReceivedMessage.bind(pubs[3]);
    pubs[3].handleReceivedMessage = async (from, message) => {
      if (message.topic === topic) rawReceipts++;
      return receive(from, message);
    };
    const decrypt = target.document._decryptBlock.bind(target.document);
    target.document._decryptBlock = async (...args) => {
      decryptions++;
      return decrypt(...args);
    };
    const sync = target.document.sync.bind(target.document);
    target.document.sync = async (...args) => {
      syncCalls++;
      return sync(...args);
    };
    pubs[3].addEventListener('message', (event) => {
      if (event.detail.topic === topic) {
        deliveries++;
        target.document._pubsubHandler(event);
      }
    });
    const sendFromD = pubs[3].sendRpc.bind(pubs[3]);
    pubs[3].sendRpc = (peer, rpc) => {
      outgoingMessages += rpc.messages.filter(
        (message) => message.topic === topic,
      ).length;
      return sendFromD(peer, rpc);
    };
    const destination = nodes[3].peerId.toString();
    const held = [[], []];
    const forwards = [
      pubs[1].sendRpc.bind(pubs[1]),
      pubs[2].sendRpc.bind(pubs[2]),
    ];
    for (let i = 0; i < 2; i++)
      pubs[i + 1].sendRpc = (peer, rpc) => {
        if (
          peer === destination &&
          rpc.messages.some((message) => message.topic === topic)
        ) {
          held[i].push({ peer, rpc });
          return true;
        }
        return forwards[i](peer, rpc);
      };
    source.setPublish(async (label, bytes) => {
      await pubs[0].publish(label, bytes);
    });
    const messages = full ? 128 : 8;
    const cacheBefore = pubs[3].seenCache.size;
    const timing = await measure(async () => {
      for (let i = 0; i < messages; i++) {
        await source.document.change((doc) =>
          doc.getMap('root').set('diamondCounter', i),
        );
        await until(() => held.every((queue) => queue.length > 0));
        // A network-schedule barrier releases the two real GossipSub RPCs.
        // No fixture seen-cache or application de-duplication is installed.
        for (let branch = 0; branch < 2; branch++)
          for (const { peer, rpc } of held[branch].splice(0))
            assert(
              forwards[branch](peer, rpc),
              'real outbound gossip stream must accept each scheduled branch',
            );
        await until(
          () =>
            rawReceipts >= (i + 1) * 2 &&
            target.document.document.getMap('root').get('diamondCounter') === i,
        );
        assert.equal(
          deliveries,
          i + 1,
          'diamond duplicates must be suppressed before application dispatch',
        );
        assert.equal(
          decryptions,
          i + 1,
          'duplicate ciphertext must not trigger another application decryption',
        );
        assert.equal(
          syncCalls,
          i + 1,
          'duplicate ciphertext must not re-enter CRDT sync',
        );
      }
    });
    assert.equal(
      pubs[3].seenCache.size - cacheBefore,
      messages,
      'actual dependency seen-cache must hold one entry per publication',
    );
    assert(
      outgoingMessages <= messages * 2,
      'D cannot re-broadcast each duplicate as a new message',
    );
    return {
      scope:
        'Four real libp2p TCP/Noise/Yamux/GossipSub nodes in a diamond, with unchanged production document ciphertext and actual document pubsub ingress at D. A delivery barrier schedules both forwarding branches; no harness deduplication is used.',
      metrics: {
        nodes: 4,
        edges: 4,
        messages,
        rawReceipts,
        deliveries,
        decryptions,
        syncCalls,
        outgoingMessages,
        seenCacheGrowth: pubs[3].seenCache.size - cacheBefore,
        ...measuredOnly(timing),
        converged: true,
      },
      gaps: [
        'This verifies the installed GossipSub dependency with an explicit four-node overlay and production crypto/ingress. Default Peerborne peer discovery, WebRTC routing, cache expiry/restarts and long-duration replay budgets are outside this TCP component scenario.',
      ],
    };
  } finally {
    await target?.close();
    await source.close();
    await Promise.allSettled(nodes.map((node) => node.stop()));
  }
}
