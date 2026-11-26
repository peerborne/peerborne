import assert from 'node:assert/strict';
import test from 'node:test';
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

for (const method of ['log', 'info', 'debug', 'warn'])
  console[method] = () => {};

async function until(label, predicate, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (!(await predicate())) {
    if (Date.now() > deadline)
      throw new Error(`Timed out waiting for ${label}`);
    await delay(100);
  }
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

async function peer(relayAddress, keys = {}) {
  const identity =
    keys.identity ??
    (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['sign', 'verify'],
    ));
  const kem =
    keys.kem ??
    (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveBits'],
    ));
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
    loadQuorumEnabled: false,
  });
  await swarm.connect([relayAddress]);
  let circuit;
  await until('circuit reservation', () => {
    circuit = swarm.libp2p
      .getMultiaddrs()
      .map(String)
      .find((address) => address.includes('/p2p-circuit'));
    return circuit !== undefined;
  });
  const rawKem = new Uint8Array(
    await crypto.subtle.exportKey('raw', kem.publicKey),
  );
  return { swarm, identity, kem, rawKem, circuit };
}

async function network(t, path, count) {
  const relay = await relayNode(path);
  const peers = [];
  t.after(async () => {
    for (const { swarm } of peers.reverse())
      await swarm.heliaNode.stop().catch(() => {});
    await relay.stop().catch(() => {});
  });
  const relayAddress = String(relay.getMultiaddrs()[0]);
  const join = async (keys) => {
    const joined = await peer(relayAddress, keys);
    peers.push(joined);
    return joined;
  };
  const started = [];
  for (let index = 0; index < count; index++) started.push(await join());
  return [...started, join];
}

async function founded(founder, path, body) {
  const document = founder.swarm.doc(path);
  await document.setKemKeyPair(founder.kem);
  await document.create();
  document.historyVisibility = 'full_history';
  await document.change((draft) => {
    draft.body = body;
  });
  return document;
}

const serialize = (key) => new SubtleCrypto().serializePublicKey(key);

async function members(document, list) {
  return Promise.all((await document[list]()).map(serialize));
}

const hex = (bytes) => Buffer.from(bytes).toString('hex');

async function holdsKey(document, keyId) {
  return (await document._keychain.keys()).some(
    ([id]) => hex(id) === hex(keyId),
  );
}

test('addReader rejects a new identity without consuming the collaborator slot', async (t) => {
  const path = `/reshare/direct-${crypto.randomUUID()}`;
  const [founder, recipient] = await network(t, path, 2);
  const document = await founded(founder, path, 'shared');
  const founderId = await serialize(founder.identity.publicKey);

  await assert.rejects(
    document.addReader(recipient.identity.publicKey, recipient.rawKem),
    /cannot onboard a new identity.*createInvitation\(\)/,
  );
  assert.deepEqual(await members(document, 'getReaders'), [founderId]);
  assert.deepEqual(await members(document, 'getWriters'), [founderId]);
  assert.equal(document._beekemInitialized, false);

  const offer = await document.createInvitation({
    role: 'reader',
    rendezvous: [founder.circuit],
  });
  const joined = await recipient.swarm.acceptInvitation(offer, recipient.kem);
  await until('invited reader state', () => joined.document?.body === 'shared');
  assert.deepEqual(
    (await members(document, 'getReaders')).sort(),
    [founderId, await serialize(recipient.identity.publicKey)].sort(),
  );
});

test('a founder re-shares after revoking its only collaborator', async (t) => {
  const path = `/reshare/revoked-${crypto.randomUUID()}`;
  const [founder, removed, replacement] = await network(t, path, 3);
  const document = await founded(founder, path, 'before removal');
  const rendezvous = [founder.circuit];
  const staleOffer = await document.createInvitation({
    role: 'reader',
    rendezvous,
  });
  const firstOffer = await document.createInvitation({
    role: 'editor',
    rendezvous,
  });

  const former = await removed.swarm.acceptInvitation(firstOffer, removed.kem);
  await until(
    'first member state',
    () => former.document?.body === 'before removal',
  );
  await former.change((draft) => {
    draft.fromRemoved = 'joined';
  });
  await until(
    'first member edit',
    () => document.document.fromRemoved === 'joined',
  );

  await assert.rejects(
    document.createInvitation({ role: 'reader', rendezvous }),
    /requires exactly one founder writer/,
  );
  await document.removeWriter(removed.identity.publicKey);
  await document.removeReader(removed.identity.publicKey);
  const [revokedEpoch] = await document._keychain.current();
  assert.equal(await holdsKey(former, revokedEpoch), false);
  assert.equal(document._beekem.hasOnlyLocalLiveLeaf(), true);

  await assert.rejects(
    replacement.swarm.acceptInvitation(staleOffer, replacement.kem),
    /Unable to accept invitation/,
  );
  assert.equal(replacement.swarm._documentRegistry.has(path), false);

  const offer = await document.createInvitation({ role: 'editor', rendezvous });
  const joined = await replacement.swarm.acceptInvitation(
    offer,
    replacement.kem,
  );
  await until(
    'replacement state',
    () => joined.document?.body === 'before removal',
  );
  assert.equal(joined.document.fromRemoved, 'joined');
  assert.equal(await holdsKey(joined, revokedEpoch), true);
  assert.equal(document._beekem.hasOnlyLocalLiveLeaf(), false);
  assert.equal(document._beekem.memberCount, 2);

  await document.change((draft) => {
    draft.body = 'after re-share';
  });
  await joined.change((draft) => {
    draft.fromReplacement = 'hello';
  });
  await until(
    're-shared convergence',
    () =>
      joined.document.body === 'after re-share' &&
      document.document.fromReplacement === 'hello',
  );
  await former.requestSync().catch(() => {});
  await delay(1500);
  assert.equal(former.document.body, 'before removal');
  assert.equal(former.document.fromReplacement, undefined);
  assert.equal(
    await holdsKey(former, (await document._keychain.current())[0]),
    false,
  );
  assert.deepEqual(
    (await members(document, 'getWriters')).sort(),
    [
      await serialize(founder.identity.publicKey),
      await serialize(replacement.identity.publicKey),
    ].sort(),
  );
});

test('a founder that persists before acceptance can revoke the collaborator after a crash', async (t) => {
  const path = `/reshare/crash-${crypto.randomUUID()}`;
  const [founder, member, join] = await network(t, path, 2);
  const document = await founded(founder, path, 'before crash');
  await assert.rejects(
    document.createInvitation({
      role: 'editor',
      rendezvous: [founder.circuit],
      beforeAcceptance: 'persist',
    }),
    TypeError,
  );
  let accepted = false;
  let attempts = 0;
  let saved;
  const offer = await document.createInvitation({
    role: 'editor',
    rendezvous: [founder.circuit],
    beforeAcceptance: async () => {
      attempts++;
      assert.equal(accepted, false);
      assert.equal(
        await document._readers.check(member.identity.publicKey),
        true,
      );
      if (attempts === 1) throw new Error('storage unavailable');
      saved = await document.exportCheckpoint();
    },
  });

  await assert.rejects(
    member.swarm.acceptInvitation(offer, member.kem),
    /Unable to accept invitation/,
  );
  assert.equal(member.swarm._documentRegistry.has(path), false);
  const joined = await member.swarm.acceptInvitation(offer, member.kem);
  accepted = true;
  await until('member state', () => joined.document?.body === 'before crash');
  assert.equal(attempts, 2);

  await founder.swarm.heliaNode.stop();
  const restarted = await join({
    identity: founder.identity,
    kem: founder.kem,
  });
  const restored = restarted.swarm.doc(path);
  await restored.setKemKeyPair(founder.kem);
  await restored.restoreCheckpoint(saved);
  await restored.open();
  const memberId = await serialize(member.identity.publicKey);
  assert.ok((await members(restored, 'getReaders')).includes(memberId));
  assert.ok((await members(restored, 'getWriters')).includes(memberId));

  await restored.removeWriter(member.identity.publicKey);
  await restored.removeReader(member.identity.publicKey);
  const [epoch] = await restored._keychain.current();
  assert.equal(await holdsKey(joined, epoch), false);
  assert.equal(
    (await members(restored, 'getReaders')).includes(memberId),
    false,
  );
  await restored.change((draft) => {
    draft.body = 'after revocation';
  });
  await delay(1500);
  assert.equal(joined.document.body, 'before crash');

  const revoked = await restored.exportCheckpoint();
  await restarted.swarm.heliaNode.stop();
  const reopened = await join({ identity: founder.identity, kem: founder.kem });
  const resumed = reopened.swarm.doc(path);
  await resumed.setKemKeyPair(founder.kem);
  await resumed.restoreCheckpoint(revoked);
  await resumed.open();
  const replacement = await join();
  const shared = await replacement.swarm.acceptInvitation(
    await resumed.createInvitation({
      role: 'reader',
      rendezvous: [reopened.circuit],
    }),
    replacement.kem,
  );
  await until(
    're-shared state',
    () => shared.document?.body === 'after revocation',
  );
  assert.equal(await holdsKey(shared, epoch), true);
  assert.equal(joined.document.body, 'before crash');
});
