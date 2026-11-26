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
  BeeKEM,
  DEFAULT_DOCUMENT_TOPIC_PREFIX,
  Peerborne,
  SubtleCrypto,
  deriveEpochIdFromRootSecret,
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

const wallClock = Date.now.bind(Date);
let clockSkewMs = 0;
Date.now = () => wallClock() + clockSkewMs;
const leaveRemaining = (offer, remainingMs) => {
  clockSkewMs += offer.expiresAtMs - Date.now() - remainingMs;
};
const unstored = async () => {};

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
    beforeAcceptance: unstored,
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
    beforeAcceptance: unstored,
  });
  const firstOffer = await document.createInvitation({
    role: 'editor',
    rendezvous,
    beforeAcceptance: unstored,
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
    document.createInvitation({
      role: 'reader',
      rendezvous,
      beforeAcceptance: unstored,
    }),
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

  const offer = await document.createInvitation({
    role: 'editor',
    rendezvous,
    beforeAcceptance: unstored,
  });
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

test('a collaborator cannot plant its own key or ratchet tree in the founder', async (t) => {
  const path = `/reshare/forged-welcome-${crypto.randomUUID()}`;
  const [founder, mallory, replacement] = await network(t, path, 3);
  const document = await founded(founder, path, 'before');
  const rendezvous = [founder.circuit];
  const editor = await mallory.swarm.acceptInvitation(
    await document.createInvitation({
      role: 'editor',
      rendezvous,
      beforeAcceptance: unstored,
    }),
    mallory.kem,
  );
  await until('collaborator state', () => editor.document?.body === 'before');
  const keyIds = async (replica) =>
    (await replica._keychain.keys()).map(([id]) => hex(id));
  const honestKeys = await keyIds(document);
  const honestTree = document._beekem;

  // Any writer can publish a reader row, including one for the founder.
  await editor._makeChangeOnce(
    await editor._readers.add(founder.identity.publicKey),
    'reader',
  );
  await until(
    'founder reader row',
    async () =>
      (await document._readers.check(founder.identity.publicKey)) === true,
  );

  // A tree whose ghost leaf the collaborator controls, sealed to the founder.
  const ecdh = { name: 'ECDH', namedCurve: 'P-256' };
  const founderKem = new Uint8Array(
    await crypto.subtle.exportKey('raw', founder.kem.publicKey),
  );
  const ghost = await crypto.subtle.generateKey(ecdh, false, ['deriveBits']);
  const forgedTree = new BeeKEM();
  await forgedTree.initialize(ghost.privateKey, ghost.publicKey);
  await forgedTree.addMember(mallory.kem.publicKey);
  while (forgedTree.generation < honestTree.generation) {
    await forgedTree.update();
  }
  const { welcome } = await forgedTree.addMember(
    await crypto.subtle.importKey('raw', founderKem, ecdh, true, []),
  );
  const forger = new AutomergeKeychainProvider().initialize();
  forger.merge(editor._keychain.history());
  const [forgedKey] = await forger.add();

  const outcomes = [];
  const evaluate = document._evaluateAndApplyBeeKEMWelcome.bind(document);
  document._evaluateAndApplyBeeKEMWelcome = async (...args) => {
    const outcome = await evaluate(...args);
    outcomes.push(outcome);
    return outcome;
  };
  const liveKeychain = editor._keychain;
  editor._keychain = forger;
  try {
    await editor._sendBeeKEMWelcome(
      founder.identity.publicKey,
      founderKem,
      welcome,
      editor._changesSerializer.serializeChanges(forger.history()),
    );
  } finally {
    editor._keychain = liveKeychain;
  }
  await until('forged Welcome handled', () => outcomes.length > 0);

  assert.deepEqual(outcomes, ['terminal']);
  assert.deepEqual(await keyIds(document), honestKeys);
  assert.equal(await holdsKey(document, forgedKey), false);
  assert.equal(document._beekem, honestTree);
  assert.equal(document._invitationEpoch, undefined);

  await editor._makeChangeOnce(
    await editor._readers.remove(founder.identity.publicKey),
    'reader',
  );
  await until(
    'founder reader row removed',
    async () =>
      (await document._readers.check(founder.identity.publicKey)) !== true,
  );
  await document.change((draft) => {
    draft.body = 'shared';
  });
  await until('collaborator edit', () => editor.document.body === 'shared');

  let rotation;
  const distribute = document._distributeBeeKEMPathUpdate.bind(document);
  document._distributeBeeKEMPathUpdate = async (update, epoch) => {
    rotation = update;
    return distribute(update, epoch);
  };
  await document.removeWriter(mallory.identity.publicKey);
  await document.removeReader(mallory.identity.publicKey);
  const [rotated] = await document._keychain.current();
  assert.equal(await holdsKey(editor, rotated), false);
  await assert.rejects(forgedTree.processPathUpdate(rotation));
  assert.deepEqual(await keyIds(document), [...honestKeys, hex(rotated)]);
  assert.equal(document._beekem.hasOnlyLocalLiveLeaf(), true);

  const joined = await replacement.swarm.acceptInvitation(
    await document.createInvitation({
      role: 'editor',
      rendezvous,
      beforeAcceptance: unstored,
    }),
    replacement.kem,
  );
  await until('replacement state', () => joined.document?.body === 'shared');
  assert.deepEqual(await keyIds(joined), await keyIds(document));
  await joined.change((draft) => {
    draft.reply = 'converged';
  });
  await until(
    'founder sees the replacement',
    () => document.document.reply === 'converged',
  );
});

test('a collaborator cannot plant a leaf in the founder tree through its own PathUpdate', async (t) => {
  const path = `/reshare/planted-leaf-${crypto.randomUUID()}`;
  const [founder, mallory, replacement] = await network(t, path, 3);
  const document = await founded(founder, path, 'before');
  const rendezvous = [founder.circuit];
  const editor = await mallory.swarm.acceptInvitation(
    await document.createInvitation({
      role: 'editor',
      rendezvous,
      beforeAcceptance: unstored,
    }),
    mallory.kem,
  );
  await until('collaborator state', () => editor.document?.body === 'before');
  const keyIds = async (replica) =>
    (await replica._keychain.keys()).map(([id]) => hex(id));
  const processed = [];
  const handle = document.handleBeeKEMPathUpdateRequestData.bind(document);
  document.handleBeeKEMPathUpdateRequestData = async (...args) => {
    await handle(...args);
    processed.push(document._beekem.generation);
  };
  const send = async (transition) => {
    const count = processed.length;
    await editor._distributeBeeKEMPathUpdate(
      transition.pathUpdate,
      await deriveEpochIdFromRootSecret(transition.rootSecret),
    );
    await until('PathUpdate handled', () => processed.length > count);
  };

  const ghostKeys = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const planted = await editor._beekem.clone().addMember(ghostKeys.publicKey);
  const ghost = new BeeKEM();
  await ghost.processWelcome(
    planted.welcome,
    ghostKeys.privateKey,
    ghostKeys.publicKey,
  );
  const honestKeys = await keyIds(document);
  const honestTree = document._beekem;
  await send(planted);
  // A refreshed leaf key would hide the editor's leaf from removeReader.
  await send(await editor._beekem.clone().update());
  assert.equal(document._beekem, honestTree);
  assert.equal(document._beekem.memberCount, 2);
  assert.deepEqual(await keyIds(document), honestKeys);

  const pathOnly = await editor._beekem.updatePath();
  await send(pathOnly);
  const [memberEpoch] = await document._keychain.current();
  assert.equal(
    hex(memberEpoch),
    hex(await deriveEpochIdFromRootSecret(pathOnly.rootSecret)),
  );

  let rotation;
  const distribute = document._distributeBeeKEMPathUpdate.bind(document);
  document._distributeBeeKEMPathUpdate = async (update, epoch) => {
    rotation = update;
    return distribute(update, epoch);
  };
  await document.removeWriter(mallory.identity.publicKey);
  await document.removeReader(mallory.identity.publicKey);
  const [rotated] = await document._keychain.current();
  assert.equal(await holdsKey(editor, rotated), false);
  await assert.rejects(ghost.processPathUpdate(rotation));
  assert.equal(document._beekem.hasOnlyLocalLiveLeaf(), true);

  const joined = await replacement.swarm.acceptInvitation(
    await document.createInvitation({
      role: 'reader',
      rendezvous,
      beforeAcceptance: unstored,
    }),
    replacement.kem,
  );
  await until('replacement state', () => joined.document?.body === 'before');
  assert.deepEqual(await keyIds(joined), await keyIds(document));
});

test('a founder restored from its acceptance checkpoint revokes the collaborator and re-shares', async (t) => {
  const path = `/reshare/crash-${crypto.randomUUID()}`;
  const [founder, member, join] = await network(t, path, 2);
  const document = await founded(founder, path, 'before crash');
  for (const beforeAcceptance of [undefined, 'persist']) {
    await assert.rejects(
      document.createInvitation({
        role: 'editor',
        rendezvous: [founder.circuit],
        beforeAcceptance,
      }),
      TypeError,
    );
  }
  let accepted = false;
  let saved;
  const offer = await document.createInvitation({
    role: 'editor',
    rendezvous: [founder.circuit],
    beforeAcceptance: async () => {
      assert.equal(accepted, false);
      assert.equal(
        await document._readers.check(member.identity.publicKey),
        true,
      );
      saved = await document.exportCheckpoint();
    },
  });
  const joined = await member.swarm.acceptInvitation(offer, member.kem);
  accepted = true;
  await until('member state', () => joined.document?.body === 'before crash');

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

  const replacement = await join();
  const shared = await replacement.swarm.acceptInvitation(
    await restored.createInvitation({
      role: 'reader',
      rendezvous: [restarted.circuit],
      beforeAcceptance: unstored,
    }),
    replacement.kem,
  );
  await until(
    're-shared state',
    () => shared.document?.body === 'after revocation',
  );
  assert.equal(await holdsKey(shared, epoch), true);
  await restored.change((draft) => {
    draft.body = 'shared again';
  });
  await until(
    'replacement edit',
    () => shared.document.body === 'shared again',
  );
  await delay(1000);
  assert.equal(joined.document.body, 'before crash');
});

test('an exact retry completes a committed membership inside the last 30 seconds', async (t) => {
  const path = `/reshare/late-retry-${crypto.randomUUID()}`;
  const [founder, member] = await network(t, path, 2);
  const document = await founded(founder, path, 'late');
  let attempts = 0;
  const offer = await document.createInvitation({
    role: 'editor',
    rendezvous: [founder.circuit],
    expiresInMs: 60_000,
    beforeAcceptance: async () => {
      attempts++;
      if (attempts > 1) return;
      leaveRemaining(offer, 6_000);
      throw new Error('storage unavailable');
    },
  });

  await assert.rejects(
    member.swarm.acceptInvitation(offer, member.kem),
    /Unable to accept invitation/,
  );
  assert.equal(member.swarm._documentRegistry.has(path), false);
  assert.equal(await document._writers.check(member.identity.publicKey), true);
  assert.ok(offer.expiresAtMs - Date.now() < 30_000);

  const joined = await member.swarm.acceptInvitation(offer, member.kem);
  await until('late member state', () => joined.document?.body === 'late');
  assert.equal(attempts, 2);

  await delay(7_000);
  assert.ok(Date.now() > offer.expiresAtMs);
  assert.equal(await document._writers.check(member.identity.publicKey), true);
  await document.change((draft) => {
    draft.body = 'after expiry';
  });
  await until(
    'member after expiry',
    () => joined.document.body === 'after expiry',
  );
});

test('an acceptance that is never produced is revoked when its offer expires', async (t) => {
  const path = `/reshare/unsent-${crypto.randomUUID()}`;
  const [founder, member] = await network(t, path, 2);
  const document = await founded(founder, path, 'unsent');
  const offer = await document.createInvitation({
    role: 'editor',
    rendezvous: [founder.circuit],
    expiresInMs: 60_000,
    beforeAcceptance: async () => {
      leaveRemaining(offer, 2_000);
      throw new Error('storage unavailable');
    },
  });

  await assert.rejects(
    member.swarm.acceptInvitation(offer, member.kem),
    /Unable to accept invitation/,
  );
  assert.equal(await document._readers.check(member.identity.publicKey), true);
  await assert.rejects(
    document.createInvitation({
      role: 'reader',
      rendezvous: [founder.circuit],
      beforeAcceptance: unstored,
    }),
    /requires exactly one founder writer/,
  );
  const [unsentEpoch] = await document._keychain.current();

  await until(
    'unsent membership revocation',
    async () =>
      (await document._readers.check(member.identity.publicKey)) !== true &&
      document._beekem.hasOnlyLocalLiveLeaf(),
    10_000,
  );
  assert.notEqual(
    hex((await document._keychain.current())[0]),
    hex(unsentEpoch),
  );

  const joined = await member.swarm.acceptInvitation(
    await document.createInvitation({
      role: 'reader',
      rendezvous: [founder.circuit],
      beforeAcceptance: unstored,
    }),
    member.kem,
  );
  await until(
    're-invited member state',
    () => joined.document?.body === 'unsent',
  );
});

test('a removal that races the acceptance withholds it from the claimant', async (t) => {
  const path = `/reshare/race-${crypto.randomUUID()}`;
  const [founder, member] = await network(t, path, 2);
  const document = await founded(founder, path, 'raced');
  const guard = member.swarm._recipientInvitationReplayGuard;
  const observeAcceptance = guard.observeAcceptance.bind(guard);
  let received = 0;
  guard.observeAcceptance = (...args) => {
    received++;
    return observeAcceptance(...args);
  };
  const remove = async () => {
    await document.removeWriter(member.identity.publicKey);
    await document.removeReader(member.identity.publicKey);
  };
  const process = founder.swarm._processInvitationJoin.bind(founder.swarm);
  const outcomes = [];
  let raceWriting = false;
  founder.swarm._processInvitationJoin = async (...args) => {
    let acceptance;
    try {
      acceptance = await process(...args);
    } catch (error) {
      outcomes.push('withheld');
      throw error;
    }
    outcomes.push('produced');
    if (raceWriting) {
      raceWriting = false;
      await remove();
    }
    return acceptance;
  };

  const signer = founder.swarm._invitationSignatureProvider.bind(founder.swarm);
  let raceSigning = false;
  founder.swarm._invitationSignatureProvider = () => {
    const provider = signer();
    return {
      ...provider,
      sign: async (data, key) => {
        if (raceSigning) {
          raceSigning = false;
          await remove();
        }
        return provider.sign(data, key);
      },
    };
  };
  const signingOffer = await document.createInvitation({
    role: 'editor',
    rendezvous: [founder.circuit],
    beforeAcceptance: unstored,
  });
  raceSigning = true;
  await assert.rejects(
    member.swarm.acceptInvitation(signingOffer, member.kem),
    /Unable to accept invitation/,
  );
  assert.equal(raceSigning, false);
  assert.deepEqual(outcomes, ['withheld']);
  assert.equal(received, 0);
  assert.equal(document._beekem.hasOnlyLocalLiveLeaf(), true);

  const writingOffer = await document.createInvitation({
    role: 'editor',
    rendezvous: [founder.circuit],
    beforeAcceptance: unstored,
  });
  raceWriting = true;
  await assert.rejects(
    member.swarm.acceptInvitation(writingOffer, member.kem),
    /Unable to accept invitation/,
  );
  assert.equal(raceWriting, false);
  assert.deepEqual(outcomes, ['withheld', 'produced']);
  assert.equal(received, 0);
  assert.equal(member.swarm._documentRegistry.has(path), false);
  assert.equal(await document._readers.check(member.identity.publicKey), false);
  assert.equal(document._beekem.hasOnlyLocalLiveLeaf(), true);
});
