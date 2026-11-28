import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import {
  circuitRelayServer,
  circuitRelayTransport,
} from '@libp2p/circuit-relay-v2';
import {
  gossipsub,
  TopicValidatorResult,
  type GossipSub,
  type GossipSubEvents,
} from '@libp2p/gossipsub';
import { identify } from '@libp2p/identify';
import { webSockets } from '@libp2p/websockets';
import {
  DEFAULT_DOCUMENT_TOPIC_PREFIX,
  DocumentReplayJournal,
  GroupSecurityCoordinatorError,
  InMemoryDocumentJournalRollbackAnchor,
  InMemoryDocumentJournalStore,
  Peerborne,
} from '@peerborne/core';
import {
  AutomergeACLProvider,
  AutomergeJSONSerializer,
  AutomergeKeychainProvider,
  AutomergeProvider,
} from '@peerborne/automerge';
import { MemoryBlockstore } from 'blockstore-core/memory';
import { MemoryDatastore } from 'datastore-core/memory';
import { createLibp2p } from 'libp2p';
import {
  isDocumentCatchUpCheckpointFrame,
  isDocumentCatchUpRequestFrame,
} from '../../packages/core/src/document-catch-up-wire.js';
import { decodeEncryptedDocumentContent } from '../../packages/core/src/document-security-wire.js';
import { collect, setupCoordinatedDocument } from './coordinated-fixture.js';

const path = '/native-real-gossipsub-coordinated-document';
const loopback = '/ip4/127.0.0.1/tcp/';
const listen = `${loopback}0/ws`;
const timeout = 20_000;
type Document = Record<string, number>;

function isLoopback(address: { toString(): string }) {
  return address.toString().startsWith(loopback);
}

async function until<T>(description: string, read: () => T | undefined) {
  const deadline = performance.now() + timeout;
  for (;;) {
    const value = read();
    if (value) return value;
    if (performance.now() >= deadline)
      throw new Error(`Timed out waiting for ${description}`);
    await delay(25);
  }
}

async function waitForSubscription(
  pubsub: GossipSub,
  topic: string,
  peerId: string,
) {
  await until('the connected peer to subscribe', () =>
    pubsub.getSubscribers(topic).some((peer) => peer.toString() === peerId),
  );
}

function receivedPublication(
  pubsub: GossipSub,
  topic: string,
  sender: string,
  predicate: (data: Uint8Array) => boolean,
) {
  let received: Uint8Array | undefined;
  const read = ({ detail }: GossipSubEvents['message']) => {
    if (
      detail.type === 'signed' &&
      detail.topic === topic &&
      detail.from.toString() === sender &&
      !received &&
      predicate(detail.data)
    ) {
      received = detail.data.slice();
    }
  };
  pubsub.addEventListener('message', read);
  return {
    read: () => received,
    close: () => pubsub.removeEventListener('message', read),
  };
}

export async function runNetworkDocumentChecks() {
  const f = await setupCoordinatedDocument(path, [2, 2]);
  const journalStores = f.members.map(() => new InMemoryDocumentJournalStore());
  const journalAnchors = f.members.map(
    () => new InMemoryDocumentJournalRollbackAnchor(),
  );
  const journalKeys = await Promise.all(
    f.members.map(() =>
      crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
        'encrypt',
        'decrypt',
      ]),
    ),
  );
  const journal = (index: number) =>
    new DocumentReplayJournal(
      path,
      f.logs[index].genesisId,
      journalKeys[index],
      journalStores[index],
      journalAnchors[index],
    );
  const stops = new Set<() => void | Promise<void>>();
  async function start(index: number, listenAddresses = [listen]) {
    const serializer = new AutomergeJSONSerializer();
    const swarm = new Peerborne(
      f.signing[index].privateKey,
      f.signing[index].publicKey,
      new AutomergeProvider<Document>(),
      serializer,
      serializer,
      serializer,
      f.auth,
      new AutomergeACLProvider(),
      new AutomergeKeychainProvider(),
    );
    await swarm.initialize({
      pubsubDocumentPrefix: DEFAULT_DOCUMENT_TOPIC_PREFIX,
      helia: {
        blockstore: new MemoryBlockstore(),
        datastore: new MemoryDatastore(),
        libp2p: {
          addresses: { listen: listenAddresses },
          transports: [
            webSockets(),
            circuitRelayTransport({ reservationConcurrency: 1 }),
          ],
          connectionEncrypters: [noise()],
          streamMuxers: [yamux()],
          connectionGater: {
            denyDialMultiaddr: async (address) => !isLoopback(address),
          },
          services: {
            identify: identify(),
            pubsub: gossipsub({
              allowPublishToZeroTopicPeers: true,
              emitSelf: false,
              floodPublish: true,
              globalSignaturePolicy: 'StrictSign',
              runOnLimitedConnection: true,
              scoreParams: {
                IPColocationFactorWhitelist: new Set(['127.0.0.1']),
              },
            }),
          },
        },
      },
    });
    const doc = swarm.doc(path, {
      security: {
        coordinator: f.coordinators[index],
        authority: f.logs[index],
        requireGroupRosterMatch: true,
        enableAuthenticatedCatchUp: true,
        journal: journal(index),
      },
    });
    const stop = async () => {
      try {
        await doc.close();
      } finally {
        await swarm.heliaNode.stop();
        stops.delete(stop);
      }
    };
    stops.add(stop);
    const libp2p = swarm.heliaNode.libp2p;
    return {
      swarm,
      doc,
      libp2p,
      pubsub: libp2p.services.pubsub,
      stop,
      peerId: libp2p.peerId.toString(),
    };
  }

  const retainedAuthority = async (index: number) => {
    const record = (await journal(index).restore()).findLast(
      (entry) => entry.authorityRecords.length > 0,
    );
    assert.ok(record, 'the member durably accepted the signed role history');
    return record.authorityRecords;
  };
  const observe = (
    peer: Awaited<ReturnType<typeof start>>,
    topic: string,
    source: Awaited<ReturnType<typeof start>>,
    predicate: (data: Uint8Array) => boolean,
  ) => {
    const publication = receivedPublication(
      peer.pubsub,
      topic,
      source.peerId,
      predicate,
    );
    stops.add(publication.close);
    return publication.read;
  };

  try {
    const relay = await createLibp2p({
      addresses: { listen: [listen] },
      transports: [webSockets()],
      connectionEncrypters: [noise()],
      streamMuxers: [yamux()],
      connectionGater: {
        denyDialMultiaddr: async (address) => !isLoopback(address),
      },
      services: { identify: identify(), relay: circuitRelayServer() },
    });
    stops.add(() => relay.stop());
    const relayAddress = relay.getMultiaddrs().map(String).find(isLoopback);
    assert.ok(relayAddress, 'relay must listen on the owned loopback');
    const controller = f.coordinators[0];
    const source = await start(0, [listen, '/p2p-circuit']);
    const sourceAddress = source.libp2p
      .getMultiaddrs()
      .map(String)
      .find(isLoopback);
    assert.ok(sourceAddress, 'controller must listen on owned loopback');
    await source.swarm.connect([relayAddress], {
      signal: AbortSignal.timeout(timeout),
    });
    const circuit = await until(
      'the controller’s owned relay reservation',
      () =>
        source.libp2p
          .getMultiaddrs()
          .map(String)
          .find(
            (address) =>
              address === `${relayAddress}/p2p-circuit/p2p/${source.peerId}`,
          ),
    );
    const survivor = await start(1);
    const revoked = await start(2);
    await source.doc.create();
    await Promise.all([survivor.doc.open(), revoked.doc.open()]);
    const [topic] = source.pubsub.getTopics();
    assert.ok(
      topic && source.pubsub.getTopics().length === 1 && !topic.includes(path),
    );

    async function connectToController(peer: typeof source, address: string) {
      await peer.swarm.connect([address], {
        signal: AbortSignal.timeout(timeout),
      });
      await Promise.all([
        waitForSubscription(source.pubsub, topic, peer.peerId),
        waitForSubscription(peer.pubsub, topic, source.peerId),
      ]);
    }

    await Promise.all([
      connectToController(survivor, sourceAddress),
      connectToController(revoked, sourceAddress),
    ]);
    await source.doc.change((draft) => {
      draft.common = 1;
    });
    await until(
      'the first edit on both authorized peers',
      () =>
        survivor.doc.document.common === 1 && revoked.doc.document.common === 1,
    );
    await revoked.doc.change((draft) => {
      draft.acceptedBeforeRemoval = 2;
    });
    await until(
      'the future revoked writer’s edit at the controller and survivor',
      () =>
        source.doc.document.acceptedBeforeRemoval === 2 &&
        survivor.doc.document.acceptedBeforeRemoval === 2,
    );
    await survivor.doc.change((draft) => {
      draft.retainedLocal = 6;
    });
    await until(
      'the survivor’s accepted edit at the controller',
      () => source.doc.document.retainedLocal === 6,
    );

    const [survivorRoles, revokedRoles] = await Promise.all([
      retainedAuthority(1),
      retainedAuthority(2),
    ]);
    await survivor.stop();

    await controller.createCommit(
      { changes: [{ kind: 'remove', memberId: f.members[2] }] },
      {
        operationId: crypto.getRandomValues(new Uint8Array(32)),
        requestDigest: crypto.getRandomValues(new Uint8Array(32)),
        action: 'remove',
        subjectId: f.members[2],
      },
    );
    const removal = await collect(controller);
    assert.ok(removal.commit);
    const commit = removal.commit;
    await f.coordinators[1].applyCommit(commit, removal.controlRecord, []);
    const currentRoles = await f.logs[0].signUpdate(
      controller.documentContext,
      f.roster.slice(0, 2),
      f.signing[0].privateKey,
    );
    await source.doc.applySecurityAuthorityUpdate(currentRoles);

    const receivedAtRevoked = observe(revoked, topic, source, (data) => {
      try {
        decodeEncryptedDocumentContent(data);
        return true;
      } catch {
        return false;
      }
    });
    await source.doc.change((draft) => {
      draft.missed = 3;
    });
    const currentFrame = await until(
      'the controller’s next-epoch publication at the old member',
      receivedAtRevoked,
    );
    await assert.rejects(() => revoked.doc.receiveSecurityFrame(currentFrame), {
      message: 'Document epoch is unavailable',
    });
    assert.equal(revoked.doc.document.missed, undefined);

    const appliedRemoval = await f.coordinators[2].applyCommit(
      commit,
      removal.controlRecord,
      [],
    );
    assert.equal(appliedRemoval.status, 'removed');
    await assert.rejects(() => revoked.doc.createSecurityCatchUpRequest());
    await assert.rejects(
      () =>
        revoked.doc.change(() =>
          assert.fail('a removed writer ran its mutation'),
        ),
      /remov/i,
    );
    assert.throws(() => revoked.doc.document, /remov/i);
    await revoked.stop();
    await assert.rejects(
      () => f.restoreReplica(2, revokedRoles),
      (error) =>
        error instanceof GroupSecurityCoordinatorError &&
        error.code === 'removed-from-group',
    );

    const restored = await f.restoreReplica(1, survivorRoles);
    f.coordinators[1] = restored.coordinator;
    f.logs[1] = restored.authority;
    const returning = await start(1, []);
    assert.notEqual(returning.peerId, survivor.peerId);
    await returning.doc.applySecurityAuthorityUpdateBeforeOpen(currentRoles);
    await returning.doc.open();
    assert.equal(returning.doc.document.common, 1);
    assert.equal(returning.doc.document.acceptedBeforeRemoval, 2);
    assert.equal(returning.doc.document.retainedLocal, 6);
    assert.equal(returning.doc.document.missed, undefined);

    const receivedRequest = observe(
      source,
      topic,
      returning,
      isDocumentCatchUpRequestFrame,
    );
    const receivedCheckpoint = observe(
      returning,
      topic,
      source,
      isDocumentCatchUpCheckpointFrame,
    );
    // A cached network redelivery must not satisfy the checkpoint assertion.
    const isOriginalFrame = (data: Uint8Array) =>
      data.length === currentFrame.length &&
      data.every((byte, index) => byte === currentFrame[index]);
    returning.pubsub.topicValidators.set(topic, (_, message) =>
      isOriginalFrame(message.data)
        ? TopicValidatorResult.Ignore
        : TopicValidatorResult.Accept,
    );
    const receivedOriginalFrame = observe(
      returning,
      topic,
      source,
      isOriginalFrame,
    );
    const reconnectStarted = performance.now();
    await connectToController(returning, circuit);
    const reconnectMs = Math.round(performance.now() - reconnectStarted);
    assert.ok(
      reconnectMs <= timeout,
      'relayed reconnect completed within the bound',
    );
    const catchUpStarted = performance.now();
    await returning.doc.requestSecurityCatchUp();
    await until('a signed survivor request over GossipSub', receivedRequest);
    await until(
      'a signed controller checkpoint over GossipSub',
      receivedCheckpoint,
    );
    await until(
      'the skipped edit after authenticated catch-up',
      () => returning.doc.document.missed === 3,
    );
    const catchUpMs = Math.round(performance.now() - catchUpStarted);
    assert.ok(
      catchUpMs <= timeout,
      'checkpoint recovery completed within the bound',
    );
    assert.ok(
      !receivedOriginalFrame(),
      'the checkpoint recovered the skipped edit without its original publication',
    );
    assert.equal(returning.doc.document.acceptedBeforeRemoval, 2);
    assert.equal(returning.doc.document.retainedLocal, 6);
    await source.doc.change((draft) => {
      draft.afterRecovery = 4;
    });
    await until(
      'the next live controller edit',
      () => returning.doc.document.afterRecovery === 4,
    );
    await returning.doc.change((draft) => {
      draft.returnedWriter = 5;
    });
    await until(
      'the returned writer’s live edit at the controller',
      () => source.doc.document.returnedWriter === 5,
    );
    const connections = returning.libp2p.getConnections(source.libp2p.peerId);
    assert.ok(
      connections.length === 1 &&
        connections[0].remoteAddr.toString() === circuit,
      'the returning member exchanged content only with the relayed controller',
    );
    await returning.stop();
    const current = await f.restoreReplica(1, await retainedAuthority(1));
    f.coordinators[1] = current.coordinator;
    f.logs[1] = current.authority;
    const recovered = await start(1);
    await recovered.doc.open();
    assert.equal(recovered.doc.document.acceptedBeforeRemoval, 2);
    assert.equal(recovered.doc.document.retainedLocal, 6);
    assert.equal(recovered.doc.document.missed, 3);
    assert.equal(recovered.doc.document.afterRecovery, 4);
    assert.equal(recovered.doc.document.returnedWriter, 5);

    return {
      transport:
        'GossipSub over loopback WebSockets with Noise, Yamux and Circuit Relay v2',
      applicationIdentities: 3,
      applicationDeliveredSignedControlAndRoles: true,
      revokedMemberReceivedButCouldNotApplyCurrentCiphertext: true,
      removalSurvivesReferenceStoreReconstruction: true,
      authorizedMemberCaughtUpOverGossipSubAfterReconstruction: true,
      catchUpPreservedPriorLocalEdit: true,
      returningMemberConnectedToControllerOnlyThroughRelay: true,
      observedReconnectMs: reconnectMs,
      observedCatchUpMs: catchUpMs,
      bidirectionalLiveEditsAfterCatchUp: true,
      recoveredContentSurvivesReferenceStoreReconstruction: true,
    };
  } finally {
    await Promise.all(Array.from(stops, (stop) => stop()));
  }
}
