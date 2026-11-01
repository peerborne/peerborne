import {
  Peerborne,
  GroupSecurityCoordinator,
  InMemoryGroupStateStore,
  InMemoryGroupSecurityRollbackAnchor,
  WebCryptoGroupStateProtector,
  createGroupSecurityDurableAcceptance,
  DocumentAuthorityLog,
  DocumentGroupControlAuthority,
  DocumentReplayJournal,
  InMemoryDocumentJournalStore,
  IndexedDBDocumentJournalStore,
  InMemoryDocumentJournalRollbackAnchor,
  type AuthProvider,
  type GroupSecurityDelivery,
  type GroupSecurityCoordinatorConfig,
} from '@peerborne/core';
import {
  AutomergeProvider,
  AutomergeJSONSerializer,
} from '@peerborne/automerge';
import { YjsProvider, YjsJSONSerializer } from '@peerborne/yjs';
import { MlsProviderSpike } from './provider.js';
import { JsonTestCodec } from '../../packages/core/src/__testutils__/group-security-coordinator.js';

const encoder = new TextEncoder();
const equal = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((value, index) => value === b[index]);
const hex = (value: Uint8Array) =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
const random = () => crypto.getRandomValues(new Uint8Array(32));
function check(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}
async function rejects(action: () => Promise<unknown>) {
  let rejected = false;
  try {
    await action();
  } catch {
    rejected = true;
  }
  check(rejected, 'expected document boundary rejection');
}

async function collect(coordinator: GroupSecurityCoordinator) {
  const values: GroupSecurityDelivery[] = [];
  await coordinator.flushOutbox(async (value) => {
    values.push(value);
    return createGroupSecurityDurableAcceptance(value);
  });
  check(values.length === 1, 'one membership delivery');
  return values[0];
}

async function setup(documentId: string) {
  const members = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)],
    groupId = random(),
    credential = encoder.encode('document integration fixture');
  const pinned = new Map<string, Uint8Array>();
  const policy = async (binding: {
    memberId: Uint8Array;
    signingKey: Uint8Array;
    credential: Uint8Array;
  }) =>
    equal(
      pinned.get(hex(binding.memberId)) ?? new Uint8Array(),
      binding.signingKey,
    ) && equal(binding.credential, credential);
  const engines = await Promise.all(
    members.map((member) =>
      MlsProviderSpike.initialize(member, members[0], policy),
    ),
  );
  engines.forEach((engine, index) =>
    pinned.set(hex(members[index]), engine.credentialSigningKey),
  );
  const signing = await Promise.all(
    members.map(() =>
      crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']),
    ),
  );
  const publicKeys = await Promise.all(
    signing.map((pair) =>
      crypto.subtle
        .exportKey('raw', pair.publicKey)
        .then((bytes) => hex(new Uint8Array(bytes))),
    ),
  );
  const controls = engines.map(
    (engine) =>
      new DocumentGroupControlAuthority(engine.protocol, groupId, members[0]),
  );
  const stores = members.map(() => new InMemoryGroupStateStore()),
    anchors = members.map(() => new InMemoryGroupSecurityRollbackAnchor());
  const protectors = await Promise.all(
    members.map((_, index) =>
      WebCryptoGroupStateProtector.generate(`document-fixture-${index}`),
    ),
  );
  const auth: AuthProvider<CryptoKey, CryptoKey, string> = {
    nonceBytes: 12,
    sign: async (bytes, key) =>
      new Uint8Array(
        await crypto.subtle.sign('Ed25519', key, bytes as BufferSource),
      ),
    verify: async (bytes, key, signature) =>
      crypto.subtle.verify(
        'Ed25519',
        key,
        signature as BufferSource,
        bytes as BufferSource,
      ),
    serializePublicKey: async (key) =>
      hex(new Uint8Array(await crypto.subtle.exportKey('raw', key))),
    deserializePublicKey: async (value) => {
      if (!/^[0-9a-f]{64}$/.test(value))
        throw new Error('Malformed fixture public key');
      return crypto.subtle.importKey(
        'raw',
        Uint8Array.from(value.match(/../g)!, (byte) => parseInt(byte, 16)),
        'Ed25519',
        true,
        ['verify'],
      );
    },
    encrypt: async () => {
      throw new Error('Legacy encryption was invoked');
    },
    decrypt: async () => {
      throw new Error('Legacy decryption was invoked');
    },
  };
  const configuration = (index: number): GroupSecurityCoordinatorConfig => ({
    provider: engines[index],
    store: stores[index],
    storeKey: { protocol: engines[index].protocol, groupId },
    rollbackAnchor: anchors[index],
    protector: protectors[index],
    actorId: members[index],
    signControlRecord: async (bytes) =>
      auth.sign(bytes, signing[index].privateKey),
    verifyControlSignature: async (bytes, signature, actor) => {
      const index = members.findIndex((member) => equal(member, actor));
      return (
        index >= 0 && auth.verify(bytes, signing[index].publicKey, signature)
      );
    },
    authorizeControl: controls[index].authorize,
    outboxCodec: new JsonTestCodec(),
  });
  const controller = await GroupSecurityCoordinator.bootstrap(
    configuration(0),
    { groupId, creatorMemberId: members[0], credential },
    { operationId: random(), subjectId: members[0] },
  );
  const genesis = await collect(controller);
  const initialMembers = [
    { memberId: members[0], publicKey: publicKeys[0], role: 3 as const },
  ];
  const log = await DocumentAuthorityLog.create(
    documentId,
    controller.documentContext,
    initialMembers,
    signing[0].privateKey,
    auth,
    controls[0],
  );
  const packageValue = await GroupSecurityCoordinator.createPendingKeyPackage(
    configuration(1),
    { operationId: random(), groupId, memberId: members[1], credential },
  );
  await controller.createCommit(
    {
      changes: [
        { kind: 'add', memberId: members[1], keyPackage: packageValue },
      ],
    },
    {
      operationId: random(),
      requestDigest: random(),
      action: 'add',
      subjectId: members[1],
    },
  );
  const addition = await collect(controller);
  const roster = [
    ...initialMembers,
    { memberId: members[1], publicKey: publicKeys[1], role: 2 as const },
  ];
  await log.applyUpdate(
    controller,
    await log.signUpdate(
      controller.documentContext,
      roster,
      signing[0].privateKey,
    ),
  );
  const recipientLog = await DocumentAuthorityLog.restore(
    log.exportRecords(),
    log.genesisId,
    auth,
    controls[1],
  );
  await engines[1].clearKeyPackageState(packageValue.reference);
  const recipient = await GroupSecurityCoordinator.joinFromInvitation(
    configuration(1),
    {
      subjectId: members[1],
      keyPackageRef: packageValue.reference,
      controlPrefix: [genesis.controlRecord, addition.controlRecord],
      commit: addition.commit!,
      welcome: addition.welcomes[0],
    },
  );
  return {
    coordinators: [controller, recipient],
    logs: [log, recipientLog],
    members,
    signing,
    auth,
    roster,
  };
}

export async function runProductionDocumentChecks() {
  const results: Record<string, unknown> = {};
  for (const backend of ['automerge', 'yjs'] as const) {
    const path = `/native-${backend}-private-document`,
      f = await setup(path);
    const exportRecords = f.logs[0].exportRecords.bind(f.logs[0]);
    let authorityExports = 0;
    f.logs[0].exportRecords = () => {
      authorityExports++;
      return exportRecords();
    };
    const provider: any =
      backend === 'automerge' ? new AutomergeProvider() : new YjsProvider();
    const serializer: any =
      backend === 'automerge'
        ? new AutomergeJSONSerializer()
        : new YjsJSONSerializer();
    const journalStores = [0, 1].map((index) =>
      typeof indexedDB === 'undefined'
        ? new InMemoryDocumentJournalStore()
        : new IndexedDBDocumentJournalStore(
            `native-document-${backend}-${index}-${hex(random())}`,
          ),
    );
    const journalAnchors = [0, 1].map(
      () => new InMemoryDocumentJournalRollbackAnchor(),
    );
    const keys = await Promise.all(
      [0, 1].map(() =>
        crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
          'encrypt',
          'decrypt',
        ]),
      ),
    );
    const publications: { sender: number; topic: string; data: Uint8Array }[] =
      [];
    const noLegacy = { initialize: () => ({}) } as any;
    const swarms = [0, 1].map((index) => {
      const pubsub = new EventTarget() as any;
      pubsub.subscribe = () => {};
      pubsub.unsubscribe = () => {};
      pubsub.publish = async (topic: string, data: Uint8Array) => {
        publications.push({ sender: index, topic, data: data.slice() });
      };
      const swarm = new Peerborne<any, any, any, CryptoKey, CryptoKey, string>(
        f.signing[index].privateKey,
        f.signing[index].publicKey,
        provider,
        serializer,
        serializer,
        serializer,
        f.auth,
        noLegacy,
        noLegacy,
      );
      Object.assign(swarm, {
        _heliaNode: { libp2p: { services: { pubsub } } },
        _config: { enableSigning: false },
      });
      return swarm;
    });
    const makeDocument = (index: number) =>
      swarms[index].doc(path, {
        security: {
          coordinator: f.coordinators[index],
          authority: f.logs[index],
          journal: new DocumentReplayJournal(
            path,
            f.logs[index].genesisId,
            keys[index],
            journalStores[index],
            journalAnchors[index],
          ),
        },
      });
    const docs = [makeDocument(0), makeDocument(1)];
    await docs[0].create();
    await docs[1].open();
    const change = (field: string, value: number) =>
      backend === 'automerge'
        ? (doc: any) => {
            doc[field] = value;
          }
        : (doc: any) => {
            doc.getMap('values').set(field, value);
          };
    const read = (doc: any) =>
      backend === 'automerge'
        ? { ...doc.document }
        : doc.document.getMap('values').toJSON();
    await docs[0].change(change('a', 1));
    await docs[1].change(change('b', 2));
    const first = publications.splice(0);
    for (const publication of first) {
      check(!publication.topic.includes(path), 'opaque group topic');
      const event = new Event('message') as any;
      event.detail = { topic: publication.topic, data: publication.data };
      (
        swarms[1 - publication.sender].heliaNode.libp2p.services.pubsub as any
      ).dispatchEvent(event);
    }
    // Queue a replay behind the event callback to await the same real receive path.
    for (const publication of first)
      await docs[1 - publication.sender].receiveSecurityFrame(publication.data);
    check(
      read(docs[0]).a === 1 &&
        read(docs[0]).b === 2 &&
        read(docs[1]).a === 1 &&
        read(docs[1]).b === 2,
      'concurrent real CRDT convergence through PeerborneDocument',
    );
    const damaged = first[0].data.slice();
    damaged[damaged.length - 1] ^= 1;
    await rejects(() => docs[1].receiveSecurityFrame(damaged));
    await rejects(() => docs[0].load());
    await rejects(() => docs[0].addWriter(f.signing[1].publicKey));
    check(
      (await docs[0].sync({ documentId: path } as any)) === false,
      'legacy sync is rejected',
    );
    docs[0].startChange();
    docs[0].addChange(change('c', 3));
    docs[0].addChange(change('d', 4));
    await docs[0].endChange();
    const batch = publications.splice(0);
    check(batch.length === 1, 'one authenticated transaction frame');
    await docs[1].receiveSecurityFrame(batch[0].data);
    // Exercise two actual native snapshots plus bounded WAL pruning.
    for (let index = 0; index < 130; index++) {
      await docs[0].change(change('counter', index));
      const publication = publications.shift()!;
      await docs[1].receiveSecurityFrame(publication.data);
    }
    check(authorityExports <= 3, 'routine deltas do not copy the role history');
    await docs[1].close();
    const restoredJournal = await new DocumentReplayJournal(
      path,
      f.logs[1].genesisId,
      keys[1],
      journalStores[1],
      journalAnchors[1],
    ).restore();
    const retainedHistory = restoredJournal.findLast(
      (item) => item.authorityRecords.length > 0,
    );
    check(
      retainedHistory?.authorityRecords.length ===
        f.logs[1].exportRecords().length,
      'checkpoint retains the complete signed role history',
    );
    docs[1] = makeDocument(1);
    await docs[1].open();
    check(
      read(docs[1]).counter === 129 && read(docs[1]).a === 1,
      'native checkpoint restart',
    );
    check(
      !(await docs[1].receiveSecurityFrame(first[0].data)),
      'durable native replay floor',
    );
    const stage = journalStores[0].stage.bind(journalStores[0]);
    let entered!: () => void, release!: () => void;
    const staged = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    journalStores[0].stage = async (...args) => {
      await stage(...args);
      entered();
      await blocked;
    };
    const liveMutation = docs[0].change(change('duplicateSurvives', 5));
    await staged;
    const beforeDuplicate = await journalStores[0].load(
      hex(f.logs[0].genesisId),
    );
    const duplicate = makeDocument(0);
    await rejects(() => duplicate.receiveSecurityFrame(first[0].data));
    await rejects(() => duplicate.applySecurityAuthorityUpdate(new Uint8Array([1])));
    await rejects(() => duplicate.open());
    const afterDuplicate = await journalStores[0].load(
      hex(f.logs[0].genesisId),
    );
    check(
      !!beforeDuplicate.pending &&
        !!afterDuplicate.pending &&
        equal(beforeDuplicate.pending.token, afterDuplicate.pending.token),
      'duplicate activation cannot alter a live pending journal',
    );
    release();
    await liveMutation;
    journalStores[0].stage = stage;
    const livePublication = publications.splice(0);
    check(
      livePublication.length === 1,
      'live owner survives duplicate activation',
    );
    await docs[1].receiveSecurityFrame(livePublication[0].data);
    check(
      read(docs[1]).duplicateSurvives === 5,
      'live mutation remains deliverable',
    );
    const pubsub = swarms[0].heliaNode.libp2p.services.pubsub as any;
    const publish = pubsub.publish;
    pubsub.publish = async () => {
      throw new Error('Injected publication failure');
    };
    let callbackCalls = 0;
    await rejects(() =>
      docs[0].change((doc: any) => {
        callbackCalls++;
        change('retry', 7)(doc);
      }),
    );
    check(
      read(docs[0]).retry === 7,
      'publication failure is an accepted local mutation',
    );
    await docs[0].close();
    docs[0] = makeDocument(0);
    pubsub.publish = publish;
    await docs[0].open();
    await docs[0].retrySecurityPublications();
    const retried = publications.splice(0);
    check(
      retried.length === 1 && callbackCalls === 1,
      'durable retry preserves exact frame without rerunning callback',
    );
    await docs[1].receiveSecurityFrame(retried[0].data);
    check(read(docs[1]).retry === 7, 'restarted publication converges');
    await docs[0].close();
    await docs[1].close();
    for (const store of journalStores)
      if (store instanceof IndexedDBDocumentJournalStore) await store.close();
    results[backend] = {
      actualDocumentAPI: true,
      simulatedPubsub: true,
      concurrentConvergence: true,
      batchedChange: true,
      malformedCiphertextRejected: true,
      legacyBypassRejected: true,
      nativeCheckpointAndRestart: true,
      durableReplaySuppression: true,
      durablePublicationRetry: true,
      duplicateActivationIsolated: true,
      roleHistoryCopiedOnlyAtCheckpoints: true,
      indexedDB: typeof indexedDB !== 'undefined',
    };
  }
  return results;
}
