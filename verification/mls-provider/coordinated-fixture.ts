import {
  GroupSecurityCoordinator,
  InMemoryGroupStateStore,
  InMemoryGroupSecurityRollbackAnchor,
  WebCryptoGroupStateProtector,
  createGroupSecurityDurableAcceptance,
  DocumentAuthorityLog,
  DocumentGroupControlAuthority,
  type AuthProvider,
  type DocumentMemberAuthority,
  type GroupSecurityDelivery,
  type GroupSecurityCoordinatorConfig,
} from '@peerborne/core';
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

export async function collect(coordinator: GroupSecurityCoordinator) {
  const values: GroupSecurityDelivery[] = [];
  await coordinator.flushOutbox(async (value) => {
    values.push(value);
    return createGroupSecurityDurableAcceptance(value);
  });
  check(values.length === 1, 'one membership delivery');
  return values[0];
}

export async function setupCoordinatedDocument(
  documentId: string,
  recipientRoles: readonly (1 | 2)[] = [2],
) {
  const members = Array.from(
      { length: 1 + recipientRoles.length },
      (_, index) => new Uint8Array(32).fill(index + 1),
    ),
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
  const auth: AuthProvider<CryptoKey, CryptoKey, CryptoKey> = {
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
  const roster: DocumentMemberAuthority[] = [
    { memberId: members[0], publicKey: publicKeys[0], role: 3 },
  ];
  const log = await DocumentAuthorityLog.create(
    documentId,
    controller.documentContext,
    roster,
    signing[0].privateKey,
    auth,
    controls[0],
  );
  const coordinators = [controller];
  const logs = [log];
  const controlPrefix = [genesis.controlRecord];
  for (const [offset, role] of recipientRoles.entries()) {
    const index = offset + 1;
    const memberId = members[index];
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      configuration(index),
      { operationId: random(), groupId, memberId, credential },
    );
    await controller.createCommit(
      { changes: [{ kind: 'add', memberId, keyPackage }] },
      {
        operationId: random(),
        requestDigest: random(),
        action: 'add',
        subjectId: memberId,
      },
    );
    const addition = await collect(controller);
    check(addition.commit && addition.welcomes.length === 1, 'one invitation');
    controlPrefix.push(addition.controlRecord);
    roster.push({ memberId, publicKey: publicKeys[index], role });
    const roleUpdate = await log.signUpdate(
      controller.documentContext,
      roster,
      signing[0].privateKey,
    );
    await log.applyUpdate(controller, roleUpdate);
    for (let existing = 1; existing < coordinators.length; existing++) {
      const coordinator = coordinators[existing];
      await coordinator.applyCommit(
        addition.commit,
        addition.controlRecord,
        addition.welcomes,
      );
      await logs[existing].applyUpdate(coordinator, roleUpdate);
    }
    logs.push(
      await DocumentAuthorityLog.restore(
        log.exportRecords(),
        log.genesisId,
        auth,
        controls[index],
      ),
    );
    await engines[index].clearKeyPackageState(keyPackage.reference);
    coordinators.push(
      await GroupSecurityCoordinator.joinFromInvitation(configuration(index), {
        subjectId: memberId,
        keyPackageRef: keyPackage.reference,
        controlPrefix,
        commit: addition.commit,
        welcome: addition.welcomes[0],
      }),
    );
  }
  const pinnedGenesis = log.genesisId;
  const restoreReplica = async (
    index: number,
    authorityRecords: readonly Uint8Array[],
  ) => {
    const config = configuration(index);
    const engine = await MlsProviderSpike.initialize(
      members[index],
      members[0],
      policy,
    );
    const control = new DocumentGroupControlAuthority(
      engine.protocol,
      groupId,
      members[0],
    );
    const authority = await DocumentAuthorityLog.restore(
      authorityRecords,
      pinnedGenesis,
      auth,
      control,
    );
    if (await engines[index].hasActiveGroup())
      await engines[index].clearGroupState();
    const coordinator = await GroupSecurityCoordinator.restore({
      ...config,
      provider: engine,
      authorizeControl: control.authorize,
    });
    engines[index] = engine;
    controls[index] = control;
    return { coordinator, authority };
  };

  return {
    coordinators,
    logs,
    restoreReplica,
    members,
    signing,
    auth,
    roster,
  };
}
