import {
  GroupSecurityCoordinator,
  InMemoryGroupStateStore,
  InMemoryGroupSecurityRollbackAnchor,
  WebCryptoGroupStateProtector,
  createGroupSecurityDurableAcceptance,
  type GroupSecurityCoordinatorConfig,
  type GroupSecurityDelivery,
  type GroupSecurityProvider,
  type MembershipControlSignatureVerifier,
} from '@peerborne/core/browser-primitives';
import { JsonTestCodec } from '../../packages/core/src/__testutils__/group-security-coordinator.js';
import { MlsProviderSpike } from './provider.js';

const encoder = new TextEncoder();
const label = (value: Uint8Array) => Array.from(value).join(',');
const equal = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((value, index) => value === b[index]);
const random = () => crypto.getRandomValues(new Uint8Array(32));
function check(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}

async function rejects(
  operation: () => unknown | Promise<unknown>,
  code?: string,
) {
  try {
    await operation();
  } catch (error) {
    if (code)
      check(
        error instanceof Error && 'code' in error && error.code === code,
        'expected terminal coordinator failure',
      );
    return;
  }
  throw new Error('removed member operation unexpectedly succeeded');
}

function coordinatorProvider(engine: MlsProviderSpike): GroupSecurityProvider {
  return {
    protocol: engine.protocol,
    lifecycleIdentity: engine.lifecycleIdentity,
    hasActiveGroup: () => engine.hasActiveGroup(),
    createKeyPackage: (value) => engine.createKeyPackage(value),
    authenticateKeyPackageMember: (value) =>
      engine.authenticateKeyPackageMember(value),
    authenticateKeyPackageRequestCommitment: (value) =>
      engine.authenticateKeyPackageRequestCommitment(value),
    exportEncryptedKeyPackage: (value, protector) =>
      engine.exportEncryptedKeyPackage(value, protector),
    importEncryptedKeyPackage: (value, protector) =>
      engine.importEncryptedKeyPackage(value, protector),
    clearKeyPackageState: (value) => engine.clearKeyPackageState(value),
    createGroup: (value) => engine.createGroup(value),
    joinGroup: (value) => engine.joinGroup(value),
    createCommit: (value) => engine.createCommit(value),
    applyCommit: (value) => engine.applyCommit(value),
    exportSecret: (value) => engine.exportSecret(value),
    getPublicState: () => engine.getPublicState(),
    exportEncryptedState: (protector) => engine.exportEncryptedState(protector),
    importEncryptedState: (value, protector) =>
      engine.importEncryptedState(value, protector),
    clearGroupState: () => engine.clearGroupState(),
  };
}

async function collect(coordinator: GroupSecurityCoordinator) {
  const deliveries: GroupSecurityDelivery[] = [];
  await coordinator.flushOutbox(async (delivery) => {
    deliveries.push(delivery);
    return createGroupSecurityDurableAcceptance(delivery);
  });
  check(deliveries.length === 1, 'one exact outbox delivery');
  return deliveries[0];
}

export async function runCoordinatorChecks() {
  const groupId = random();
  const members = ['controller', 'recipient'].map((value) =>
    encoder.encode(value),
  );
  const credential = encoder.encode('public coordinator integration fixture');
  const requestDigest = async (
    action: string,
    subject: Uint8Array,
    reference?: Uint8Array,
  ) =>
    new Uint8Array(
      await crypto.subtle.digest(
        'SHA-256',
        encoder.encode(
          JSON.stringify({
            group: label(groupId),
            action,
            subject: label(subject),
            keyPackage: reference && label(reference),
          }),
        ),
      ),
    );
  const trustedMls = new Map<string, Uint8Array>();
  const policy = async (binding: {
    memberId: Uint8Array;
    signingKey: Uint8Array;
    credential: Uint8Array;
  }) => {
    const key = trustedMls.get(label(binding.memberId));
    return (
      key !== undefined &&
      equal(key, binding.signingKey) &&
      equal(binding.credential, credential)
    );
  };
  const engines = await Promise.all(
    members.map((member) =>
      MlsProviderSpike.initialize(member, members[0], policy),
    ),
  );
  engines.forEach((engine, index) =>
    trustedMls.set(label(members[index]), engine.credentialSigningKey),
  );
  const signingKeys = await Promise.all(
    members.map(() =>
      crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']),
    ),
  );
  const verify: MembershipControlSignatureVerifier = async (
    payload,
    signature,
    actor,
  ) => {
    const index = members.findIndex((member) => equal(actor, member));
    return (
      index >= 0 &&
      crypto.subtle.verify(
        'Ed25519',
        signingKeys[index].publicKey,
        signature as BufferSource,
        payload as BufferSource,
      )
    );
  };
  const stores = members.map(() => new InMemoryGroupStateStore());
  const anchors = members.map(() => new InMemoryGroupSecurityRollbackAnchor());
  const protectors = await Promise.all(
    members.map((_, index) =>
      WebCryptoGroupStateProtector.generate(`coordinator-fixture-${index}`),
    ),
  );
  const configuration = (
    engine: MlsProviderSpike,
    index: number,
  ): GroupSecurityCoordinatorConfig => ({
    provider: coordinatorProvider(engine),
    store: stores[index],
    storeKey: { protocol: engine.protocol, groupId },
    rollbackAnchor: anchors[index],
    protector: protectors[index],
    actorId: members[index],
    signControlRecord: async (payload, actor) => {
      check(equal(actor, members[index]), 'sign only the configured actor');
      return new Uint8Array(
        await crypto.subtle.sign(
          'Ed25519',
          signingKeys[index].privateKey,
          payload as BufferSource,
        ),
      );
    },
    verifyControlSignature: verify,
    authorizeControl: async ({ record }) => equal(record.actorId, members[0]),
    outboxCodec: new JsonTestCodec(),
  });

  const original = await GroupSecurityCoordinator.bootstrap(
    configuration(engines[0], 0),
    {
      groupId,
      creatorMemberId: members[0],
      credential,
    },
    { operationId: random(), subjectId: members[0] },
  );
  const genesis = await collect(original);
  const controllerEngine = await MlsProviderSpike.initialize(
    members[0],
    members[0],
    policy,
  );
  const controller = await GroupSecurityCoordinator.restore(
    configuration(controllerEngine, 0),
  );
  check(
    controller.publicState.confirmedTranscriptHash.length === 0,
    'coordinator restores the real genesis transcript',
  );

  const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
    configuration(engines[1], 1),
    {
      operationId: random(),
      groupId,
      memberId: members[1],
      credential,
    },
  );
  await engines[1].clearKeyPackageState(keyPackage.reference);
  await controller.createCommit(
    { changes: [{ kind: 'add', memberId: members[1], keyPackage }] },
    {
      operationId: random(),
      requestDigest: await requestDigest(
        'add',
        members[1],
        keyPackage.reference,
      ),
      action: 'add',
      subjectId: members[1],
    },
  );
  const addition = await collect(controller);
  check(
    addition.commit && addition.welcomes.length === 1,
    'authenticated add delivers one Welcome',
  );
  const recipientEngine = await MlsProviderSpike.initialize(
    members[1],
    members[0],
    policy,
  );
  const recipient = await GroupSecurityCoordinator.joinFromInvitation(
    configuration(recipientEngine, 1),
    {
      subjectId: members[1],
      keyPackageRef: keyPackage.reference,
      controlPrefix: [genesis.controlRecord, addition.controlRecord],
      commit: addition.commit,
      welcome: addition.welcomes[0],
    },
  );
  const exporter = {
    label: 'peerborne/coordinator-self-update-fixture/v1',
    context: groupId,
    length: 32,
  };
  const prior = await controllerEngine.exportSecret(exporter);
  check(
    equal(prior, await recipientEngine.exportSecret(exporter)),
    'joined exporter convergence',
  );

  await controller.createCommit(
    { changes: [] },
    {
      operationId: random(),
      requestDigest: await requestDigest('update', members[0]),
      action: 'update',
      subjectId: members[0],
    },
  );
  const update = await collect(controller);
  check(
    update.commit && update.welcomes.length === 0,
    'self-update delivers no Welcome',
  );
  await recipient.applyCommit(
    update.commit,
    update.controlRecord,
    update.welcomes,
  );
  const next = await controllerEngine.exportSecret(exporter);
  check(
    equal(next, await recipientEngine.exportSecret(exporter)) &&
      !equal(next, prior),
    'coordinator self-update rotates and converges exporters',
  );
  check(
    recipient.publicState.epoch === 2n,
    'self-update advances exactly one epoch',
  );
  const replay = await recipient.applyCommit(
    update.commit,
    update.controlRecord,
    [],
  );
  check(replay.status === 'duplicate', 'self-update replay is idempotent');

  const restoredEngine = await MlsProviderSpike.initialize(
    members[1],
    members[0],
    policy,
  );
  const restored = await GroupSecurityCoordinator.restore(
    configuration(restoredEngine, 1),
  );
  check(
    restored.publicState.epoch === 2n &&
      equal(await restoredEngine.exportSecret(exporter), next),
    'encrypted self-update checkpoint restores through the coordinator',
  );
  await recipientEngine.clearGroupState();
  await controller.createCommit(
    { changes: [{ kind: 'remove', memberId: members[1] }] },
    {
      operationId: random(),
      requestDigest: await requestDigest('remove', members[1]),
      action: 'remove',
      subjectId: members[1],
    },
  );
  const removal = await collect(controller);
  check(
    removal.commit && removal.welcomes.length === 0,
    'removal has no Welcome',
  );
  const removed = await restored.applyCommit(
    removal.commit,
    removal.controlRecord,
    [],
  );
  check(
    removed.status === 'removed' && !(await restoredEngine.hasActiveGroup()),
    'coordinator retires the removed native provider',
  );
  await rejects(() => restoredEngine.exportSecret(exporter));
  await rejects(() => restored.publicState, 'removed-from-group');
  const survivorSecret = await controllerEngine.exportSecret(exporter);
  check(
    !equal(survivorSecret, next),
    'removal changes the surviving epoch exporter',
  );
  survivorSecret.fill(0);

  const restartAfterRemoval = await MlsProviderSpike.initialize(
    members[1],
    members[0],
    policy,
  );
  const restartConfig = configuration(restartAfterRemoval, 1);
  let imports = 0;
  const importState = restartConfig.provider.importEncryptedState.bind(
    restartConfig.provider,
  );
  restartConfig.provider.importEncryptedState = async (state, protector) => {
    imports++;
    return importState(state, protector);
  };
  await rejects(
    () => GroupSecurityCoordinator.restore(restartConfig),
    'removed-from-group',
  );
  check(
    imports === 0,
    'retirement blocks the retained older encrypted checkpoint before import',
  );
  await restartAfterRemoval.clearGroupState();
  prior.fill(0);
  next.fill(0);
  await Promise.all(
    [engines[0], engines[1], controllerEngine].map(
      (engine) => engine.clearGroupState(),
    ),
  );
  return {
    signedGenesisRecovery: true,
    pendingJoinRecovery: true,
    selfUpdate: true,
    exporterRotationAndConvergence: true,
    selfUpdateReplay: true,
    encryptedSelfUpdateRecovery: true,
    terminalRemoval: true,
    removedMemberHasNoNextEpochSecrets: true,
    removalBlocksCheckpointRollback: true,
  };
}
