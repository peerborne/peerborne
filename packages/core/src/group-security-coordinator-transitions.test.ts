import { describe, expect, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';
import {
  AppliedGroupMembershipDelta,
  CreateGroupCommitInput,
  CreateGroupInput,
  CreateKeyPackageInput,
  EncryptedKeyPackageState,
  EncryptedGroupState,
  ExportGroupSecretInput,
  GroupKeyPackage,
  GroupSecurityApplyResult,
  GroupSecurityCommit,
  GroupSecurityCommitResult,
  GroupSecurityCreateResult,
  GroupSecurityProvider,
  GroupSecurityPublicState,
  GroupStateProtector,
  GroupWelcome,
  JoinGroupInput,
} from './group-security-provider.js';
import {
  GroupSecurityCoordinator,
  GroupSecurityCoordinatorConfig,
  GroupSecurityDelivery,
  GroupSecurityJoinInvitation,
  GroupSecurityOutboxCodec,
  CreatePendingKeyPackageInput,
  GROUP_SECURITY_OUTBOX_KIND,
  canonicalGroupSecurityCommit,
  canonicalGroupSecurityState,
} from './group-security-coordinator.js';
import {
  DurableGroupStateStore,
  GroupStateStoreKey,
  GroupStateStoreSnapshot,
  GroupStateStoreTransaction,
  InMemoryGroupStateStore,
} from './group-state-store.js';
import {
  DurableGroupSecurityRollbackAnchor,
  GroupSecurityRollbackForkPoison,
  GroupSecurityRollbackAnchorValue,
  InMemoryGroupSecurityRollbackAnchor,
} from './group-security-rollback-anchor.js';
import { createGroupSecurityDurableAcceptance } from './group-security-durable-acceptance.js';
import { groupSecurityStoreSnapshotCommitment } from './group-security-store-commitment.js';
import {
  MembershipControlAuthorizationContext,
  MembershipControlAuthorizer,
  MembershipControlRecord,
  MembershipControlSignatureVerifier,
  MembershipControlSigner,
  UnsignedMembershipControlRecord,
  deserializeMembershipControlRecord,
  membershipControlRecordId,
  serializeMembershipControlRecord,
  signMembershipControlRecord,
} from './membership-control-record.js';
import { WebCryptoGroupStateProtector } from './webcrypto-group-state-protector.js';
import {
  protocol,
  groupId,
  storeKey,
  id,
  publicState,
  deltaFromCommitPayload,
  ContractTestProvider,
  AuthorizationPolicy,
  FailOnceStore,
  TestContext,
  context,
  config,
  bootstrap,
  control,
  transitionInput,
  createTransition,
  flushAndCollect,
  cloneContextWithProvider,
  toHex,
} from './__mocks__/group-security-coordinator.js';

describe('GroupSecurityCoordinator transitions', () => {
  test('serializes concurrent transitions for one group', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    const results = await Promise.all([
      createTransition(coordinator, control(2)),
      createTransition(coordinator, control(3)),
    ]);

    expect(results.map((result) => result.status)).toEqual([
      'committed',
      'committed',
    ]);
    expect(value.provider.maxActiveTransitions).toBe(1);
    expect(coordinator.publicState.epoch).toBe(2n);
  });

  test('rolls back from an independent checkpoint after provider-retained export mutation', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    value.provider.failNextCreateCommitAfterRetainedCheckpointMutation = true;

    await expect(createTransition(coordinator, control(2))).rejects.toThrow(
      /retained checkpoint mutation/,
    );
    expect(value.provider.importCalls).toBe(1);
    expect(coordinator.publicState.epoch).toBe(0n);
    await expect(
      createTransition(coordinator, control(3)),
    ).resolves.toMatchObject({ status: 'committed' });
  });

  test('snapshots bootstrap and queued transition inputs at invocation', async () => {
    const value = await context();
    const groupInput: CreateGroupInput = {
      groupId: new Uint8Array(groupId),
      creatorMemberId: new Uint8Array(value.identities.actorId),
      credential: new Uint8Array(value.identities.actorId),
      authenticatedData: new Uint8Array([0x31]),
    };
    const bootstrapControl = {
      operationId: id(1),
      subjectId: new Uint8Array(value.identities.actorId),
    };
    const pendingBootstrap = GroupSecurityCoordinator.bootstrap(
      config(value),
      groupInput,
      bootstrapControl,
    );
    groupInput.groupId.fill(0xee);
    groupInput.creatorMemberId.fill(0xee);
    groupInput.credential.fill(0xee);
    groupInput.authenticatedData!.fill(0xee);
    bootstrapControl.operationId.fill(0xee);
    bootstrapControl.subjectId.fill(0xee);
    const coordinator = await pendingBootstrap;
    expect(coordinator.publicState.groupId).toEqual(groupId);
    await flushAndCollect(coordinator);

    const requested = control(2, 'update', id(0xd1), id(0xe1));
    const requestedInput = transitionInput(requested);
    const expectedSubject = new Uint8Array(requested.subjectId);
    const expectedOperation = new Uint8Array(requested.operationId);
    const expectedDigest = new Uint8Array(requested.requestDigest);
    const expectedReference = new Uint8Array(
      requestedInput.changes[0].kind === 'remove'
        ? new Uint8Array()
        : requestedInput.changes[0].keyPackage.reference,
    );
    const pending = coordinator.createCommit(requestedInput, requested);
    requested.operationId.fill(0xdd);
    requested.requestDigest.fill(0xdd);
    requested.subjectId.fill(0xdd);
    requestedInput.changes[0].memberId.fill(0xdd);
    if (requestedInput.changes[0].kind !== 'remove') {
      requestedInput.changes[0].keyPackage.reference.fill(0xdd);
      requestedInput.changes[0].keyPackage.payload.fill(0xdd);
    }

    const result = await pending;
    expect(result).toMatchObject({ status: 'committed' });
    if (result.status !== 'committed')
      throw new Error('transition was not committed');
    expect(result.controlRecord.operationId).toEqual(expectedOperation);
    expect(result.controlRecord.subjectId).toEqual(expectedSubject);
    expect(toHex(result.controlRecord.controlPayload)).toContain(
      toHex(expectedDigest),
    );
    const [delivery] = await flushAndCollect(coordinator);
    expect(deltaFromCommitPayload(delivery.commit!.payload)).toEqual({
      changes: [
        {
          kind: 'update',
          memberId: expectedSubject,
          keyPackageRef: expectedReference,
        },
      ],
    });
  });

  test('snapshots received deliveries before queued application', async () => {
    const source = await context();
    const target: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: source.protector,
      identities: source.identities,
      authorization: new AuthorizationPolicy(source.identities.actorId),
      codec: source.codec,
    };
    const sourceCoordinator = await bootstrap(source);
    const targetCoordinator = await bootstrap(target);
    await flushAndCollect(sourceCoordinator);
    await flushAndCollect(targetCoordinator);
    await createTransition(sourceCoordinator, control(2));
    const [delivery] = await flushAndCollect(sourceCoordinator);
    const expectedRecord = serializeMembershipControlRecord(
      delivery.controlRecord,
    );

    const pending = targetCoordinator.applyCommit(
      delivery.commit!,
      delivery.controlRecord,
      delivery.welcomes,
    );
    delivery.commit!.groupId.fill(0xee);
    delivery.commit!.payload.fill(0xee);
    delivery.controlRecord.groupId.fill(0xee);
    delivery.controlRecord.operationId.fill(0xee);
    delivery.controlRecord.controlPayload.fill(0xee);
    delivery.controlRecord.signature.fill(0xee);

    const result = await pending;
    expect(result).toMatchObject({ status: 'committed' });
    if (result.status !== 'committed')
      throw new Error('transition was not committed');
    expect(serializeMembershipControlRecord(result.controlRecord)).toEqual(
      expectedRecord,
    );
  });

  test('does not invoke Welcome iterators and accepts canonical null-prototype controls', async () => {
    const source = await context();
    const target: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: source.protector,
      identities: source.identities,
      authorization: new AuthorizationPolicy(source.identities.actorId),
      codec: source.codec,
    };
    const sourceCoordinator = await bootstrap(source);
    const targetCoordinator = await bootstrap(target);
    await flushAndCollect(sourceCoordinator);
    await flushAndCollect(targetCoordinator);
    await createTransition(sourceCoordinator, control(2));
    const [delivery] = await flushAndCollect(sourceCoordinator);
    const hostileWelcomes = [...delivery.welcomes];
    let iteratorCalls = 0;
    Object.defineProperty(hostileWelcomes, Symbol.iterator, {
      enumerable: false,
      value: function* () {
        iteratorCalls += 1;
        throw new Error('hostile array iterator must not be consumed');
      },
    });

    await expect(
      targetCoordinator.applyCommit(
        delivery.commit!,
        delivery.controlRecord,
        hostileWelcomes,
      ),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(iteratorCalls).toBe(0);
    expect(target.provider.applyCommitCalls).toBe(0);

    const nullProtocol = Object.assign(
      Object.create(null) as Record<string, unknown>,
      delivery.controlRecord.protocol,
      { ignoredProtocolField: true },
    );
    const nullRecord = Object.assign(
      Object.create(null) as Record<string, unknown>,
      delivery.controlRecord,
      { protocol: nullProtocol, ignoredRecordField: true },
    ) as unknown as MembershipControlRecord;
    await expect(
      targetCoordinator.applyCommit(
        delivery.commit!,
        nullRecord,
        delivery.welcomes,
      ),
    ).resolves.toMatchObject({ status: 'committed' });
  });

  test('rejects accessor-backed incoming control records before reading them', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2));
    const [delivery] = await flushAndCollect(coordinator);
    const accessorRecord = { ...delivery.controlRecord };
    let payloadReads = 0;
    Object.defineProperty(accessorRecord, 'controlPayload', {
      configurable: true,
      enumerable: true,
      get() {
        payloadReads += 1;
        return payloadReads === 1
          ? new Uint8Array([1])
          : new Uint8Array(4 * 1024 * 1024);
      },
    });
    const verifyCalls = value.identities.verifyCalls;

    await expect(
      coordinator.applyCommit(
        delivery.commit!,
        accessorRecord,
        delivery.welcomes,
      ),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(payloadReads).toBe(0);
    expect(value.identities.verifyCalls).toBe(verifyCalls);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const sharedGroupId = new Uint8Array(
        new SharedArrayBuffer(delivery.controlRecord.groupId.byteLength),
      );
      sharedGroupId.set(delivery.controlRecord.groupId);
      await expect(
        coordinator.applyCommit(
          delivery.commit!,
          { ...delivery.controlRecord, groupId: sharedGroupId },
          delivery.welcomes,
        ),
      ).rejects.toMatchObject({ code: 'control-mismatch' });
      expect(value.identities.verifyCalls).toBe(verifyCalls);
    }
  });

  test('rolls provider and chain state back after store, signer, authorizer, or codec failure', async () => {
    const delegate = new InMemoryGroupStateStore();
    const failingStore = new FailOnceStore(delegate);
    const value = await context(failingStore);
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    const before = await delegate.load(storeKey);

    failingStore.failNextTransaction = true;
    await expect(createTransition(coordinator, control(2))).rejects.toThrow(
      /durable commit failure/,
    );
    expect(coordinator.publicState.epoch).toBe(0n);
    expect(await delegate.load(storeKey)).toEqual(before);

    value.identities.failNextSign = true;
    await expect(createTransition(coordinator, control(3))).rejects.toThrow(
      /signer failure/,
    );
    expect(coordinator.publicState.epoch).toBe(0n);

    value.authorization.allowed = false;
    await expect(
      createTransition(coordinator, control(4)),
    ).rejects.toMatchObject({ code: 'unauthorized-control' });
    value.authorization.allowed = true;
    expect(coordinator.publicState.epoch).toBe(0n);

    value.codec.failDecode = true;
    await expect(
      createTransition(coordinator, control(5)),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    value.codec.failDecode = false;
    expect(coordinator.publicState.epoch).toBe(0n);
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
    expect(await delegate.load(storeKey)).toEqual(before);
  });

  test('descriptor-snapshots provider transition results before reading fields', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    const before = await value.store.load(storeKey);
    const createCommit = value.provider.createCommit.bind(value.provider);
    let stateReads = 0;
    value.provider.createCommit = async (input) => {
      const result = await createCommit(input);
      const output = {
        commit: result.commit,
        welcomes: result.welcomes,
        appliedMembership: result.appliedMembership,
      } as Partial<GroupSecurityCommitResult>;
      Object.defineProperty(output, 'state', {
        enumerable: true,
        get() {
          stateReads += 1;
          return result.state;
        },
      });
      return output as GroupSecurityCommitResult;
    };

    await expect(createTransition(coordinator, control(2))).rejects.toThrow(
      /own data properties/,
    );
    expect(stateReads).toBe(0);
    expect(coordinator.publicState.epoch).toBe(0n);
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
    expect(await value.store.load(storeKey)).toEqual(before);
  });

  test('snapshots create-commit input/change descriptors and rejects shared key-package bytes before mutation', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    const before = await value.store.load(storeKey);
    const providerCalls = value.provider.createCommitCalls;
    const localControl = control(2, 'update', id(0xd1));
    const validInput = transitionInput(localControl);

    let changesReads = 0;
    const accessorInput: Record<string, unknown> = {};
    Object.defineProperty(accessorInput, 'changes', {
      configurable: true,
      enumerable: true,
      get() {
        changesReads += 1;
        return changesReads === 1 ? validInput.changes : [];
      },
    });
    await expect(
      coordinator.createCommit(
        new Proxy(accessorInput, {}) as unknown as CreateGroupCommitInput,
        localControl,
      ),
    ).rejects.toThrow(/own data properties/);
    expect(changesReads).toBe(0);

    const validChange = validInput.changes[0];
    if (validChange.kind === 'remove') {
      throw new Error('test setup requires a KeyPackage-bearing change');
    }
    let keyPackageReads = 0;
    const accessorChange = { ...validChange };
    Object.defineProperty(accessorChange, 'keyPackage', {
      configurable: true,
      enumerable: true,
      get() {
        keyPackageReads += 1;
        return keyPackageReads === 1 ? validChange.keyPackage : undefined;
      },
    });
    await expect(
      coordinator.createCommit(
        {
          changes: [new Proxy(accessorChange, {})],
        } as CreateGroupCommitInput,
        localControl,
      ),
    ).rejects.toThrow(/own data properties/);
    expect(keyPackageReads).toBe(0);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const sharedPayload = new Uint8Array(new SharedArrayBuffer(32));
      await expect(
        coordinator.createCommit(
          {
            changes: [
              {
                ...validChange,
                keyPackage: {
                  ...validChange.keyPackage,
                  payload: sharedPayload,
                },
              },
            ],
          },
          localControl,
        ),
      ).rejects.toThrow(/bounded unshared Uint8Array/);
    }

    expect(value.provider.createCommitCalls).toBe(providerCalls);
    expect(await value.store.load(storeKey)).toEqual(before);
    expect(coordinator.publicState.epoch).toBe(0n);
  });

  test('makes exact local and incoming retries idempotent but rejects operation reuse with changed intent', async () => {
    const source = await context();
    const target: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: source.protector,
      identities: source.identities,
      authorization: new AuthorizationPolicy(source.identities.actorId),
      codec: source.codec,
    };
    const sourceCoordinator = await bootstrap(source);
    const targetCoordinator = await bootstrap(target);
    await flushAndCollect(sourceCoordinator);
    await flushAndCollect(targetCoordinator);

    const localControl = control(2, 'add', id(0xd1), id(0xe1));
    await createTransition(sourceCoordinator, localControl);
    const calls = source.provider.createCommitCalls;
    await expect(
      createTransition(sourceCoordinator, localControl),
    ).resolves.toMatchObject({ status: 'duplicate' });
    expect(source.provider.createCommitCalls).toBe(calls);
    await expect(
      sourceCoordinator.createCommit(transitionInput(localControl), {
        ...localControl,
        action: 'remove',
      }),
    ).rejects.toMatchObject({ code: 'operation-conflict' });
    await expect(
      sourceCoordinator.createCommit(transitionInput(localControl), {
        ...localControl,
        requestDigest: id(0xe2),
      }),
    ).rejects.toMatchObject({ code: 'operation-conflict' });

    const [delivery] = await flushAndCollect(sourceCoordinator);
    await expect(
      targetCoordinator.applyCommit(
        delivery.commit!,
        delivery.controlRecord,
        delivery.welcomes,
      ),
    ).resolves.toMatchObject({ status: 'committed' });
    const applyCalls = target.provider.applyCommitCalls;
    await expect(
      targetCoordinator.applyCommit(
        delivery.commit!,
        delivery.controlRecord,
        delivery.welcomes,
      ),
    ).resolves.toMatchObject({ status: 'duplicate' });
    expect(target.provider.applyCommitCalls).toBe(applyCalls);
  });

  test('rejects a local provider delta or Welcome recipient that diverges from the requested signed control', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    const before = await value.store.load(storeKey);
    const localControl = control(2, 'update', id(0xd1));

    await expect(
      coordinator.createCommit({ changes: [] }, localControl),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(value.provider.createCommitCalls).toBe(0);

    value.provider.createDeltaOverride = {
      changes: [
        {
          kind: 'update',
          memberId: localControl.subjectId,
          keyPackageRef: id(0xfe),
        },
      ],
    };
    await expect(
      createTransition(coordinator, localControl),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(coordinator.publicState.epoch).toBe(0n);
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
    expect(await value.store.load(storeKey)).toEqual(before);

    value.provider.createDeltaOverride = undefined;
    const originalCreateCommit = value.provider.createCommit.bind(
      value.provider,
    );
    let deltaIteratorCalls = 0;
    value.provider.createCommit = async (input) => {
      const result = await originalCreateCommit(input);
      const changes = [...result.appliedMembership.changes];
      Object.defineProperty(changes, Symbol.iterator, {
        enumerable: false,
        value: function* () {
          deltaIteratorCalls += 1;
          throw new Error('hostile array iterator must not be consumed');
        },
      });
      return { ...result, appliedMembership: { changes } };
    };
    await expect(
      createTransition(coordinator, control(3, 'update', id(0xd2))),
    ).rejects.toThrow(/sparse or have extra properties/);
    expect(deltaIteratorCalls).toBe(0);
    expect(coordinator.publicState.epoch).toBe(0n);
    value.provider.createCommit = originalCreateCommit;

    value.provider.welcomeRecipientOverride = id(0xfd);
    await expect(
      createTransition(coordinator, control(4, 'add', id(0xd3))),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(coordinator.publicState.epoch).toBe(0n);
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
    expect(await value.store.load(storeKey)).toEqual(before);
  });

  test('rejects a receiving provider delta mismatch without advancing state and preserves received bindings across restart', async () => {
    const source = await context();
    const target: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: source.protector,
      identities: source.identities,
      authorization: new AuthorizationPolicy(source.identities.actorId),
      codec: source.codec,
    };
    const sourceCoordinator = await bootstrap(source);
    const targetCoordinator = await bootstrap(target);
    await flushAndCollect(sourceCoordinator);
    await flushAndCollect(targetCoordinator);

    const receivedControl = control(2, 'update', id(0xd4));
    await createTransition(sourceCoordinator, receivedControl);
    const [delivery] = await flushAndCollect(sourceCoordinator);
    const before = await target.store.load(storeKey);
    target.provider.applyDeltaOverride = {
      changes: [
        {
          kind: 'update',
          memberId: receivedControl.subjectId,
          keyPackageRef: id(0xfc),
        },
      ],
    };
    await expect(
      targetCoordinator.applyCommit(
        delivery.commit!,
        delivery.controlRecord,
        delivery.welcomes,
      ),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(targetCoordinator.publicState.epoch).toBe(0n);
    expect((await target.provider.getPublicState()).epoch).toBe(0n);
    expect(await target.store.load(storeKey)).toEqual(before);

    target.provider.applyDeltaOverride = undefined;
    await expect(
      targetCoordinator.applyCommit(
        delivery.commit!,
        delivery.controlRecord,
        delivery.welcomes,
      ),
    ).resolves.toMatchObject({ status: 'committed' });
    await flushAndCollect(targetCoordinator);

    const restartedProvider = new ContractTestProvider();
    const restarted = cloneContextWithProvider(target, restartedProvider);
    restarted.authorization.requirePrevious = true;
    const restored = await GroupSecurityCoordinator.restore(config(restarted));
    expect(restored.publicState.epoch).toBe(1n);
    await expect(
      createTransition(
        restored,
        control(3, 'remove', receivedControl.subjectId),
      ),
    ).resolves.toMatchObject({ status: 'committed' });
    expect(restarted.authorization.calls.at(-1)?.previousRecord?.epoch).toBe(
      1n,
    );
  });
});
