import { describe,expect,test } from '@jest/globals';
import {
ContractTestProvider,
ControlledRollbackAnchor,
FailOnceStore,
cloneContextWithProvider,
cloneInvitation,
config,
context,
createGroupInput,
createInvitation,
groupId,
id,
storeKey
} from './__testutils__/group-security-coordinator.js';
import {
GroupSecurityCoordinator
} from './group-security-coordinator.js';
import { groupSecurityStoreSnapshotCommitment } from './group-security-store-commitment.js';
import {
InMemoryGroupStateStore
} from './group-state-store.js';
import {
MembershipControlAuthorizer
} from './membership-control-record.js';

describe('GroupSecurityCoordinator invitations', () => {
  test('rejects an Alice KeyPackage relabeled as Bob before creating an Add', async () => {
    const recipient = await context();
    const alicePackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xd4),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const sourceProvider = new ContractTestProvider();

    await expect(
      createInvitation(
        recipient,
        alicePackage,
        recipient.identities.attackerId,
        sourceProvider,
      ),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(sourceProvider.authenticateKeyPackageCalls).toBe(1);
    expect(sourceProvider.createCommitCalls).toBe(0);
  });

  test('rejects a signed Bob invitation addressed to Alice pending state before join mutation', async () => {
    const recipient = await context();
    const alicePackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xd5),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const sourceProvider = new ContractTestProvider();
    sourceProvider.authenticatedMemberIdOverride =
      recipient.identities.attackerId;
    const invitation = await createInvitation(
      recipient,
      alicePackage,
      recipient.identities.attackerId,
      sourceProvider,
    );
    const joiningProvider = new ContractTestProvider();

    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, joiningProvider)),
        invitation,
      ),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(joiningProvider.authenticateKeyPackageCalls).toBe(1);
    expect(joiningProvider.importKeyPackageCalls).toBe(0);
    expect(joiningProvider.joinGroupCalls).toBe(0);
  });

  test('joins across provider restarts and atomically consumes the pending KeyPackage', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xd6),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const joiningProvider = new ContractTestProvider();
    const restarted = cloneContextWithProvider(recipient, joiningProvider);
    restarted.authorization.requirePrevious = true;

    const coordinator = await GroupSecurityCoordinator.joinFromInvitation(
      config(restarted),
      invitation,
    );
    expect(coordinator.publicState.epoch).toBe(1n);
    expect(joiningProvider.importKeyPackageCalls).toBe(1);
    expect(joiningProvider.joinGroupCalls).toBe(1);
    expect(joiningProvider.hasPendingKeyPackage(keyPackage.reference)).toBe(
      false,
    );
    const snapshot = (await recipient.store.load(storeKey))!;
    expect(snapshot.encryptedState?.state.epoch).toBe(1n);
    expect(snapshot.pendingKeyPackages).toHaveLength(0);
    expect(snapshot.consumedKeyPackageRefs).toEqual([keyPackage.reference]);
    expect(snapshot.replay.map((entry) => entry.epoch)).toEqual([0n, 1n]);
    expect(await recipient.rollbackAnchor.load(storeKey)).toEqual({
      revision: snapshot.revision,
      epoch: 1n,
      controlHead: snapshot.replay.at(-1)!.recordId,
      storeCommitment: await groupSecurityStoreSnapshotCommitment(
        snapshot,
        storeKey,
      ),
      forkPoison: undefined,
    });

    const restoredProvider = new ContractTestProvider();
    const restored = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(recipient, restoredProvider)),
    );
    expect(restored.publicState.epoch).toBe(1n);
    expect(restoredProvider.importCalls).toBe(1);

    const replayProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, replayProvider)),
        invitation,
      ),
    ).rejects.toMatchObject({ code: 'stale-replay' });
    expect(replayProvider.importKeyPackageCalls).toBe(0);
    expect(replayProvider.joinGroupCalls).toBe(0);
  });

  test('poisons concurrent forked joins before the first active anchor', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xd6),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const firstInvitation = await createInvitation(
      recipient,
      keyPackage,
      recipient.identities.actorId,
      new ContractTestProvider(),
      0x22,
    );
    const secondInvitation = await createInvitation(
      recipient,
      keyPackage,
      recipient.identities.actorId,
      new ContractTestProvider(),
      0x23,
    );
    const firstProvider = new ContractTestProvider();
    const secondProvider = new ContractTestProvider();
    let arrivals = 0;
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    const barrier = async () => {
      arrivals += 1;
      if (arrivals === 2) release();
      await released;
    };
    firstProvider.joinGroupBarrier = barrier;
    secondProvider.joinGroupBarrier = barrier;

    const results = await Promise.allSettled([
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, firstProvider)),
        firstInvitation,
      ),
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, secondProvider)),
        secondInvitation,
      ),
    ]);
    expect(results.some((result) => result.status === 'rejected')).toBe(true);
    expect(
      (await recipient.rollbackAnchor.load(storeKey))?.forkPoison,
    ).toBeDefined();
    const restartedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(recipient, restartedProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(restartedProvider.importCalls).toBe(0);
  });

  test('rolls a consumed provider back to fresh state when the join store transaction fails', async () => {
    const delegate = new InMemoryGroupStateStore();
    const failingStore = new FailOnceStore(delegate);
    const recipient = await context(failingStore);
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xd7),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const failedProvider = new ContractTestProvider();
    failingStore.failNextTransaction = true;

    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, failedProvider)),
        invitation,
      ),
    ).rejects.toMatchObject({ code: 'rollback-failed' });
    expect(failedProvider.joinGroupCalls).toBe(1);
    expect(failedProvider.clearCalls).toBe(1);
    expect(failedProvider.clearKeyPackageCalls).toBe(1);
    expect(failedProvider.hasPendingKeyPackage(keyPackage.reference)).toBe(
      false,
    );
    await expect(failedProvider.getPublicState()).rejects.toThrow(
      /not initialized/,
    );
    const afterFailure = (await delegate.load(storeKey))!;
    expect(afterFailure.encryptedState).toBeUndefined();
    expect(afterFailure.pendingKeyPackages).toHaveLength(1);
    expect(afterFailure.consumedKeyPackageRefs).toHaveLength(0);
    expect(await recipient.rollbackAnchor.load(storeKey)).toBeUndefined();

    const retryProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, retryProvider)),
        invitation,
      ),
    ).resolves.toBeInstanceOf(GroupSecurityCoordinator);
    expect(retryProvider.joinGroupCalls).toBe(1);
  });

  test('rejects malformed, substituted, and changed-group invitations before provider mutation', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xd8),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const substitutePackage =
      await GroupSecurityCoordinator.createPendingKeyPackage(
        config(recipient),
        {
          operationId: id(0xd9),
          groupId,
          memberId: recipient.identities.attackerId,
          credential: recipient.identities.attackerId,
        },
      );

    const malformed = cloneInvitation(invitation);
    malformed.controlPrefix.at(-1)!.signature.fill(0);
    const malformedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, malformedProvider)),
        malformed,
      ),
    ).rejects.toMatchObject({ code: 'bad-signature' });
    expect(malformedProvider.importKeyPackageCalls).toBe(0);
    expect(malformedProvider.joinGroupCalls).toBe(0);

    const substituted = cloneInvitation(invitation);
    substituted.keyPackageRef.set(substitutePackage.reference);
    substituted.welcome.recipientKeyPackageRef.set(substitutePackage.reference);
    const substitutedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, substitutedProvider)),
        substituted,
      ),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect(substitutedProvider.importKeyPackageCalls).toBe(0);

    const changedGroup = cloneInvitation(invitation);
    changedGroup.commit.groupId[0] ^= 0xff;
    changedGroup.welcome.groupId[0] ^= 0xff;
    const changedGroupProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, changedGroupProvider)),
        changedGroup,
      ),
    ).rejects.toThrow();
    expect(changedGroupProvider.importKeyPackageCalls).toBe(0);
  });

  test('never restores a reusable KeyPackage after post-store anchor failure', async () => {
    const recipient = await context();
    const rollbackAnchor = new ControlledRollbackAnchor();
    recipient.rollbackAnchor = rollbackAnchor;
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xda),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const provider = new ContractTestProvider();
    rollbackAnchor.rejectNextAdvance = true;

    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, provider)),
        invitation,
      ),
    ).rejects.toMatchObject({ code: 'rollback-failed' });
    const snapshot = (await recipient.store.load(storeKey))!;
    expect(snapshot.encryptedState?.state.epoch).toBe(1n);
    expect(snapshot.pendingKeyPackages).toHaveLength(0);
    expect(snapshot.consumedKeyPackageRefs).toEqual([keyPackage.reference]);
    expect(provider.hasPendingKeyPackage(keyPackage.reference)).toBe(false);
    expect(provider.clearCalls).toBe(0);
    expect(provider.clearKeyPackageCalls).toBe(0);
    expect(await rollbackAnchor.load(storeKey)).toBeUndefined();

    const replayProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, replayProvider)),
        invitation,
      ),
    ).rejects.toMatchObject({ code: 'stale-replay' });
    expect(replayProvider.importKeyPackageCalls).toBe(0);
  });

  test('snapshots a mutable invitation before asynchronous verification', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xdb),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const provider = new ContractTestProvider();
    const pending = GroupSecurityCoordinator.joinFromInvitation(
      config(cloneContextWithProvider(recipient, provider)),
      invitation,
    );

    invitation.subjectId.fill(0xee);
    invitation.keyPackageRef.fill(0xee);
    invitation.controlPrefix[0].controlPayload.fill(0xee);
    invitation.controlPrefix.at(-1)!.signature.fill(0xee);
    invitation.commit.payload.fill(0xee);
    invitation.welcome.recipientKeyPackageRef.fill(0xee);
    invitation.welcome.payload.fill(0xee);
    invitation.authenticatedData?.fill(0xee);

    await expect(pending).resolves.toBeInstanceOf(GroupSecurityCoordinator);
    expect(provider.joinGroupCalls).toBe(1);
  });

  test('rejects a truthy non-boolean invitation-chain authorization result', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xda),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const provider = new ContractTestProvider();

    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        {
          ...config(cloneContextWithProvider(recipient, provider)),
          authorizeControl:
            (async () => ({})) as unknown as MembershipControlAuthorizer,
        },
        invitation,
      ),
    ).rejects.toThrow(/unauthorized/);
    expect(provider.importKeyPackageCalls).toBe(0);
    expect(await recipient.rollbackAnchor.load(storeKey)).toBeUndefined();
  });

  test('rejects an aggregate oversized invitation prefix before verification', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xdc),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const oversizedRecord = {
      ...invitation.controlPrefix[1],
      controlPayload: new Uint8Array(2 * 1024 * 1024),
    };
    const verifyCalls = recipient.identities.verifyCalls;
    const joiningProvider = new ContractTestProvider();

    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, joiningProvider), {
          maxReplayEntries: 128,
        }),
        {
          ...invitation,
          controlPrefix: new Array(65).fill(oversizedRecord),
        },
      ),
    ).rejects.toThrow(/prefix exceeds its byte bound/);
    expect(recipient.identities.verifyCalls).toBe(verifyCalls);
    expect(joiningProvider.importKeyPackageCalls).toBe(0);
  });

  test('rejects invitation iterator overrides and accessor-backed records before reading them', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xde),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const verifyCalls = recipient.identities.verifyCalls;
    let ownKeysCalls = 0;
    const oversizedPrefix = new Proxy(new Array(9), {
      ownKeys() {
        ownKeysCalls += 1;
        throw new Error('oversized prefix keys must not be enumerated');
      },
    });
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient)),
        { ...invitation, controlPrefix: oversizedPrefix },
      ),
    ).rejects.toThrow(/outside configured bounds/);
    expect(ownKeysCalls).toBe(0);
    const overriddenPrefix = [...invitation.controlPrefix];
    Object.defineProperty(overriddenPrefix, Symbol.iterator, {
      configurable: true,
      value: function* () {
        throw new Error('hostile array iterator must not be consumed');
      },
    });
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient)),
        { ...invitation, controlPrefix: overriddenPrefix },
      ),
    ).rejects.toThrow(/extra properties/);

    let payloadReads = 0;
    const accessorRecord = { ...invitation.controlPrefix[0] };
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
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient)),
        {
          ...invitation,
          controlPrefix: [accessorRecord, invitation.controlPrefix[1]],
        },
      ),
    ).rejects.toThrow(/own data properties/);
    expect(payloadReads).toBe(0);
    expect(recipient.identities.verifyCalls).toBe(verifyCalls);
  });

  test('snapshots outer invitation descriptors and rejects shared bytes before provider or store mutation', async () => {
    const recipient = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(recipient),
      {
        operationId: id(0xdf),
        groupId,
        memberId: recipient.identities.actorId,
        credential: recipient.identities.actorId,
      },
    );
    const invitation = await createInvitation(recipient, keyPackage);
    const before = await recipient.store.load(storeKey);
    const joiningProvider = new ContractTestProvider();
    let subjectReads = 0;
    const accessorInvitation = { ...invitation };
    Object.defineProperty(accessorInvitation, 'subjectId', {
      configurable: true,
      enumerable: true,
      get() {
        subjectReads += 1;
        return subjectReads === 1
          ? recipient.identities.actorId
          : new Uint8Array(4 * 1024 * 1024);
      },
    });
    const proxiedInvitation = new Proxy(accessorInvitation, {});

    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(recipient, joiningProvider)),
        proxiedInvitation,
      ),
    ).rejects.toThrow(/own data properties/);
    expect(subjectReads).toBe(0);
    expect(joiningProvider.importKeyPackageCalls).toBe(0);
    expect(joiningProvider.joinGroupCalls).toBe(0);
    expect(await recipient.store.load(storeKey)).toEqual(before);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const sharedAuthenticatedData = new Uint8Array(new SharedArrayBuffer(32));
      await expect(
        GroupSecurityCoordinator.joinFromInvitation(
          config(cloneContextWithProvider(recipient, joiningProvider)),
          {
            ...invitation,
            authenticatedData: sharedAuthenticatedData,
          },
        ),
      ).rejects.toThrow(/bounded unshared Uint8Array/);
      expect(joiningProvider.importKeyPackageCalls).toBe(0);
      expect(joiningProvider.joinGroupCalls).toBe(0);
      expect(await recipient.store.load(storeKey)).toEqual(before);
    }
  });

  test('rejects an existing rollback anchor or active provider before recipient mutation', async () => {
    const anchored = await context();
    const anchoredPackage =
      await GroupSecurityCoordinator.createPendingKeyPackage(config(anchored), {
        operationId: id(0xdc),
        groupId,
        memberId: anchored.identities.actorId,
        credential: anchored.identities.actorId,
      });
    const anchoredInvitation = await createInvitation(
      anchored,
      anchoredPackage,
    );
    const anchoredSnapshot = (await anchored.store.load(storeKey))!;
    await anchored.rollbackAnchor.advance(storeKey, undefined, {
      revision: 1,
      epoch: 0n,
      controlHead: id(0x88),
      storeCommitment: await groupSecurityStoreSnapshotCommitment(
        anchoredSnapshot,
        storeKey,
      ),
      forkPoison: undefined,
    });
    const anchoredProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(anchored, anchoredProvider)),
        anchoredInvitation,
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(anchoredProvider.importKeyPackageCalls).toBe(0);

    const active = await context();
    const activePackage =
      await GroupSecurityCoordinator.createPendingKeyPackage(config(active), {
        operationId: id(0xdd),
        groupId,
        memberId: active.identities.actorId,
        credential: active.identities.actorId,
      });
    const activeInvitation = await createInvitation(active, activePackage);
    const activeProvider = new ContractTestProvider();
    await activeProvider.createGroup(createGroupInput);
    activeProvider.failStateExports = true;
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(active, activeProvider)),
        activeInvitation,
      ),
    ).rejects.toMatchObject({ code: 'already-initialized' });
    expect(activeProvider.importKeyPackageCalls).toBe(0);
    expect(activeProvider.joinGroupCalls).toBe(0);
    expect(activeProvider.exportStateCalls).toBe(0);
  });
});
