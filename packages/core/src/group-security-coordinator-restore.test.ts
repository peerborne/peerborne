import { describe,expect,test } from '@jest/globals';
import {
AdversarialStore,
AuthorizationPolicy,
ContractTestProvider,
ControlledRollbackAnchor,
StaticSnapshotStore,
TestContext,
bootstrap,
cloneContextWithProvider,
config,
context,
control,
createGroupInput,
createInvitation,
createTransition,
encoder,
flushAndCollect,
groupId,
id,
privateBytes,
protocol,
publicState,
replaceReplayHead,
restoreFromSignedSnapshot,
rewriteSignedReplayChain,
storeKey,
toHex,
} from './__testutils__/group-security-coordinator.js';
import {
GroupSecurityCoordinator,
canonicalGroupSecurityCommit
} from './group-security-coordinator.js';
import { createGroupSecurityDurableAcceptance } from './group-security-durable-acceptance.js';
import {
EncryptedGroupState,
EncryptedKeyPackageState,
GroupSecurityPublicState
} from './group-security-provider.js';
import {
InMemoryGroupSecurityRollbackAnchor
} from './group-security-rollback-anchor.js';
import { groupSecurityStoreSnapshotCommitment } from './group-security-store-commitment.js';
import {
GroupStateStoreSnapshot,
GroupStateStoreTransaction,
InMemoryGroupStateStore
} from './group-state-store.js';
import {
MembershipControlRecord,
signMembershipControlRecord
} from './membership-control-record.js';

describe('GroupSecurityCoordinator restore', () => {
  test('restores the signed chain before provider import and supplies previousRecord authorization context', async () => {
    const first = await context();
    first.authorization.requirePrevious = true;
    const coordinator = await bootstrap(first);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2));
    await flushAndCollect(coordinator);

    const restartedProvider = new ContractTestProvider();
    const restarted = cloneContextWithProvider(first, restartedProvider);
    const restored = await GroupSecurityCoordinator.restore(config(restarted));
    expect(restored.publicState.epoch).toBe(1n);
    expect(restartedProvider.importCalls).toBe(1);

    await expect(createTransition(restored, control(3))).resolves.toMatchObject(
      { status: 'committed' },
    );
    const latest = first.authorization.calls.at(-1)!;
    expect(latest.previousRecord?.epoch).toBe(1n);
    expect(latest.previousRecordId).toEqual(latest.record.parentRecordId);
  });

  test('rejects a signed non-head genesis with a noncanonical payload before provider import', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2));
    await flushAndCollect(coordinator);
    const original = (await value.store.load(storeKey))!;
    const rewritten = await rewriteSignedReplayChain(
      original,
      value.identities,
      (record) => {
        if (record.action !== 'create') return record;
        const payload = new Uint8Array(record.controlPayload.byteLength + 1);
        payload.set(record.controlPayload);
        payload[payload.byteLength - 1] = 0xee;
        return { ...record, controlPayload: payload };
      },
    );
    const provider = new ContractTestProvider();

    await expect(
      restoreFromSignedSnapshot(value, provider, rewritten),
    ).rejects.toMatchObject({ code: 'malformed-state' });
    expect(provider.importCalls).toBe(0);
  });

  test('rejects signed non-head controls with truncated or mismatched embedded commits before provider import', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2));
    const [epochOne] = await flushAndCollect(coordinator);
    await createTransition(coordinator, control(3));
    await flushAndCollect(coordinator);
    const original = (await value.store.load(storeKey))!;
    const canonicalCommit = canonicalGroupSecurityCommit(epochOne.commit!);
    const commitDomainLength = encoder.encode(
      'peerborne/group-security-commit/v1\0',
    ).byteLength;
    const rewritten = await rewriteSignedReplayChain(
      original,
      value.identities,
      (record) => {
        if (record.epoch !== 1n) return record;
        const prefixLength =
          record.controlPayload.byteLength - canonicalCommit.byteLength;
        const payload = new Uint8Array(prefixLength + commitDomainLength);
        payload.set(record.controlPayload.subarray(0, payload.byteLength));
        return { ...record, controlPayload: payload };
      },
    );
    const provider = new ContractTestProvider();

    await expect(
      restoreFromSignedSnapshot(value, provider, rewritten),
    ).rejects.toMatchObject({ code: 'malformed-state' });
    expect(provider.importCalls).toBe(0);

    const mismatchedGroupId = new Uint8Array(epochOne.commit!.groupId);
    mismatchedGroupId[0] ^= 0xff;
    const mismatchedCommit = canonicalGroupSecurityCommit({
      ...epochOne.commit!,
      groupId: mismatchedGroupId,
    });
    const mismatched = await rewriteSignedReplayChain(
      original,
      value.identities,
      (record) => {
        if (record.epoch !== 1n) return record;
        const prefixLength =
          record.controlPayload.byteLength - canonicalCommit.byteLength;
        const payload = new Uint8Array(
          prefixLength + mismatchedCommit.byteLength,
        );
        payload.set(record.controlPayload.subarray(0, prefixLength));
        payload.set(mismatchedCommit, prefixLength);
        return { ...record, controlPayload: payload };
      },
    );
    const mismatchedProvider = new ContractTestProvider();

    await expect(
      restoreFromSignedSnapshot(value, mismatchedProvider, mismatched),
    ).rejects.toMatchObject({ code: 'malformed-state' });
    expect(mismatchedProvider.importCalls).toBe(0);
  });

  test('preserves lifecycle errors when applyCommit receives malformed attachments', async () => {
    const value = await context();
    const rollbackAnchor = new ControlledRollbackAnchor();
    value.rollbackAnchor = rollbackAnchor;
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    rollbackAnchor.rejectNextAdvance = true;
    await expect(
      createTransition(coordinator, control(2)),
    ).rejects.toMatchObject({ code: 'rollback-failed' });

    await expect(
      coordinator.applyCommit(undefined as never, undefined as never),
    ).rejects.toMatchObject({ code: 'poisoned' });
    expect(value.provider.applyCommitCalls).toBe(0);
  });

  test('retires a restoring provider when state advances or poisons during import', async () => {
    const advanced = await context();
    const active = await bootstrap(advanced);
    await flushAndCollect(active);
    const restoringProvider = new ContractTestProvider();
    let importEntered!: () => void;
    const importStarted = new Promise<void>((resolve) => {
      importEntered = resolve;
    });
    let releaseImport!: () => void;
    const importRelease = new Promise<void>((resolve) => {
      releaseImport = resolve;
    });
    restoringProvider.importEncryptedStateBarrier = async () => {
      importEntered();
      await importRelease;
    };
    const restoring = GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(advanced, restoringProvider)),
    );
    await importStarted;
    await createTransition(active, control(2));
    releaseImport();
    await expect(restoring).rejects.toMatchObject({ code: 'rollback-failed' });
    expect(restoringProvider.clearCalls).toBe(1);
    const latest = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(advanced)),
    );
    expect(latest.publicState.epoch).toBe(1n);

    const poisoned = await context();
    const poisonedActive = await bootstrap(poisoned);
    await flushAndCollect(poisonedActive);
    const poisonedProvider = new ContractTestProvider();
    let poisonImportEntered!: () => void;
    const poisonImportStarted = new Promise<void>((resolve) => {
      poisonImportEntered = resolve;
    });
    let releasePoisonImport!: () => void;
    const poisonImportRelease = new Promise<void>((resolve) => {
      releasePoisonImport = resolve;
    });
    poisonedProvider.importEncryptedStateBarrier = async () => {
      poisonImportEntered();
      await poisonImportRelease;
    };
    const restoringPoisoned = GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(poisoned, poisonedProvider)),
    );
    await poisonImportStarted;
    await poisoned.rollbackAnchor.poison(storeKey, {
      epoch: 0n,
      parentRecordId: id(0x61),
      firstRecordId: id(0x62),
      secondRecordId: id(0x63),
      evidenceHash: id(0x64),
    });
    releasePoisonImport();
    await expect(restoringPoisoned).rejects.toMatchObject({
      code: 'rollback-failed',
    });
    expect(poisonedProvider.clearCalls).toBe(1);
    const finalProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(poisoned, finalProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(finalProvider.importCalls).toBe(0);
  });

  test('clears a fresh provider after bootstrap failure and explicitly flags an unavailable reset', async () => {
    const clearable = await context();
    clearable.identities.failNextSign = true;
    await expect(bootstrap(clearable)).rejects.toThrow(/signer failure/);
    expect(clearable.provider.clearCalls).toBe(1);
    await expect(clearable.provider.getPublicState()).rejects.toThrow(
      /not initialized/,
    );

    const undisposable = await context();
    Object.defineProperty(undisposable.provider, 'clearGroupState', {
      value: undefined,
    });
    undisposable.identities.failNextSign = true;
    await expect(bootstrap(undisposable)).rejects.toMatchObject({
      code: 'rollback-unavailable',
    });
    expect((await undisposable.provider.getPublicState()).epoch).toBe(0n);
  });

  test('retires a provider when bootstrap cleanup reports success but leaves its group active', async () => {
    const value = await context();
    value.identities.failNextSign = true;
    value.provider.clearGroupState = async () => {
      value.provider.clearCalls += 1;
    };

    await expect(bootstrap(value)).rejects.toMatchObject({
      code: 'rollback-failed',
    });
    expect(value.provider.clearCalls).toBe(1);
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
    await expect(bootstrap(value)).rejects.toMatchObject({
      code: 'already-initialized',
    });
    expect(value.provider.createGroupCalls).toBe(1);
  });

  test('retires a joining provider when cleanup reports success but leaves the joined group active', async () => {
    const value = await context();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(value),
      {
        operationId: id(0xe7),
        groupId,
        memberId: value.identities.actorId,
        credential: value.identities.actorId,
      },
    );
    const invitation = await createInvitation(value, keyPackage);
    const provider = new ContractTestProvider();
    provider.getPublicStateOverrideOnce = publicState(7n);
    provider.clearGroupState = async () => {
      provider.clearCalls += 1;
    };
    const joining = cloneContextWithProvider(value, provider);

    await expect(
      GroupSecurityCoordinator.joinFromInvitation(config(joining), invitation),
    ).rejects.toMatchObject({ code: 'rollback-failed' });
    expect(provider.clearCalls).toBe(1);
    expect((await provider.getPublicState()).epoch).toBe(1n);
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(config(joining), invitation),
    ).rejects.toMatchObject({ code: 'already-initialized' });
    expect(provider.joinGroupCalls).toBe(1);
  });

  test('restores a preexisting provider checkpoint when restore import mutates then fails', async () => {
    const stored = await context();
    const coordinator = await bootstrap(stored);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2));
    await flushAndCollect(coordinator);

    const provider = new ContractTestProvider();
    await provider.createGroup(createGroupInput);
    provider.failNextImportAfterMutation = true;
    const restarted = cloneContextWithProvider(stored, provider);
    await expect(
      GroupSecurityCoordinator.restore(config(restarted)),
    ).rejects.toThrow(/import failure after mutation/);
    expect((await provider.getPublicState()).epoch).toBe(0n);
    expect(provider.importCalls).toBe(2);
  });

  test('does not replace an active provider when its restore checkpoint export fails', async () => {
    const stored = await context();
    await bootstrap(stored);

    const provider = new ContractTestProvider();
    const activeGroupId = new Uint8Array([0x81, 0x82]);
    await provider.createGroup({
      ...createGroupInput,
      groupId: activeGroupId,
    });
    provider.failStateExports = true;

    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(stored, provider)),
      ),
    ).rejects.toThrow(/export failure/);
    expect(provider.importCalls).toBe(0);
    expect((await provider.getPublicState()).groupId).toEqual(activeGroupId);
  });

  test('does not replace an active provider from a stale exported restore checkpoint', async () => {
    const stored = await context();
    await bootstrap(stored);

    const provider = new ContractTestProvider();
    const activeGroupId = new Uint8Array([0x84, 0x85]);
    await provider.createGroup({
      ...createGroupInput,
      groupId: activeGroupId,
    });
    const staleState = publicState(7n, activeGroupId);
    const staleCheckpoint = await EncryptedGroupState.seal(
      staleState,
      privateBytes(staleState.epoch),
      stored.protector,
    );
    provider.exportEncryptedState = async () => staleCheckpoint;

    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(stored, provider)),
      ),
    ).rejects.toThrow(/public state/);
    expect(provider.importCalls).toBe(0);
    expect(await provider.getPublicState()).toEqual(
      publicState(0n, activeGroupId),
    );
  });

  test('compares restore import against state independent of the provider argument', async () => {
    const stored = await context();
    await bootstrap(stored);
    const provider = new ContractTestProvider();
    provider.importedStateOverrideAfterOpen = publicState(7n);

    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(stored, provider)),
      ),
    ).rejects.toMatchObject({ code: 'malformed-state' });
    expect(provider.importCalls).toBe(1);
    expect(provider.clearCalls).toBe(1);
    await expect(provider.getPublicState()).rejects.toThrow(/not initialized/);
  });

  test('rejects a restore whose provider reports the import but retains another state', async () => {
    const stored = await context();
    await bootstrap(stored);
    const provider = new ContractTestProvider();
    provider.getPublicStateOverrideOnce = publicState(7n);

    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(stored, provider)),
      ),
    ).rejects.toMatchObject({ code: 'malformed-state' });
    expect(provider.importCalls).toBe(1);
    expect(provider.clearCalls).toBe(1);
  });

  test('detects rollback to a complete independently populated snapshot before provider import', async () => {
    const advanced = await context();
    const older: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: advanced.protector,
      identities: advanced.identities,
      authorization: new AuthorizationPolicy(advanced.identities.actorId),
      codec: advanced.codec,
    };
    const advancedCoordinator = await bootstrap(advanced);
    const olderCoordinator = await bootstrap(older);
    await flushAndCollect(advancedCoordinator);
    await flushAndCollect(olderCoordinator);
    await createTransition(advancedCoordinator, control(2));
    await flushAndCollect(advancedCoordinator);

    const olderSnapshot = (await older.store.load(storeKey))!;
    const advancedAnchor = (await advanced.rollbackAnchor.load(storeKey))!;
    expect(olderSnapshot.encryptedState?.state.epoch).toBe(0n);
    expect(advancedAnchor.epoch).toBe(1n);
    const provider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config({
          ...older,
          provider,
          rollbackAnchor: advanced.rollbackAnchor,
        }),
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(provider.importCalls).toBe(0);
  });

  test('rejects aggregate replay amplification before verification, authorization, or provider import', async () => {
    const value = await context();
    await bootstrap(value);
    const snapshot = (await value.store.load(storeKey))!;
    const aliasedControlRecord = new Uint8Array(4 * 1024 * 1024);
    const replay = Array.from({ length: 2048 }, (_, index) => {
      const recordId = id(0x81);
      const operationId = id(0x82);
      new DataView(recordId.buffer).setUint32(28, index, false);
      new DataView(operationId.buffer).setUint32(28, index, false);
      return {
        recordId,
        operationId,
        epoch: BigInt(index),
        controlRecord: aliasedControlRecord,
      };
    });
    value.identities.verifyCalls = 0;
    value.authorization.calls = [];
    const provider = new ContractTestProvider();

    await expect(
      GroupSecurityCoordinator.restore(
        config(
          {
            ...value,
            provider,
            store: new StaticSnapshotStore({ ...snapshot, replay }),
          },
          { maxReplayEntries: 2048 },
        ),
      ),
    ).rejects.toThrow(/exceeds its bound/);
    expect(value.identities.verifyCalls).toBe(0);
    expect(value.authorization.calls).toHaveLength(0);
    expect(provider.importCalls).toBe(0);
  });

  test('rejects same-revision pending and consumed metadata substitution before provider import', async () => {
    const value = await context();
    await bootstrap(value);
    const snapshot = (await value.store.load(storeKey))!;
    const pending = await EncryptedKeyPackageState.seal(
      {
        protocol,
        groupId,
        reference: new Uint8Array([0xa1]),
        payload: new Uint8Array([0xa2]),
      },
      new Uint8Array([0xa3]),
      value.protector,
    );
    const variants: GroupStateStoreSnapshot[] = [
      {
        ...snapshot,
        pendingKeyPackages: [pending],
        pendingKeyPackageRequests: [
          {
            operationId: id(0xa4),
            requestCommitment: id(0xa5),
            keyPackageReference: new Uint8Array([0xa1]),
          },
        ],
      },
      {
        ...snapshot,
        consumedKeyPackageRefs: [new Uint8Array([0xb1])],
      },
    ];
    value.identities.verifyCalls = 0;
    value.authorization.calls = [];

    for (const substituted of variants) {
      const provider = new ContractTestProvider();
      await expect(
        GroupSecurityCoordinator.restore(
          config({
            ...value,
            provider,
            store: new StaticSnapshotStore(substituted),
          }),
        ),
      ).rejects.toMatchObject({ code: 'rollback-detected' });
      expect(provider.importCalls).toBe(0);
      expect(value.identities.verifyCalls).toBe(0);
      expect(value.authorization.calls).toHaveLength(0);
    }
  });

  test('rejects same-revision outbox deletion before count or delivery', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);
    const coordinator = await bootstrap(value);
    store.mutateLoads = (snapshot) => ({
      ...snapshot,
      outbox: [],
    });

    await expect(coordinator.pendingOutboxCount()).rejects.toMatchObject({
      code: 'rollback-detected',
    });
    let sends = 0;
    await expect(
      coordinator.flushOutbox(async (delivery) => {
        sends += 1;
        return createGroupSecurityDurableAcceptance(delivery);
      }),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(sends).toBe(0);
    expect((await delegate.load(storeKey))?.outbox).toHaveLength(1);
  });

  test('rejects same-revision pending and consumed substitution during runtime reads', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);
    const coordinator = await bootstrap(value);
    const pending = await EncryptedKeyPackageState.seal(
      {
        protocol,
        groupId,
        reference: new Uint8Array([0xc1]),
        payload: new Uint8Array([0xc2]),
      },
      new Uint8Array([0xc3]),
      value.protector,
    );
    const mutations = [
      (snapshot: GroupStateStoreSnapshot): GroupStateStoreSnapshot => ({
        ...snapshot,
        pendingKeyPackages: [pending],
        pendingKeyPackageRequests: [
          {
            operationId: id(0xc4),
            requestCommitment: id(0xc5),
            keyPackageReference: new Uint8Array([0xc1]),
          },
        ],
      }),
      (snapshot: GroupStateStoreSnapshot): GroupStateStoreSnapshot => ({
        ...snapshot,
        consumedKeyPackageRefs: [new Uint8Array([0xd1])],
      }),
    ];

    for (const mutate of mutations) {
      store.mutateLoads = mutate;
      await expect(coordinator.pendingOutboxCount()).rejects.toMatchObject({
        code: 'rollback-detected',
      });
    }
  });

  test('rejects transaction-base deletion before a transition can launder it', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);
    const coordinator = await bootstrap(value);
    const before = (await delegate.load(storeKey))!;
    store.mutateNextTransaction = (transaction) => {
      for (const entry of transaction.outbox) {
        transaction.removeOutbox(entry.id);
      }
    };

    await expect(
      createTransition(coordinator, control(2)),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(coordinator.publicState.epoch).toBe(0n);
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
    expect(await delegate.load(storeKey)).toEqual(before);
  });

  test('rejects truthy non-boolean durable transaction method results', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    const before = await delegate.load(storeKey);
    store.mutateNextTransaction = (transaction) => {
      const markReplay = transaction.markReplay.bind(transaction);
      Object.defineProperty(transaction, 'markReplay', {
        configurable: true,
        value: (
          entry: Parameters<GroupStateStoreTransaction['markReplay']>[0],
        ) => {
          markReplay(entry);
          return {};
        },
      });
    };

    await expect(
      createTransition(coordinator, control(2)),
    ).rejects.toMatchObject({ code: 'store-conflict' });
    expect(await delegate.load(storeKey)).toEqual(before);
    expect(coordinator.publicState.epoch).toBe(0n);
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
  });

  test('verifies the committed snapshot before advancing its anchor', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    store.mutateNextLoadAfterTransaction = (snapshot) => ({
      ...snapshot,
      outbox: [],
    });
    const value = await context(store);

    await expect(bootstrap(value)).rejects.toMatchObject({
      code: 'rollback-failed',
    });
    expect((await delegate.load(storeKey))?.outbox).toHaveLength(1);
    expect(await value.rollbackAnchor.load(storeKey)).toBeUndefined();
  });

  test('ignores an untrusted transaction result and adopts only the reloaded authorized view', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);
    value.authorization.requirePrevious = true;
    const coordinator = await bootstrap(value);
    const [genesis] = await flushAndCollect(coordinator);
    const forgedRecord = {
      ...genesis.controlRecord,
      epoch: 99n,
      operationId: id(0xee),
    };
    store.mutateNextTransactionResult = (result) => {
      if (result !== null && typeof result === 'object' && 'view' in result) {
        const returned = result as {
          view: {
            headRecordId: Uint8Array;
            lastControlRecord: MembershipControlRecord;
            recordsById: Map<string, MembershipControlRecord>;
          };
        };
        returned.view.headRecordId = id(0xee);
        returned.view.lastControlRecord = forgedRecord;
        returned.view.recordsById = new Map([[toHex(id(0xee)), forgedRecord]]);
        return returned;
      }
      return { view: { lastControlRecord: forgedRecord } };
    };

    const first = await createTransition(coordinator, control(2));
    expect(first.status).toBe('committed');
    expect(coordinator.publicState.epoch).toBe(1n);
    await createTransition(coordinator, control(3));

    const epochTwoAuthorization = value.authorization.calls.findLast(
      (call) => call.record.epoch === 2n,
    );
    expect(epochTwoAuthorization?.previousRecord?.epoch).toBe(1n);
    expect(epochTwoAuthorization?.previousRecordId).toEqual(first.recordId);
  });

  test('advances the anchor when restore prunes replay metadata', async () => {
    const value = await context();
    const coordinator = await bootstrap(value, {
      maxReplayEntries: 8,
      replayWindowEpochs: 4n,
    });
    await flushAndCollect(coordinator);
    for (let operation = 2; operation <= 4; operation++) {
      await createTransition(coordinator, control(operation));
      await flushAndCollect(coordinator);
    }
    const before = (await value.store.load(storeKey))!;
    expect(before.replay.map((entry) => entry.epoch)).toEqual([0n, 1n, 2n, 3n]);

    const restored = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(value), {
        maxReplayEntries: 8,
        replayWindowEpochs: 1n,
      }),
    );
    const after = (await value.store.load(storeKey))!;
    const anchor = (await value.rollbackAnchor.load(storeKey))!;
    expect(restored.publicState.epoch).toBe(3n);
    expect(after.revision).toBe(before.revision + 1);
    expect(after.replay.map((entry) => entry.epoch)).toEqual([2n, 3n]);
    expect(anchor).toEqual({
      revision: after.revision,
      epoch: 3n,
      controlHead: after.replay.at(-1)!.recordId,
      storeCommitment: await groupSecurityStoreSnapshotCommitment(
        after,
        storeKey,
      ),
    });
  });

  test('poisons the coordinator when rollback-anchor CAS is rejected after commit', async () => {
    const value = await context();
    const rollbackAnchor = new ControlledRollbackAnchor();
    value.rollbackAnchor = rollbackAnchor;
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    const beforeAnchor = (await rollbackAnchor.load(storeKey))!;

    rollbackAnchor.rejectNextAdvance = true;
    await expect(
      createTransition(coordinator, control(2)),
    ).rejects.toMatchObject({ code: 'rollback-failed' });
    const snapshot = (await value.store.load(storeKey))!;
    expect(snapshot.revision).toBe(beforeAnchor.revision + 1);
    expect(snapshot.encryptedState?.state.epoch).toBe(1n);
    expect(await rollbackAnchor.load(storeKey)).toEqual(beforeAnchor);
    expect(() => coordinator.publicState).toThrow(/poisoned/);
    expect((await value.provider.getPublicState()).epoch).toBe(1n);

    const provider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(value, provider)),
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(provider.importCalls).toBe(0);
  });

  test('rejects a truthy non-boolean rollback-anchor CAS result', async () => {
    const value = await context();
    const rollbackAnchor = new ControlledRollbackAnchor();
    rollbackAnchor.malformedNextAdvance = {};
    value.rollbackAnchor = rollbackAnchor;

    await expect(bootstrap(value)).rejects.toMatchObject({
      code: 'rollback-failed',
    });
    expect((await value.store.load(storeKey))?.encryptedState).toBeDefined();
    expect(await rollbackAnchor.load(storeKey)).toBeUndefined();
    expect(value.provider.clearCalls).toBe(0);
  });

  test('fails closed when initial rollback-anchor persistence throws', async () => {
    const value = await context();
    const rollbackAnchor = new ControlledRollbackAnchor();
    rollbackAnchor.failNextAdvance = true;
    value.rollbackAnchor = rollbackAnchor;

    await expect(bootstrap(value)).rejects.toMatchObject({
      code: 'rollback-failed',
    });
    expect((await value.store.load(storeKey))?.encryptedState).toBeDefined();
    expect(await rollbackAnchor.load(storeKey)).toBeUndefined();
    expect((await value.provider.getPublicState()).epoch).toBe(0n);
    expect(value.provider.clearCalls).toBe(0);

    const provider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(value, provider)),
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(provider.importCalls).toBe(0);
  });

  test('rejects tampered persisted actor authorization and broken linkage before provider import', async () => {
    const actorValue = await context();
    const actorCoordinator = await bootstrap(actorValue);
    await flushAndCollect(actorCoordinator);
    await createTransition(actorCoordinator, control(2));
    await flushAndCollect(actorCoordinator);
    await replaceReplayHead(actorValue, async (record) => {
      const { signature: _signature, ...unsignedRecord } = record;
      return signMembershipControlRecord(
        {
          ...unsignedRecord,
          actorId: actorValue.identities.attackerId,
        },
        async (payload, actorId) =>
          actorValue.identities.signAs(actorId, payload),
      );
    });
    const actorProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(actorValue, actorProvider)),
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(actorProvider.importCalls).toBe(0);

    const linkValue = await context();
    const linkCoordinator = await bootstrap(linkValue);
    await flushAndCollect(linkCoordinator);
    await createTransition(linkCoordinator, control(2));
    await flushAndCollect(linkCoordinator);
    await replaceReplayHead(linkValue, async (record) => {
      const { signature: _signature, ...unsignedRecord } = record;
      return signMembershipControlRecord(
        { ...unsignedRecord, parentRecordId: id(0xff) },
        linkValue.identities.sign,
      );
    });
    const linkProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(linkValue, linkProvider)),
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(linkProvider.importCalls).toBe(0);
  });

  test('rejects a tampered persisted control signature before provider import', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2));
    await flushAndCollect(coordinator);
    await replaceReplayHead(value, async (record) => ({
      ...record,
      signature: new Uint8Array(record.signature.length),
    }));

    const provider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(value, provider)),
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(provider.importCalls).toBe(0);
  });

  test('rejects a same-group/same-epoch encrypted-state fork not bound by the signed head', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    await createTransition(coordinator, control(2));
    await flushAndCollect(coordinator);
    const forkedState: GroupSecurityPublicState = {
      ...publicState(1n),
      confirmedTranscriptHash: new Uint8Array(32).fill(0xee),
      treeHash: new Uint8Array(32).fill(0xdd),
    };
    const forkedEnvelope = await EncryptedGroupState.seal(
      forkedState,
      privateBytes(1n),
      value.protector,
    );
    await value.store.transaction(storeKey, (transaction) => {
      transaction.setEncryptedState(forkedEnvelope);
    });

    const provider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(value, provider)),
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(provider.importCalls).toBe(0);
  });
});
