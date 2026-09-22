import { describe,expect,test } from '@jest/globals';
import {
AdversarialStore,
AuthorizationPolicy,
ContractTestProvider,
ControlledRollbackAnchor,
FailOnceStore,
ReconciliationLoadFailureStore,
TestContext,
bootstrap,
cloneContextWithProvider,
config,
context,
control,
createGroupInput,
createTransition,
flushAndCollect,
id,
publicState,
storeKey
} from './__testutils__/group-security-coordinator.js';
import {
GroupSecurityCoordinator,
canonicalGroupSecurityState
} from './group-security-coordinator.js';
import {
InMemoryGroupSecurityRollbackAnchor
} from './group-security-rollback-anchor.js';
import { groupSecurityStoreSnapshotCommitment } from './group-security-store-commitment.js';
import {
InMemoryGroupStateStore
} from './group-state-store.js';
import {
signMembershipControlRecord
} from './membership-control-record.js';

describe('GroupSecurityCoordinator forks', () => {
  test('durably fails closed when partitioned coordinators rejoin with same-parent siblings', async () => {
    const left = await context();
    const right: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: left.protector,
      identities: left.identities,
      authorization: new AuthorizationPolicy(left.identities.actorId),
      codec: left.codec,
    };
    const leftCoordinator = await bootstrap(left);
    const rightCoordinator = await bootstrap(right);
    await flushAndCollect(leftCoordinator);
    await flushAndCollect(rightCoordinator);

    await createTransition(leftCoordinator, control(2, 'update', id(0xd1)));
    await createTransition(rightCoordinator, control(3, 'update', id(0xd2)));
    const [leftDelivery] = await flushAndCollect(leftCoordinator);
    const [rightDelivery] = await flushAndCollect(rightCoordinator);

    await expect(
      leftCoordinator.applyCommit(
        rightDelivery.commit!,
        rightDelivery.controlRecord,
        rightDelivery.welcomes,
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    await expect(
      rightCoordinator.applyCommit(
        leftDelivery.commit!,
        leftDelivery.controlRecord,
        leftDelivery.welcomes,
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(left.provider.applyCommitCalls).toBe(0);
    expect(right.provider.applyCommitCalls).toBe(0);
    expect(() => leftCoordinator.publicState).toThrow(/same-parent/);
    await expect(leftCoordinator.pendingOutboxCount()).rejects.toMatchObject({
      code: 'fork-detected',
    });

    const leftFork = (await left.store.load(storeKey))!.forkEvidence;
    const rightFork = (await right.store.load(storeKey))!.forkEvidence;
    expect(
      (await left.rollbackAnchor.load(storeKey))?.forkPoison,
    ).toBeDefined();
    expect(
      (await right.rollbackAnchor.load(storeKey))?.forkPoison,
    ).toBeDefined();
    expect(leftFork).toBeDefined();
    expect(rightFork).toBeDefined();
    expect(leftFork?.firstRecordId).toEqual(rightFork?.firstRecordId);
    expect(leftFork?.secondRecordId).toEqual(rightFork?.secondRecordId);

    const restartedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(left, restartedProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(restartedProvider.importCalls).toBe(0);
    expect((await left.store.load(storeKey))?.forkEvidence).toEqual(leftFork);
  });

  test('reconciles concurrent incoming siblings but does not poison an exact incoming race', async () => {
    const target = await context();
    const sourceLeft: TestContext = {
      ...target,
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      authorization: new AuthorizationPolicy(target.identities.actorId),
    };
    const sourceRight: TestContext = {
      ...sourceLeft,
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      authorization: new AuthorizationPolicy(target.identities.actorId),
    };
    const targetBase = await bootstrap(target);
    const leftSource = await bootstrap(sourceLeft);
    const rightSource = await bootstrap(sourceRight);
    await flushAndCollect(targetBase);
    await flushAndCollect(leftSource);
    await flushAndCollect(rightSource);
    await createTransition(leftSource, control(0x41, 'update', id(0xd1)));
    await createTransition(rightSource, control(0x42, 'update', id(0xd2)));
    const [leftDelivery] = await flushAndCollect(leftSource);
    const [rightDelivery] = await flushAndCollect(rightSource);

    const firstProvider = new ContractTestProvider();
    const secondProvider = new ContractTestProvider();
    const first = await GroupSecurityCoordinator.restore(
      config({
        ...target,
        provider: firstProvider,
        authorization: new AuthorizationPolicy(target.identities.actorId),
      }),
    );
    const second = await GroupSecurityCoordinator.restore(
      config({
        ...target,
        provider: secondProvider,
        authorization: new AuthorizationPolicy(target.identities.actorId),
      }),
    );
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
    firstProvider.applyCommitBarrier = barrier;
    secondProvider.applyCommitBarrier = barrier;
    const forkResults = await Promise.allSettled([
      first.applyCommit(
        leftDelivery.commit!,
        leftDelivery.controlRecord,
        leftDelivery.welcomes,
      ),
      second.applyCommit(
        rightDelivery.commit!,
        rightDelivery.controlRecord,
        rightDelivery.welcomes,
      ),
    ]);
    expect(forkResults.some((result) => result.status === 'rejected')).toBe(
      true,
    );
    expect(
      (await target.rollbackAnchor.load(storeKey))?.forkPoison,
    ).toBeDefined();
    const poisonedRestartProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config({ ...target, provider: poisonedRestartProvider }),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(poisonedRestartProvider.importCalls).toBe(0);

    const exactTarget: TestContext = {
      ...target,
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      authorization: new AuthorizationPolicy(target.identities.actorId),
    };
    const exactBase = await bootstrap(exactTarget);
    await flushAndCollect(exactBase);
    const exactFirstProvider = new ContractTestProvider();
    const exactSecondProvider = new ContractTestProvider();
    const exactFirst = await GroupSecurityCoordinator.restore(
      config({
        ...exactTarget,
        provider: exactFirstProvider,
        authorization: new AuthorizationPolicy(target.identities.actorId),
      }),
    );
    const exactSecond = await GroupSecurityCoordinator.restore(
      config({
        ...exactTarget,
        provider: exactSecondProvider,
        authorization: new AuthorizationPolicy(target.identities.actorId),
      }),
    );
    arrivals = 0;
    let releaseExact!: () => void;
    const exactReleased = new Promise<void>((resolve) => {
      releaseExact = resolve;
    });
    const exactBarrier = async () => {
      arrivals += 1;
      if (arrivals === 2) releaseExact();
      await exactReleased;
    };
    exactFirstProvider.applyCommitBarrier = exactBarrier;
    exactSecondProvider.applyCommitBarrier = exactBarrier;
    const exactResults = await Promise.allSettled([
      exactFirst.applyCommit(
        leftDelivery.commit!,
        leftDelivery.controlRecord,
        leftDelivery.welcomes,
      ),
      exactSecond.applyCommit(
        leftDelivery.commit!,
        leftDelivery.controlRecord,
        leftDelivery.welcomes,
      ),
    ]);
    expect(
      exactResults.filter((result) => result.status === 'fulfilled'),
    ).toHaveLength(1);
    expect(
      (await exactTarget.rollbackAnchor.load(storeKey))?.forkPoison,
    ).toBeUndefined();
    const exactRestart = await GroupSecurityCoordinator.restore(
      config({ ...exactTarget, provider: new ContractTestProvider() }),
    );
    expect(exactRestart.publicState.epoch).toBe(1n);
  });

  test('durably poisons an authenticated ambiguity when conflict reconciliation cannot load', async () => {
    const delegate = new InMemoryGroupStateStore();
    const winner = await context(delegate);
    const winnerCoordinator = await bootstrap(winner);
    await flushAndCollect(winnerCoordinator);
    const failingStore = new ReconciliationLoadFailureStore(delegate);
    const loserProvider = new ContractTestProvider();
    const loserContext: TestContext = {
      ...winner,
      provider: loserProvider,
      store: failingStore,
      authorization: new AuthorizationPolicy(winner.identities.actorId),
    };
    const loser = await GroupSecurityCoordinator.restore(config(loserContext));
    const losingTransition = createTransition(
      loser,
      control(0x51, 'update', id(0xd2)),
    );
    await failingStore.transactionEntered;
    await createTransition(
      winnerCoordinator,
      control(0x52, 'update', id(0xd1)),
    );
    failingStore.release();

    await expect(losingTransition).rejects.toMatchObject({
      code: 'fork-detected',
    });
    const poison = (await winner.rollbackAnchor.load(storeKey))?.forkPoison;
    expect(poison).toMatchObject({
      reason: 'unreconciled-authenticated-candidate',
      epoch: 1n,
    });
    const restartedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(winner, restartedProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(restartedProvider.importCalls).toBe(0);
  });

  test('durably poisons an unreconciled first-anchor candidate', async () => {
    const delegate = new InMemoryGroupStateStore();
    const winner = await context(delegate);
    const failingStore = new ReconciliationLoadFailureStore(delegate);
    const loserContext: TestContext = {
      ...winner,
      provider: new ContractTestProvider(),
      store: failingStore,
      authorization: new AuthorizationPolicy(winner.identities.actorId),
    };
    const losingBootstrap = GroupSecurityCoordinator.bootstrap(
      config(loserContext),
      createGroupInput,
      { operationId: id(2), subjectId: winner.identities.actorId },
    );
    await failingStore.transactionEntered;
    await bootstrap(winner);
    failingStore.release();

    await expect(losingBootstrap).rejects.toMatchObject({
      code: 'fork-detected',
    });
    expect(
      (await winner.rollbackAnchor.load(storeKey))?.forkPoison,
    ).toMatchObject({
      reason: 'unreconciled-first-anchor-candidate',
      epoch: 0n,
      candidateRevision: 1,
    });
    const restartedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(winner, restartedProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(restartedProvider.importCalls).toBe(0);
  });

  test('recovers exact commits when a durable transaction rejects after commit', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const value = await context(store);

    store.throwAfterNextTransaction = true;
    const coordinator = await bootstrap(value);
    expect(coordinator.publicState.epoch).toBe(0n);

    store.throwAfterNextTransaction = true;
    await expect(flushAndCollect(coordinator)).resolves.toHaveLength(1);
    expect(await coordinator.pendingOutboxCount()).toBe(0);

    store.throwAfterNextTransaction = true;
    await expect(
      createTransition(coordinator, control(3)),
    ).resolves.toMatchObject({ status: 'committed' });
    expect(value.provider.importCalls).toBe(0);

    const snapshot = (await delegate.load(storeKey))!;
    const anchor = (await value.rollbackAnchor.load(storeKey))!;
    expect(anchor.revision).toBe(snapshot.revision);
    expect(anchor.storeCommitment).toEqual(
      await groupSecurityStoreSnapshotCommitment(snapshot, storeKey),
    );
    const restored = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(value)),
    );
    expect(restored.publicState.epoch).toBe(1n);
  });

  test('rejects a no-op anchor response instead of claiming an ambiguity was durably poisoned', async () => {
    const delegate = new InMemoryGroupStateStore();
    const anchor = new ControlledRollbackAnchor();
    const winner = await context(delegate);
    winner.rollbackAnchor = anchor;
    const winnerCoordinator = await bootstrap(winner);
    await flushAndCollect(winnerCoordinator);
    const failingStore = new ReconciliationLoadFailureStore(delegate);
    const loserContext: TestContext = {
      ...winner,
      provider: new ContractTestProvider(),
      store: failingStore,
      authorization: new AuthorizationPolicy(winner.identities.actorId),
    };
    const loser = await GroupSecurityCoordinator.restore(config(loserContext));
    const losingTransition = createTransition(
      loser,
      control(0x53, 'update', id(0xd4)),
    );
    await failingStore.transactionEntered;
    await createTransition(
      winnerCoordinator,
      control(0x54, 'update', id(0xd5)),
    );
    anchor.noOpNextPoison = true;
    failingStore.release();

    await expect(losingTransition).rejects.toMatchObject({
      code: 'rollback-failed',
    });
    expect((await anchor.load(storeKey))?.forkPoison).toBeUndefined();
    expect(() => loser.publicState).toThrow(/poisoned/);
  });

  test('retains terminal fork poison when the store audit transaction fails', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new FailOnceStore(delegate);
    const left = await context(store);
    const right: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: left.protector,
      identities: left.identities,
      authorization: new AuthorizationPolicy(left.identities.actorId),
      codec: left.codec,
    };
    const leftCoordinator = await bootstrap(left);
    const rightCoordinator = await bootstrap(right);
    await flushAndCollect(leftCoordinator);
    await flushAndCollect(rightCoordinator);
    await createTransition(leftCoordinator, control(2, 'update', id(0xd1)));
    await createTransition(rightCoordinator, control(3, 'update', id(0xd2)));
    await flushAndCollect(leftCoordinator);
    const [conflict] = await flushAndCollect(rightCoordinator);
    store.failNextTransaction = true;

    await expect(
      leftCoordinator.applyCommit(
        conflict.commit!,
        conflict.controlRecord,
        conflict.welcomes,
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect((await delegate.load(storeKey))?.forkEvidence).toBeUndefined();
    expect(
      (await left.rollbackAnchor.load(storeKey))?.forkPoison,
    ).toBeDefined();

    const restartedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(left, restartedProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(restartedProvider.importCalls).toBe(0);
  });

  test('stops synchronous access as soon as anchor poison wins before audit persistence', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new AdversarialStore(delegate);
    const left = await context(store);
    const right: TestContext = {
      ...left,
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      authorization: new AuthorizationPolicy(left.identities.actorId),
    };
    const leftCoordinator = await bootstrap(left);
    const rightCoordinator = await bootstrap(right);
    await flushAndCollect(leftCoordinator);
    await flushAndCollect(rightCoordinator);
    await createTransition(leftCoordinator, control(0x55, 'update', id(0xd1)));
    await createTransition(rightCoordinator, control(0x56, 'update', id(0xd2)));
    await flushAndCollect(leftCoordinator);
    const [conflict] = await flushAndCollect(rightCoordinator);
    let auditEntered!: () => void;
    const auditStarted = new Promise<void>((resolve) => {
      auditEntered = resolve;
    });
    let releaseAudit!: () => void;
    const auditRelease = new Promise<void>((resolve) => {
      releaseAudit = resolve;
    });
    store.beforeNextTransaction = async () => {
      auditEntered();
      await auditRelease;
    };
    const applying = leftCoordinator.applyCommit(
      conflict.commit!,
      conflict.controlRecord,
      conflict.welcomes,
    );
    await auditStarted;
    expect(() => leftCoordinator.publicState).toThrow(/same-parent/);
    releaseAudit();
    await expect(applying).rejects.toMatchObject({ code: 'fork-detected' });
  });

  test('poisons an authenticated Add sibling before checking its missing Welcome', async () => {
    const left = await context();
    const right: TestContext = {
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      protector: left.protector,
      identities: left.identities,
      authorization: new AuthorizationPolicy(left.identities.actorId),
      codec: left.codec,
    };
    const leftCoordinator = await bootstrap(left);
    const rightCoordinator = await bootstrap(right);
    await flushAndCollect(leftCoordinator);
    await flushAndCollect(rightCoordinator);
    await createTransition(leftCoordinator, control(2, 'add', id(0xd1)));
    await createTransition(rightCoordinator, control(3, 'add', id(0xd2)));
    await flushAndCollect(leftCoordinator);
    const [conflict] = await flushAndCollect(rightCoordinator);
    expect(conflict.welcomes).toHaveLength(1);

    await expect(
      leftCoordinator.applyCommit(conflict.commit!, conflict.controlRecord, []),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(left.provider.applyCommitCalls).toBe(0);
    expect(
      (await left.rollbackAnchor.load(storeKey))?.forkPoison,
    ).toBeDefined();
  });

  test('durably poisons a second authenticated genesis and rejects restart', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    const [genesis] = await flushAndCollect(coordinator);
    const alternateState = {
      ...publicState(0n),
      treeHash: id(0x99),
    };
    const original = genesis.controlRecord;
    const alternate = await signMembershipControlRecord(
      {
        version: original.version,
        protocol: { ...original.protocol },
        groupId: new Uint8Array(original.groupId),
        epoch: 0n,
        operationId: id(0x92),
        action: 'create',
        actorId: new Uint8Array(original.actorId),
        subjectId: new Uint8Array(original.subjectId),
        controlPayload: canonicalGroupSecurityState(alternateState),
      },
      value.identities.sign,
    );

    await expect(
      coordinator.applyCommit(undefined as never, alternate, []),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(
      (await value.rollbackAnchor.load(storeKey))?.forkPoison,
    ).toBeDefined();
    const restartedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(value, restartedProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(restartedProvider.importCalls).toBe(0);
  });

  test('poisons concurrent same-parent commits without requiring loser redelivery', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    const firstProvider = new ContractTestProvider();
    const secondProvider = new ContractTestProvider();
    const first = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(value, firstProvider)),
    );
    const second = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(value, secondProvider)),
    );
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
    firstProvider.createCommitBarrier = barrier;
    secondProvider.createCommitBarrier = barrier;
    const results = await Promise.allSettled([
      createTransition(first, control(2, 'update', id(0xd1))),
      createTransition(second, control(3, 'update', id(0xd2))),
    ]);

    expect(results.some((result) => result.status === 'rejected')).toBe(true);
    expect(
      (await value.rollbackAnchor.load(storeKey))?.forkPoison,
    ).toBeDefined();
    const restartedProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(value, restartedProvider)),
      ),
    ).rejects.toMatchObject({ code: 'fork-detected' });
    expect(restartedProvider.importCalls).toBe(0);
  });
});
