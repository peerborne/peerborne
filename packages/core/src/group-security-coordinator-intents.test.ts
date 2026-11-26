import { describe, expect, test } from '@jest/globals';
import {
  AdversarialStore,
  ContractTestProvider,
  ControlledRollbackAnchor,
  StaticSnapshotStore,
  TestContext,
  bootstrap,
  cloneContextWithProvider,
  config,
  context,
  control,
  createInvitation,
  createTransition,
  flushAndCollect,
  groupId,
  id,
  storeKey,
} from './__testutils__/group-security-coordinator.js';
import { GroupSecurityCoordinator } from './group-security-coordinator.js';
import type { GroupSecurityRollbackIntent } from './group-security-rollback-anchor.js';
import { groupSecurityStoreSnapshotCommitment } from './group-security-store-commitment.js';
import {
  DurableGroupStateStore,
  GroupStateStoreKey,
  GroupStateStoreSnapshot,
  GroupStateStoreTransaction,
  InMemoryGroupStateStore,
} from './group-state-store.js';

class TransientFailureStore implements DurableGroupStateStore {
  failedTransactions = 0;
  failedLoads = 0;
  loadsFailingAfterTransaction = 0;

  constructor(readonly delegate: InMemoryGroupStateStore) {}

  async load(
    key: GroupStateStoreKey,
  ): Promise<GroupStateStoreSnapshot | undefined> {
    if (this.failedLoads > 0) {
      this.failedLoads -= 1;
      throw new Error('injected transient load failure');
    }
    return this.delegate.load(key);
  }

  async transaction<T>(
    key: GroupStateStoreKey,
    operation: (transaction: GroupStateStoreTransaction) => T | Promise<T>,
  ): Promise<T> {
    if (this.failedTransactions > 0) {
      this.failedTransactions -= 1;
      this.failedLoads = this.loadsFailingAfterTransaction;
      throw new Error('injected transient transaction failure');
    }
    return this.delegate.transaction(key, operation);
  }
}

interface Fixture {
  value: TestContext;
  delegate: InMemoryGroupStateStore;
  store: AdversarialStore;
  anchor: ControlledRollbackAnchor;
}

async function fixture(): Promise<Fixture> {
  const delegate = new InMemoryGroupStateStore();
  const store = new AdversarialStore(delegate);
  const value = await context(store);
  const anchor = new ControlledRollbackAnchor();
  value.rollbackAnchor = anchor;
  return { value, delegate, store, anchor };
}

async function restoreFrom(
  value: TestContext,
  snapshot?: GroupStateStoreSnapshot,
  provider = new ContractTestProvider(),
): Promise<GroupSecurityCoordinator> {
  return GroupSecurityCoordinator.restore(
    config({
      ...value,
      provider,
      store:
        snapshot === undefined
          ? value.store
          : new StaticSnapshotStore(snapshot),
    }),
  );
}

async function interruptedTransition(): Promise<
  Fixture & {
    base: GroupStateStoreSnapshot;
    older: GroupStateStoreSnapshot;
    committed: GroupStateStoreSnapshot;
  }
> {
  const setup = await fixture();
  const coordinator = await bootstrap(setup.value);
  await flushAndCollect(coordinator);
  const older = (await setup.delegate.load(storeKey))!;
  await createTransition(coordinator, control(2));
  const base = (await setup.delegate.load(storeKey))!;
  setup.anchor.failNextAdvance = true;
  await expect(createTransition(coordinator, control(3))).rejects.toMatchObject(
    { code: 'rollback-failed' },
  );
  const committed = (await setup.delegate.load(storeKey))!;
  expect(committed.revision).toBe(base.revision + 1);
  expect((await setup.anchor.load(storeKey))?.revision).toBe(base.revision);
  return { ...setup, base, older, committed };
}

describe('GroupSecurityCoordinator write-ahead rollback intents', () => {
  test('restores after an uncommitted transaction and failed reconciliation read with no competing writer', async () => {
    const delegate = new InMemoryGroupStateStore();
    const store = new TransientFailureStore(delegate);
    const value = await context(store);
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);
    const before = (await delegate.load(storeKey))!;
    const beforeAnchor = (await value.rollbackAnchor.load(storeKey))!;

    store.failedTransactions = 1;
    store.loadsFailingAfterTransaction = 1;
    await expect(
      createTransition(coordinator, control(2)),
    ).rejects.toMatchObject({ code: 'rollback-failed' });
    expect(store.failedLoads).toBe(0);
    expect(() => coordinator.publicState).toThrow(/poisoned/);
    expect(await delegate.load(storeKey)).toEqual(before);
    expect(await value.rollbackAnchor.load(storeKey)).toEqual(beforeAnchor);
    expect(
      (await value.rollbackAnchor.loadIntent(storeKey))?.baseRevision,
    ).toBe(before.revision);

    const restored = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(value)),
    );
    expect(restored.publicState.epoch).toBe(0n);
    expect(await value.rollbackAnchor.loadIntent(storeKey)).toBeUndefined();
    await expect(createTransition(restored, control(2))).resolves.toMatchObject(
      { status: 'committed' },
    );
  });

  test('restores after a transient rollback-anchor failure following a committed transition', async () => {
    const value = await context();
    const rollbackAnchor = new ControlledRollbackAnchor();
    value.rollbackAnchor = rollbackAnchor;
    const coordinator = await bootstrap(value);
    await flushAndCollect(coordinator);

    rollbackAnchor.failNextAdvance = true;
    await expect(
      createTransition(coordinator, control(2)),
    ).rejects.toMatchObject({ code: 'rollback-failed' });

    const restored = await GroupSecurityCoordinator.restore(
      config(cloneContextWithProvider(value)),
    );
    expect(restored.publicState.epoch).toBe(1n);
    expect(await restored.pendingOutboxCount()).toBe(1);
    const [delivery] = await flushAndCollect(restored);
    expect(delivery.controlRecord.epoch).toBe(1n);
  });

  const transitionCrashes = {
    'intent write fails before recording': {
      arm: ({ anchor }: Fixture) => {
        anchor.failNextPrepare = true;
      },
      outcome: { code: 'rollback-failed' },
      storeAdvanced: false,
      intentLeft: false,
      usable: true,
    },
    'intent write fails after recording': {
      arm: ({ anchor }: Fixture) => {
        anchor.failNextPrepareAfterWrite = true;
      },
      outcome: { code: 'rollback-failed' },
      storeAdvanced: false,
      intentLeft: true,
      usable: true,
    },
    'store commit fails before writing': {
      arm: ({ store }: Fixture) => {
        store.beforeNextTransaction = async () => {
          throw new Error('injected store failure before commit');
        };
      },
      outcome: { message: 'injected store failure before commit' },
      storeAdvanced: false,
      intentLeft: true,
      usable: true,
    },
    'store commit fails after writing': {
      arm: ({ store }: Fixture) => {
        store.throwAfterNextTransaction = true;
      },
      outcome: undefined,
      storeAdvanced: true,
      intentLeft: false,
      usable: true,
    },
    'anchor advance fails before writing': {
      arm: ({ anchor }: Fixture) => {
        anchor.failNextAdvance = true;
      },
      outcome: { code: 'rollback-failed' },
      storeAdvanced: true,
      intentLeft: true,
      usable: false,
    },
    'anchor advance fails after writing': {
      arm: ({ anchor }: Fixture) => {
        anchor.failNextAdvanceAfterWrite = true;
      },
      outcome: { code: 'rollback-failed' },
      storeAdvanced: true,
      intentLeft: false,
      usable: false,
    },
  } as const;

  test.each(
    Object.keys(transitionCrashes) as Array<keyof typeof transitionCrashes>,
  )('recovers a transition when the %s', async (name) => {
    const crash = transitionCrashes[name];
    const setup = await fixture();
    const coordinator = await bootstrap(setup.value);
    await flushAndCollect(coordinator);
    const before = (await setup.delegate.load(storeKey))!;
    const beforeAnchor = (await setup.anchor.load(storeKey))!;

    crash.arm(setup);
    const attempt = createTransition(coordinator, control(2));
    if (crash.outcome === undefined) {
      await expect(attempt).resolves.toMatchObject({ status: 'committed' });
    } else {
      await expect(attempt).rejects.toMatchObject(crash.outcome);
    }
    const after = (await setup.delegate.load(storeKey))!;
    const anchor = (await setup.anchor.load(storeKey))!;
    const intent = await setup.anchor.loadIntent(storeKey);
    expect(after.revision).toBe(
      before.revision + (crash.storeAdvanced ? 1 : 0),
    );
    if (!crash.storeAdvanced) expect(after).toEqual(before);
    expect(intent !== undefined).toBe(crash.intentLeft);
    if (intent !== undefined) {
      expect(intent.baseRevision).toBe(beforeAnchor.revision);
      expect(intent.baseStoreCommitment).toEqual(beforeAnchor.storeCommitment);
      expect(anchor).toEqual(beforeAnchor);
    }
    if (crash.usable) {
      expect(coordinator.publicState.epoch).toBe(crash.storeAdvanced ? 1n : 0n);
    } else {
      expect(() => coordinator.publicState).toThrow(/poisoned/);
    }

    const provider = new ContractTestProvider();
    const restored = await restoreFrom(setup.value, undefined, provider);
    const epoch = crash.storeAdvanced ? 1n : 0n;
    expect(restored.publicState.epoch).toBe(epoch);
    expect(provider.importCalls).toBe(1);
    expect(await setup.anchor.loadIntent(storeKey)).toBeUndefined();
    const anchored = (await setup.anchor.load(storeKey))!;
    const current = (await setup.delegate.load(storeKey))!;
    expect(anchored.revision).toBe(current.revision);
    expect(anchored.storeCommitment).toEqual(
      await groupSecurityStoreSnapshotCommitment(current, storeKey),
    );
    await expect(createTransition(restored, control(4))).resolves.toMatchObject(
      {
        status: 'committed',
        state: { epoch: epoch + 1n },
      },
    );
  });

  test('replaces a stale uncommitted intent on the next live commit', async () => {
    const setup = await fixture();
    const coordinator = await bootstrap(setup.value);
    await flushAndCollect(coordinator);
    setup.store.beforeNextTransaction = async () => {
      throw new Error('injected store failure before commit');
    };
    await expect(createTransition(coordinator, control(2))).rejects.toThrow(
      /injected store failure/,
    );
    const stale = (await setup.anchor.loadIntent(storeKey))!;

    await createTransition(coordinator, control(3));
    expect(setup.anchor.prepared).toHaveLength(4);
    expect(setup.anchor.prepared.at(-1)).not.toEqual(stale);
    expect(await setup.anchor.loadIntent(storeKey)).toBeUndefined();
    const restored = await restoreFrom(setup.value);
    expect(restored.currentControlRecord.operationId).toEqual(id(3));
  });

  const firstAnchorCrashes = {
    'intent write fails before recording': {
      arm: ({ anchor }: Fixture) => {
        anchor.failNextPrepare = true;
      },
      groupStored: false,
    },
    'intent write fails after recording': {
      arm: ({ anchor }: Fixture) => {
        anchor.failNextPrepareAfterWrite = true;
      },
      groupStored: false,
    },
    'store commit fails before writing': {
      arm: ({ store }: Fixture) => {
        store.beforeNextTransaction = async () => {
          throw new Error('injected store failure before commit');
        };
      },
      groupStored: false,
    },
    'anchor advance fails before writing': {
      arm: ({ anchor }: Fixture) => {
        anchor.failNextAdvance = true;
      },
      groupStored: true,
    },
    'anchor advance fails after writing': {
      arm: ({ anchor }: Fixture) => {
        anchor.failNextAdvanceAfterWrite = true;
      },
      groupStored: true,
    },
  } as const;

  test.each(
    Object.keys(firstAnchorCrashes) as Array<keyof typeof firstAnchorCrashes>,
  )('recovers a bootstrap when the %s', async (name) => {
    const crash = firstAnchorCrashes[name];
    const setup = await fixture();
    crash.arm(setup);
    await expect(bootstrap(setup.value)).rejects.toBeDefined();
    const stored = await setup.delegate.load(storeKey);
    expect(stored?.encryptedState !== undefined).toBe(crash.groupStored);

    if (crash.groupStored) {
      const restored = await restoreFrom(setup.value);
      expect(restored.publicState.epoch).toBe(0n);
      expect(await setup.anchor.loadIntent(storeKey)).toBeUndefined();
      expect((await setup.anchor.load(storeKey))?.storeCommitment).toEqual(
        await groupSecurityStoreSnapshotCommitment(stored!, storeKey),
      );
      return;
    }
    await expect(restoreFrom(setup.value)).rejects.toMatchObject({
      code: 'not-initialized',
    });
    expect(await setup.anchor.load(storeKey)).toBeUndefined();
    expect(await setup.anchor.loadIntent(storeKey)).toBeUndefined();
    const rebuilt = await bootstrap(cloneContextWithProvider(setup.value));
    expect(rebuilt.publicState.epoch).toBe(0n);
  });

  test('completes interrupted outbox ACK and restore-pruning commits', async () => {
    const ack = await fixture();
    const acking = await bootstrap(ack.value);
    ack.anchor.failNextAdvance = true;
    await expect(flushAndCollect(acking)).rejects.toMatchObject({
      code: 'rollback-failed',
    });
    expect((await ack.delegate.load(storeKey))!.outbox).toHaveLength(0);
    expect(await ack.anchor.loadIntent(storeKey)).toBeDefined();
    const ackRestored = await restoreFrom(ack.value);
    expect(await ackRestored.pendingOutboxCount()).toBe(0);

    const pruning = await fixture();
    const coordinator = await bootstrap(pruning.value, {
      maxReplayEntries: 8,
      replayWindowEpochs: 4n,
    });
    await flushAndCollect(coordinator);
    for (let operation = 2; operation <= 4; operation++) {
      await createTransition(coordinator, control(operation));
      await flushAndCollect(coordinator);
    }
    const before = (await pruning.delegate.load(storeKey))!;
    const narrow = (provider = new ContractTestProvider()) =>
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(pruning.value, provider), {
          maxReplayEntries: 8,
          replayWindowEpochs: 1n,
        }),
      );
    pruning.anchor.failNextAdvance = true;
    await expect(narrow()).rejects.toMatchObject({ code: 'rollback-failed' });
    const pruned = (await pruning.delegate.load(storeKey))!;
    expect(pruned.revision).toBe(before.revision + 1);
    expect(pruned.replay.map((entry) => entry.epoch)).toEqual([2n, 3n]);
    const restored = await narrow();
    expect(restored.publicState.epoch).toBe(3n);
    expect((await pruning.anchor.load(storeKey))?.revision).toBe(
      pruned.revision,
    );
    expect(await pruning.anchor.loadIntent(storeKey)).toBeUndefined();
  });

  test('rejects stale and relabeled stores while an intent is pending', async () => {
    const setup = await interruptedTransition();
    const candidates = [
      setup.older,
      { ...setup.older, revision: setup.committed.revision },
      { ...setup.base, revision: setup.committed.revision },
    ];
    for (const snapshot of candidates) {
      const provider = new ContractTestProvider();
      await expect(
        restoreFrom(setup.value, snapshot, provider),
      ).rejects.toMatchObject({ code: 'rollback-detected' });
      expect(provider.importCalls).toBe(0);
    }
    expect(await setup.anchor.loadIntent(storeKey)).toBeDefined();
    const restored = await restoreFrom(setup.value);
    expect(restored.publicState.epoch).toBe(2n);
  });

  test('rejects a next store state other than the one the intent names', async () => {
    const setup = await interruptedTransition();
    expect(setup.committed.outbox.length).toBeGreaterThan(0);
    const substitutes: GroupStateStoreSnapshot[] = [
      { ...setup.committed, outbox: [] },
      { ...setup.committed, outbox: setup.committed.outbox.slice(1) },
      { ...setup.committed, replay: setup.base.replay },
      { ...setup.base, revision: setup.committed.revision, outbox: [] },
    ];
    for (const snapshot of substitutes) {
      const provider = new ContractTestProvider();
      await expect(
        restoreFrom(setup.value, snapshot, provider),
      ).rejects.toMatchObject({ code: 'rollback-detected' });
      expect(provider.importCalls).toBe(0);
      expect((await setup.anchor.load(storeKey))?.revision).toBe(
        setup.base.revision,
      );
      expect(await setup.anchor.loadIntent(storeKey)).toBeDefined();
    }
    const restored = await restoreFrom(setup.value);
    expect(restored.publicState.epoch).toBe(2n);
    expect(await restored.pendingOutboxCount()).toBe(
      setup.committed.outbox.length,
    );
  });

  test('never completes an intent after restore discards it for the base store', async () => {
    const setup = await interruptedTransition();
    const atBase = await restoreFrom(setup.value, setup.base);
    expect(atBase.publicState.epoch).toBe(1n);
    expect(await setup.anchor.loadIntent(storeKey)).toBeUndefined();

    const provider = new ContractTestProvider();
    await expect(
      restoreFrom(setup.value, setup.committed, provider),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(provider.importCalls).toBe(0);
  });

  test('rejects replayed and tampered intents before provider import', async () => {
    const setup = await interruptedTransition();
    const pending = (await setup.anchor.loadIntent(storeKey))!;
    const replayed: GroupSecurityRollbackIntent = setup.anchor.prepared.at(-2)!;
    expect(replayed.baseRevision).toBeLessThan(pending.baseRevision);
    const flipped = (bytes: Uint8Array) => {
      const copy = new Uint8Array(bytes);
      copy[0] ^= 0xff;
      return copy;
    };
    const tampered: Array<[unknown, RegExp]> = [
      [replayed, /does not extend/],
      [
        {
          ...pending,
          baseStoreCommitment: flipped(pending.baseStoreCommitment!),
        },
        /does not extend/,
      ],
      [
        {
          ...pending,
          next: { ...pending.next, epoch: pending.next.epoch + 1n },
        },
        /does not extend/,
      ],
      [
        {
          ...pending,
          next: { ...pending.next, revision: pending.next.revision + 1 },
        },
        /malformed/,
      ],
      [{ ...pending, extra: true }, /malformed/],
      [
        {
          ...pending,
          next: {
            ...pending.next,
            forkPoison: {
              epoch: pending.next.epoch,
              parentRecordId: id(1),
              firstRecordId: id(2),
              secondRecordId: id(3),
              evidenceHash: id(4),
            },
          },
        },
        /malformed/,
      ],
    ];
    for (const [intent, message] of tampered) {
      setup.anchor.malformedNextIntent = intent;
      const provider = new ContractTestProvider();
      await expect(
        restoreFrom(setup.value, undefined, provider),
      ).rejects.toMatchObject({
        code: 'rollback-detected',
        message: expect.stringMatching(message),
      });
      expect(provider.importCalls).toBe(0);
    }

    setup.anchor.malformedNextIntent = {
      ...pending,
      next: {
        ...pending.next,
        storeCommitment: flipped(pending.next.storeCommitment),
      },
    };
    const provider = new ContractTestProvider();
    await expect(
      restoreFrom(setup.value, undefined, provider),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(provider.importCalls).toBe(0);
    expect(await setup.anchor.loadIntent(storeKey)).toEqual(pending);

    const restored = await restoreFrom(setup.value);
    expect(restored.publicState.epoch).toBe(2n);
  });

  test('keeps restore retryable when resolving an intent fails', async () => {
    const completing = await interruptedTransition();
    completing.anchor.failNextAdvance = true;
    await expect(restoreFrom(completing.value)).rejects.toMatchObject({
      code: 'rollback-failed',
    });
    expect(await completing.anchor.loadIntent(storeKey)).toBeDefined();
    expect((await restoreFrom(completing.value)).publicState.epoch).toBe(2n);

    const discarding = await interruptedTransition();
    discarding.anchor.failNextDiscard = true;
    await expect(
      restoreFrom(discarding.value, discarding.base),
    ).rejects.toMatchObject({ code: 'rollback-failed' });
    expect(await discarding.anchor.loadIntent(storeKey)).toBeDefined();
    expect(
      (await restoreFrom(discarding.value, discarding.base)).publicState.epoch,
    ).toBe(1n);
  });

  test('keeps queued outbox entries when an interrupted ACK is discarded', async () => {
    const setup = await fixture();
    const coordinator = await bootstrap(setup.value);
    const queued = (await setup.delegate.load(storeKey))!;
    expect(queued.outbox).toHaveLength(1);
    setup.anchor.failNextAdvance = true;
    await expect(flushAndCollect(coordinator)).rejects.toMatchObject({
      code: 'rollback-failed',
    });

    const restored = await restoreFrom(setup.value, queued);
    expect(await restored.pendingOutboxCount()).toBe(1);
    expect(await setup.anchor.loadIntent(storeKey)).toBeUndefined();
    await expect(
      restoreFrom(setup.value, (await setup.delegate.load(storeKey))!),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
  });

  test('never makes a consumed KeyPackage pending again', async () => {
    const setup = await fixture();
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      config(setup.value),
      {
        operationId: id(0xdb),
        groupId,
        memberId: setup.value.identities.actorId,
        credential: setup.value.identities.actorId,
      },
    );
    const pending = (await setup.delegate.load(storeKey))!;
    const invitation = await createInvitation(setup.value, keyPackage);
    setup.anchor.failNextAdvance = true;
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config(cloneContextWithProvider(setup.value)),
        invitation,
      ),
    ).rejects.toMatchObject({ code: 'rollback-failed' });
    const joined = (await setup.delegate.load(storeKey))!;
    expect(joined.consumedKeyPackageRefs).toEqual([keyPackage.reference]);
    expect(await setup.anchor.load(storeKey)).toBeUndefined();
    expect(await setup.anchor.loadIntent(storeKey)).toMatchObject({
      baseRevision: pending.revision,
      baseStoreCommitment: await groupSecurityStoreSnapshotCommitment(
        pending,
        storeKey,
      ),
    });

    const resurrected = {
      ...joined,
      pendingKeyPackages: pending.pendingKeyPackages,
      pendingKeyPackageRequests: pending.pendingKeyPackageRequests,
      consumedKeyPackageRefs: [],
    };
    const rejectedProvider = new ContractTestProvider();
    await expect(
      restoreFrom(setup.value, resurrected, rejectedProvider),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(rejectedProvider.importCalls).toBe(0);
    expect(await setup.anchor.loadIntent(storeKey)).toBeDefined();

    const restored = await restoreFrom(setup.value);
    expect(restored.publicState.epoch).toBe(1n);
    const rejoinProvider = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.joinFromInvitation(
        config({
          ...setup.value,
          provider: rejoinProvider,
          store: new StaticSnapshotStore(pending),
        }),
        invitation,
      ),
    ).rejects.toMatchObject({ code: 'rollback-detected' });
    expect(rejoinProvider.importKeyPackageCalls).toBe(0);
  });
});
