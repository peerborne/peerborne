import { describe, expect, test } from '@jest/globals';
import {
  ContractTestProvider,
  ControlledRollbackAnchor,
  bootstrap,
  cloneContextWithProvider,
  config,
  context,
  control,
  flushAndCollect,
  id,
  storeKey,
} from './__testutils__/group-security-coordinator.js';
import { GroupSecurityCoordinator } from './group-security-coordinator.js';
import type {
  GroupSecurityProvider,
  GroupSecurityRemovedApplyResult,
} from './group-security-provider.js';
import { publicState } from './__testutils__/group-security-coordinator.js';
import { InMemoryGroupStateStore } from './group-state-store.js';

async function fixture(
  overrides: Partial<GroupSecurityRemovedApplyResult> = {},
  erase = true,
) {
  const source = await context();
  const author = await bootstrap(source);
  const snapshot = (await source.store.load(storeKey))!;
  const position = (await source.rollbackAnchor.load(storeKey))!;
  await flushAndCollect(author);
  await author.createCommit(
    { changes: [{ kind: 'remove', memberId: source.identities.actorId }] },
    control(2, 'remove', source.identities.actorId),
  );
  const [delivery] = await flushAndCollect(author);
  const anchor = new ControlledRollbackAnchor();
  const receiver = {
    ...cloneContextWithProvider(source, new ContractTestProvider()),
    store: new InMemoryGroupStateStore(),
    rollbackAnchor: anchor,
  };
  await receiver.store.transaction(storeKey, (transaction) => {
    transaction.setEncryptedState(snapshot.encryptedState!);
    for (const entry of snapshot.replay) transaction.markReplay(entry);
    for (const entry of snapshot.outbox) transaction.enqueueOutbox(entry);
  });
  await anchor.advance(storeKey, undefined, position);
  const coordinator = await GroupSecurityCoordinator.restore(config(receiver));
  const apply = receiver.provider.applyCommit.bind(receiver.provider);
  const provider: GroupSecurityProvider = receiver.provider;
  provider.applyCommit = async (commit) => {
    const accepted = await apply(commit);
    if (erase) await receiver.provider.clearGroupState();
    return {
      status: 'removed',
      memberId: receiver.identities.actorId,
      appliedMembership: accepted.appliedMembership,
      ...overrides,
    };
  };
  return { coordinator, receiver, anchor, delivery };
}

describe('GroupSecurityCoordinator terminal removal', () => {
  test('anchors a verified local removal without importing or inventing next-epoch private state', async () => {
    const { coordinator, receiver, anchor, delivery } = await fixture();
    const imports = receiver.provider.importCalls;
    const result = await coordinator.applyCommit(
      delivery.commit!,
      delivery.controlRecord,
      [],
    );
    expect(result.status).toBe('removed');
    expect(receiver.provider.importCalls).toBe(imports);
    expect(await receiver.provider.hasActiveGroup()).toBe(false);
    expect((await anchor.load(storeKey))?.removal).toMatchObject({
      epoch: 1n,
      memberId: receiver.identities.actorId,
      recordId: result.recordId,
    });
    expect(() => coordinator.publicState).toThrow(/removed/);
    await expect(
      coordinator.createCommit(
        { changes: [] },
        control(3, 'update', receiver.identities.actorId),
      ),
    ).rejects.toMatchObject({ code: 'removed-from-group' });
    const fresh = new ContractTestProvider();
    await expect(
      GroupSecurityCoordinator.restore(
        config(cloneContextWithProvider(receiver, fresh)),
      ),
    ).rejects.toMatchObject({ code: 'removed-from-group' });
    expect(fresh.importCalls).toBe(0);
    expect(
      (await receiver.store.load(storeKey))?.encryptedState?.state.epoch,
    ).toBe(0n);
  });

  test.each([
    { memberId: id(0xee) },
    { appliedMembership: { changes: [] } },
    {
      appliedMembership: {
        changes: [{ kind: 'remove' as const, memberId: id(0xee) }],
      },
    },
  ])(
    'rejects a mismatched removed-member result before retirement: %#',
    async (overrides) => {
      const { coordinator, receiver, anchor, delivery } =
        await fixture(overrides);
      await expect(
        coordinator.applyCommit(delivery.commit!, delivery.controlRecord, []),
      ).rejects.toMatchObject({ code: 'control-mismatch' });
      expect((await anchor.load(storeKey))?.removal).toBeUndefined();
      expect(coordinator.publicState.epoch).toBe(0n);
      expect((await receiver.provider.getPublicState()).epoch).toBe(0n);
    },
  );

  test('rejects a removed result that reports invented next-epoch state', async () => {
    const invalid = { status: 'removed' as const, state: publicState(1n) };
    const { coordinator, anchor, delivery } = await fixture(invalid);
    await expect(
      coordinator.applyCommit(delivery.commit!, delivery.controlRecord, []),
    ).rejects.toThrow(/cannot report a next-epoch state/);
    expect((await anchor.load(storeKey))?.removal).toBeUndefined();
    expect(coordinator.publicState.epoch).toBe(0n);
  });

  test('rejects a provider that reports removal while retaining active private state', async () => {
    const { coordinator, anchor, delivery } = await fixture({}, false);
    await expect(
      coordinator.applyCommit(delivery.commit!, delivery.controlRecord, []),
    ).rejects.toMatchObject({ code: 'control-mismatch' });
    expect((await anchor.load(storeKey))?.removal).toBeUndefined();
    expect(coordinator.publicState.epoch).toBe(0n);
  });

  test.each(['failNextRetire', 'noOpNextRetire', 'rejectNextRetire'] as const)(
    'fails closed without restoring removed private state when %s',
    async (flag) => {
      const { coordinator, receiver, anchor, delivery } = await fixture();
      const imports = receiver.provider.importCalls;
      anchor[flag] = true;
      await expect(
        coordinator.applyCommit(delivery.commit!, delivery.controlRecord, []),
      ).rejects.toMatchObject({ code: 'rollback-failed' });
      expect(await receiver.provider.hasActiveGroup()).toBe(false);
      expect(receiver.provider.importCalls).toBe(imports);
      await expect(
        coordinator.createCommit(
          { changes: [] },
          control(3, 'update', receiver.identities.actorId),
        ),
      ).rejects.toMatchObject({ code: 'removed-from-group' });
    },
  );
});
