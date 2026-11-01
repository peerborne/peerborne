import { describe, expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import {
  AuthorizationPolicy,
  ContractTestProvider,
  bootstrap,
  config,
  context,
  control,
  createGroupInput,
  flushAndCollect,
  id,
  storeKey,
} from './__testutils__/group-security-coordinator.js';
import { GroupSecurityCoordinator } from './group-security-coordinator.js';
import { InMemoryGroupStateStore } from './group-state-store.js';
import { InMemoryGroupSecurityRollbackAnchor } from './group-security-rollback-anchor.js';
import type { GroupWelcome } from './group-security-provider.js';

const prepared = (
  commit: () => void = () => {},
  isAuthorizationCurrent: () => boolean = () => true,
) => ({ commit, isAuthorizationCurrent });

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}

async function sourceDelivery() {
  const source = await context();
  const sender = await bootstrap(source);
  await flushAndCollect(sender);
  await sender.createCommit(
    { changes: [] },
    control(2, 'update', source.identities.actorId),
  );
  const [delivery] = await flushAndCollect(sender);
  return { source, delivery };
}

async function fixture(
  countLimit: number,
  byteLimit = 1024 * 1024,
  invalidSignature = false,
  base?: Awaited<ReturnType<typeof sourceDelivery>>,
) {
  const initial = base ?? (await sourceDelivery());
  const source = initial.source;
  const delivery = {
    ...initial.delivery,
    controlRecord: { ...initial.delivery.controlRecord },
  };
  if (invalidSignature)
    Object.assign(delivery.controlRecord, {
      signature: new Uint8Array([0xde, 0xad]),
    });
  const target = {
    ...source,
    provider: new ContractTestProvider(),
    store: new InMemoryGroupStateStore(),
    rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
    authorization: new AuthorizationPolicy(source.identities.actorId),
  };
  const entered = deferred();
  const authenticated = deferred();
  const release = deferred();
  let held = false;
  let trusted = true;
  let calls = 0;
  const coordinator = await GroupSecurityCoordinator.bootstrap(
    {
      ...config(target),
      maxPendingControlOperations: countLimit,
      maxPendingControlBytes: byteLimit,
      verifyControlSignature: async (payload, signature, actor) => {
        if (held && (!invalidSignature || signature.length === 2)) {
          calls += 1;
          entered.resolve();
          await release.promise;
        }
        const valid = await source.identities.verify(payload, signature, actor);
        const accepted = trusted && valid;
        if (held && accepted) authenticated.resolve();
        return accepted;
      },
    },
    createGroupInput,
    { operationId: id(1), subjectId: source.identities.actorId },
  );
  held = true;
  return {
    coordinator,
    target,
    delivery,
    entered,
    authenticated,
    release,
    calls: () => calls,
    revokeTrust: () => {
      trusted = false;
    },
  };
}

describe('control ingress admission', () => {
  test('rechecks mutable application trust after preauthentication while a delivery waits for adoption', async () => {
    const value = await fixture(1);
    const queueEntered = deferred();
    const queueRelease = deferred();
    const originalLoad = value.target.store.load.bind(value.target.store);
    const load = jest
      .spyOn(value.target.store, 'load')
      .mockImplementationOnce(async (key) => {
        queueEntered.resolve();
        await queueRelease.promise;
        return originalLoad(key);
      });
    const blocker = value.coordinator.pendingOutboxCount();
    await queueEntered.promise;
    const pending = value.coordinator
      .applyCommit(value.delivery.commit!, value.delivery.controlRecord, [])
      .then(
        (result) => result.status,
        (error: { code: string }) => error.code,
      );
    try {
      value.release.resolve();
      await value.authenticated.promise;
      value.revokeTrust();
      queueRelease.resolve();
      await blocker;
      expect(await pending).toBe('bad-signature');
      expect(value.coordinator.publicState.epoch).toBe(0n);
      expect(value.target.provider.applyCommitCalls).toBe(0);
      expect(value.coordinator.pendingControlOperations.operations).toBe(0);
    } finally {
      queueRelease.resolve();
      value.release.resolve();
      await Promise.allSettled([blocker, pending]);
      load.mockRestore();
    }
  });
  test('bounds suspended native signature work without blocking document finalization', async () => {
    const base = await sourceDelivery();
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 4 }),
        fc.integer({ min: 1, max: 10 }),
        async (capacity, incoming) => {
          const value = await fixture(capacity, 1024 * 1024, false, base);
          const { coordinator, delivery } = value;
          const results: Array<Promise<string>> = [];
          try {
            for (let index = 0; index < incoming; index++) {
              results.push(
                coordinator
                  .applyCommit(delivery.commit!, delivery.controlRecord, [])
                  .then(
                    (result) => result.status,
                    (error: { code: string }) => error.code,
                  ),
              );
              expect(coordinator.pendingControlOperations.operations).toBe(
                Math.min(index + 1, capacity),
              );
              expect(
                coordinator.pendingControlOperations.bytes,
              ).toBeLessThanOrEqual(1024 * 1024);
            }
            await value.entered.promise;
            expect(value.calls()).toBe(Math.min(incoming, capacity));
            let documentApplied = false;
            await coordinator.runDocumentOperation(
              coordinator.documentContext,
              new Uint8Array([1]),
              async () =>
                prepared(() => {
                  documentApplied = true;
                }),
            );
            expect(documentApplied).toBe(true);
            expect(coordinator.publicState.epoch).toBe(0n);
            value.release.resolve();
            const statuses = await Promise.all(results);
            expect(
              statuses.filter((status) => status === 'committed'),
            ).toHaveLength(1);
            expect(
              statuses.filter((status) => status === 'duplicate'),
            ).toHaveLength(Math.min(incoming, capacity) - 1);
            expect(
              statuses.filter((status) => status === 'admission-capacity'),
            ).toHaveLength(Math.max(0, incoming - capacity));
            expect(value.target.provider.applyCommitCalls).toBe(1);
            expect(coordinator.pendingControlOperations).toEqual({
              operations: 0,
              bytes: 0,
            });
          } finally {
            value.release.resolve();
            await Promise.allSettled(results);
          }
        },
      ),
      { seed: 2011104, numRuns: 40 },
    );
  });

  test('allows a local ratchet to finish while an invalid remote signature remains suspended', async () => {
    const value = await fixture(1, 1024 * 1024, true);
    const { coordinator, delivery } = value;
    const pending = coordinator
      .applyCommit(delivery.commit!, delivery.controlRecord, [])
      .catch((error: { code: string }) => error.code);
    try {
      await value.entered.promise;
      await coordinator.createCommit(
        { changes: [] },
        control(3, 'update', value.target.identities.actorId),
      );
      expect(coordinator.publicState.epoch).toBe(1n);
      value.release.resolve();
      expect(await pending).toBe('bad-signature');
      expect(coordinator.publicState.epoch).toBe(1n);
      expect(coordinator.pendingControlOperations.operations).toBe(0);
    } finally {
      value.release.resolve();
      await pending;
    }
  });

  test('rejects a byte-budget overflow before crypto and releases both reservations', async () => {
    const value = await fixture(2, 1);
    const { coordinator, delivery } = value;
    await expect(
      coordinator.applyCommit(delivery.commit!, delivery.controlRecord, []),
    ).rejects.toMatchObject({ code: 'admission-capacity' });
    expect(value.calls()).toBe(0);
    expect(coordinator.pendingControlOperations).toEqual({
      operations: 0,
      bytes: 0,
    });
  });

  test('charges and copies the same captured proxy fields', async () => {
    const base = await sourceDelivery();
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom('control', 'commit', 'welcome'),
        fc.integer({ min: 1024, max: 64 * 1024 }),
        fc.boolean(),
        async (field, expansion, resizeDuringCapture) => {
          const value = await fixture(1, 1024 * 1024, false, base);
          const originalLength =
            value.delivery.controlRecord.controlPayload.length;
          const backing = new ArrayBuffer(originalLength, {
            maxByteLength: originalLength + expansion,
          });
          const tracking = new Uint8Array(backing);
          tracking.set(value.delivery.controlRecord.controlPayload);
          const originalControl = {
            ...value.delivery.controlRecord,
            controlPayload: tracking,
          };
          const originalCommit = value.delivery.commit!;
          const originalWelcome: GroupWelcome = {
            protocol: originalCommit.protocol,
            groupId: originalCommit.groupId,
            epoch: originalCommit.epoch,
            recipientKeyPackageRef: id(5),
            payload: new Uint8Array(1),
          };
          let reads = 0;
          const replacing = <T extends object>(
            target: T,
            property: string,
            onPayload?: () => void,
          ): T =>
            new Proxy(
              { ...target },
              {
                getOwnPropertyDescriptor(object, key) {
                  if (key === 'payload') onPayload?.();
                  const descriptor = Reflect.getOwnPropertyDescriptor(
                    object,
                    key,
                  );
                  if (key !== property) return descriptor;
                  reads += 1;
                  return {
                    ...descriptor,
                    value:
                      reads === 1
                        ? descriptor!.value
                        : new Uint8Array(expansion),
                  };
                },
              },
            );
          const incomingControl =
            field === 'control'
              ? replacing(originalControl, 'controlPayload')
              : originalControl;
          const incomingCommit = resizeDuringCapture
            ? replacing(
                originalCommit,
                field === 'commit' ? 'payload' : '',
                () => backing.resize(originalLength + expansion),
              )
            : field === 'commit'
              ? replacing(originalCommit, 'payload')
              : originalCommit;
          const welcomes =
            field === 'welcome' ? [replacing(originalWelcome, 'payload')] : [];
          const charge =
            4096 +
            originalControl.groupId.length +
            originalControl.operationId.length +
            originalControl.actorId.length +
            originalControl.subjectId.length +
            originalControl.controlPayload.length +
            originalControl.signature.length +
            (originalControl.parentRecordId?.length ?? 0) +
            4096 +
            originalCommit.groupId.length +
            originalCommit.payload.length +
            (field === 'welcome'
              ? 512 +
                originalWelcome.groupId.length +
                originalWelcome.recipientKeyPackageRef.length +
                1
              : 0);
          const pending = value.coordinator
            .applyCommit(incomingCommit, incomingControl, welcomes)
            .then(
              (result) => result.status,
              (error: { code: string }) => error.code,
            );
          try {
            await Promise.race([
              value.entered.promise,
              pending.then((code) => {
                throw new Error(`authentication did not start: ${code}`);
              }),
            ]);
            expect(reads).toBe(1);
            expect(value.coordinator.pendingControlOperations).toEqual({
              operations: 1,
              bytes: charge,
            });
            value.release.resolve();
            expect(await pending).toBe(
              field === 'welcome' ? 'control-mismatch' : 'committed',
            );
            expect(reads).toBe(1);
            expect(value.coordinator.pendingControlOperations).toEqual({
              operations: 0,
              bytes: 0,
            });
          } finally {
            value.release.resolve();
            await pending;
          }
        },
      ),
      { seed: 2011107, numRuns: 30 },
    );
  });

  test('bounds aliased Welcome sets returned by a decoder before visiting the whole set', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 8192, max: 65536 }),
        async (payloadBytes) => {
          const value = await context();
          const coordinator = await bootstrap(value);
          await flushAndCollect(coordinator);
          await coordinator.createCommit(
            { changes: [] },
            control(2, 'update', value.identities.actorId),
          );
          const entry = (await value.store.load(storeKey))!.outbox[0];
          const delivery = value.codec.decode(entry.payload);
          const welcome: GroupWelcome = {
            protocol: delivery.commit!.protocol,
            groupId: delivery.commit!.groupId,
            epoch: delivery.commit!.epoch,
            recipientKeyPackageRef: id(5),
            payload: new Uint8Array(payloadBytes),
          };
          const count = Math.floor((1024 * 1024) / payloadBytes) + 4;
          const welcomes = Array<GroupWelcome>(count).fill(welcome);
          let lateVisits = 0;
          welcomes[count - 1] = new Proxy(welcome, {
            getOwnPropertyDescriptor() {
              lateVisits += 1;
              throw new Error('late synthetic descriptor');
            },
          });
          const decode = jest
            .spyOn(value.codec, 'decode')
            .mockImplementation(() => ({ ...delivery, welcomes }));
          try {
            await expect(flushAndCollect(coordinator)).rejects.toBeDefined();
            expect(lateVisits).toBe(0);
            expect(coordinator.publicState.epoch).toBe(1n);
          } finally {
            decode.mockRestore();
          }
        },
      ),
      { seed: 2011105, numRuns: 35 },
    );
  });
});
