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

  test('quarantines unobservable work at every verifier and authorizer position during admission', async () => {
    const base = await sourceDelivery();
    const source = base.source;
    const targetContext = () => ({
      ...source,
      provider: new ContractTestProvider(),
      store: new InMemoryGroupStateStore(),
      rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
      authorization: new AuthorizationPolicy(source.identities.actorId),
    });
    const baselineConfig = config(targetContext());
    const counts = { signature: 0, authorization: 0 };
    let measuring = false;
    const baseline = await GroupSecurityCoordinator.bootstrap(
      {
        ...baselineConfig,
        verifyControlSignature: (...args) => {
          if (measuring) counts.signature++;
          return baselineConfig.verifyControlSignature(...args);
        },
        authorizeControl: (...args) => {
          if (measuring) counts.authorization++;
          return baselineConfig.authorizeControl(...args);
        },
      },
      createGroupInput,
      { operationId: id(1), subjectId: source.identities.actorId },
    );
    measuring = true;
    await baseline.applyCommit(
      base.delivery.commit!,
      base.delivery.controlRecord,
      [],
    );
    expect(counts.signature).toBeGreaterThan(1);
    expect(counts.authorization).toBeGreaterThan(0);
    const maximum = Math.max(counts.signature, counts.authorization);
    expect(maximum).toBeLessThanOrEqual(16);
    const examples: Array<['signature' | 'authorization', number]> = [];
    for (const kind of ['signature', 'authorization'] as const)
      for (let position = 1; position <= counts[kind]; position++)
        examples.push([kind, position]);
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom('signature', 'authorization'),
        fc.integer({ min: 1, max: maximum }),
        async (kind, choice) => {
          const position = ((choice - 1) % counts[kind]) + 1;
          const native = config(targetContext());
          const release = deferred();
          const finished = deferred();
          let enabled = false;
          let accessorReads = 0;
          const calls = { signature: 0, authorization: 0 };
          const selected = (candidate: typeof kind) =>
            enabled && ++calls[candidate] === position && candidate === kind;
          const blocked = (run: () => boolean | Promise<boolean>) => {
            const pending = release.promise.then(async () => {
              try {
                return await run();
              } finally {
                finished.resolve();
              }
            });
            Object.defineProperty(pending, 'constructor', {
              get() {
                accessorReads++;
                throw new Error('must not inspect');
              },
            });
            return pending;
          };
          const coordinator = await GroupSecurityCoordinator.bootstrap(
            {
              ...native,
              maxPendingControlOperations: 1,
              verifyControlSignature: (...args) =>
                selected('signature')
                  ? blocked(() => native.verifyControlSignature(...args))
                  : native.verifyControlSignature(...args),
              authorizeControl: (...args) =>
                selected('authorization')
                  ? blocked(() => native.authorizeControl(...args))
                  : native.authorizeControl(...args),
            },
            createGroupInput,
            { operationId: id(1), subjectId: source.identities.actorId },
          );
          enabled = true;
          try {
            await expect(
              coordinator.applyCommit(
                base.delivery.commit!,
                base.delivery.controlRecord,
                [],
              ),
            ).rejects.toMatchObject({
              code:
                kind === 'signature' ? 'bad-signature' : 'unauthorized-control',
            });
            expect(coordinator.pendingControlOperations.operations).toBe(1);
            await expect(
              coordinator.applyCommit(
                base.delivery.commit!,
                base.delivery.controlRecord,
                [],
              ),
            ).rejects.toBeDefined();
            expect(calls[kind]).toBeGreaterThanOrEqual(position);
          } finally {
            release.resolve();
            await finished.promise;
            await coordinator.pendingOutboxCount().catch(() => {});
          }
          expect(accessorReads).toBe(0);
          expect(coordinator.pendingControlOperations.operations).toBe(1);
        },
      ),
      { seed: 2011109, numRuns: 12, examples },
    );
  });

  test('rejects boxed non-boolean verifier values before an async return can assimilate them', async () => {
    const base = await sourceDelivery();
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom('then-getter', 'then-function', 'number', 'object'),
        fc.constantFrom('signature', 'authorization'),
        async (kind, boundary) => {
          const target = {
            ...base.source,
            provider: new ContractTestProvider(),
            store: new InMemoryGroupStateStore(),
            rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
            authorization: new AuthorizationPolicy(
              base.source.identities.actorId,
            ),
          };
          const native = config(target);
          let enabled = false;
          let hookCalls = 0;
          const invalidResult = () => {
            const value = kind === 'number' ? 1 : {};
            const result = Promise.resolve(value);
            if (kind === 'then-getter')
              Object.defineProperty(value, 'then', {
                get() {
                  hookCalls++;
                  return (resolve: (value: boolean) => void) => resolve(true);
                },
              });
            if (kind === 'then-function')
              Object.defineProperty(value, 'then', {
                value(resolve: (value: boolean) => void) {
                  hookCalls++;
                  resolve(true);
                },
              });
            return result as unknown as Promise<boolean>;
          };
          const coordinator = await GroupSecurityCoordinator.bootstrap(
            {
              ...native,
              verifyControlSignature: (...args) => {
                if (!enabled || boundary !== 'signature')
                  return native.verifyControlSignature(...args);
                return invalidResult();
              },
              authorizeControl: (...args) =>
                !enabled || boundary !== 'authorization'
                  ? native.authorizeControl(...args)
                  : invalidResult(),
            },
            createGroupInput,
            { operationId: id(1), subjectId: base.source.identities.actorId },
          );
          enabled = true;
          await expect(
            coordinator.applyCommit(
              base.delivery.commit!,
              base.delivery.controlRecord,
              [],
            ),
          ).rejects.toMatchObject({
            code:
              boundary === 'signature'
                ? 'bad-signature'
                : 'unauthorized-control',
          });
          expect(hookCalls).toBe(0);
          expect(coordinator.publicState.epoch).toBe(0n);
          expect(target.provider.applyCommitCalls).toBe(0);
          expect(coordinator.pendingControlOperations).toEqual({
            operations: 0,
            bytes: 0,
          });
        },
      ),
      {
        seed: 2011111,
        numRuns: 16,
        examples: [
          ['then-getter', 'signature'],
          ['then-function', 'signature'],
          ['number', 'signature'],
          ['object', 'signature'],
          ['then-getter', 'authorization'],
          ['then-function', 'authorization'],
        ],
      },
    );
  });

  test('preserves control arrival order when later epochs authenticate first without holding the membership queue', async () => {
    const source = await context();
    const sender = await bootstrap(source);
    await flushAndCollect(sender);
    const deliveries: Awaited<ReturnType<typeof flushAndCollect>> = [];
    for (let index = 0; index < 4; index++) {
      await sender.createCommit(
        { changes: [] },
        control(index + 2, 'update', source.identities.actorId),
      );
      deliveries.push(...(await flushAndCollect(sender)));
    }
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 2, max: 4 }),
        fc.boolean(),
        async (count, invalidHead) => {
          const target = {
            ...source,
            provider: new ContractTestProvider(),
            store: new InMemoryGroupStateStore(),
            rollbackAnchor: new InMemoryGroupSecurityRollbackAnchor(),
            authorization: new AuthorizationPolicy(source.identities.actorId),
          };
          const release = deferred();
          const laterAuthenticated = deferred();
          let enabled = false;
          let calls = 0;
          let later = 0;
          const coordinator = await GroupSecurityCoordinator.bootstrap(
            {
              ...config(target),
              verifyControlSignature: async (payload, signature, actor) => {
                const call = enabled ? ++calls : 0;
                if (call === 1) await release.promise;
                const valid = await source.identities.verify(
                  payload,
                  signature,
                  actor,
                );
                if (call > 1 && ++later === count - 1 + (invalidHead ? 1 : 0))
                  laterAuthenticated.resolve();
                return valid;
              },
            },
            createGroupInput,
            { operationId: id(1), subjectId: source.identities.actorId },
          );
          enabled = true;
          let settled = 0;
          const incoming = deliveries.slice(0, count);
          if (invalidHead)
            incoming.unshift({
              ...incoming[0],
              controlRecord: {
                ...incoming[0].controlRecord,
                signature: new Uint8Array([0xde, 0xad]),
              },
            });
          const pending = incoming.map((delivery) =>
            coordinator
              .applyCommit(delivery.commit!, delivery.controlRecord, [])
              .then(
                (result) => {
                  settled++;
                  return result.status;
                },
                (error: { code: string }) => {
                  settled++;
                  return error.code;
                },
              ),
          );
          try {
            await laterAuthenticated.promise;
            await new Promise<void>((resolve) => setImmediate(resolve));
            expect(settled).toBe(0);
            expect(coordinator.publicState.epoch).toBe(0n);
            let localApplied = false;
            await coordinator.runDocumentOperation(
              coordinator.documentContext,
              new Uint8Array([1]),
              async () =>
                prepared(() => {
                  localApplied = true;
                }),
            );
            expect(localApplied).toBe(true);
            release.resolve();
            expect(await Promise.all(pending)).toEqual(
              invalidHead
                ? ['bad-signature', ...Array(count).fill('committed')]
                : Array(count).fill('committed'),
            );
            expect(coordinator.publicState.epoch).toBe(BigInt(count));
            expect(coordinator.pendingControlOperations).toEqual({
              operations: 0,
              bytes: 0,
            });
          } finally {
            release.resolve();
            await Promise.all(pending);
          }
        },
      ),
      {
        seed: 2011110,
        numRuns: 16,
        examples: [
          [2, false],
          [4, false],
          [2, true],
          [4, true],
        ],
      },
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
