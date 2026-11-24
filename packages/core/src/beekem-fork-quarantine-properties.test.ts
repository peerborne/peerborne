import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  BeeKEMForkQuarantine,
  type BeeKEMForkRecord,
  type DurableBeeKEMForkStore,
} from './beekem-fork-quarantine.js';

const path = '/fork-quarantine';
const identity = 'fixture-identity';
const scope = { documentPath: path, identity };

type Fault = 'none' | 'before-write' | 'after-write';

function gate() {
  let resolve!: () => void;
  const promise = new Promise<void>((completion) => {
    resolve = completion;
  });
  return { promise, resolve };
}

function storage(
  select: BeeKEMForkRecord['phase'] | undefined = undefined,
  fault: Fault = 'none',
  pause?: Promise<void>,
) {
  const records = new Map<string, BeeKEMForkRecord>();
  const invoked = gate();
  const store: DurableBeeKEMForkStore = {
    async load(scope) {
      const record = records.get(JSON.stringify(scope));
      return record && { ...record };
    },
    async compareAndSwap(scope, expected, next) {
      const selected = next.phase === select;
      if (selected) {
        invoked.resolve();
        await pause;
        if (fault === 'before-write')
          throw new Error('Interrupted before write');
      }
      const key = JSON.stringify(scope);
      if (JSON.stringify(records.get(key)) !== JSON.stringify(expected))
        return false;
      records.set(key, { ...next });
      if (selected && fault === 'after-write')
        throw new Error('Interrupted before acknowledgment');
      return true;
    },
  };
  return {
    store,
    invoked: invoked.promise,
    open: (documentPath = path, serializedIdentity = identity) =>
      new BeeKEMForkQuarantine(store, documentPath, () => serializedIdentity),
  };
}

test('scoped acquisition and clean release preserve exclusive ownership through restarts', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(fc.integer({ min: 2, max: 7 }), { minLength: 1, maxLength: 8 }),
      async (restartCompetitors) => {
        const { store, open } = storage();
        await expect(open().acquire()).rejects.toThrow(/not provisioned/);
        await expect(open().provision()).resolves.toBe(true);
        const closed: BeeKEMForkQuarantine[] = [];
        for (const [restart, count] of restartCompetitors.entries()) {
          const contenders = Array.from({ length: count }, () => open());
          const attempts = await Promise.allSettled(
            contenders.map((guard) => guard.acquire()),
          );
          expect(
            attempts.filter((attempt) => attempt.status === 'fulfilled'),
          ).toHaveLength(1);
          const [owner] = contenders.filter((guard) => guard.acceptsWork);
          expect(owner).toBeDefined();
          const active = await store.load(scope);
          expect(active).toMatchObject({
            phase: 'active',
            revision: restart * 2 + 1,
          });
          await Promise.all(closed.map((guard) => guard.release()));
          expect(await store.load(scope)).toEqual(active);
          expect(await open(`${path}-different`).provision()).toBe(
            restart === 0,
          );
          expect(await open(path, `${identity}-different`).provision()).toBe(
            restart === 0,
          );
          owner.beginClose();
          expect(owner.acceptsWork).toBe(false);
          await owner.release();
          closed.push(owner);
          expect(await store.load(scope)).toEqual({
            phase: 'available',
            revision: restart * 2 + 2,
          });
        }
      },
    ),
    { seed: 0x424b4601, numRuns: 45 },
  );
});

test('a fork observed before close or during drain fences restarts across every persistence outcome', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.integer({ min: 1, max: 0xffff_ffff }),
      fc.constantFrom<Fault>('none', 'before-write', 'after-write'),
      fc.boolean(),
      async (generation, fault, closeBeforeObservation) => {
        const resume = gate();
        const { store, invoked, open } = storage(
          'quarantined',
          fault,
          resume.promise,
        );
        const owner = open();
        await owner.provision();
        await owner.acquire();
        const prior = await store.load(scope);
        if (closeBeforeObservation) owner.beginClose();
        const persisted = owner.quarantine(generation).then(
          () => true,
          () => false,
        );
        await invoked;
        owner.beginClose();
        await owner.release();
        expect(owner.acceptsWork).toBe(false);
        expect(owner.competingGeneration).toBe(generation);
        expect(await store.load(scope)).toEqual(prior);
        await expect(open().acquire()).rejects.toThrow(
          /blocks document activation/,
        );

        resume.resolve();
        expect(await persisted).toBe(fault === 'none');
        await owner.release();
        expect(await store.load(scope)).toEqual(
          fault === 'before-write'
            ? prior
            : {
                phase: 'quarantined',
                revision: 2,
                generation,
              },
        );
        const restarted = open();
        await expect(restarted.provision()).resolves.toBe(false);
        await expect(restarted.acquire()).rejects.toThrow(
          /blocks document activation/,
        );
        expect(restarted.competingGeneration).toBe(
          fault === 'before-write' ? undefined : generation,
        );
      },
    ),
    { seed: 0x424b4602, numRuns: 60 },
  );
});

test('unconfirmed acquisition exposes no state and cannot release an ambiguously acquired lease', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom<Fault>('none', 'before-write', 'after-write'),
      fc.integer({ min: 1, max: 5 }),
      async (fault, concurrentCalls) => {
        const resume = gate();
        const { store, invoked, open } = storage(
          'active',
          fault,
          resume.promise,
        );
        const owner = open();
        await owner.provision();
        const work = Promise.allSettled(
          Array.from({ length: concurrentCalls }, () => owner.acquire()),
        );
        await invoked;
        expect(owner.acceptsWork).toBe(false);
        owner.beginClose();
        const releasing = owner.release();
        expect(owner.acceptsWork).toBe(false);
        resume.resolve();
        expect(
          (await work).every((attempt) => attempt.status === 'rejected'),
        ).toBe(true);
        await releasing;
        expect(await store.load(scope)).toMatchObject({
          phase: fault === 'after-write' ? 'active' : 'available',
          revision: fault === 'none' ? 2 : fault === 'before-write' ? 0 : 1,
        });
        if (fault === 'after-write') {
          await expect(open().acquire()).rejects.toThrow(
            /blocks document activation/,
          );
        }
      },
    ),
    { seed: 0x424b4603, numRuns: 45 },
  );
});

test('malformed persisted anchors fail closed before making any store writes', async () => {
  const available = { phase: 'available', revision: 0 } as const;
  await fc.assert(
    fc.asyncProperty(
      fc.oneof(
        fc.integer({ max: -1 }).map((revision) => ({ ...available, revision })),
        fc
          .constantFrom(-0, Number.NaN, Number.POSITIVE_INFINITY, 0.5)
          .map((revision) => ({ ...available, revision })),
        fc.string().map((unrecognized) => ({ ...available, unrecognized })),
        fc.constantFrom(null, [], { phase: 'active', revision: 1 }),
      ),
      async (record) => {
        let writes = 0;
        const store: DurableBeeKEMForkStore = {
          async load() {
            return record as unknown as BeeKEMForkRecord;
          },
          async compareAndSwap() {
            writes++;
            return true;
          },
        };
        const guard = new BeeKEMForkQuarantine(store, path, () => identity);
        await expect(guard.acquire()).rejects.toThrow();
        expect(guard.acceptsWork).toBe(false);
        guard.beginClose();
        await guard.release();
        expect(writes).toBe(0);
      },
    ),
    { seed: 0x424b4604, numRuns: 45 },
  );
});
