import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  InMemoryGroupStateStore,
  type GroupStateStoreKey,
  type GroupStateStoreTransaction,
} from './group-state-store.js';
import { EncryptedGroupState } from './group-security-provider.js';
import { WebCryptoGroupStateProtector } from './webcrypto-group-state-protector.js';

const protocol = { id: 'property.test', version: 1 };
const keyFor = (group: number): GroupStateStoreKey => ({
  protocol,
  groupId: new Uint8Array([group + 1]),
});
const id = (value: number) => new Uint8Array(32).fill(value);
const operation = fc.record({
  group: fc.integer({ min: 0, max: 1 }),
  id: fc.integer({ min: 0, max: 15 }),
  value: fc.integer({ min: 0, max: 255 }),
  remove: fc.boolean(),
  abort: fc.boolean(),
});

describe('generated encrypted group-store transaction histories', () => {
  test('commits atomically, isolates groups and snapshots, and closes escaped transactions', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(operation, { maxLength: 35 }),
        async (program) => {
          const store = new InMemoryGroupStateStore();
          const protector =
            await WebCryptoGroupStateProtector.generate('property-key');
          const revisions = [1, 1],
            model = [new Map<number, number>(), new Map<number, number>()];
          for (let group = 0; group < 2; group++) {
            const key = keyFor(group);
            const encrypted = await EncryptedGroupState.seal(
              {
                protocol,
                groupId: key.groupId,
                epoch: 0n,
                confirmedTranscriptHash: new Uint8Array(32).fill(1),
                treeHash: new Uint8Array(32).fill(2),
              },
              new Uint8Array([42]),
              protector,
            );
            await store.transaction(key, (transaction) =>
              transaction.setEncryptedState(encrypted),
            );
          }
          for (const step of program) {
            const before = model[step.group];
            const candidate = new Map(before);
            const conflict =
              !step.remove &&
              before.has(step.id) &&
              before.get(step.id) !== step.value;
            const shouldReject = step.abort || conflict;
            if (step.remove) candidate.delete(step.id);
            else candidate.set(step.id, step.value);
            let escaped: GroupStateStoreTransaction | undefined;
            const callerKey = keyFor(step.group);
            const pending = store.transaction(
              callerKey,
              async (transaction) => {
                escaped = transaction;
                expect(transaction.baseRevision).toBe(revisions[step.group]);
                if (step.remove) transaction.removeOutbox(id(step.id));
                else {
                  const entry = {
                    id: id(step.id),
                    kind: 'group.transition' as const,
                    epoch: 0n,
                    payload: new Uint8Array([step.value]),
                    createdAt: 1000 + step.id,
                  };
                  transaction.enqueueOutbox(entry);
                  entry.id.fill(99);
                  entry.payload.fill(99);
                }
                await Promise.resolve();
                if (step.abort) throw new Error('synthetic rollback');
              },
            );
            callerKey.groupId.fill(254);
            if (shouldReject) await expect(pending).rejects.toThrow();
            else {
              await pending;
              model[step.group] = candidate;
              revisions[step.group]++;
            }
            expect(() => escaped!.baseRevision).toThrow();
            for (let group = 0; group < 2; group++) {
              const loaded = (await store.load(keyFor(group)))!;
              expect(loaded.revision).toBe(revisions[group]);
              const projected = loaded.outbox
                .map((entry) => [entry.id[0], entry.payload[0]])
                .sort((a, b) => a[0] - b[0]);
              expect(projected).toEqual(
                [...model[group]].sort((a, b) => a[0] - b[0]),
              );
              loaded.outbox.forEach((entry) => {
                entry.id.fill(88);
                entry.payload.fill(88);
              });
              const again = (await store.load(keyFor(group)))!;
              expect(
                again.outbox
                  .map((entry) => [entry.id[0], entry.payload[0]])
                  .sort((a, b) => a[0] - b[0]),
              ).toEqual(projected);
            }
          }
        },
      ),
      { seed: 9542, numRuns: 100 },
    );
  });

  test('concurrent transaction queues preserve per-group revision order through failures', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.record({
            group: fc.integer({ min: 0, max: 2 }),
            fail: fc.boolean(),
            turns: fc.integer({ min: 0, max: 3 }),
          }),
          { maxLength: 40 },
        ),
        async (program) => {
          const store = new InMemoryGroupStateStore();
          const revisions = [0, 0, 0],
            active = [0, 0, 0];
          const results = await Promise.allSettled(
            program.map((step) =>
              store.transaction(keyFor(step.group), async (transaction) => {
                expect(transaction.baseRevision).toBe(revisions[step.group]);
                expect(++active[step.group]).toBe(1);
                try {
                  for (let turn = 0; turn < step.turns; turn++)
                    await Promise.resolve();
                  if (step.fail) throw new Error('synthetic failure');
                  revisions[step.group]++;
                } finally {
                  active[step.group]--;
                }
              }),
            ),
          );
          results.forEach((result, index) =>
            expect(result.status).toBe(
              program[index].fail ? 'rejected' : 'fulfilled',
            ),
          );
          for (let group = 0; group < 3; group++)
            expect((await store.load(keyFor(group)))?.revision ?? 0).toBe(
              revisions[group],
            );
        },
      ),
      { seed: 9543, numRuns: 150 },
    );
  });
});
