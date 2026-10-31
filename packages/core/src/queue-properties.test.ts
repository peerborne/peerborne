import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { InvitationMembershipQueue } from './invitation-membership.js';
import { InMemoryInvitationAcceptanceCoordinator } from './invitation-policy.js';
import { closeHeliaStores, openHeliaStores } from './store-lifecycle.js';

describe('generated asynchronous lifecycle schedules', () => {
  test('membership work is FIFO, exclusive, and recovers after arbitrary failures', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.record({
            reject: fc.boolean(),
            turns: fc.integer({ min: 0, max: 4 }),
          }),
          { maxLength: 50 },
        ),
        async (program) => {
          const queue = new InvitationMembershipQueue();
          const starts: number[] = [];
          let active = 0;
          const outcomes = await Promise.allSettled(
            program.map((step, index) =>
              queue.run(async () => {
                starts.push(index);
                active++;
                expect(active).toBe(1);
                try {
                  for (let turn = 0; turn < step.turns; turn++)
                    await Promise.resolve();
                  if (step.reject) throw new Error('synthetic failure');
                  return index;
                } finally {
                  active--;
                }
              }),
            ),
          );
          expect(starts).toEqual(program.map((_, index) => index));
          expect(active).toBe(0);
          outcomes.forEach((outcome, index) =>
            expect(outcome.status).toBe(
              program[index].reject ? 'rejected' : 'fulfilled',
            ),
          );
          await expect(queue.run(async () => 42)).resolves.toBe(42);
        },
      ),
      { seed: 9502, numRuns: 150 },
    );
  });

  test('successful onboarding is cached exactly once, including undefined results', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.integer({ min: 0, max: 5 }), { maxLength: 30 }),
        fc.option(fc.integer(), { nil: undefined }),
        async (requests, value) => {
          const coordinator = new InMemoryInvitationAcceptanceCoordinator<
            number | undefined
          >();
          const claims = new Map<number, number>();
          const starts = new Map<number, number>();
          const run = (key: number) =>
            coordinator.run(
              String(key),
              Number.MAX_SAFE_INTEGER,
              undefined,
              async () => {
                claims.set(key, (claims.get(key) ?? 0) + 1);
                await Promise.resolve();
              },
              () => {},
              async () => {
                starts.set(key, (starts.get(key) ?? 0) + 1);
                await Promise.resolve();
                return value;
              },
            );
          await Promise.all(requests.map(run));
          for (const key of requests) expect(await run(key)).toBe(value);
          for (const key of new Set(requests)) {
            expect(claims.get(key)).toBe(1);
            expect(starts.get(key)).toBe(1);
          }
          expect(coordinator.cachedCount).toBe(new Set(requests).size);
          expect(coordinator.inFlightCount).toBe(0);
        },
      ),
      { seed: 9503, numRuns: 150, examples: [[[0], undefined]] },
    );
  });

  test('store startup rollback closes exactly the opened stores in reverse order', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.integer({ min: 0, max: 7 }), { maxLength: 20 }),
        fc.option(fc.integer({ min: 0, max: 7 }), { nil: undefined }),
        fc.array(fc.boolean(), { minLength: 8, maxLength: 8 }),
        async (order, failAt, closeFailures) => {
          const events: string[] = [];
          const stores = Array.from({ length: 8 }, (_, index) => ({
            open: async () => {
              events.push('open' + index);
              if (index === failAt) throw new Error('open failure');
            },
            close: async () => {
              events.push('close' + index);
              if (closeFailures[index]) throw new Error('close failure');
            },
          }));
          const unique = [...new Set(order)];
          const failed = unique.findIndex((index) => index === failAt);
          const opened = failed === -1 ? unique : unique.slice(0, failed);
          if (failed === -1) {
            const result = await openHeliaStores(
              ...order.map((index) => stores[index]),
            );
            expect(result).toEqual(opened.map((index) => stores[index]));
            await closeHeliaStores(result);
          } else
            await expect(
              openHeliaStores(...order.map((index) => stores[index])),
            ).rejects.toThrow('open failure');
          const attempted =
            failed === -1 ? unique : unique.slice(0, failed + 1);
          expect(events).toEqual([
            ...attempted.map((index) => 'open' + index),
            ...opened.reverse().map((index) => 'close' + index),
          ]);
        },
      ),
      { seed: 9504, numRuns: 150 },
    );
  });
});
