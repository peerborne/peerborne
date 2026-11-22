import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import { GossipReceiveAdmission } from './gossip-receive-admission.js';
import { GroupDocumentOperationBudget } from './group-document-operation.js';
import {
  SIGNATURE_VERIFICATION_CONCURRENCY,
  verifyMemberSignature,
} from './internal/signature-verification.js';

const turn = () => new Promise<void>((resolve) => setImmediate(resolve));

test('receive credits follow started work through rejection, close, and replacement', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(
        fc.record({
          action: fc.constantFrom('start', 'start', 'settle', 'replace'),
          selector: fc.nat(10),
          bytes: fc.nat(9),
          fails: fc.boolean(),
        }),
        { minLength: 10, maxLength: 100 },
      ),
      async (steps) => {
        const aggregate = new GroupDocumentOperationBudget(4, 12);
        function scope() {
          const local = new GroupDocumentOperationBudget(2, 7);
          return {
            local,
            receive: new GossipReceiveAdmission(local, aggregate),
          };
        }
        const scopes = [scope(), scope(), scope()];
        const allScopes = [...scopes];
        const pending: {
          owner: (typeof scopes)[number];
          bytes: number;
          settle: () => Promise<void>;
        }[] = [];
        const usage = (work: typeof pending) => ({
          operations: work.length,
          bytes: work.reduce((sum, operation) => sum + operation.bytes, 0),
        });

        for (const { action, selector, bytes, fails } of steps) {
          const index = selector % scopes.length;
          const owner = scopes[index];
          if (action === 'replace') {
            owner.receive.close();
            expect(
              await owner.receive.run(new Uint8Array([1]), async () => {
                throw new Error('Closed scope started work');
              }),
            ).toBeUndefined();
            scopes[index] = scope();
            allScopes.push(scopes[index]);
          } else if (action === 'settle' && pending.length > 0) {
            const [operation] = pending.splice(selector % pending.length, 1);
            await operation.settle();
          } else if (action === 'start') {
            const local = usage(pending.filter((work) => work.owner === owner));
            const shared = usage(pending);
            const admitted =
              bytes > 0 &&
              local.operations < 2 &&
              local.bytes + bytes <= 7 &&
              shared.operations < 4 &&
              shared.bytes + bytes <= 12;
            const stop = Promise.withResolvers<void>();
            const input = new Uint8Array(bytes).fill(selector);
            let started = false;
            const result = owner.receive.run(input, async (frame) => {
              started = true;
              await stop.promise;
              expect(frame).toEqual(new Uint8Array(bytes).fill(selector));
              if (fails) throw new Error('Simulated processing failure');
              return bytes;
            });
            const observed = result.then(
              (value) => ({ value }),
              (error: unknown) => ({ error }),
            );
            input.fill(255);
            expect(started).toBe(admitted);
            if (admitted) {
              pending.push({
                owner,
                bytes,
                settle: async () => {
                  stop.resolve();
                  expect(await observed).toEqual(
                    fails
                      ? { error: new Error('Simulated processing failure') }
                      : { value: bytes },
                  );
                },
              });
            } else {
              expect(await observed).toEqual({ value: undefined });
            }
          }
          expect(aggregate.usage).toEqual(usage(pending));
          for (const owner of allScopes) {
            expect(owner.local.usage).toEqual(
              usage(pending.filter((work) => work.owner === owner)),
            );
          }
        }

        for (const operation of pending) await operation.settle();
        expect(aggregate.usage).toEqual({ operations: 0, bytes: 0 });
      },
    ),
    { seed: 20261121, numRuns: 60 },
  );
});

test('member signatures use bounded batches and wait for outstanding native work', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(fc.constantFrom('valid', 'invalid', 'error'), { maxLength: 30 }),
      async (outcomes) => {
        type Outcome = (typeof outcomes)[number];
        const pending = new Map<number, PromiseWithResolvers<boolean>>();
        let settled = false;
        const verify = verifyMemberSignature(
          outcomes.map((_, index) => index),
          (index) => {
            const completion = Promise.withResolvers<boolean>();
            pending.set(index, completion);
            return completion.promise;
          },
        ).then(
          (result) => {
            settled = true;
            return result;
          },
          () => {
            settled = true;
            return 'error' as const;
          },
        );
        let expected: boolean | 'error' = false;
        for (
          let offset = 0;
          offset < outcomes.length;
          offset += SIGNATURE_VERIFICATION_CONCURRENCY
        ) {
          const batch = outcomes.slice(
            offset,
            offset + SIGNATURE_VERIFICATION_CONCURRENCY,
          );
          const complete = (outcome: Outcome, index: number) => {
            const task = pending.get(offset + index)!;
            pending.delete(offset + index);
            if (outcome === 'error')
              task.reject(new Error('Simulated provider failure'));
            else task.resolve(outcome === 'valid');
          };
          expect([...pending.keys()]).toEqual(
            batch.map((_, index) => offset + index),
          );
          for (let index = batch.length - 1; index > 0; index--)
            complete(batch[index], index);
          await turn();
          expect(settled).toBe(false);
          expect([...pending.keys()]).toEqual([offset]);
          complete(batch[0], 0);
          await turn();
          if (batch.includes('valid')) {
            expected = true;
            break;
          }
          if (batch.includes('error')) {
            expected = 'error';
            break;
          }
        }
        expect(await verify).toBe(expected);
        expect(pending.size).toBe(0);
      },
    ),
    { seed: 20261122, numRuns: 60 },
  );
});
