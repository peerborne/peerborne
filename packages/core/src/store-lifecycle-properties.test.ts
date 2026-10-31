import { beforeAll, describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  EncryptedGroupState,
  EncryptedKeyPackageState,
} from './group-security-provider.js';
import { InMemoryGroupStateStore } from './group-state-store.js';
import { WebCryptoGroupStateProtector } from './webcrypto-group-state-protector.js';

const protocol = { id: 'partition.property', version: 1 };
const storeKey = { protocol, groupId: new Uint8Array([1]) };
const id = (value: number) => new Uint8Array(32).fill(value);
let group: EncryptedGroupState;
let packages: EncryptedKeyPackageState[];

beforeAll(async () => {
  const protector =
    await WebCryptoGroupStateProtector.generate('partition-property');
  group = await EncryptedGroupState.seal(
    {
      protocol,
      groupId: storeKey.groupId,
      epoch: 0n,
      confirmedTranscriptHash: id(1),
      treeHash: id(2),
    },
    new Uint8Array([1]),
    protector,
  );
  packages = await Promise.all(
    Array.from({ length: 8 }, (_, index) =>
      EncryptedKeyPackageState.seal(
        {
          protocol,
          groupId: storeKey.groupId,
          reference: id(index + 1),
          payload: id(index + 16),
        },
        new Uint8Array([index]),
        protector,
      ),
    ),
  );
});

describe('generated package partition and native transaction histories', () => {
  test('consumes each reference once, retains bindings, and rolls back every failed transition', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.record({
            reference: fc.integer({ min: 0, max: 7 }),
            consume: fc.boolean(),
            abort: fc.boolean(),
          }),
          { maxLength: 35 },
        ),
        async (program) => {
          const store = new InMemoryGroupStateStore();
          await store.transaction(storeKey, (transaction) =>
            transaction.setEncryptedState(group),
          );
          let pending = new Set<number>(),
            consumed = new Set<number>(),
            revision = 1;
          for (const step of program) {
            const blocked =
              consumed.has(step.reference) ||
              (step.consume && !pending.has(step.reference));
            const transaction = store.transaction(storeKey, async (working) => {
              if (step.consume)
                working.consumePendingKeyPackage(id(step.reference + 1));
              else {
                working.putPendingKeyPackage(packages[step.reference]);
                working.bindPendingKeyPackageRequest({
                  operationId: id(step.reference + 32),
                  requestCommitment: id(step.reference + 64),
                  keyPackageReference: id(step.reference + 1),
                });
              }
              await Promise.resolve();
              if (step.abort) throw new Error('synthetic rollback');
            });
            if (blocked || step.abort)
              await expect(transaction).rejects.toThrow();
            else {
              await transaction;
              revision++;
              if (step.consume) {
                pending.delete(step.reference);
                consumed.add(step.reference);
              } else pending.add(step.reference);
            }
            const loaded = (await store.load(storeKey))!;
            expect(loaded.revision).toBe(revision);
            expect(
              loaded.pendingKeyPackages
                .map((entry) => entry.keyPackage.reference[0] - 1)
                .sort(),
            ).toEqual([...pending].sort());
            expect(
              loaded.consumedKeyPackageRefs
                .map((reference) => reference[0] - 1)
                .sort(),
            ).toEqual([...consumed].sort());
            expect(
              loaded.pendingKeyPackageRequests
                .map((entry) => [
                  entry.operationId[0] - 32,
                  entry.keyPackageReference[0] - 1,
                ])
                .sort(),
            ).toEqual(
              [...pending].sort().map((reference) => [reference, reference]),
            );
            loaded.consumedKeyPackageRefs.forEach((reference) =>
              reference.fill(255),
            );
            const again = (await store.load(storeKey))!;
            expect(
              again.consumedKeyPackageRefs
                .map((reference) => reference[0] - 1)
                .sort(),
            ).toEqual([...consumed].sort());
          }
        },
      ),
      {
        seed: 9601,
        numRuns: 100,
        examples: [
          [
            [
              { reference: 0, consume: false, abort: false },
              { reference: 0, consume: true, abort: false },
              { reference: 0, consume: false, abort: false },
            ],
          ],
        ],
      },
    );
  }, 30_000);
});
