import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  activateDocumentReplacement,
  documentRecoveryContentDigest,
  type DocumentRecoveryApproval,
  type DocumentRecoveryLocator,
  type DocumentRecoveryOptions,
} from './document-recovery.js';

const base: DocumentRecoveryLocator = {
  revision: 7,
  documentPath: '/record/original',
  context: '01'.repeat(32),
  receipt: null,
};

async function approvalFor(
  selected: Uint8Array,
  branch = 'replacement',
): Promise<DocumentRecoveryApproval> {
  return {
    logicalDocumentId: 'record',
    base: { ...base },
    replacementPath: `/record/${branch}`,
    replacementContext: '02'.repeat(32),
    contentDigest: await documentRecoveryContentDigest(selected),
  };
}

type Failure = 'none' | 'after-stage' | 'before-cas' | 'after-cas';

function fixture(initial = base) {
  let locator = { ...initial };
  const artifacts = new Map<string, Uint8Array>();
  let commits = 0;
  let stages = 0;
  function open(failure: Failure = 'none'): DocumentRecoveryOptions {
    return {
      authorize: () => true,
      async stage(next, selected) {
        stages++;
        artifacts.set(next.receipt!, selected.slice());
        if (failure === 'after-stage') throw new Error('Interrupted staging');
        return true;
      },
      locator: {
        async load(id) {
          return id === 'record' ? { ...locator } : undefined;
        },
        async compareAndSwap(id, expected, next) {
          if (failure === 'before-cas')
            throw new Error('Interrupted publication');
          expect(id).toBe('record');
          expect(artifacts.has(next.receipt!)).toBe(true);
          if (
            !Object.is(locator.revision, expected.revision) ||
            locator.documentPath !== expected.documentPath ||
            locator.context !== expected.context ||
            locator.receipt !== expected.receipt
          )
            return false;
          locator = { ...next };
          commits++;
          if (failure === 'after-cas')
            throw new Error('Interrupted acknowledgment');
          return true;
        },
      },
    };
  }
  return {
    open,
    artifacts,
    get commits() {
      return commits;
    },
    get stages() {
      return stages;
    },
  };
}

test('only one replacement becomes visible across restarts after staging or publication faults', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.uint8Array({ maxLength: 128 }),
      fc.constantFrom<Failure>('after-stage', 'before-cas', 'after-cas'),
      fc.integer({ min: 1, max: 8 }),
      async (selected, failure, retries) => {
        const approval = await approvalFor(selected);
        const storage = fixture();
        await expect(
          activateDocumentReplacement(
            approval,
            selected,
            storage.open(failure),
          ),
        ).rejects.toThrow(/Interrupted/);
        const current = await storage.open().locator.load('record');
        expect(current?.revision).toBe(
          base.revision + (failure === 'after-cas' ? 1 : 0),
        );
        const repaired = await activateDocumentReplacement(
          approval,
          selected,
          storage.open(),
        );
        expect(repaired.status).toBe(
          failure === 'after-cas' ? 'already-active' : 'activated',
        );
        for (let index = 0; index < retries; index++) {
          await expect(
            activateDocumentReplacement(approval, selected, storage.open()),
          ).resolves.toEqual({
            status: 'already-active',
            locator: repaired.locator,
          });
        }
        expect(storage.commits).toBe(1);
        expect(storage.stages).toBe(failure === 'after-cas' ? 1 : 2);
        expect(storage.artifacts.get(repaired.locator.receipt!)).toEqual(
          selected,
        );
        expect(base.receipt).toBeNull();
      },
    ),
    { seed: 20261121, numRuns: 25 },
  );
});

test('independently prepared replacements compete on the same anchored locator', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.uint8Array({ maxLength: 64 }),
      fc.constantFrom('same', 'different-path', 'different-content'),
      async (selected, scenario) => {
        const same = scenario === 'same';
        const storage = fixture();
        const first = await approvalFor(selected);
        const alternate =
          scenario === 'different-content'
            ? Uint8Array.of(...selected, 1)
            : selected;
        const second = same
          ? first
          : await approvalFor(
              alternate,
              scenario === 'different-path' ? 'other' : 'replacement',
            );
        let pending = 0;
        let unblock!: () => void;
        const stagedTogether = new Promise<void>((resolve) => {
          unblock = resolve;
        });
        function open(): DocumentRecoveryOptions {
          const options = storage.open();
          return {
            ...options,
            async stage(next, content) {
              const ready = await options.stage(next, content);
              if (++pending === 2) unblock();
              await stagedTogether;
              return ready;
            },
          };
        }
        const results = await Promise.allSettled([
          activateDocumentReplacement(first, selected, open()),
          activateDocumentReplacement(second, alternate, open()),
        ]);
        const successful = results.flatMap((result) =>
          result.status === 'fulfilled' ? [result.value] : [],
        );
        expect(storage.stages).toBe(2);
        expect(storage.commits).toBe(1);
        expect(successful).toHaveLength(same ? 2 : 1);
        expect(
          successful.filter(({ status }) => status === 'activated'),
        ).toHaveLength(1);
        expect(await storage.open().locator.load('record')).toEqual(
          successful[0].locator,
        );
        expect(storage.artifacts.size).toBe(same ? 1 : 2);
      },
    ),
    { seed: 20261122, numRuns: 24 },
  );
});

test('requires the exact approved content and source context and captures them across awaits', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.uint8Array({ minLength: 1, maxLength: 64 }),
      fc.constantFrom(
        'allow',
        'deny',
        'wrong-content',
        'wrong-context',
        'wrong-path',
        'invalid-digest',
        'wrong-receipt',
        'unstaged',
      ),
      async (selected, scenario) => {
        const correct = await approvalFor(selected);
        const input =
          scenario === 'invalid-digest'
            ? {
                ...correct,
                replacementContext: correct.replacementContext + '\n',
              }
            : correct;
        const callerBytes = selected.slice();
        const storage = fixture({
          ...base,
          context:
            scenario === 'wrong-context' ? '03'.repeat(32) : base.context,
          receipt: scenario === 'wrong-receipt' ? '04'.repeat(32) : null,
          documentPath:
            scenario === 'wrong-path'
              ? '/record/other-origin'
              : base.documentPath,
        });
        if (scenario === 'wrong-content') callerBytes[0] ^= 1;
        const options = storage.open();
        const result = activateDocumentReplacement(input, callerBytes, {
          ...options,
          async authorize(owned) {
            expect(Object.isFrozen(owned.base)).toBe(true);
            await Promise.resolve();
            Object.assign(input.base, { context: '05'.repeat(32) });
            callerBytes.fill(0);
            return scenario === 'deny' ? (1 as unknown as boolean) : true;
          },
          async stage(next, bytes) {
            return scenario !== 'unstaged' && options.stage(next, bytes);
          },
        });
        if (scenario === 'allow') {
          const accepted = await result;
          expect(storage.commits).toBe(1);
          expect(storage.artifacts.get(accepted.locator.receipt!)).toEqual(
            selected,
          );
        } else {
          await expect(result).rejects.toThrow();
          expect(storage.commits).toBe(0);
          expect(storage.stages).toBe(0);
        }
      },
    ),
    { seed: 20261123, numRuns: 30 },
  );
});
