import { beforeAll, describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { canonicalKeychain } from './keychain-canonical.js';
import type { PreparedCommitClaim } from './prepared-commit.js';

let key: CryptoKey;
beforeAll(async () => {
  key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
});

describe('generated prepared-claim callback schedules', () => {
  test('rejects stale and hydrating claims, finalizes once, and preserves a claim reserved through publication', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.constantFrom('begin', 'finish', 'claim', 'finalize', 'stale'),
          { maxLength: 45 },
        ),
        async (program) => {
          let release!: () => void;
          const hydration = new Promise<void>((resolve) => {
            release = resolve;
          });
          let fresh = true,
            hydrated = false,
            hydrating = false,
            phase: 'prepared' | 'claimed' | 'committed' = 'prepared';
          let publications = 0,
            cacheFinalizations = 0,
            deserializations = 0;
          const tasks: Promise<unknown>[] = [];
          let claim: PreparedCommitClaim | undefined;
          const prepared = canonicalKeychain.createMergeClaim({
            stagedEntries: [['00'.repeat(32), 'synthetic']],
            deserializeKey: async () => {
              deserializations++;
              await hydration;
              return key;
            },
            isBaseCurrent: () => fresh,
            prepareCacheSet: () => () => {
              cacheFinalizations++;
            },
            publish: () => {
              publications++;
            },
          });
          try {
            for (const command of program) {
              if (command === 'stale' && phase === 'prepared') fresh = false;
              if (command === 'begin') {
                if (phase !== 'prepared')
                  await expect(prepared.hydrateKeys()).rejects.toThrow();
                else {
                  const task = prepared.hydrateKeys();
                  tasks.push(task);
                  if (hydrated) await task;
                  else hydrating = true;
                }
              }
              if (command === 'finish') {
                release();
                await Promise.all(tasks);
                hydrated = tasks.length > 0 || hydrated;
                hydrating = false;
              }
              if (command === 'claim') {
                if (phase !== 'prepared' || !fresh || hydrating)
                  expect(() => prepared.claimCommit()).toThrow();
                else {
                  claim = prepared.claimCommit();
                  phase = 'claimed';
                }
              }
              if (command === 'finalize' && claim) {
                claim.finalize();
                phase = 'committed';
              }
              expect(publications).toBe(phase === 'committed' ? 1 : 0);
              expect(cacheFinalizations).toBe(publications);
              expect(deserializations).toBeLessThanOrEqual(1);
            }
          } finally {
            release();
            await Promise.allSettled(tasks);
          }
        },
      ),
      {
        seed: 9607,
        numRuns: 150,
        examples: [
          [['begin', 'claim', 'finish', 'claim', 'finalize', 'finalize']],
          [['stale', 'claim']],
        ],
      },
    );
  });
});
