import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  getPeerborneDocumentCacheKey,
  getPeerborneHookCaches,
  resetPeerborneHookCaches,
} from './hooks-cache.js';

describe('generated React cache ownership histories', () => {
  test('keeps instances and document results isolated across arbitrary interleavings', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 8 }),
        fc.array(
          fc.record({
            instance: fc.integer({ min: 0, max: 7 }),
            path: fc.string({ maxLength: 60 }),
            value: fc.integer(),
            remove: fc.boolean(),
          }),
          { maxLength: 100 },
        ),
        (count, program) => {
          resetPeerborneHookCaches();
          try {
            const identities = Array.from({ length: count }, () => ({}));
            const caches = identities.map(getPeerborneHookCaches);
            const expected = identities.map(() => new Map<string, number>());
            expect(
              new Set(
                caches.map((cache) => getPeerborneDocumentCacheKey(cache, '')),
              ).size,
            ).toBe(count);
            for (const step of program) {
              const index = step.instance % count;
              const cache = getPeerborneHookCaches(identities[index]);
              expect(cache).toBe(caches[index]);
              if (step.remove) {
                cache.openTaskResults.delete(step.path);
                expected[index].delete(step.path);
              } else {
                cache.openTaskResults.set(step.path, { document: step.value });
                expected[index].set(step.path, step.value);
              }
              for (let other = 0; other < count; other++) {
                expect(caches[other].openTaskResults.size).toBe(
                  expected[other].size,
                );
                expect(
                  caches[other].openTaskResults.get(step.path)?.document,
                ).toBe(expected[other].get(step.path));
              }
            }
          } finally {
            resetPeerborneHookCaches();
          }
        },
      ),
      { seed: 9530, numRuns: 200 },
    );
  });
});
