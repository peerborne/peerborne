import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { LRUCache } from './lru-cache.js';

type Entry = { key: number; value: number | undefined };
const entry = fc.record({
  key: fc.integer({ min: 0, max: 15 }),
  value: fc.option(fc.integer(), { nil: undefined }),
});
const command = fc.record({
  kind: fc.constantFrom('set', 'get', 'has', 'stage', 'finalize', 'abandon'),
  entry,
  batch: fc.array(entry, { maxLength: 12 }),
});

describe('LRU cache generated state transitions', () => {
  test('matches an independent ordered-list model across staging, abandonment and eviction', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 8 }),
        fc.array(command, { maxLength: 100 }),
        (capacity, program) => {
          const cache = new LRUCache<number, number | undefined>(capacity);
          let model: Entry[] = [];
          let pending: Entry[] | undefined;
          let finalize: (() => void) | undefined;
          const insert = (entries: Entry[], value: Entry) => {
            const result = entries.filter((item) => item.key !== value.key);
            result.push({ ...value });
            return result.slice(-capacity);
          };
          for (const step of program) {
            const { key, value } = step.entry;
            if (step.kind === 'set') {
              cache.set(key, value);
              model = insert(model, step.entry);
              pending = pending?.filter((item) => item.key !== key);
            } else if (step.kind === 'get') {
              const found = model.find((item) => item.key === key);
              expect(cache.get(key)).toBe(found?.value);
              if (found) model = insert(model, found);
            } else if (step.kind === 'has') {
              expect(cache.has(key)).toBe(
                model.some((item) => item.key === key),
              );
            } else if (step.kind === 'stage' && !finalize) {
              const values = new Map(
                step.batch.map((item) => [item.key, item.value]),
              );
              pending = [];
              for (const [key, value] of values)
                pending = insert(pending, { key, value });
              finalize = cache.prepareSetMany(values);
              values.clear();
            } else if (step.kind === 'finalize' && finalize) {
              finalize();
              finalize();
              for (const value of pending!) model = insert(model, value);
              finalize = undefined;
              pending = undefined;
            } else if (step.kind === 'abandon') {
              finalize = undefined;
              pending = undefined;
            }
            expect(cache.size).toBe(model.length);
            expect(cache.size).toBeLessThanOrEqual(capacity);
            for (let known = 0; known < 16; known++) {
              expect(cache.has(known)).toBe(
                model.some((item) => item.key === known),
              );
            }
          }
          for (let key = 0; key < 16; key++)
            expect(cache.get(key)).toBe(
              model.find((item) => item.key === key)?.value,
            );
        },
      ),
      { seed: 9501, numRuns: 200 },
    );
  });
});
