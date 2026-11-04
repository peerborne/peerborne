import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  keychainHistoryTailClock,
  orderKeychainHistory,
} from './policy/keychain-order.js';

type Link = { id: string; parent: string };
const id = fc.oneof(
  fc.string({ minLength: 1, maxLength: 10 }),
  fc.constantFrom(
    '__proto__',
    'constructor',
    'size',
    'get',
    'set',
    'has',
    '\0',
  ),
);
const chain = fc.uniqueArray(id, { maxLength: 40 }).chain((ids) => {
  const links = ids.map((value, index) => ({
    id: value,
    parent: index === 0 ? '' : ids[index - 1],
  }));
  return fc.shuffledSubarray(links, {
    minLength: links.length,
    maxLength: links.length,
  });
});
const links = fc.oneof(
  chain,
  fc.array(fc.record({ id: fc.oneof(id, fc.constant('')), parent: id }), {
    maxLength: 40,
  }),
);

function arrayOracle(links: readonly Link[]) {
  if (
    links.some(
      (link, index) =>
        link.id === '' ||
        links.findIndex((other) => other.id === link.id) !== index ||
        links.findIndex((other) => other.parent === link.parent) !== index,
    )
  )
    return { valid: false, order: [], probes: 0 };
  const order: number[] = [];
  let cursor = '';
  for (let step = 0; step <= links.length; step++) {
    const next = links.findIndex((link) => link.parent === cursor);
    if (next === -1)
      return {
        valid: order.length === links.length,
        order,
        probes: order.length + 1,
      };
    if (order.includes(next)) throw new Error('Invalid oracle cycle');
    order.push(next);
    cursor = links[next].id;
  }
  throw new Error('Unbounded oracle traversal');
}

test('native Map and Set history ordering agrees with an independent array oracle', () => {
  fc.assert(
    fc.property(links, (links) => {
      const ids = Object.freeze(links.map((link) => link.id));
      const parents = Object.freeze(links.map((link) => link.parent));
      expect(orderKeychainHistory(ids, parents)).toEqual(arrayOracle(links));
    }),
    {
      seed: 2011902,
      numRuns: 500,
      examples: [
        [[]],
        [
          [
            { id: 'a', parent: '' },
            { id: 'b', parent: 'a' },
            { id: 'c', parent: 'a' },
          ],
        ],
        [
          [
            { id: 'a', parent: 'b' },
            { id: 'b', parent: 'a' },
          ],
        ],
        [
          [
            { id: 'a', parent: '' },
            { id: 'b', parent: 'missing' },
          ],
        ],
        [[{ id: '', parent: '' }]],
        [
          [
            { id: 'a', parent: '' },
            { id: 'a', parent: 'a' },
          ],
        ],
        [
          [
            { id: '__proto__', parent: 'size' },
            { id: 'size', parent: '' },
          ],
        ],
      ],
    },
  );
});

test('history plans own their output and require only linear input element reads', () => {
  fc.assert(
    fc.property(chain, (links) => {
      let reads = 0;
      const counted = (values: string[]) =>
        new Proxy(values, {
          get(target, key, receiver) {
            if (typeof key === 'string' && /^\d+$/.test(key)) reads++;
            return Reflect.get(target, key, receiver);
          },
        });
      const ids = links.map((link) => link.id);
      const parents = links.map((link) => link.parent);
      const expected = arrayOracle(links);
      const plan = orderKeychainHistory(counted(ids), counted(parents));
      expect(plan).toEqual(expected);
      expect(reads).toBeLessThanOrEqual(3 * links.length);
      (plan.order as number[]).fill(-1);
      expect(ids).toEqual(links.map((link) => link.id));
      expect(parents).toEqual(links.map((link) => link.parent));
      expect(orderKeychainHistory(ids, parents)).toEqual(expected);
    }),
    {
      seed: 2011903,
      numRuns: 200,
      examples: [
        [
          Array.from({ length: 1000 }, (_, index) => ({
            id: String(index),
            parent: index === 0 ? '' : String(index - 1),
          })).reverse(),
        ],
      ],
    },
  );
});

test('native operation tail clocks agree with exact BigInt arithmetic near overflow', () => {
  fc.assert(
    fc.property(
      fc.oneof(
        fc.maxSafeNat(),
        fc
          .integer({ min: 0, max: 1200 })
          .map((offset) => Number.MAX_SAFE_INTEGER - offset),
      ),
      fc.integer({ min: 1, max: 1000 }),
      (clock, length) => {
        const exact = BigInt(clock) + BigInt(length) - 1n;
        const actual = keychainHistoryTailClock(clock, length);
        expect(actual).toBe(
          exact > BigInt(Number.MAX_SAFE_INTEGER) ? -1 : Number(exact),
        );
        expect(Number.isSafeInteger(actual)).toBe(true);
      },
    ),
    {
      seed: 2011904,
      numRuns: 1000,
      examples: [
        [Number.MAX_SAFE_INTEGER, 1],
        [Number.MAX_SAFE_INTEGER, 2],
        [Number.MAX_SAFE_INTEGER - 1, 3],
        [Number.MAX_SAFE_INTEGER - 999, 1000],
        [0, 1000],
      ],
    },
  );
});
