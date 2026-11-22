import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { extractField } from './field-extractor.js';

const segment = fc.oneof(
  fc.constantFrom('a', 'b', 'nested'),
  fc.integer({ min: 0, max: 3 }).map(String),
);
const scalar = fc.oneof(
  fc.string(),
  fc.double(),
  fc.boolean(),
  fc.constant(null),
  fc.constant(undefined),
);

describe('extractField generated object/array paths', () => {
  test('finds arbitrary nested falsey values, preserves inputs, and stops at missing or primitive boundaries', () => {
    fc.assert(
      fc.property(
        fc.array(segment, { minLength: 1, maxLength: 12 }),
        scalar,
        (segments, value) => {
          let root: unknown = value;
          for (const key of [...segments].reverse()) {
            if (/^[0-3]$/.test(key)) {
              const array: unknown[] = [];
              array[Number(key)] = root;
              root = Object.freeze(array);
            } else
              root = Object.freeze(
                Object.defineProperty(Object.create(null), key, {
                  value: root,
                  enumerable: true,
                }),
              );
          }
          const path = segments.join('.');
          expect(Object.is(extractField(root, path), value)).toBe(true);
          expect(extractField(root, '__missing__.' + path)).toBeUndefined();
          expect(extractField(root, path + '.child')).toBeUndefined();
          expect(extractField(value, path)).toBeUndefined();
        },
      ),
      {
        seed: 9545,
        numRuns: 1000,
        examples: [
          [['a'], null],
          [['a'], false],
          [['a'], 0],
          [['a', '1'], ''],
        ],
      },
    );
  });

  test('only reads own data properties and never invokes getters', () => {
    fc.assert(
      fc.property(
        fc.array(segment, { minLength: 1, maxLength: 12 }),
        scalar,
        (segments, value) => {
          const prefix = segments.slice(0, -1);
          const key = segments.at(-1)!;
          const wrap = (target: object) =>
            prefix.reduceRight((nested, pathSegment) => ({
              [pathSegment]: nested,
            }), target);
          const path = segments.join('.');
          const data = { [key]: value };
          let reads = 0;
          const accessor = Object.defineProperty({}, key, {
            get() {
              reads++;
              return value;
            },
          });
          expect(Object.is(extractField(wrap(data), path), value)).toBe(true);
          expect(extractField(wrap(Object.create(data)), path)).toBeUndefined();
          expect(extractField(wrap(accessor), path)).toBeUndefined();
          expect(reads).toBe(0);
        },
      ),
      { seed: 9546, numRuns: 300 },
    );
  });
});
