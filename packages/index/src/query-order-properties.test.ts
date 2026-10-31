import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  compareCodeUnits,
  compareFiniteNumbers,
  compareQueryKeys,
  takeQueryPage,
} from './query-order.js';

const finite = fc.double({ noNaN: true, noDefaultInfinity: true });
const units = fc.array(fc.integer({ min: 0, max: 0xffff }), { maxLength: 40 });
function orderedFloat(value: number): bigint {
  if (value === 0) return 0x8000000000000000n;
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, value);
  const bits = view.getBigUint64(0);
  return bits >> 63n ? ~bits & 0xffffffffffffffffn : bits ^ 0x8000000000000000n;
}

describe('query ordering runtime model calibration', () => {
  test('finite numeric order matches sortable IEEE-754 bit patterns, including extreme magnitudes', () => {
    fc.assert(
      fc.property(finite, finite, finite, (a, b, c) => {
        const ka = orderedFloat(a),
          kb = orderedFloat(b);
        expect(compareFiniteNumbers(a, b)).toBe(
          ka === kb ? 0 : ka < kb ? -1 : 1,
        );
        if (compareFiniteNumbers(a, b) <= 0 && compareFiniteNumbers(b, c) <= 0)
          expect(compareFiniteNumbers(a, c)).toBeLessThanOrEqual(0);
      }),
      {
        seed: 9604,
        numRuns: 2000,
        examples: [
          [Number.MAX_VALUE, -Number.MAX_VALUE, 0],
          [Number.MIN_VALUE, 0, -Number.MIN_VALUE],
          [-0, 0, 1],
        ],
      },
    );
  });

  test('UTF-16 ordering matches a code-unit oracle, including unpaired surrogates', () => {
    fc.assert(
      fc.property(units, units, (a, b) => {
        let expected = a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
        for (let index = 0; index < Math.min(a.length, b.length); index++) {
          if (a[index] !== b[index]) {
            expected = a[index] < b[index] ? -1 : 1;
            break;
          }
        }
        expect(
          compareCodeUnits(
            String.fromCharCode(...a),
            String.fromCharCode(...b),
          ),
        ).toBe(expected);
      }),
      { seed: 9605, numRuns: 1500 },
    );
  });

  test('mixed directions are antisymmetric and lazy, and successive page prefixes preserve the sequence', () => {
    fc.assert(
      fc.property(
        fc.array(fc.tuple(finite, finite, fc.boolean()), { maxLength: 8 }),
        fc.string(),
        fc.string(),
        fc.array(fc.integer(), { maxLength: 40 }),
        fc.integer({ min: 1, max: 8 }),
        (fields, aPath, bPath, values, pageSize) => {
          const directions = fields.map(([, , descending]) => ({
            direction: descending ? ('desc' as const) : ('asc' as const),
          }));
          const called: number[] = [];
          const result = compareQueryKeys(
            directions,
            (index) => {
              called.push(index);
              return compareFiniteNumbers(fields[index][0], fields[index][1]);
            },
            aPath,
            bPath,
          );
          const reverse = compareQueryKeys(
            directions,
            (index) => compareFiniteNumbers(fields[index][1], fields[index][0]),
            bPath,
            aPath,
          );
          expect(result === -reverse).toBe(true);
          const firstDifference = fields.findIndex(([a, b]) => a !== b);
          expect(called).toEqual(
            Array.from(
              {
                length:
                  firstDifference === -1 ? fields.length : firstDifference + 1,
              },
              (_, index) => index,
            ),
          );
          const received: number[] = [];
          for (let offset = 0; offset < values.length; offset += pageSize) {
            received.push(
              ...takeQueryPage(
                values.filter((_, index) => index >= offset),
                pageSize,
              ),
            );
          }
          expect(received).toEqual(values);
        },
      ),
      { seed: 9606, numRuns: 500 },
    );
  });
});
