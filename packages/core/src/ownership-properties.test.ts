import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { copyUnsharedUint8Array, snapshotDeepEnumerableData } from './utils.js';

const scalar = fc.oneof(
  fc.string({ maxLength: 50 }),
  fc.integer(),
  fc.boolean(),
  fc.constant(null),
);
const branch = fc.oneof(
  scalar,
  fc.array(scalar, { maxLength: 6 }),
  fc.dictionary(fc.string({ maxLength: 12 }), scalar, { maxKeys: 6 }),
);
const data = fc.oneof(
  branch,
  fc.array(branch, { maxLength: 6 }),
  fc.dictionary(fc.string({ maxLength: 12 }), branch, { maxKeys: 6 }),
);

describe('generated native ownership and reflection boundaries', () => {
  test('snapshots detach repeated aliases from both producers and other consumers', () => {
    fc.assert(
      fc.property(data, (value) => {
        const owned = JSON.parse(JSON.stringify(value)) as typeof value;
        const input = { left: owned, right: owned };
        const snapshot = snapshotDeepEnumerableData(input);
        const expected = JSON.stringify({ left: value, right: value });
        expect(JSON.stringify(snapshot)).toBe(expected);
        if (owned !== null && typeof owned === 'object') {
          expect(snapshot.left).not.toBe(owned);
          expect(snapshot.left).not.toBe(snapshot.right);
          Object.defineProperty(owned, '__mutation__', {
            value: 1,
            enumerable: true,
            configurable: true,
          });
          expect(JSON.stringify(snapshot)).toBe(expected);
          Object.defineProperty(snapshot.left!, '__consumer__', {
            value: 2,
            enumerable: true,
            configurable: true,
          });
          expect(JSON.stringify(snapshot.right)).toBe(JSON.stringify(value));
        }
      }),
      { seed: 9560, numRuns: 500 },
    );
  });

  test('never invokes enumerable accessors and rejects cyclic data', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 30 }),
        data,
        (key, value) => {
          let calls = 0;
          const record = Object.defineProperty({}, key, {
            enumerable: true,
            get: () => {
              calls++;
              return value;
            },
          });
          expect(() => snapshotDeepEnumerableData(record)).toThrow();
          expect(calls).toBe(0);
          const cycle: { value: unknown; self?: unknown } = { value };
          cycle.self = cycle;
          expect(() => snapshotDeepEnumerableData(cycle)).toThrow(
            /cycle|cyclic/i,
          );
        },
      ),
      { seed: 9561, numRuns: 300 },
    );
  });

  test('copies only a byte view range and rejects shared backing buffers', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 1024 }), (payload) => {
        const backing = new Uint8Array([19, ...payload, 20]);
        const view = backing.subarray(1, payload.length + 1);
        const result = copyUnsharedUint8Array(view, 0, payload.length);
        expect([...result]).toEqual([...payload]);
        expect(result.buffer).not.toBe(view.buffer);
        view.fill(7);
        expect([...result]).toEqual([...payload]);
        const shared = new Uint8Array(new SharedArrayBuffer(payload.length));
        expect(() => copyUnsharedUint8Array(shared, 0, payload.length)).toThrow(
          TypeError,
        );
      }),
      { seed: 9562, numRuns: 500 },
    );
  });
});
