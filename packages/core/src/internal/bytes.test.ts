import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { runInNewContext } from 'node:vm';
import {
  byteLengthOf,
  compareBytes,
  concatBytes,
  copyUnsharedUint8Array,
  equalBytes,
  optionalEqualBytes,
} from './bytes.js';

const bytes = fc.uint8Array({ maxLength: 64 });

function spoofedLength<T extends Uint8Array>(value: T, byteLength: number): T {
  Object.defineProperty(value, 'byteLength', { value: byteLength });
  Object.defineProperty(value, 'length', { value: byteLength });
  return value;
}

describe('equalBytes', () => {
  test('agrees with element-wise equality', () => {
    fc.assert(
      fc.property(bytes, bytes, (left, right) => {
        const expected =
          left.length === right.length &&
          left.every((value, index) => value === right[index]);
        expect(equalBytes(left, right)).toBe(expected);
        expect(equalBytes(left, new Uint8Array(left))).toBe(true);
      }),
      { seed: 9701, numRuns: 200 },
    );
  });

  test('reads intrinsic lengths instead of shadowed properties', () => {
    const left = spoofedLength(new Uint8Array([1, 2]), 1);
    expect(byteLengthOf(left)).toBe(2);
    expect(equalBytes(left, new Uint8Array([1]))).toBe(false);
    expect(equalBytes(left, new Uint8Array([1, 2]))).toBe(true);
  });

  test('treats two absent optional values as equal', () => {
    const value = new Uint8Array([1]);
    expect(optionalEqualBytes(undefined, undefined)).toBe(true);
    expect(optionalEqualBytes(value, undefined)).toBe(false);
    expect(optionalEqualBytes(undefined, value)).toBe(false);
    expect(optionalEqualBytes(value, new Uint8Array([1]))).toBe(true);
  });
});

describe('compareBytes', () => {
  test('orders lexicographically with proper prefixes first', () => {
    fc.assert(
      fc.property(bytes, bytes, (left, right) => {
        const order = Math.sign(compareBytes(left, right));
        expect(Math.sign(compareBytes(right, left)) + order).toBe(0);
        expect(order === 0).toBe(equalBytes(left, right));
        expect(
          compareBytes(left, concatBytes([left, right])),
        ).toBeLessThanOrEqual(0);
        const leftHex = Buffer.from(left).toString('hex');
        const rightHex = Buffer.from(right).toString('hex');
        expect(order).toBe(
          leftHex < rightHex ? -1 : leftHex > rightHex ? 1 : 0,
        );
      }),
      { seed: 9702, numRuns: 200 },
    );
  });
});

describe('concatBytes', () => {
  test('preserves every part in order', () => {
    fc.assert(
      fc.property(fc.array(bytes, { maxLength: 8 }), (parts) => {
        expect([...concatBytes(parts)]).toEqual(
          parts.flatMap((part) => [...part]),
        );
      }),
      { seed: 9703, numRuns: 200 },
    );
  });

  test('should concatenate multiple Uint8Array', () => {
    const arr1 = new Uint8Array([1, 2, 3]);
    const arr2 = new Uint8Array([4, 5, 6]);
    const arr3 = new Uint8Array([7, 8, 9]);
    const result = concatBytes([arr1, arr2, arr3]);
    expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]));
  });

  test('should handle empty arrays', () => {
    const arr1 = new Uint8Array([]);
    const arr2 = new Uint8Array([1, 2]);
    const result = concatBytes([arr1, arr2]);
    expect(result).toEqual(new Uint8Array([1, 2]));
  });

  test('should handle single array', () => {
    const arr = new Uint8Array([1, 2, 3]);
    const result = concatBytes([arr]);
    expect(result).toEqual(arr);
  });

  test('should handle no arrays', () => {
    const result = concatBytes([]);
    expect(result).toEqual(new Uint8Array([]));
  });
});

describe('copyUnsharedUint8Array', () => {
  test('accepts genuine cross-realm bytes and ignores shadowed metadata', () => {
    const crossRealm = runInNewContext('new Uint8Array([1, 2, 3])') as unknown;
    expect(copyUnsharedUint8Array(crossRealm, 3, 3)).toEqual(
      new Uint8Array([1, 2, 3]),
    );

    const shadowed = new Uint8Array([4, 5, 6]);
    Object.defineProperty(shadowed, 'byteLength', {
      get() {
        throw new Error('shadowed getter must not run');
      },
    });
    expect(copyUnsharedUint8Array(shadowed, 3, 3)).toEqual(
      new Uint8Array([4, 5, 6]),
    );
  });

  test('uses captured intrinsic dispatch after Reflect.apply is replaced', () => {
    const descriptor = Object.getOwnPropertyDescriptor(Reflect, 'apply')!;
    let copied: Uint8Array | undefined;
    let failure: unknown;
    try {
      Object.defineProperty(Reflect, 'apply', {
        ...descriptor,
        value: () => {
          throw new Error('poisoned Reflect.apply');
        },
      });
      copied = copyUnsharedUint8Array(new Uint8Array([1, 2, 3]), 3, 3);
    } catch (error) {
      failure = error;
    } finally {
      Object.defineProperty(Reflect, 'apply', descriptor);
    }

    expect(failure).toBeUndefined();
    expect(copied).toEqual(new Uint8Array([1, 2, 3]));
  });

  test('rejects SharedArrayBuffer-backed bytes', () => {
    if (typeof SharedArrayBuffer === 'undefined') return;
    expect(() =>
      copyUnsharedUint8Array(new Uint8Array(new SharedArrayBuffer(3)), 3, 3),
    ).toThrow(/backing buffer/);
  });
});
