import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  asciiBytes,
  encodeU16,
  encodeU32,
  encodeU64,
  encodeU8,
  lengthPrefixed16,
  lengthPrefixed32,
  MAX_U64,
  requireU64,
} from './big-endian.js';

describe('big-endian integers', () => {
  test('round-trip through DataView at every width', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 0xff }),
        fc.integer({ min: 0, max: 0xffff }),
        fc.integer({ min: 0, max: 0xffffffff }),
        fc.bigInt({ min: 0n, max: MAX_U64 }),
        (u8, u16, u32, u64) => {
          expect(encodeU8(u8)).toEqual(new Uint8Array([u8]));
          const view = (bytes: Uint8Array) => new DataView(bytes.buffer);
          expect(view(encodeU16(u16)).getUint16(0, false)).toBe(u16);
          expect(view(encodeU32(u32)).getUint32(0, false)).toBe(u32);
          expect(view(encodeU64(u64)).getBigUint64(0, false)).toBe(u64);
        },
      ),
      { seed: 9704, numRuns: 200 },
    );
  });

  test.each([
    [encodeU8, 0x100],
    [encodeU16, 0x10000],
    [encodeU32, 0x100000000],
  ])('rejects out-of-range and non-integer numbers', (encode, overflow) => {
    for (const value of [-1, 0.5, Number.NaN, overflow]) {
      expect(() => encode(value)).toThrow(/does not fit/);
    }
  });

  test('rejects values outside the unsigned 64-bit range', () => {
    expect(() => encodeU64(MAX_U64 + 1n, 'epoch')).toThrow(
      'epoch must be an unsigned 64-bit bigint',
    );
    expect(() => encodeU64(-1n)).toThrow(/u64 must be/);
    expect(() => requireU64(1, 'count')).toThrow(
      /count must be/,
    );
  });
});

describe('length-prefixed bytes', () => {
  test('prefix the exact byte length', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 300 }), (value) => {
        const short = lengthPrefixed16(value);
        const long = lengthPrefixed32(value);
        expect(new DataView(short.buffer).getUint16(0)).toBe(value.length);
        expect(new DataView(long.buffer).getUint32(0)).toBe(value.length);
        expect(short.subarray(2)).toEqual(value);
        expect(long.subarray(4)).toEqual(value);
      }),
      { seed: 9705, numRuns: 200 },
    );
  });

  test('reject a value too long for a u16 prefix', () => {
    expect(() => lengthPrefixed16(new Uint8Array(0x10000))).toThrow(
      'value does not fit in u16',
    );
  });
});

describe('asciiBytes', () => {
  test('encodes ASCII and rejects wider code units', () => {
    expect(asciiBytes('a/1\0')).toEqual(new Uint8Array([0x61, 0x2f, 0x31, 0]));
    expect(() => asciiBytes('é')).toThrow(/must be ASCII/);
  });
});
