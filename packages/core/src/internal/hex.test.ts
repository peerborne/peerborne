import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { bytesToHex, tryDecodeLowercaseHex } from './hex.js';
import { randomHex } from './random.js';

describe('lowercase hex', () => {
  test('matches Node hex encoding and round-trips', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 64 }), (bytes) => {
        const hex = bytesToHex(bytes);
        expect(hex).toBe(Buffer.from(bytes).toString('hex'));
        expect(tryDecodeLowercaseHex(hex, bytes.length)).toEqual(bytes);
      }),
      { seed: 9706, numRuns: 200 },
    );
  });

  test('encodes the view, not its backing buffer', () => {
    const view = new Uint8Array([0, 0xab, 0xcd, 0]).subarray(1, 3);
    expect(bytesToHex(view)).toBe('abcd');
  });

  test.each(['ABCD', 'abc', 'abcdef', 'zz00', ' abc', 'ab\ncd'])(
    'rejects non-canonical input %p',
    (value) => {
      expect(tryDecodeLowercaseHex(value, 2)).toBeUndefined();
    },
  );

  test('random identifiers have the requested width', () => {
    expect(randomHex(16)).toMatch(/^[0-9a-f]{32}$/);
  });
});
