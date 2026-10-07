import { describe, expect, test } from '@jest/globals';
import { tipsHashToHex } from './tips-hash.js';

describe('tipsHashToHex', () => {
  test('produces lowercase hex of correct length', () => {
    const bytes = new Uint8Array([0x00, 0x0f, 0xff, 0xab]);
    expect(tipsHashToHex(bytes)).toBe('000fffab');
  });
});
