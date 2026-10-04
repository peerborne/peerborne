import { describe, expect, test } from '@jest/globals';
import { EPOCH_ID_LENGTH, toHex } from './epoch.js';

describe('epoch identifiers', () => {
  test('use 32-byte IDs', () => {
    expect(EPOCH_ID_LENGTH).toBe(32);
  });

  test('toHex produces zero-padded lowercase hex', () => {
    expect(toHex(new Uint8Array([0x00, 0x0a, 0xff, 0x10]))).toBe('000aff10');
    expect(toHex(new Uint8Array())).toBe('');
  });
});
