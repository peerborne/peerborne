import { describe, expect, test } from '@jest/globals';
import { EPOCH_ID_LENGTH } from './epoch.js';

describe('epoch identifiers', () => {
  test('use 32-byte IDs', () => {
    expect(EPOCH_ID_LENGTH).toBe(32);
  });
});
