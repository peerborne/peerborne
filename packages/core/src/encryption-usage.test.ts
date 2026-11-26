import { afterEach, describe, expect, jest, test } from '@jest/globals';
import {
  ENCRYPTION_LIMIT,
  ENCRYPTION_WARNING_THRESHOLD,
  EncryptionUsageCounter,
} from './encryption-usage.js';

afterEach(() => {
  jest.restoreAllMocks();
});

describe('EncryptionUsageCounter', () => {
  test('defaults to a warning past 2^31 and a limit of 2^32 encryptions', () => {
    expect(ENCRYPTION_WARNING_THRESHOLD).toBe(2 ** 31);
    expect(ENCRYPTION_LIMIT).toBe(2 ** 32);
  });

  test('warns once after the threshold and refuses past the limit', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const counter = new EncryptionUsageCounter<object>(2, 4);
    const key = {};

    counter.record(key);
    counter.record(key);
    expect(warn).not.toHaveBeenCalled();
    counter.record(key);
    expect(warn).toHaveBeenCalledTimes(1);
    counter.record(key);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(() => counter.record(key)).toThrow('rotate the document key');
    expect(() => counter.record(key)).toThrow('rotate the document key');
    expect(warn).toHaveBeenCalledTimes(1);
  });

  test('counts each key separately', () => {
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    const counter = new EncryptionUsageCounter<object>(0, 1);
    const first = {};
    const second = {};

    counter.record(first);
    expect(() => counter.record(first)).toThrow();
    expect(() => counter.record(second)).not.toThrow();
  });

  test.each([
    [-1, 2],
    [3, 2],
    [1.5, 2],
    [1, Number.POSITIVE_INFINITY],
  ])('rejects thresholds %p and %p', (warning, limit) => {
    expect(() => new EncryptionUsageCounter(warning, limit)).toThrow(
      RangeError,
    );
  });
});
