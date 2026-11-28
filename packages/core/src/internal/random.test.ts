import { describe, expect, test } from '@jest/globals';
import { shuffleArray } from './random.js';

describe('shuffleArray', () => {
  test('should shuffle array elements', () => {
    const arr = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const original = [...arr];
    shuffleArray(arr);
    // Array should have same elements but potentially in different order
    expect(arr.sort()).toEqual(original.sort());
    expect(arr.length).toBe(original.length);
  });

  test('should handle empty array', () => {
    const arr: number[] = [];
    shuffleArray(arr);
    expect(arr).toEqual([]);
  });

  test('should handle single element array', () => {
    const arr = [1];
    shuffleArray(arr);
    expect(arr).toEqual([1]);
  });
});
