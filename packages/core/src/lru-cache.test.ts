import { describe, expect, test } from '@jest/globals';
import { LRUCache } from './lru-cache.js';

describe('LRUCache', () => {
  test('get/set basic operations', () => {
    const cache = new LRUCache<string, number>(3);
    cache.set('a', 1);
    cache.set('b', 2);
    expect(cache.get('a')).toBe(1);
    expect(cache.get('c')).toBeUndefined();
    expect(cache.size).toBe(2);
  });

  test('evicts least recently used when full', () => {
    const cache = new LRUCache<string, number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('c', 3); // evicts 'a'
    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('b')).toBe(2);
    expect(cache.get('c')).toBe(3);
  });

  test('get() refreshes insertion order (LRU)', () => {
    const cache = new LRUCache<string, number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    cache.get('a'); // refresh 'a' -- 'b' is now oldest
    cache.set('c', 3); // evicts 'b', not 'a'
    expect(cache.get('a')).toBe(1);
    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('c')).toBe(3);
  });

  test('overwrite existing key does not increase size', () => {
    const cache = new LRUCache<string, number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('a', 10); // overwrite
    expect(cache.size).toBe(2);
    expect(cache.get('a')).toBe(10);
  });

  test('maxSize=1 only keeps one entry', () => {
    const cache = new LRUCache<string, number>(1);
    cache.set('a', 1);
    cache.set('b', 2);
    expect(cache.size).toBe(1);
    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('b')).toBe(2);
  });

  test('has() returns correct membership', () => {
    const cache = new LRUCache<string, number>(2);
    cache.set('a', 1);
    expect(cache.has('a')).toBe(true);
    expect(cache.has('b')).toBe(false);
  });

  test('constructor rejects invalid maxSize', () => {
    expect(() => new LRUCache(0)).toThrow(RangeError);
    expect(() => new LRUCache(-1)).toThrow(RangeError);
    expect(() => new LRUCache(NaN)).toThrow(RangeError);
    expect(() => new LRUCache(Infinity)).toThrow(RangeError);
  });

  test('non-integer maxSize is floored', () => {
    const cache = new LRUCache<string, number>(2.9);
    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('c', 3); // effective maxSize=2, evicts 'a'
    expect(cache.get('a')).toBeUndefined();
    expect(cache.size).toBe(2);
  });
});
