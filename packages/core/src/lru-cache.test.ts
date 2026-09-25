import { describe, expect, jest, test } from '@jest/globals';
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

  test('reading a finalized entry preserves eager-insertion eviction and recency', () => {
    const eager = new LRUCache<string, number>(2);
    const deferred = new LRUCache<string, number>(2);
    for (const cache of [eager, deferred]) {
      cache.set('a', 1);
      cache.set('b', 2);
    }
    deferred.prepareSet('c', 3)();
    eager.set('c', 3);
    for (const key of ['c', 'a', 'b', 'c']) {
      expect(deferred.get(key)).toBe(eager.get(key));
    }
    eager.set('d', 4);
    deferred.set('d', 4);
    for (const key of ['a', 'b', 'c', 'd']) {
      expect(deferred.get(key)).toBe(eager.get(key));
    }
  });

  test('prepared set stays hidden and finalizes without touching Map', () => {
    const cache = new LRUCache<string, number>(2);
    cache.set('a', 1);
    const finalize = cache.prepareSet('b', 2);
    expect(cache.has('b')).toBe(false);
    expect(cache.get('b')).toBeUndefined();
    expect(cache.size).toBe(1);

    const backing = (
      cache as unknown as { _map: Map<string, number> }
    )._map;
    const set = jest.spyOn(backing, 'set').mockImplementation(() => {
      throw new Error('Map insertion must not run during finalization');
    });

    expect(() => finalize()).not.toThrow();
    finalize();

    expect(set).not.toHaveBeenCalled();
    expect(cache.has('b')).toBe(true);
    expect(cache.get('b')).toBe(2);
    expect(cache.size).toBe(2);
    set.mockRestore();
  });

  test('prepared set preserves writes made before finalization', () => {
    const cache = new LRUCache<string, number>(3);
    cache.set('a', 1);
    const finalize = cache.prepareSet('b', 2);

    cache.set('c', 3);
    finalize();

    expect(cache.get('a')).toBe(1);
    expect(cache.get('b')).toBe(2);
    expect(cache.get('c')).toBe(3);
    expect(cache.size).toBe(3);
  });

  test('prepared batch stays hidden and finalizes without Map work', () => {
    const cache = new LRUCache<string, number>(2);
    cache.set('a', 1);
    const entries = new Map<string, number>([
      ['b', 2],
      ['c', 3],
    ]);
    const finalize = cache.prepareSetMany(entries);
    entries.set('d', 4);

    expect(cache.has('a')).toBe(true);
    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('c')).toBeUndefined();

    const internals = cache as unknown as {
      _setMapEntry(key: string, value: number, map?: Map<string, number>): void;
    };
    const setMapEntry = jest
      .spyOn(internals, '_setMapEntry')
      .mockImplementation(() => {
        throw new Error('Batch finalization must not perform Map work');
      });
    try {
      expect(finalize()).toBeUndefined();
      expect(finalize()).toBeUndefined();
      expect(setMapEntry).not.toHaveBeenCalled();
    } finally {
      setMapEntry.mockRestore();
    }

    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('b')).toBe(2);
    expect(cache.get('c')).toBe(3);
    expect(cache.get('d')).toBeUndefined();
    expect(cache.size).toBe(2);
  });

  test('prepared batch preserves intervening reads when choosing eviction', () => {
    const cache = new LRUCache<string, number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    const finalize = cache.prepareSetMany(new Map([['c', 3]]));

    expect(cache.get('a')).toBe(1);
    finalize();

    expect(cache.has('b')).toBe(false);
    expect(cache.get('a')).toBe(1);
    expect(cache.get('c')).toBe(3);
  });

  test('prepared batch preserves intervening writes', () => {
    const cache = new LRUCache<string, number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    const finalize = cache.prepareSetMany(new Map([['c', 3]]));

    cache.set('d', 4);
    finalize();

    expect(cache.has('b')).toBe(false);
    expect(cache.get('c')).toBe(3);
    expect(cache.get('d')).toBe(4);
  });

  test('write to a staged key before finalization supersedes the staged value', () => {
    const cache = new LRUCache<string, number>(3);
    cache.set('a', 1);
    const finalize = cache.prepareSetMany(
      new Map([
        ['b', 2],
        ['c', 3],
      ]),
    );

    cache.set('c', 4);
    finalize();

    expect(cache.get('c')).toBe(4);
    expect(cache.get('b')).toBe(2);
    expect(cache.get('a')).toBe(1);
    expect(cache.size).toBe(3);
  });

  test('write after finalization replaces the finalized value', () => {
    const cache = new LRUCache<string, number>(2);
    const finalize = cache.prepareSet('c', 3);
    finalize();

    cache.set('c', 4);
    finalize();

    expect(cache.get('c')).toBe(4);
    expect(cache.size).toBe(1);
  });

  test('later batch preparation never flushes an abandoned batch', () => {
    const cache = new LRUCache<string, number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    cache.get('a');

    cache.prepareSetMany(new Map([['c', 3]]));
    const finalizeNext = cache.prepareSetMany(new Map([['d', 4]]));
    finalizeNext();

    expect(cache.has('b')).toBe(false);
    expect(cache.get('a')).toBe(1);
    expect(cache.get('c')).toBeUndefined();
    expect(cache.get('d')).toBe(4);
  });

  test('prepared batch only exposes the last bounded entries', () => {
    const cache = new LRUCache<string, number>(2);
    const finalize = cache.prepareSetMany(
      new Map([
        ['a', 1],
        ['b', 2],
        ['c', 3],
      ]),
    );

    finalize();

    expect(cache.has('a')).toBe(false);
    expect(cache.get('b')).toBe(2);
    expect(cache.get('c')).toBe(3);
    expect(cache.size).toBe(2);
  });

  test('failed batch preparation never exposes a partial insertion', () => {
    const cache = new LRUCache<string, number>(3);
    cache.set('a', 1);
    const entries = {
      *[Symbol.iterator]() {
        yield ['b', 2] as const;
        throw new Error('malformed batch');
      },
    } as unknown as ReadonlyMap<string, number>;

    expect(() => cache.prepareSetMany(entries)).toThrow('malformed batch');
    expect(cache.get('a')).toBe(1);
    expect(cache.get('b')).toBeUndefined();
    expect(cache.size).toBe(1);
  });

  test('abandoning a prepared set leaves membership and recency unchanged', () => {
    const cache = new LRUCache<string, number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    cache.get('a');

    cache.prepareSet('c', 3);
    expect(cache.get('c')).toBeUndefined();
    expect(cache.has('c')).toBe(false);
    expect(cache.size).toBe(2);
    expect(cache.get('missing')).toBeUndefined();
    expect(cache.has('missing')).toBe(false);
    cache.set('d', 4);

    expect(cache.get('a')).toBe(1);
    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('c')).toBeUndefined();
    expect(cache.get('d')).toBe(4);
    expect(cache.size).toBe(2);
  });

  test('later preparation never flushes an abandoned prepared set', () => {
    const cache = new LRUCache<string, number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    cache.get('a');

    cache.prepareSet('c', 3);
    const finalizeNext = cache.prepareSet('d', 4);

    expect(cache.get('c')).toBeUndefined();
    expect(cache.has('c')).toBe(false);
    expect(cache.size).toBe(2);

    finalizeNext();

    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('a')).toBe(1);
    expect(cache.get('c')).toBeUndefined();
    expect(cache.get('d')).toBe(4);
    expect(cache.size).toBe(2);
  });

  test('prepared set preserves the cache bound and LRU eviction', () => {
    const cache = new LRUCache<string, number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    const finalize = cache.prepareSet('c', 3);

    expect(cache.size).toBe(2);
    expect(cache.has('a')).toBe(true);
    expect(cache.has('c')).toBe(false);

    finalize();

    expect(cache.size).toBe(2);
    expect(cache.has('a')).toBe(false);
    expect(cache.has('b')).toBe(true);
    expect(cache.has('c')).toBe(true);
    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('b')).toBe(2);
    expect(cache.get('c')).toBe(3);
  });

  test('prepared set uses current recency after intervening writes', () => {
    const cache = new LRUCache<string, number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    const finalize = cache.prepareSet('c', 3);

    cache.set('d', 4);
    finalize();

    expect(cache.size).toBe(2);
    expect(cache.has('c')).toBe(true);
    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('c')).toBe(3);
    expect(cache.get('d')).toBe(4);
  });

  test('prepared set uses current recency after intervening reads', () => {
    const cache = new LRUCache<string, number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    const finalize = cache.prepareSet('c', 3);

    expect(cache.get('a')).toBe(1);
    finalize();

    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('a')).toBe(1);
    expect(cache.get('c')).toBe(3);
    expect(cache.size).toBe(2);
  });

  test('prepared replacement refreshes recency without evicting an entry', () => {
    const cache = new LRUCache<string, number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    const finalize = cache.prepareSet('a', 10);

    finalize();
    expect(cache.get('a')).toBe(10);
    expect(cache.size).toBe(2);
    cache.set('c', 3);

    expect(cache.get('a')).toBe(10);
    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('c')).toBe(3);
    expect(cache.size).toBe(2);
  });
});
