/**
 * Simple LRU cache with bounded size using Map insertion order.
 * Evicts the least-recently-used entry when the cache is full.
 */
export class LRUCache<K, V> {
  private readonly _map = new Map<K, V>();
  private readonly _maxSize: number;

  constructor(maxSize: number = 1000) {
    if (!Number.isFinite(maxSize) || maxSize < 1) {
      throw new RangeError(`LRUCache maxSize must be a finite number >= 1, got ${maxSize}`);
    }
    this._maxSize = Math.floor(maxSize);
  }

  get(key: K): V | undefined {
    // get() returns undefined for both missing keys and stored undefined;
    // use has() to distinguish those cases before updating recency.
    const value = this._map.get(key);
    if (value !== undefined || this._map.has(key)) {
      // Move to end (most recently used)
      this._map.delete(key);
      this._map.set(key, value!);
      return value;
    }
    return undefined;
  }

  set(key: K, value: V): void {
    if (this._map.has(key)) {
      this._map.delete(key);
    } else if (this._map.size >= this._maxSize) {
      // Evict oldest (first) entry
      const firstKey = this._map.keys().next().value!;
      this._map.delete(firstKey);
    }
    this._map.set(key, value);
  }

  has(key: K): boolean {
    return this._map.has(key);
  }

  get size(): number {
    return this._map.size;
  }
}
