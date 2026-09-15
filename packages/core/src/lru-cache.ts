/**
 * Simple LRU cache with bounded size using Map insertion order.
 * Evicts the least-recently-used entry when the cache is full.
 */
type DeferredCacheEntry<K, V> = {
  readonly key: K;
  readonly value: V;
};

export class LRUCache<K, V> {
  private readonly _map = new Map<K, V>();
  private readonly _maxSize: number;
  private _deferredEntry: DeferredCacheEntry<K, V> | undefined;

  constructor(maxSize: number = 1000) {
    if (!Number.isFinite(maxSize) || maxSize < 1) {
      throw new RangeError(`LRUCache maxSize must be a finite number >= 1, got ${maxSize}`);
    }
    this._maxSize = Math.floor(maxSize);
  }

  get(key: K): V | undefined {
    const deferred = this._deferredEntry;
    if (deferred !== undefined && sameValueZero(deferred.key, key)) {
      return deferred.value;
    }
    this._flushDeferredEntry();
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
    this._flushDeferredEntry();
    this._setMapEntry(key, value);
  }

  /**
   * Stage an insertion whose returned finalizer only exposes a preallocated
   * entry. The entry remains hidden until finalization, and ordinary cache
   * operations materialize it into the backing Map afterward. The finalizer
   * is idempotent and performs no Map work. Callers must not finalize
   * competing prepared insertions.
   */
  prepareSet(key: K, value: V): () => void {
    this._flushDeferredEntry();
    const entry: DeferredCacheEntry<K, V> = { key, value };
    let finalized = false;
    return () => {
      if (finalized) return;
      this._deferredEntry = entry;
      finalized = true;
    };
  }

  private _setMapEntry(key: K, value: V): void {
    if (this._map.has(key)) {
      this._map.delete(key);
    } else if (this._map.size >= this._maxSize) {
      // Evict oldest (first) entry
      const firstKey = this._map.keys().next().value!;
      this._map.delete(firstKey);
    }
    this._map.set(key, value);
  }

  private _flushDeferredEntry(): void {
    const deferred = this._deferredEntry;
    if (deferred === undefined) return;
    this._setMapEntry(deferred.key, deferred.value);
    this._deferredEntry = undefined;
  }

  has(key: K): boolean {
    const deferred = this._deferredEntry;
    if (deferred !== undefined) {
      if (sameValueZero(deferred.key, key)) return true;
      this._flushDeferredEntry();
    }
    return this._map.has(key);
  }

  get size(): number {
    const deferred = this._deferredEntry;
    if (deferred === undefined || this._map.has(deferred.key)) {
      return this._map.size;
    }
    return Math.min(this._maxSize, this._map.size + 1);
  }
}

function sameValueZero(left: unknown, right: unknown): boolean {
  return left === right || (left !== left && right !== right);
}
