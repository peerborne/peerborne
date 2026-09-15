/**
 * Simple LRU cache with bounded size using Map insertion order.
 * Evicts the least-recently-used entry when the cache is full.
 */
export class LRUCache<K, V> {
  private readonly _map = new Map<K, V>();
  private readonly _maxSize: number;
  private _deferredEntries: Map<K, V> | undefined;

  constructor(maxSize: number = 1000) {
    if (!Number.isFinite(maxSize) || maxSize < 1) {
      throw new RangeError(`LRUCache maxSize must be a finite number >= 1, got ${maxSize}`);
    }
    this._maxSize = Math.floor(maxSize);
  }

  get(key: K): V | undefined {
    const deferred = this._deferredEntries;
    if (deferred !== undefined && deferred.has(key)) {
      const value = deferred.get(key)!;
      deferred.delete(key);
      deferred.set(key, value);
      return value;
    }
    this._flushDeferredEntries();
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
    this._flushDeferredEntries();
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
    return this.prepareSetMany(new Map([[key, value]]));
  }

  /**
   * Stage a bounded batch insertion as a deferred overlay. All Map work needed
   * to build the overlay happens before this method returns; the returned
   * finalizer only exposes the prebuilt overlay. Cache activity before
   * finalization is retained when the overlay is later materialized. Callers
   * must not finalize competing prepared insertions.
   */
  prepareSetMany(entries: ReadonlyMap<K, V>): () => void {
    this._flushDeferredEntries();
    const deferredEntries = new Map<K, V>();
    for (const [key, value] of entries) {
      this._setMapEntry(key, value, deferredEntries);
    }
    let finalized = false;
    return () => {
      if (finalized) return;
      this._deferredEntries = deferredEntries;
      finalized = true;
    };
  }

  private _setMapEntry(key: K, value: V, map = this._map): void {
    if (map.has(key)) {
      map.delete(key);
    } else if (map.size >= this._maxSize) {
      // Evict oldest (first) entry
      const firstKey = map.keys().next().value!;
      map.delete(firstKey);
    }
    map.set(key, value);
  }

  private _flushDeferredEntries(): void {
    const deferred = this._deferredEntries;
    if (deferred === undefined) return;
    for (const [key, value] of deferred) {
      this._setMapEntry(key, value);
    }
    this._deferredEntries = undefined;
  }

  has(key: K): boolean {
    const deferred = this._deferredEntries;
    if (deferred !== undefined) {
      if (deferred.has(key)) return true;
      this._flushDeferredEntries();
    }
    return this._map.has(key);
  }

  get size(): number {
    const deferred = this._deferredEntries;
    if (deferred === undefined) return this._map.size;
    let additions = 0;
    for (const key of deferred.keys()) {
      if (!this._map.has(key)) additions++;
    }
    return Math.min(this._maxSize, this._map.size + additions);
  }
}
