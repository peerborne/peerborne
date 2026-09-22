/**
 * Simple LRU cache with bounded size using Map insertion order.
 * Evicts the least-recently-used entry when the cache is full.
 */
export class LRUCache<K, V> {
  private readonly _map = new Map<K, V>();
  private readonly _maxSize: number;
  private _finalizedEntries: Map<K, V> | undefined;

  constructor(maxSize: number = 1000) {
    if (!Number.isFinite(maxSize) || maxSize < 1) {
      throw new RangeError(`LRUCache maxSize must be a finite number >= 1, got ${maxSize}`);
    }
    this._maxSize = Math.floor(maxSize);
  }

  get(key: K): V | undefined {
    const finalized = this._finalizedEntries;
    if (finalized !== undefined && finalized.has(key)) {
      // The overlay is newer than backing entries; refresh recency within it.
      const value = finalized.get(key)!;
      finalized.delete(key);
      finalized.set(key, value);
      return value;
    }
    this._materializeFinalizedEntries();
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
    this._materializeFinalizedEntries();
    this._setMapEntry(key, value);
  }

  /**
   * Stage an insertion whose returned finalizer only exposes a preallocated
   * entry. Unfinalized entries remain closure-local; only the finalizer assigns
   * `_finalizedEntries`. Ordinary cache operations materialize those committed
   * entries into the backing Map afterward. The finalizer
   * is idempotent and performs no Map work. Callers must not finalize
   * competing prepared insertions.
   * @internal Used within an externally reserved commit boundary.
   */
  prepareSet(key: K, value: V): () => void {
    return this.prepareSetMany(new Map([[key, value]]));
  }

  /**
   * Stage a bounded batch insertion as a closure-local overlay. All Map work needed
   * to build the overlay happens before this method returns; the returned
   * finalizer only exposes the prebuilt overlay. Cache activity before
   * finalization is retained when the overlay is later materialized. Callers
   * must reserve the cache from claim through finalization and must not compose
   * competing prepared insertions. Finalization cannot check or throw after
   * another provider may already have committed; validate before obtaining it.
   * @internal Used within an externally reserved commit boundary.
   */
  prepareSetMany(entries: ReadonlyMap<K, V>): () => void {
    this._materializeFinalizedEntries();
    const preparedEntries = new Map<K, V>();
    for (const [key, value] of entries) {
      this._setMapEntry(key, value, preparedEntries);
    }
    let finalized = false;
    return () => {
      if (finalized) return;
      this._finalizedEntries = preparedEntries;
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

  private _materializeFinalizedEntries(): void {
    const finalized = this._finalizedEntries;
    if (finalized === undefined) return;
    for (const [key, value] of finalized) {
      this._setMapEntry(key, value);
    }
    this._finalizedEntries = undefined;
  }

  has(key: K): boolean {
    const finalized = this._finalizedEntries;
    if (finalized !== undefined) {
      if (finalized.has(key)) return true;
      this._materializeFinalizedEntries();
    }
    return this._map.has(key);
  }

  get size(): number {
    const finalized = this._finalizedEntries;
    if (finalized === undefined) return this._map.size;
    let additions = 0;
    for (const key of finalized.keys()) {
      if (!this._map.has(key)) additions++;
    }
    return Math.min(this._maxSize, this._map.size + additions);
  }
}
