/**
 * Simple LRU cache with bounded size using Map insertion order.
 * Evicts the least-recently-used entry when the cache is full.
 */
type CacheEntry<K, V> = {
  readonly key: K;
  readonly value: V;
};

export class LRUCache<K, V> {
  private readonly _map = new Map<K, V>();
  private readonly _maxSize: number;
  private _finalizedEntry: CacheEntry<K, V> | undefined;

  constructor(maxSize: number = 1000) {
    if (!Number.isFinite(maxSize) || maxSize < 1) {
      throw new RangeError(`LRUCache maxSize must be a finite number >= 1, got ${maxSize}`);
    }
    this._maxSize = Math.floor(maxSize);
  }

  get(key: K): V | undefined {
    const finalized = this._finalizedEntry;
    if (finalized !== undefined && sameValueZero(finalized.key, key)) {
      return finalized.value;
    }
    this._materializeFinalizedEntry();
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
    this._materializeFinalizedEntry();
    this._setMapEntry(key, value);
  }

  /**
   * Stage an insertion whose returned finalizer only exposes a preallocated
   * entry. Unfinalized entries remain closure-local; only the finalizer assigns
   * `_finalizedEntry`. Ordinary cache operations materialize that committed
   * entry into the backing Map afterward. The finalizer
   * is idempotent and performs no Map work. Callers must not finalize
   * competing prepared insertions.
   */
  prepareSet(key: K, value: V): () => void {
    this._materializeFinalizedEntry();
    const entry: CacheEntry<K, V> = { key, value };
    let finalized = false;
    return () => {
      if (finalized) return;
      this._finalizedEntry = entry;
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

  private _materializeFinalizedEntry(): void {
    const finalized = this._finalizedEntry;
    if (finalized === undefined) return;
    this._setMapEntry(finalized.key, finalized.value);
    this._finalizedEntry = undefined;
  }

  has(key: K): boolean {
    const finalized = this._finalizedEntry;
    if (finalized !== undefined) {
      if (sameValueZero(finalized.key, key)) return true;
      this._materializeFinalizedEntry();
    }
    return this._map.has(key);
  }

  get size(): number {
    const finalized = this._finalizedEntry;
    if (finalized === undefined || this._map.has(finalized.key)) {
      return this._map.size;
    }
    return Math.min(this._maxSize, this._map.size + 1);
  }
}

function sameValueZero(left: unknown, right: unknown): boolean {
  return left === right || (left !== left && right !== right);
}
