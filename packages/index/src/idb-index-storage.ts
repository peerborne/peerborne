import { openDB, IDBPDatabase } from 'idb';
import { IndexFieldDefinition, FieldFilter, SortClause } from './types.js';
import { IndexStorage, IndexEntry } from './index-storage.js';

/**
 * IndexedDB-backed implementation of IndexStorage using the `idb` library.
 * Each index is stored as a separate IDB object store with `documentPath` as key path.
 */
export class IDBIndexStorage implements IndexStorage {
  private _dbName: string;
  private _db: IDBPDatabase | null = null;
  private _initializedStores: Set<string> = new Set();
  /** Tracks which IDB indexes exist per store, so query() can use them for fast lookups. */
  private _indexedFields: Map<string, Set<string>> = new Map();

  constructor(dbName: string = 'collabswarm-index') {
    this._dbName = dbName;
  }

  async initialize(indexName: string, fields: IndexFieldDefinition[]): Promise<void> {
    // If we've previously initialized this store and the connection is open,
    // we can skip reopening *only* when the cached IDB-index set already
    // covers every field the caller is requesting. Callers may invoke
    // `initialize(indexName, fields)` again later in the same process with
    // additional fields (e.g. as the application defines new indexes), and
    // we must perform a schema upgrade to create indexes for those fields.
    if (this._initializedStores.has(indexName) && this._db) {
      const cached = this._indexedFields.get(indexName);
      const allCovered = !!cached && fields.every((f) => cached.has(f.path));
      if (allCovered) return;
    }

    // Close existing connection before upgrading
    if (this._db) {
      this._db.close();
      this._db = null;
    }

    // Open + (optionally) upgrade. Wrapped in a retry loop because another
    // tab/worker may upgrade the DB between our version-read and our reopen,
    // causing `openDB(name, currentVersion + 1)` to throw a VersionError.
    // On VersionError we re-read the current version and try again.
    const MAX_OPEN_ATTEMPTS = 4;
    const RETRY_BASE_DELAY_MS = 25;
    let existingIndexNames: string[] = [];
    for (let attempt = 0; attempt < MAX_OPEN_ATTEMPTS; attempt++) {
      // Read current version + existing schema so we can decide whether we
      // need to upgrade to create a new store or add missing indexes.
      const existingDb = await openDB(this._dbName);
      const currentVersion = existingDb.version;
      const storeAlreadyExists = existingDb.objectStoreNames.contains(indexName);
      const probedIndexNames: string[] = [];
      if (storeAlreadyExists) {
        const tx = existingDb.transaction(indexName, 'readonly');
        const store = tx.objectStore(indexName);
        // DOMStringList isn't iterable under this project's tsconfig
        // (lib includes "DOM" but not "DOM.Iterable"), so iterate by index.
        const idxNames = store.indexNames;
        for (let i = 0; i < idxNames.length; i++) {
          const idxName = idxNames.item(i);
          if (idxName !== null) probedIndexNames.push(idxName);
        }
        // Await the readonly transaction before closing the DB. We issued no
        // requests, but some IDB implementations hold locks until the
        // transaction completes so awaiting here avoids keeping it alive.
        await tx.done;
      }
      existingDb.close();

      // Determine which requested fields are missing IDB indexes on the
      // persisted store. If any are missing we need to bump the version and
      // create them in an `upgrade` callback; otherwise we can reopen at the
      // current version.
      const missingIndexFields = storeAlreadyExists
        ? fields.filter((f) => !probedIndexNames.includes(f.path))
        : fields;
      const needsUpgrade = !storeAlreadyExists || missingIndexFields.length > 0;

      try {
        if (needsUpgrade) {
          const newVersion = currentVersion + 1;
          this._db = await openDB(this._dbName, newVersion, {
            upgrade(db, _oldVersion, _newVersion, tx) {
              let store;
              if (!db.objectStoreNames.contains(indexName)) {
                store = db.createObjectStore(indexName, { keyPath: 'documentPath' });
              } else {
                store = tx.objectStore(indexName);
              }
              for (const field of missingIndexFields) {
                // Guard in case a concurrent upgrade already created the index.
                if (!store.indexNames.contains(field.path)) {
                  store.createIndex(field.path, `fields.${field.path}`, { unique: false });
                }
              }
            },
          });
        } else {
          this._db = await openDB(this._dbName, currentVersion);
        }
        existingIndexNames = probedIndexNames;
        break;
      } catch (err) {
        const isVersionError =
          typeof DOMException !== 'undefined' &&
          err instanceof DOMException &&
          err.name === 'VersionError';
        if (isVersionError && attempt < MAX_OPEN_ATTEMPTS - 1) {
          // A concurrent tab/worker upgraded the DB between our two opens.
          // Back off briefly with exponential delay + jitter to break ties
          // when many openers race to upgrade, then re-probe at the new
          // version.
          const delay = RETRY_BASE_DELAY_MS * (1 << attempt) + Math.floor(Math.random() * RETRY_BASE_DELAY_MS);
          await new Promise<void>((resolve) => setTimeout(resolve, delay));
          continue;
        }
        throw err;
      }
    }

    // Track which fields now have IDB indexes for this store. Combine the
    // pre-existing index names with the ones we just created so query() never
    // calls store.index() for an index that doesn't exist.
    const fieldSet = new Set<string>(existingIndexNames);
    for (const field of fields) {
      fieldSet.add(field.path);
    }
    this._indexedFields.set(indexName, fieldSet);

    this._initializedStores.add(indexName);
  }

  async put(indexName: string, documentPath: string, fields: Record<string, unknown>): Promise<void> {
    const db = this._getDB();
    await db.put(indexName, { documentPath, fields: { ...fields } });
  }

  async delete(indexName: string, documentPath: string): Promise<void> {
    const db = this._getDB();
    await db.delete(indexName, documentPath);
  }

  async query(
    indexName: string,
    filters: FieldFilter[],
    sort?: SortClause[],
    limit?: number,
    offset?: number,
  ): Promise<IndexEntry[]> {
    const db = this._getDB();

    if (offset !== undefined && offset < 0) {
      throw new RangeError(`offset must be non-negative, got ${offset}`);
    }
    if (limit !== undefined && limit < 0) {
      throw new RangeError(`limit must be non-negative, got ${limit}`);
    }

    if (!db.objectStoreNames.contains(indexName)) return [];

    const tx = db.transaction(indexName, 'readonly');
    const store = tx.objectStore(indexName);

    let results: IndexEntry[] = [];

    // Optimization: leverage IDB indexes for single-field equality or range queries
    // on indexed fields instead of always doing a full JS scan.
    const idbStrategy = this._pickIDBStrategy(indexName, filters);

    if (idbStrategy) {
      const { indexFieldPath, keyRange, remainingFilters } = idbStrategy;
      const idbIndex = store.index(indexFieldPath);
      let cursor = await idbIndex.openCursor(keyRange);
      while (cursor) {
        const record = cursor.value as { documentPath: string; fields: Record<string, unknown> };
        if (this._matchesFilters(record.fields, remainingFilters)) {
          results.push({ documentPath: record.documentPath, fields: { ...record.fields } });
        }
        cursor = await cursor.continue();
      }
    } else {
      // Fallback: full scan with JS-side filtering
      let cursor = await store.openCursor();
      while (cursor) {
        const record = cursor.value as { documentPath: string; fields: Record<string, unknown> };
        if (this._matchesFilters(record.fields, filters)) {
          results.push({ documentPath: record.documentPath, fields: { ...record.fields } });
        }
        cursor = await cursor.continue();
      }
    }

    await tx.done;

    // Sort in JavaScript
    if (sort && sort.length > 0) {
      results.sort((a, b) => this._compareEntries(a.fields, b.fields, sort));
    }

    // Apply pagination
    const start = offset ?? 0;
    if (limit !== undefined) {
      results = results.slice(start, start + limit);
    } else if (start > 0) {
      results = results.slice(start);
    }

    return results;
  }

  async get(indexName: string, documentPath: string): Promise<Record<string, unknown> | undefined> {
    const db = this._getDB();

    if (!db.objectStoreNames.contains(indexName)) return undefined;

    const record = await db.get(indexName, documentPath) as { documentPath: string; fields: Record<string, unknown> } | undefined;
    return record ? { ...record.fields } : undefined;
  }

  async clear(indexName: string): Promise<void> {
    const db = this._getDB();
    if (db.objectStoreNames.contains(indexName)) {
      await db.clear(indexName);
    }
  }

  async close(): Promise<void> {
    if (this._db) {
      this._db.close();
      this._db = null;
    }
    // After close(), initialize() will reopen the database; this set just tracks which stores exist.
  }

  private _getDB(): IDBPDatabase {
    if (!this._db) {
      throw new Error('IDBIndexStorage: database not initialized. Call initialize() first.');
    }
    return this._db;
  }

  /**
   * Determine whether an IDB index can accelerate the query.
   *
   * Eligible cases (the first matching filter wins):
   *   - A single-field `eq` filter on an indexed field uses `IDBKeyRange.only(value)`.
   *   - A single-field `gt`/`gte` filter on an indexed numeric field uses
   *     `IDBKeyRange.lowerBound(value)`. (`lt`/`lte` are intentionally
   *     full-scanned — see the comment in `_isIDBAcceleratable`.)
   *   - A `prefix` filter on an indexed string field uses a lower/upper bound range.
   *
   * Any remaining filters that cannot be served by the IDB index are returned
   * as `remainingFilters` and applied in JavaScript after the cursor scan.
   */
  private _pickIDBStrategy(
    indexName: string,
    filters: FieldFilter[],
  ): { indexFieldPath: string; keyRange: IDBKeyRange | null; remainingFilters: FieldFilter[] } | null {
    if (filters.length === 0) return null;

    const indexedFields = this._indexedFields.get(indexName);
    if (!indexedFields) return null;

    for (let i = 0; i < filters.length; i++) {
      const filter = filters[i];
      // Only use IDB-accelerated lookup when an IDB index exists for this field
      if (!indexedFields.has(filter.path)) continue;

      let keyRange: IDBKeyRange | null = null;

      // IDB key ranges compare filter.value against the raw stored field value,
      // while the JS-side _matchesFilter path normalizes values via
      // _normalizeForComparison (e.g., Date -> timestamp, ISO-8601 string ->
      // timestamp). Using the IDB strategy for values that require normalization
      // would produce different results from the JS path, so we restrict the
      // IDB-accelerated path to filter values that are primitive strings/numbers
      // for which normalization is a no-op.
      if (!this._isIDBAcceleratable(filter.operator, filter.value)) continue;

      // `eq` is the only operator we can fully delegate to IDB: `IDBKeyRange.only`
      // matches by strict-equal semantics that the JS-side `eq` path also uses,
      // so the cursor only yields records that already satisfy the filter and
      // it can be removed from `remainingFilters`.
      //
      // Range operators (`gt`/`gte`/`lt`/`lte`) cannot be dropped: IDB's total
      // key order (per the W3C IndexedDB spec) is `number < Date < string <
      // binary < Array`, so e.g. a numeric `lowerBound(5)` cursor will also
      // iterate over every Date, string, binary, and Array key in the index.
      // We keep the range filter in `remainingFilters` so the JS-side
      // `_matchesFilter` re-checks the type and bound on each candidate.
      //
      // `prefix` likewise cannot be dropped. We need a true lexicographic
      // successor of the prefix as the upper bound so the cursor doesn't
      // skip stored keys whose suffix happens to consist of high code units.
      // A simple `value + '\uffff'` (or any fixed-length `\uffff` padding)
      // is incorrect: e.g. prefix "hello" would miss "hello\uffff\uffff"
      // because that key sorts above "hello\uffff" but below
      // "hello\uffff\uffff\uffff". We compute the true successor by
      // incrementing the final code unit; if the prefix ends in a code unit
      // that cannot be incremented (or is empty), we fall back to a
      // lower-bound-only range so the cursor visits every key >= prefix and
      // the JS-side filter rejects non-matches. We also keep the prefix
      // filter in `remainingFilters` so `_matchesFilter` re-validates every
      // candidate with `String.prototype.startsWith` -- both as defense in
      // depth and so any future change to the bound can't silently widen
      // the result set.
      let dropAcceleratedFilter = false;
      switch (filter.operator) {
        case 'eq':
          keyRange = IDBKeyRange.only(filter.value);
          dropAcceleratedFilter = true;
          break;
        case 'gt':
          keyRange = IDBKeyRange.lowerBound(filter.value, true);
          break;
        case 'gte':
          keyRange = IDBKeyRange.lowerBound(filter.value, false);
          break;
        // `lt`/`lte` are rejected by `_isIDBAcceleratable` (see comment there)
        // and so never reach this switch — handled by the full-scan fallback.
        case 'prefix': {
          const prefix = filter.value as string;
          const successor = this._lexicographicSuccessor(prefix);
          if (successor === null) {
            // No representable successor (empty prefix or final code unit at
            // 0xFFFF). Fall back to an open-ended lower bound; the JS-side
            // filter still validates `startsWith`.
            keyRange = IDBKeyRange.lowerBound(prefix, false);
          } else {
            // Half-open range [prefix, successor): every key with the given
            // prefix is included, no padding heuristics required.
            keyRange = IDBKeyRange.bound(prefix, successor, false, true);
          }
          break;
        }
        default:
          continue;
      }

      const remainingFilters = dropAcceleratedFilter
        ? filters.filter((_, idx) => idx !== i)
        : filters.slice();
      return { indexFieldPath: filter.path, keyRange, remainingFilters };
    }

    return null;
  }

  /**
   * Determine whether a filter value is safe to use directly in an IDBKeyRange
   * without diverging from the JS-side `_matchesFilter` / `_normalizeForComparison`
   * semantics.
   *
   * - `eq`: safe for both strings and numbers. `IDBKeyRange.only` does an
   *   exact-type equality match, and the JS-side `eq` path uses `===` (no
   *   normalization), so ISO-8601-like date strings are acceptable here -- they
   *   are only problematic when the two sides disagree about normalization.
   * - `prefix`: safe only for strings (bounded string range).
   * - `gt`/`gte`/`lt`/`lte`: accelerated only for finite numeric filter values.
   *   JS comparison coerces cross-type operands (e.g. `10 > '2'` is true) while
   *   `IDBKeyRange` treats each key type as distinct, so allowing strings for
   *   a range operator would silently change the result set when stored keys
   *   are numeric. Date objects and ISO-8601-like date strings are excluded to
   *   avoid diverging from `_normalizeForComparison`, which normalizes them to
   *   numeric timestamps for the JS range path while IDB would compare them by
   *   their raw native ordering.
   */
  private _isIDBAcceleratable(operator: FieldFilter['operator'], value: unknown): boolean {
    if (operator === 'prefix') {
      return typeof value === 'string';
    }
    // Range operators: only `gt`/`gte` are safe to accelerate.
    //
    // IDB key ordering is `number < Date < string < binary < Array`, while
    // JS `<`/`<=`/`>`/`>=` coerce cross-type operands. With a numeric filter
    // value:
    //   - `lowerBound(N)` (gt/gte): yields all keys >= N, *including* Date,
    //     string, binary, and Array keys (they sort above numbers). The JS
    //     `_matchesFilter` re-checks each candidate, so any cross-type
    //     records are correctly filtered out — at worst we visit too many.
    //   - `upperBound(N)` (lt/lte): yields only numeric keys <= N. Stored
    //     string keys like `'2'` that JS `<=` would coerce-and-match are
    //     *never visited* by the cursor, so JS can't recover them. To keep
    //     query results identical to the JS-only path under mixed-type
    //     data, we leave `lt`/`lte` to the full-scan fallback.
    if (operator === 'gt' || operator === 'gte') {
      return typeof value === 'number' && Number.isFinite(value);
    }
    if (operator === 'lt' || operator === 'lte') {
      return false;
    }
    // `eq`: strict-equality on both sides — safe for numbers and strings,
    // including ISO date strings. Date objects are excluded here because the
    // two sides disagree on Date equality: `IDBKeyRange.only(dateObj)`
    // matches stored Dates by timestamp, while JS `===` in `_matchesFilter`
    // compares by object identity. Accelerating would silently change which
    // records match. Booleans are excluded because they are not valid IDB
    // keys per the IndexedDB spec — `IDBKeyRange.only(true/false)` throws
    // `DataError` at runtime, so they must use the JS-side scan path.
    if (operator === 'eq') {
      if (typeof value === 'number') return Number.isFinite(value);
      if (typeof value === 'string') return true;
      return false;
    }
    // Any other operators (neq / in / contains) are not accelerated.
    return false;
  }

  /**
   * Compute the lexicographic successor of `prefix` for the purpose of
   * forming a half-open IDB key range `[prefix, successor)` that matches
   * every string with the given prefix.
   *
   * Strategy: walk back from the final code unit and increment the first
   * one that is not 0xFFFF, truncating any trailing 0xFFFFs. If no code
   * unit is incrementable (the prefix is empty or consists entirely of
   * 0xFFFF), return null so the caller can fall back to a lower-bound-only
   * range.
   *
   * Note: we operate on UTF-16 code units (not code points). This is
   * correct for IDB string ordering, which compares strings code-unit by
   * code-unit per the W3C IndexedDB spec.
   */
  private _lexicographicSuccessor(prefix: string): string | null {
    for (let i = prefix.length - 1; i >= 0; i--) {
      const code = prefix.charCodeAt(i);
      if (code < 0xffff) {
        return prefix.slice(0, i) + String.fromCharCode(code + 1);
      }
    }
    return null;
  }

  private _matchesFilters(fields: Record<string, unknown>, filters: FieldFilter[]): boolean {
    return filters.every(filter => this._matchesFilter(fields, filter));
  }

  private _matchesFilter(fields: Record<string, unknown>, filter: FieldFilter): boolean {
    const value = this._resolveFieldPath(fields, filter.path);

    switch (filter.operator) {
      case 'eq':
        return value === filter.value;

      case 'neq':
        return value !== filter.value;

      case 'gt': {
        const [nv, nfv] = [this._normalizeForComparison(value), this._normalizeForComparison(filter.value)];
        return nv !== undefined && nv !== null && nfv !== undefined && nfv !== null && nv > nfv;
      }

      case 'gte': {
        const [nv, nfv] = [this._normalizeForComparison(value), this._normalizeForComparison(filter.value)];
        return nv !== undefined && nv !== null && nfv !== undefined && nfv !== null && nv >= nfv;
      }

      case 'lt': {
        const [nv, nfv] = [this._normalizeForComparison(value), this._normalizeForComparison(filter.value)];
        return nv !== undefined && nv !== null && nfv !== undefined && nfv !== null && nv < nfv;
      }

      case 'lte': {
        const [nv, nfv] = [this._normalizeForComparison(value), this._normalizeForComparison(filter.value)];
        return nv !== undefined && nv !== null && nfv !== undefined && nfv !== null && nv <= nfv;
      }

      case 'prefix':
        return typeof value === 'string' && typeof filter.value === 'string' && value.startsWith(filter.value);

      case 'in':
        return Array.isArray(filter.value) && filter.value.includes(value);

      case 'contains':
        return typeof value === 'string' && typeof filter.value === 'string' && value.includes(filter.value);

      default:
        return false;
    }
  }

  private _resolveFieldPath(obj: Record<string, unknown>, path: string): unknown {
    const segments = path.split('.');
    let current: unknown = obj;
    for (const segment of segments) {
      if (current === null || current === undefined || typeof current !== 'object') {
        return undefined;
      }
      current = (current as Record<string, unknown>)[segment];
    }
    return current;
  }

  private _compareEntries(
    a: Record<string, unknown>,
    b: Record<string, unknown>,
    sort: SortClause[],
  ): number {
    for (const clause of sort) {
      const va = this._resolveFieldPath(a, clause.path);
      const vb = this._resolveFieldPath(b, clause.path);
      const cmp = this._compareValues(va, vb);
      if (cmp !== 0) {
        return clause.direction === 'desc' ? -cmp : cmp;
      }
    }
    return 0;
  }

  private _normalizeForComparison(value: unknown): number | string | boolean | null | undefined {
    if (value instanceof Date) return value.getTime();
    if (typeof value === 'string') {
      const timestamp = Date.parse(value);
      if (!isNaN(timestamp) && /^\d{4}-\d{2}-\d{2}/.test(value)) {
        return timestamp;
      }
    }
    return value as number | string | boolean | null | undefined;
  }

  private _compareValues(a: unknown, b: unknown): number {
    const na = this._normalizeForComparison(a);
    const nb = this._normalizeForComparison(b);
    if (na === nb) return 0;
    if (na === undefined || na === null) return -1;
    if (nb === undefined || nb === null) return 1;
    if (typeof na === 'number' && typeof nb === 'number') return na - nb;
    if (typeof na === 'string' && typeof nb === 'string') return na.localeCompare(nb);
    if (typeof na === 'boolean' && typeof nb === 'boolean') return (na ? 1 : 0) - (nb ? 1 : 0);
    return String(na).localeCompare(String(nb));
  }
}
