import { IndexFieldDefinition, FieldFilter, SortClause } from './types.js';
import { IndexStorage, IndexEntry } from './index-storage.js';

/**
 * In-memory implementation of IndexStorage backed by nested Maps.
 * Suitable for tests and Node.js environments where IndexedDB is unavailable.
 */
export class MemoryIndexStorage implements IndexStorage {
  /** indexName → (documentPath → fields) */
  private _stores: Map<string, Map<string, Record<string, unknown>>> = new Map();

  /** Initialize storage for the given index. Creates an empty map if one does not exist. */
  async initialize(_indexName: string, _fields: IndexFieldDefinition[]): Promise<void> {
    if (!this._stores.has(_indexName)) {
      this._stores.set(_indexName, new Map());
    }
  }

  /** Insert or update an index entry for a document in the named index. */
  async put(indexName: string, documentPath: string, fields: Record<string, unknown>): Promise<void> {
    const store = this._getStore(indexName);
    store.set(documentPath, { ...fields });
  }

  /** Remove an index entry for the given document path. No-op if the entry does not exist. */
  async delete(indexName: string, documentPath: string): Promise<void> {
    const store = this._stores.get(indexName);
    if (store) {
      store.delete(documentPath);
    }
  }

  /**
   * Query the index, applying filters, sorting, and pagination.
   * @param indexName The index to query.
   * @param filters Array of field filters to apply.
   * @param sort Optional sort clauses applied in order.
   * @param limit Maximum number of results to return.
   * @param offset Number of results to skip before returning.
   * @throws {RangeError} If offset or limit is negative.
   */
  async query(
    indexName: string,
    filters: FieldFilter[],
    sort?: SortClause[],
    limit?: number,
    offset?: number,
  ): Promise<IndexEntry[]> {
    const store = this._stores.get(indexName);
    if (!store) return [];

    if (offset !== undefined && offset < 0) {
      throw new RangeError(`offset must be non-negative, got ${offset}`);
    }
    if (limit !== undefined && limit < 0) {
      throw new RangeError(`limit must be non-negative, got ${limit}`);
    }

    let results: IndexEntry[] = [];

    for (const [documentPath, fields] of store) {
      if (this._matchesFilters(fields, filters)) {
        results.push({ documentPath, fields: { ...fields } });
      }
    }

    if (sort && sort.length > 0) {
      results.sort((a, b) => this._compareEntries(a.fields, b.fields, sort));
    }

    const start = offset ?? 0;
    if (limit !== undefined) {
      results = results.slice(start, start + limit);
    } else if (start > 0) {
      results = results.slice(start);
    }

    return results;
  }

  /** Get a single entry by document path. Returns undefined if not found. */
  async get(indexName: string, documentPath: string): Promise<Record<string, unknown> | undefined> {
    const store = this._stores.get(indexName);
    if (!store) return undefined;
    const fields = store.get(documentPath);
    return fields ? { ...fields } : undefined;
  }

  /** Remove all entries from the named index. */
  async clear(indexName: string): Promise<void> {
    const store = this._stores.get(indexName);
    if (store) {
      store.clear();
    }
  }

  /** Close the storage backend, releasing all in-memory data. */
  async close(): Promise<void> {
    this._stores.clear();
  }

  private _getStore(indexName: string): Map<string, Record<string, unknown>> {
    let store = this._stores.get(indexName);
    if (!store) {
      store = new Map();
      this._stores.set(indexName, store);
    }
    return store;
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
