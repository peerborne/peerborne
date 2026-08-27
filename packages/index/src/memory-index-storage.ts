import {
  FieldFilter,
  IndexFieldDefinition,
  IndexKeyDefinition,
  IndexScalar,
  SortClause,
} from './types.js';
import {
  IndexEntry,
  IndexStorage,
  StorageQueryRequest,
  StorageQueryResult,
  StorageSchemaIdentity,
} from './index-storage.js';
import { compareCodeUnits, compareIndexScalars, normalizeIndexScalar } from './query-ast.js';
import { extractField } from './field-extractor.js';
import { PhysicalQueryPlan, QueryIndexLookup } from './query-planner.js';
import { finalizeQueryCandidates } from './query-execution.js';

interface PhysicalRow {
  key: IndexScalar[];
  documentPath: string;
}

interface MemoryStore {
  entries: Map<string, Record<string, unknown>>;
  fields: IndexFieldDefinition[];
  physical: Map<string, { definition: IndexKeyDefinition; rows: PhysicalRow[] }>;
  identity?: StorageSchemaIdentity;
}

/** In-memory materialized storage with sorted compound secondary indexes. */
export class MemoryIndexStorage implements IndexStorage {
  readonly persistent = false;
  private _stores = new Map<string, MemoryStore>();

  async initialize(
    indexName: string,
    fields: IndexFieldDefinition[],
    physicalIndexes: IndexKeyDefinition[] = [],
    identity?: StorageSchemaIdentity,
  ): Promise<void> {
    let store = this._stores.get(indexName);
    if (!store) {
      store = { entries: new Map(), fields: [...fields], physical: new Map(), identity };
      this._stores.set(indexName, store);
    } else if (identity && (!store.identity || !sameIdentity(store.identity, identity))) {
      store.entries.clear();
      store.identity = identity;
    }
    store.fields = [...fields];
    store.physical.clear();
    for (const definition of physicalIndexes) {
      store.physical.set(definition.name, { definition: { ...definition, fields: [...definition.fields] }, rows: [] });
    }
    for (const [documentPath, entryFields] of store.entries) {
      this._insertPhysicalRows(store, documentPath, entryFields);
    }
  }

  async put(indexName: string, documentPath: string, fields: Record<string, unknown>): Promise<void> {
    const store = this._getStore(indexName);
    this._removePhysicalRows(store, documentPath);
    const copy = structuredClone(fields);
    store.entries.set(documentPath, copy);
    this._insertPhysicalRows(store, documentPath, copy);
  }

  async delete(indexName: string, documentPath: string): Promise<void> {
    const store = this._stores.get(indexName);
    if (!store) return;
    store.entries.delete(documentPath);
    this._removePhysicalRows(store, documentPath);
  }

  async query(
    indexName: string,
    filters: FieldFilter[],
    sort?: SortClause[],
    limit?: number,
    offset?: number,
  ): Promise<IndexEntry[]> {
    validatePagination(limit, offset);
    const store = this._stores.get(indexName);
    if (!store) return [];
    let results = Array.from(store.entries, ([documentPath, fields]) => ({ documentPath, fields }))
      .filter((entry) => matchesLegacyFilters(entry.fields, filters));
    if (sort?.length) results.sort((a, b) => compareLegacyEntries(a, b, sort));
    const start = offset ?? 0;
    results = limit === undefined ? results.slice(start) : results.slice(start, start + limit);
    return results.map((entry) => ({ ...entry, fields: structuredClone(entry.fields) }));
  }

  async execute(request: StorageQueryRequest): Promise<StorageQueryResult> {
    const store = this._stores.get(request.definition.name);
    if (!store) return finalizeQueryCandidates(request, [], 0, false);
    if (request.plan.kind === 'full') {
      const candidates = Array.from(store.entries, ([documentPath, fields]) => ({ documentPath, fields }));
      return finalizeQueryCandidates(request, candidates, candidates.length, false);
    }
    const plans = request.plan.kind === 'union' ? request.plan.plans : [request.plan];
    const candidates: IndexEntry[] = [];
    let rowsVisited = 0;
    for (const plan of plans) {
      const physical = store.physical.get(plan.indexName);
      if (!physical) continue;
      for (const lookup of plan.lookups) {
        const start = lowerBound(physical.rows, lookupStart(lookup));
        for (let i = start; i < physical.rows.length; i++) {
          const row = physical.rows[i];
          rowsVisited++;
          const decision = matchesLookup(row.key, lookup);
          if (decision === 'past') break;
          if (decision === 'match') {
            const fields = store.entries.get(row.documentPath);
            if (fields) candidates.push({ documentPath: row.documentPath, fields });
          }
        }
      }
    }
    const indexOrderPreserved = request.plan.kind === 'physical' &&
      request.plan.sortCovered && request.plan.lookups.length === 1;
    return finalizeQueryCandidates(request, candidates, rowsVisited, indexOrderPreserved);
  }

  async get(indexName: string, documentPath: string): Promise<Record<string, unknown> | undefined> {
    const fields = this._stores.get(indexName)?.entries.get(documentPath);
    return fields ? structuredClone(fields) : undefined;
  }

  async clear(indexName: string): Promise<void> {
    const store = this._stores.get(indexName);
    if (!store) return;
    store.entries.clear();
    for (const index of store.physical.values()) index.rows.length = 0;
  }

  async close(): Promise<void> {
    this._stores.clear();
  }

  private _getStore(indexName: string): MemoryStore {
    const store = this._stores.get(indexName);
    if (!store) throw new Error(`MemoryIndexStorage: index ${indexName} is not initialized`);
    return store;
  }

  private _insertPhysicalRows(
    store: MemoryStore,
    documentPath: string,
    fields: Record<string, unknown>,
  ): void {
    const fieldMap = new Map(store.fields.map((field) => [field.path, field]));
    for (const physical of store.physical.values()) {
      const key: IndexScalar[] = [];
      let valid = true;
      for (const path of physical.definition.fields) {
        const value = normalizeIndexScalar(extractField(fields, path), fieldMap.get(path)!);
        if (value === undefined) {
          valid = false;
          break;
        }
        key.push(value);
      }
      if (!valid) continue;
      const row = { key, documentPath };
      physical.rows.splice(lowerBoundRow(physical.rows, row), 0, row);
    }
  }

  private _removePhysicalRows(store: MemoryStore, documentPath: string): void {
    for (const physical of store.physical.values()) {
      physical.rows = physical.rows.filter((row) => row.documentPath !== documentPath);
    }
  }
}

function lookupStart(lookup: QueryIndexLookup): IndexScalar[] {
  if (lookup.range?.lower !== undefined) return [...lookup.equals, lookup.range.lower];
  if (lookup.range?.prefix !== undefined) return [...lookup.equals, lookup.range.prefix];
  return lookup.equals;
}

function matchesLookup(key: IndexScalar[], lookup: QueryIndexLookup): 'before' | 'match' | 'past' {
  for (let i = 0; i < lookup.equals.length; i++) {
    const compared = compareIndexScalars(key[i], lookup.equals[i]);
    if (compared < 0) return 'before';
    if (compared > 0) return 'past';
  }
  const range = lookup.range;
  if (!range) return 'match';
  const value = key[range.position];
  if (range.prefix !== undefined) {
    if (typeof value !== 'string') return 'past';
    if (value.startsWith(range.prefix)) return 'match';
    return compareCodeUnits(value, range.prefix) < 0 ? 'before' : 'past';
  }
  if (range.lower !== undefined) {
    const compared = compareIndexScalars(value, range.lower);
    if (compared < 0 || (compared === 0 && !range.lowerInclusive)) return 'before';
  }
  if (range.upper !== undefined) {
    const compared = compareIndexScalars(value, range.upper);
    if (compared > 0 || (compared === 0 && !range.upperInclusive)) return 'past';
  }
  return 'match';
}

function lowerBound(rows: PhysicalRow[], target: IndexScalar[]): number {
  let low = 0;
  let high = rows.length;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (compareKeyPrefix(rows[mid].key, target) < 0) low = mid + 1;
    else high = mid;
  }
  return low;
}

function lowerBoundRow(rows: PhysicalRow[], target: PhysicalRow): number {
  let low = 0;
  let high = rows.length;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (compareRows(rows[mid], target) < 0) low = mid + 1;
    else high = mid;
  }
  return low;
}

function compareRows(left: PhysicalRow, right: PhysicalRow): number {
  const compared = compareKeyPrefix(left.key, right.key);
  return compared || compareCodeUnits(left.documentPath, right.documentPath);
}

function compareKeyPrefix(left: IndexScalar[], right: IndexScalar[]): number {
  for (let i = 0; i < right.length; i++) {
    const compared = compareIndexScalars(left[i], right[i]);
    if (compared !== 0) return compared;
  }
  return 0;
}

function sameIdentity(left: StorageSchemaIdentity, right: StorageSchemaIdentity): boolean {
  return left.schemaHash === right.schemaHash && left.generation === right.generation &&
    left.collectionPrefix === right.collectionPrefix &&
    left.invalidValuePolicy === right.invalidValuePolicy;
}

function validatePagination(limit?: number, offset?: number): void {
  if (offset !== undefined && (!Number.isSafeInteger(offset) || offset < 0)) {
    throw new RangeError(`offset must be a non-negative safe integer, got ${offset}`);
  }
  if (limit !== undefined && (!Number.isSafeInteger(limit) || limit < 0)) {
    throw new RangeError(`limit must be a non-negative safe integer, got ${limit}`);
  }
}

function matchesLegacyFilters(fields: Record<string, unknown>, filters: FieldFilter[]): boolean {
  return filters.every((filter) => {
    const value = extractField(fields, filter.path);
    switch (filter.operator) {
      case 'eq': return value === filter.value;
      case 'neq': return value !== filter.value;
      case 'gt': {
        const [left, right] = [comparable(value), comparable(filter.value)];
        return left !== undefined && left !== null && right !== undefined && right !== null && left > right;
      }
      case 'gte': {
        const [left, right] = [comparable(value), comparable(filter.value)];
        return left !== undefined && left !== null && right !== undefined && right !== null && left >= right;
      }
      case 'lt': {
        const [left, right] = [comparable(value), comparable(filter.value)];
        return left !== undefined && left !== null && right !== undefined && right !== null && left < right;
      }
      case 'lte': {
        const [left, right] = [comparable(value), comparable(filter.value)];
        return left !== undefined && left !== null && right !== undefined && right !== null && left <= right;
      }
      case 'prefix': return typeof value === 'string' && typeof filter.value === 'string' && value.startsWith(filter.value);
      case 'in': return Array.isArray(filter.value) && filter.value.includes(value);
      case 'contains': return typeof value === 'string' && typeof filter.value === 'string' && value.includes(filter.value);
    }
  });
}

function compareLegacyEntries(left: IndexEntry, right: IndexEntry, sort: SortClause[]): number {
  for (const clause of sort) {
    const a = comparable(extractField(left.fields, clause.path));
    const b = comparable(extractField(right.fields, clause.path));
    const compared = compareLegacyValues(a, b);
    if (compared) return clause.direction === 'desc' ? -compared : compared;
  }
  return 0;
}

function compareLegacyValues(a: unknown, b: unknown): number {
  if (a === b) return 0;
  if (a === undefined || a === null) return -1;
  if (b === undefined || b === null) return 1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'boolean' && typeof b === 'boolean') return Number(a) - Number(b);
  if (typeof a === 'string' && typeof b === 'string') return a.localeCompare(b);
  return String(a).localeCompare(String(b));
}

function comparable(value: unknown): any {
  if (value instanceof Date) return value.getTime();
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}/.test(value)) {
    const time = Date.parse(value);
    if (Number.isFinite(time)) return time;
  }
  return value;
}
