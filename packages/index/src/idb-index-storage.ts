import { openDB, type IDBPDatabase, type OpenDBCallbacks } from 'idb';
import {
  IndexDefinition,
  IndexFieldDefinition,
  IndexKeyDefinition,
  IndexScalar,
  FieldFilter,
  SortClause,
} from './types.js';
import {
  IndexStorage,
  IndexEntry,
  StorageQueryRequest,
  StorageQueryResult,
  StorageSchemaIdentity,
} from './index-storage.js';
import { extractField } from './field-extractor.js';
import { compareCodeUnits, invalidIndexedValueReason, normalizeIndexScalar } from './query-ast.js';
import { PhysicalQueryPlan, QueryIndexLookup } from './query-planner.js';
import { finalizeQueryCandidates } from './query-execution.js';

const METADATA_STORE = '__peerborne_internal_index_schema_v2__';
const PHYSICAL_INDEX_PREFIX = '__peerborne_internal_v2__';

interface StoredRecord {
  documentPath: string;
  fields: Record<string, unknown>;
  physical?: Record<string, IDBValidKey[]>;
}

type EncodedScalar = string | number;

interface EncodedLookup {
  equals: EncodedScalar[];
  start: IDBValidKey[];
  range?: {
    position: number;
    lower?: EncodedScalar;
    lowerInclusive?: boolean;
    upper?: EncodedScalar;
    upperInclusive?: boolean;
    prefix?: string;
  };
}

function physicalIndexName(name: string): string {
  return `${PHYSICAL_INDEX_PREFIX}${name}`;
}

function physicalProperty(name: string): string {
  return `i${Array.from(
    new TextEncoder().encode(name),
    (byte) => byte.toString(16).padStart(2, '0'),
  ).join('')}`;
}

function physicalKeys(
  fields: IndexFieldDefinition[],
  indexes: IndexKeyDefinition[],
  documentPath: string,
  values: Record<string, unknown>,
): Record<string, IDBValidKey[]> {
  const fieldMap = new Map(fields.map((field) => [field.path, field]));
  const result: Record<string, IDBValidKey[]> = {};
  for (const index of indexes) {
    const key: IDBValidKey[] = [];
    let valid = true;
    for (const path of index.fields) {
      const field = fieldMap.get(path)!;
      const value = normalizeIndexScalar(extractField(values, path), field);
      if (value === undefined) {
        valid = false;
        break;
      }
      key.push(encodeScalar(value, field));
    }
    if (valid) result[physicalProperty(index.name)] = [...key, documentPath];
  }
  return result;
}

function encodeLookup(
  plan: PhysicalQueryPlan,
  lookup: QueryIndexLookup,
  definition: IndexDefinition,
): EncodedLookup {
  const fieldMap = new Map(definition.fields.map((field) => [field.path, field]));
  const equals = lookup.equals.map((value, position) =>
    encodeScalar(value, fieldMap.get(plan.fields[position])!));
  let range: EncodedLookup['range'];
  if (lookup.range) {
    const field = fieldMap.get(plan.fields[lookup.range.position])!;
    range = {
      position: lookup.range.position,
      ...(lookup.range.lower !== undefined ? {
        lower: encodeScalar(lookup.range.lower, field),
        lowerInclusive: lookup.range.lowerInclusive,
      } : {}),
      ...(lookup.range.upper !== undefined ? {
        upper: encodeScalar(lookup.range.upper, field),
        upperInclusive: lookup.range.upperInclusive,
      } : {}),
      ...(lookup.range.prefix !== undefined ? { prefix: lookup.range.prefix } : {}),
    };
  }
  const start = range?.lower !== undefined ? [...equals, range.lower] :
    range?.prefix !== undefined ? [...equals, range.prefix] : [...equals];
  return { equals, start, ...(range ? { range } : {}) };
}

function matchesEncodedLookup(
  key: IDBValidKey[],
  lookup: EncodedLookup,
): 'before' | 'match' | 'past' {
  for (let i = 0; i < lookup.equals.length; i++) {
    const compared = compareEncoded(key[i], lookup.equals[i]);
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
    const compared = compareEncoded(value, range.lower);
    if (compared < 0 || (compared === 0 && !range.lowerInclusive)) return 'before';
  }
  if (range.upper !== undefined) {
    const compared = compareEncoded(value, range.upper);
    if (compared > 0 || (compared === 0 && !range.upperInclusive)) return 'past';
  }
  return 'match';
}

function encodeScalar(value: IndexScalar, field: IndexFieldDefinition): EncodedScalar {
  return field.type === 'boolean' ? Number(value) : value as EncodedScalar;
}

function compareEncoded(left: IDBValidKey | undefined, right: EncodedScalar): number {
  if (left === right) return 0;
  if (typeof left === 'number' && typeof right === 'number') return left - right;
  return compareCodeUnits(String(left), String(right));
}

function sameIdentity(left: StorageSchemaIdentity, right: StorageSchemaIdentity): boolean {
  return left.schemaHash === right.schemaHash && left.generation === right.generation &&
    left.collectionPrefix === right.collectionPrefix &&
    left.invalidValuePolicy === right.invalidValuePolicy;
}

/**
 * IndexedDB-backed implementation of IndexStorage using the `idb` library.
 * Each index is stored as a separate IDB object store with `documentPath` as key path.
 */
export class IDBIndexStorage implements IndexStorage {
  readonly persistent = true;
  private _dbName: string;
  private _db: IDBPDatabase | null = null;
  private _initializedStores: Set<string> = new Set();
  private _initializationTail: Promise<void> = Promise.resolve();
  /** Tracks which IDB indexes exist per store, so query() can use them for fast lookups. */
  private _indexedFields: Map<string, Set<string>> = new Map();
  private _physicalIndexes: Map<string, IndexKeyDefinition[]> = new Map();
  private _fields: Map<string, IndexFieldDefinition[]> = new Map();

  constructor(dbName: string = 'collabswarm-index') {
    this._dbName = dbName;
  }

  initialize(
    indexName: string,
    fields: IndexFieldDefinition[],
    physicalIndexes: IndexKeyDefinition[] = [],
    identity?: StorageSchemaIdentity,
  ): Promise<void> {
    const operation = this._initializationTail.then(() =>
      this._initialize(indexName, fields, physicalIndexes, identity));
    this._initializationTail = operation.then(() => undefined, () => undefined);
    return operation;
  }

  private async _initialize(
    indexName: string,
    fields: IndexFieldDefinition[],
    physicalIndexes: IndexKeyDefinition[],
    identity?: StorageSchemaIdentity,
  ): Promise<void> {
    const requestedPhysical = identity ? physicalIndexes : [];
    const requestedLegacyFields = identity ? [] : fields;
    if (this._db) {
      this._db.close();
      this._db = null;
    }

    const maxAttempts = 4;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const existing = await this._openDatabase();
      const currentVersion = existing.version;
      const storeExists = existing.objectStoreNames.contains(indexName);
      const metadataExists = existing.objectStoreNames.contains(METADATA_STORE);
      const needsMetadata = identity !== undefined;
      const existingIndexes: string[] = [];
      if (storeExists) {
        const tx = existing.transaction(indexName, 'readonly');
        const names = tx.objectStore(indexName).indexNames;
        for (let i = 0; i < names.length; i++) {
          const name = names.item(i);
          if (name !== null) existingIndexes.push(name);
        }
        await tx.done;
      }
      existing.close();

      const missingFields = storeExists
        ? requestedLegacyFields.filter((field) => !existingIndexes.includes(field.path))
        : requestedLegacyFields;
      const missingPhysical = requestedPhysical.filter((index) =>
        !existingIndexes.includes(physicalIndexName(index.name)));
      const requestedPhysicalNames = new Set(requestedPhysical.map((index) =>
        physicalIndexName(index.name)));
      const obsoletePhysical = identity ? existingIndexes.filter((name) =>
        name.startsWith(PHYSICAL_INDEX_PREFIX) && !requestedPhysicalNames.has(name)) : [];
      const needsUpgrade = !storeExists || (needsMetadata && !metadataExists) ||
        missingFields.length > 0 || missingPhysical.length > 0 || obsoletePhysical.length > 0;
      try {
        this._db = needsUpgrade
          ? await this._openDatabase(currentVersion + 1, (
            db,
            _oldVersion,
            _newVersion,
            tx,
          ) => {
            if (needsMetadata && !db.objectStoreNames.contains(METADATA_STORE)) {
              db.createObjectStore(METADATA_STORE, { keyPath: 'indexName' });
            }
            const store = db.objectStoreNames.contains(indexName)
              ? tx.objectStore(indexName)
              : db.createObjectStore(indexName, { keyPath: 'documentPath' });
            for (const name of obsoletePhysical) {
              if (store.indexNames.contains(name)) store.deleteIndex(name);
            }
            for (const field of missingFields) {
              if (!store.indexNames.contains(field.path)) {
                store.createIndex(field.path, `fields.${field.path}`, { unique: false });
              }
            }
            for (const index of missingPhysical) {
              const name = physicalIndexName(index.name);
              if (!store.indexNames.contains(name)) {
                store.createIndex(name, `physical.${physicalProperty(index.name)}`, { unique: false });
              }
            }
          })
          : await this._openDatabase(currentVersion);
        break;
      } catch (error) {
        const retryable = typeof DOMException !== 'undefined' &&
          error instanceof DOMException && error.name === 'VersionError';
        if (!retryable || attempt === maxAttempts - 1) throw error;
        await new Promise<void>((resolve) => setTimeout(resolve, 25 * (1 << attempt)));
      }
    }
    if (!this._db) throw new Error('IDBIndexStorage: failed to open database');

    this._fields.set(indexName, [...fields]);
    this._physicalIndexes.set(indexName, requestedPhysical.map((index) => ({
      name: index.name,
      fields: [...index.fields],
    })));
    this._indexedFields.set(
      indexName,
      new Set(requestedLegacyFields.map((field) => field.path)),
    );
    this._initializedStores.add(indexName);

    if (identity) await this._initializeV2Rows(indexName, fields, requestedPhysical, identity);
  }

  async put(indexName: string, documentPath: string, fields: Record<string, unknown>): Promise<void> {
    await this._initializationTail;
    const db = this._getDB();
    const copy = structuredClone(fields);
    await db.put(indexName, {
      documentPath,
      fields: copy,
      physical: this._physicalKeys(indexName, documentPath, copy),
    });
  }

  async delete(indexName: string, documentPath: string): Promise<void> {
    await this._initializationTail;
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
    await this._initializationTail;
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

  async execute(request: StorageQueryRequest): Promise<StorageQueryResult> {
    await this._initializationTail;
    const db = this._getDB();
    if (!db.objectStoreNames.contains(request.definition.name)) {
      return finalizeQueryCandidates(request, [], 0, false);
    }
    const tx = db.transaction(request.definition.name, 'readonly');
    const store = tx.objectStore(request.definition.name);
    const candidates: IndexEntry[] = [];
    let rowsVisited = 0;
    if (request.plan.kind === 'full') {
      let cursor = await store.openCursor();
      while (cursor) {
        rowsVisited++;
        const record = cursor.value;
        if (isStoredRecord(record)) {
          candidates.push({ documentPath: record.documentPath, fields: record.fields });
        }
        cursor = await cursor.continue();
      }
    } else {
      const plans = request.plan.kind === 'union' ? request.plan.plans : [request.plan];
      for (const plan of plans) {
        const name = physicalIndexName(plan.indexName);
        if (!store.indexNames.contains(name)) continue;
        const index = store.index(name);
        for (const lookup of plan.lookups) {
          const encoded = encodeLookup(plan, lookup, request.definition);
          let cursor = await index.openCursor(IDBKeyRange.lowerBound(encoded.start));
          while (cursor) {
            rowsVisited++;
            const key = (cursor.key as IDBValidKey[]).slice(0, plan.fields.length);
            const decision = matchesEncodedLookup(key, encoded);
            if (decision === 'past') break;
            if (decision === 'match') {
              const record = cursor.value;
              if (isStoredRecord(record)) {
                candidates.push({ documentPath: record.documentPath, fields: record.fields });
              }
            }
            cursor = await cursor.continue();
          }
        }
      }
    }
    await tx.done;
    const indexOrderPreserved = request.plan.kind === 'physical' &&
      request.plan.sortCovered && request.plan.lookups.length === 1;
    return finalizeQueryCandidates(request, candidates, rowsVisited, indexOrderPreserved);
  }

  async get(indexName: string, documentPath: string): Promise<Record<string, unknown> | undefined> {
    await this._initializationTail;
    const db = this._getDB();

    if (!db.objectStoreNames.contains(indexName)) return undefined;

    const record = await db.get(indexName, documentPath) as { documentPath: string; fields: Record<string, unknown> } | undefined;
    return record ? { ...record.fields } : undefined;
  }

  async clear(indexName: string): Promise<void> {
    await this._initializationTail;
    const db = this._getDB();
    if (db.objectStoreNames.contains(indexName)) {
      await db.clear(indexName);
    }
  }

  async close(): Promise<void> {
    await this._initializationTail;
    if (this._db) {
      this._db.close();
      this._db = null;
    }
    // After close(), initialize() will reopen the database; this set just tracks which stores exist.
  }

  private async _initializeV2Rows(
    indexName: string,
    fields: IndexFieldDefinition[],
    physicalIndexes: IndexKeyDefinition[],
    identity: StorageSchemaIdentity,
  ): Promise<void> {
    const db = this._getDB();
    const tx = db.transaction([METADATA_STORE, indexName], 'readwrite');
    const metadata = tx.objectStore(METADATA_STORE);
    const store = tx.objectStore(indexName);
    const previous = await metadata.get(indexName) as (StorageSchemaIdentity & { indexName: string }) | undefined;
    if (previous && !sameIdentity(previous, identity)) {
      await store.clear();
      await metadata.put({ indexName, ...identity });
      await tx.done;
      return;
    }

    let cursor = await store.openCursor();
    while (cursor) {
      const record = cursor.value;
      if (!isStoredRecord(record)) {
        if (identity.invalidValuePolicy === 'reject') {
          tx.abort();
          await tx.done.catch(() => undefined);
          throw new TypeError('persisted index row has an invalid shape');
        }
        await cursor.delete();
        cursor = await cursor.continue();
        continue;
      }
      if (!record.documentPath.startsWith(identity.collectionPrefix)) {
        await cursor.delete();
        cursor = await cursor.continue();
        continue;
      }
      let invalid: { path: string; reason: string } | undefined;
      for (const field of fields) {
        const reason = invalidIndexedValueReason(extractField(record.fields, field.path), field);
        if (reason) {
          invalid = { path: field.path, reason };
          break;
        }
      }
      if (invalid) {
        if (identity.invalidValuePolicy === 'reject') {
          tx.abort();
          await tx.done.catch(() => undefined);
          throw new TypeError(
            `persisted index row ${record.documentPath} is invalid at ${invalid.path}: ${invalid.reason}`,
          );
        }
        await cursor.delete();
      } else {
        await cursor.update({
          documentPath: record.documentPath,
          fields: structuredClone(record.fields),
          physical: physicalKeys(fields, physicalIndexes, record.documentPath, record.fields),
        });
      }
      cursor = await cursor.continue();
    }
    await metadata.put({ indexName, ...identity });
    await tx.done;
  }

  private _physicalKeys(
    indexName: string,
    documentPath: string,
    fields: Record<string, unknown>,
  ): Record<string, IDBValidKey[]> {
    return physicalKeys(
      this._fields.get(indexName) ?? [],
      this._physicalIndexes.get(indexName) ?? [],
      documentPath,
      fields,
    );
  }

  private _getDB(): IDBPDatabase {
    if (!this._db) {
      throw new Error('IDBIndexStorage: database not initialized. Call initialize() first.');
    }
    return this._db;
  }

  private _openDatabase(
    version?: number,
    upgrade?: OpenDBCallbacks<unknown>['upgrade'],
  ): Promise<IDBPDatabase> {
    return new Promise((resolve, reject) => {
      let connection: IDBPDatabase | undefined;
      let settled = false;
      const opening = openDB(this._dbName, version, {
        ...(upgrade ? { upgrade } : {}),
        blocked: () => {
          if (!settled) {
            settled = true;
            reject(new Error(`IDBIndexStorage: schema upgrade blocked for ${this._dbName}`));
          }
        },
        blocking: () => {
          connection?.close();
          if (this._db === connection) this._db = null;
        },
        terminated: () => {
          if (this._db === connection) this._db = null;
        },
      });
      opening.then(
        (db) => {
          connection = db;
          if (settled) {
            db.close();
            return;
          }
          settled = true;
          resolve(db);
        },
        (error) => {
          if (!settled) {
            settled = true;
            reject(error);
          }
        },
      );
    });
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

function isStoredRecord(value: unknown): value is StoredRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return typeof record.documentPath === 'string' && record.documentPath.length > 0 &&
    record.documentPath.length <= 4096 && !/[\u0000-\u001f]/.test(record.documentPath) &&
    record.fields !== null && typeof record.fields === 'object' && !Array.isArray(record.fields);
}
