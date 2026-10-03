import { openDB, type IDBPDatabase, type OpenDBCallbacks } from 'idb';
import {
  IndexDefinition,
  IndexFieldDefinition,
  IndexKeyDefinition,
  IndexScalar,
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
  private _physicalIndexes: Map<string, IndexKeyDefinition[]> = new Map();
  private _fields: Map<string, IndexFieldDefinition[]> = new Map();

  constructor(dbName: string = 'peerborne-index') {
    this._dbName = dbName;
  }

  initialize(
    indexName: string,
    fields: IndexFieldDefinition[],
    physicalIndexes: IndexKeyDefinition[],
    identity: StorageSchemaIdentity,
  ): Promise<void> {
    if (!identity || !Array.isArray(physicalIndexes)) {
      return Promise.reject(new TypeError('Index initialization requires physical indexes and a schema identity'));
    }
    const operation = this._initializationTail.then(() =>
      this._initialize(indexName, fields, physicalIndexes, identity));
    this._initializationTail = operation.then(() => undefined, () => undefined);
    return operation;
  }

  private async _initialize(
    indexName: string,
    fields: IndexFieldDefinition[],
    physicalIndexes: IndexKeyDefinition[],
    identity: StorageSchemaIdentity,
  ): Promise<void> {
    const requestedPhysical = physicalIndexes;
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

      const missingPhysical = requestedPhysical.filter((index) =>
        !existingIndexes.includes(physicalIndexName(index.name)));
      const requestedPhysicalNames = new Set(requestedPhysical.map((index) =>
        physicalIndexName(index.name)));
      const obsoletePhysical = existingIndexes.filter((name) => !requestedPhysicalNames.has(name));
      const needsUpgrade = !storeExists || !metadataExists ||
        missingPhysical.length > 0 || obsoletePhysical.length > 0;
      try {
        this._db = needsUpgrade
          ? await this._openDatabase(currentVersion + 1, (
            db,
            _oldVersion,
            _newVersion,
            tx,
          ) => {
            if (!db.objectStoreNames.contains(METADATA_STORE)) {
              db.createObjectStore(METADATA_STORE, { keyPath: 'indexName' });
            }
            const store = db.objectStoreNames.contains(indexName)
              ? tx.objectStore(indexName)
              : db.createObjectStore(indexName, { keyPath: 'documentPath' });
            for (const name of obsoletePhysical) {
              if (store.indexNames.contains(name)) store.deleteIndex(name);
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
    this._initializedStores.add(indexName);

    await this._initializeRows(indexName, fields, requestedPhysical, identity);
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

  private async _initializeRows(
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
    if (!previous || !sameIdentity(previous, identity)) {
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
}

function isStoredRecord(value: unknown): value is StoredRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return typeof record.documentPath === 'string' && record.documentPath.length > 0 &&
    record.documentPath.length <= 4096 && !/[\u0000-\u001f]/.test(record.documentPath) &&
    record.fields !== null && typeof record.fields === 'object' && !Array.isArray(record.fields);
}
