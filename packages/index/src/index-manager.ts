import {
  IndexDefinition,
  IndexDiagnostic,
  InvalidIndexedValueReason,
  QueryAst,
  QueryAstResult,
  QueryOptions,
  QueryResult,
  DocumentSnapshotExtractor,
} from './types.js';
import { IndexStorage } from './index-storage.js';
import { extractField } from './field-extractor.js';
import {
  hashIndexDefinition,
  hashQuery,
  InvalidQueryError,
  invalidIndexedValueReason,
  legacyQueryToAst,
  physicalIndexesFor,
  projectFields,
  resolvedGeneration,
  resolvedInvalidValuePolicy,
  resolvedStorageMode,
  validateIndexDefinition,
  validateQueryAst,
} from './query-ast.js';
import { planPhysicalIndexNames, planQuery, planScanKind } from './query-planner.js';
import { createQueryCursor, isAfterQueryCursor, parseQueryCursor } from './query-cursor.js';

interface IndexGeneration {
  ready: Promise<void>;
  barrier: Promise<void>;
  operations: Set<Promise<void>>;
  schemaHash: string;
}

function isQueryAst(options: QueryOptions | QueryAst): options is QueryAst {
  return (options as { version?: unknown }).version === 2;
}

function validateDocumentPath(documentPath: string): void {
  if (typeof documentPath !== 'string' || documentPath.length === 0 ||
      documentPath.length > MAX_DOCUMENT_PATH_LENGTH || /[\u0000-\u001f]/.test(documentPath)) {
    throw new TypeError(
      `documentPath must contain 1-${MAX_DOCUMENT_PATH_LENGTH} non-control characters`,
    );
  }
}

function validateLegacyPagination(options: QueryOptions): void {
  if (options.offset !== undefined &&
      (!Number.isSafeInteger(options.offset) || options.offset < 0)) {
    throw new RangeError(`offset must be a non-negative safe integer, got ${options.offset}`);
  }
  if (options.limit !== undefined &&
      (!Number.isSafeInteger(options.limit) || options.limit < 0)) {
    throw new RangeError(`limit must be a non-negative safe integer, got ${options.limit}`);
  }
}

interface IndexSubscription {
  options: QueryOptions;
  callback: (result: QueryResult<Record<string, unknown>>) => void;
  queryRevision: number;
}

const MAX_DOCUMENT_PATH_LENGTH = 4096;
const MAX_DIAGNOSTICS = 128;

export class IndexSecurityPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IndexSecurityPolicyError';
  }
}

export class InvalidIndexedDocumentError extends Error {
  constructor(
    readonly indexName: string,
    readonly documentPath: string,
    readonly fieldPath: string,
    readonly reason: InvalidIndexedValueReason,
  ) {
    super(`document ${documentPath} is invalid for index ${indexName} at ${fieldPath}: ${reason}`);
    this.name = 'InvalidIndexedDocumentError';
  }
}

export class QueryRequiresScanError extends Error {
  constructor(indexName: string) {
    super(`query on index ${indexName} requires a full scan; set allowScan to opt in`);
    this.name = 'QueryRequiresScanError';
  }
}

/**
 * Manages index definitions, incremental updates, and queries over a local materialized index.
 *
 * Designed to be fed by CRDT change events via `PeerborneDocument.subscribe()`.
 * Queries execute locally against the configured storage backend; performance depends on
 * the underlying storage implementation and index configuration.
 *
 * @typeParam DocType The CRDT document type (e.g., Y.Doc).
 */
export class IndexManager<DocType> {
  private _storage: IndexStorage;
  private _extractor: DocumentSnapshotExtractor<DocType>;
  private _definitions: Map<string, IndexDefinition> = new Map();
  private _indexGenerations: Map<string, IndexGeneration> = new Map();
  private _indexLifecycleOperations: Map<string, Promise<void>> = new Map();
  private _subscriptions: Map<number, IndexSubscription> = new Map();
  private _documentOperations: Map<string, Promise<void>> = new Map();
  private _diagnostics: IndexDiagnostic[] = [];
  private _nextSubscriptionId = 1;

  constructor(storage: IndexStorage, extractor: DocumentSnapshotExtractor<DocType>) {
    this._storage = storage;
    this._extractor = extractor;
  }

  /**
   * Register a new index definition. Initializes the storage backend for this index.
   * Throws if an index with the same name already exists with a different configuration.
   * Re-defining with identical config is a no-op.
   */
  async defineIndex(definition: IndexDefinition): Promise<void> {
    const normalized = validateIndexDefinition(definition);
    if ((normalized.version ?? 1) === 2 && this._storage.persistent !== false &&
        resolvedStorageMode(normalized) !== 'cleartext-local') {
      throw new IndexSecurityPolicyError(
        `index storage may persist cleartext projections for ${normalized.name}; ` +
        'set storageMode to cleartext-local to opt in',
      );
    }
    const existing = this._definitions.get(normalized.name);
    if (existing) {
      // Allow idempotent re-definition with same config
      if (JSON.stringify(existing) === JSON.stringify(normalized)) {
        await this._indexGenerations.get(normalized.name)?.ready;
        return;
      }
      throw new Error(
        `Index "${normalized.name}" is already defined with a different configuration. ` +
        `Call removeIndex() first to redefine it.`,
      );
    }
    const schemaHash = (normalized.version ?? 1) === 2
      ? hashIndexDefinition(normalized)
      : Promise.resolve('');
    const generation: IndexGeneration = {
      ready: Promise.resolve(),
      barrier: Promise.resolve(),
      operations: new Set(),
      schemaHash: '',
    };
    this._definitions.set(normalized.name, normalized);
    this._indexGenerations.set(normalized.name, generation);
    generation.ready = this._enqueueIndexLifecycleOperation(
      normalized.name,
      async () => {
        generation.schemaHash = await schemaHash;
        if ((normalized.version ?? 1) === 2) {
          await this._storage.initialize(
            normalized.name,
            normalized.fields,
            physicalIndexesFor(normalized),
            {
              schemaHash: generation.schemaHash,
              generation: resolvedGeneration(normalized),
              invalidValuePolicy: resolvedInvalidValuePolicy(normalized),
            },
          );
        } else {
          await this._storage.initialize(normalized.name, normalized.fields);
        }
      },
      {
        runAfterPreviousFailure: false,
        cleanupAfterStartedFailure: true,
      },
    );
    try {
      await generation.ready;
    } catch (err) {
      if (this._indexGenerations.get(normalized.name) === generation) {
        this._indexGenerations.delete(normalized.name);
        this._definitions.delete(normalized.name);
      }
      throw err;
    }
  }

  /**
   * Remove an index definition and clear its stored data.
   */
  async removeIndex(indexName: string): Promise<void> {
    const generation = this._indexGenerations.get(indexName);
    const removedDefinition = this._definitions.delete(indexName);
    const removedGeneration = this._indexGenerations.delete(indexName);
    if (removedDefinition || removedGeneration) {
      this._notifySubscribers();
    }
    await this._enqueueIndexLifecycleOperation(
      indexName,
      async () => {
        if (generation) {
          await Promise.allSettled(Array.from(generation.operations));
        }
        await this._storage.clear(indexName);
      },
      {
        runAfterPreviousFailure: true,
        cleanupAfterStartedFailure: false,
      },
    );
  }

  /**
   * Get all currently registered index definitions.
   */
  getDefinitions(): IndexDefinition[] {
    return Array.from(this._definitions.values(), (definition) => structuredClone(definition));
  }

  /** Return bounded, value-free diagnostics for rows excluded from v2 indexes. */
  getDiagnostics(): IndexDiagnostic[] {
    return this._diagnostics.map((diagnostic) => ({ ...diagnostic }));
  }

  /** Wait for document and index operations that are currently queued. */
  async flush(documentPath?: string): Promise<void> {
    if (documentPath !== undefined) {
      validateDocumentPath(documentPath);
      await this._documentOperations.get(documentPath);
      return;
    }
    await Promise.all(Array.from(this._documentOperations.values()));
    await Promise.all(Array.from(this._indexLifecycleOperations.values()));
    await Promise.all(Array.from(this._indexGenerations.values()).flatMap((generation) =>
      Array.from(generation.operations)));
  }

  /**
   * Update the index entries for a document.
   * Extracts a snapshot, determines which indexes match the document path,
   * extracts indexed fields, and writes to storage.
   * Skips the write if the extracted fields are unchanged from the previous entry.
   */
  async updateIndex(documentPath: string, document: DocType): Promise<void> {
    validateDocumentPath(documentPath);
    const snapshot = this._extractor(document);
    const entries: Array<{
      indexName: string;
      generation: IndexGeneration;
      fields?: Record<string, unknown>;
      invalid?: { fieldPath: string; reason: InvalidIndexedValueReason };
    }> = [];

    for (const [indexName, definition] of this._definitions) {
      if (!documentPath.startsWith(definition.collectionPrefix)) {
        continue;
      }
      const generation = this._indexGenerations.get(indexName);
      if (!generation) {
        continue;
      }

      const fields: Record<string, unknown> = {};
      let invalid: { fieldPath: string; reason: InvalidIndexedValueReason } | undefined;
      for (const fieldDef of definition.fields) {
        const value = extractField(snapshot, fieldDef.path);
        if ((definition.version ?? 1) === 2) {
          const reason = invalidIndexedValueReason(value, fieldDef);
          if (reason) {
            invalid = { fieldPath: fieldDef.path, reason };
            break;
          }
        }
        this._setNestedField(fields, fieldDef.path, value);
      }
      if (invalid && resolvedInvalidValuePolicy(definition) === 'reject') {
        throw new InvalidIndexedDocumentError(
          indexName,
          documentPath,
          invalid.fieldPath,
          invalid.reason,
        );
      }
      entries.push({ indexName, generation, ...(invalid ? { invalid } : { fields }) });
    }

    await this._enqueueDocumentOperation(documentPath, async () => {
      let changed = false;

      for (const { indexName, generation, fields, invalid } of entries) {
        if (this._indexGenerations.get(indexName) !== generation) {
          continue;
        }

        await this._runIndexOperation(indexName, generation, async () => {
          if (invalid) {
            await this._storage.delete(indexName, documentPath);
            this._recordDiagnostic(indexName, documentPath, invalid.fieldPath, invalid.reason);
            changed = true;
            return;
          }
          // Diff against previous entry -- skip write if unchanged
          const existing = await this._storage.get(indexName, documentPath);
          if (existing && this._fieldsEqual(existing, fields!)) {
            return;
          }

          await this._storage.put(indexName, documentPath, fields!);
          changed = true;
        });
      }

      if (changed) {
        this._notifySubscribers();
      }
    });
  }

  /**
   * Remove a document from all indexes.
   */
  async removeFromIndex(documentPath: string): Promise<void> {
    validateDocumentPath(documentPath);
    const indexes = Array.from(this._definitions.keys()).flatMap((indexName) => {
      const generation = this._indexGenerations.get(indexName);
      return generation ? [{ indexName, generation }] : [];
    });

    await this._enqueueDocumentOperation(documentPath, async () => {
      for (const { indexName, generation } of indexes) {
        if (this._indexGenerations.get(indexName) !== generation) {
          continue;
        }
        await this._runIndexOperation(indexName, generation, async () => {
          await this._storage.delete(indexName, documentPath);
        });
      }
      this._notifySubscribers();
    });
  }

  /**
   * Query the local index.
   */
  async query(options: QueryOptions): Promise<QueryResult<Record<string, unknown>>>;
  async query(options: QueryAst): Promise<QueryAstResult<Record<string, unknown>>>;
  async query(
    options: QueryOptions | QueryAst,
  ): Promise<QueryResult<Record<string, unknown>> | QueryAstResult<Record<string, unknown>>> {
    if (isQueryAst(options)) return this._queryAst(options);
    const indexName = this._resolveIndexName(options);
    if (!indexName) {
      return { documents: [], totalCount: 0 };
    }
    const generation = this._indexGenerations.get(indexName);
    if (!generation) {
      return { documents: [], totalCount: 0 };
    }
    try {
      await generation.ready;
    } catch {
      return { documents: [], totalCount: 0 };
    }
    if (this._indexGenerations.get(indexName) !== generation) {
      return { documents: [], totalCount: 0 };
    }

    const definition = this._definitions.get(indexName)!;
    if ((definition.version ?? 1) === 2 && this._storage.execute) {
      validateLegacyPagination(options);
      const query = validateQueryAst(legacyQueryToAst({
        ...options,
        limit: undefined,
        offset: undefined,
      }), definition);
      const executed = await this._storage.execute({
        definition,
        query,
        plan: planQuery(definition, query),
      });
      const offset = options.offset ?? 0;
      const entries = options.limit === undefined
        ? executed.entries.slice(offset)
        : executed.entries.slice(offset, offset + options.limit);
      return {
        documents: entries.map((entry) => ({
          documentPath: entry.documentPath,
          snapshot: entry.fields,
        })),
        totalCount: executed.totalCount ?? executed.rowsMatched,
      };
    }

    // Get total count (unpaginated) and paginated results.
    // Two queries so that storage backends can optimize pagination natively.
    const [allEntries, paginatedEntries] = await Promise.all([
      this._storage.query(indexName, options.filters, options.sort),
      (options.limit !== undefined || (options.offset !== undefined && options.offset > 0))
        ? this._storage.query(indexName, options.filters, options.sort, options.limit, options.offset)
        : null,
    ]);
    const totalCount = allEntries.length;
    const resultEntries = paginatedEntries ?? allEntries;
    if (this._indexGenerations.get(indexName) !== generation) {
      return { documents: [], totalCount: 0 };
    }

    return {
      documents: resultEntries.map(entry => ({
        documentPath: entry.documentPath,
        snapshot: entry.fields,
      })),
      totalCount,
    };
  }

  private async _queryAst(queryInput: QueryAst): Promise<QueryAstResult<Record<string, unknown>>> {
    const indexName = this._resolveIndexName(queryInput);
    if (!indexName) throw new Error('query does not resolve to a defined index');
    const definition = this._definitions.get(indexName)!;
    const generation = this._indexGenerations.get(indexName)!;
    await generation.ready;
    if ((definition.version ?? 1) !== 2) {
      throw new InvalidQueryError('version 2 queries require a version 2 index definition');
    }
    const query = validateQueryAst(queryInput, definition);
    if (query.consistency === 'indexed') {
      await this.flush();
      if (this._indexGenerations.get(indexName) !== generation) {
        throw new Error(`index generation changed while waiting to query ${indexName}`);
      }
    }
    const plan = planQuery(definition, query);
    if (planScanKind(plan) === 'full' && !query.allowScan) throw new QueryRequiresScanError(indexName);
    if (!this._storage.execute) throw new Error('storage backend does not support v2 query execution');
    const executed = await this._storage.execute({ definition, query, plan });
    if (this._indexGenerations.get(indexName) !== generation) {
      throw new Error(`index generation changed while querying ${indexName}`);
    }
    const queryHash = await hashQuery(query);
    const orderBy = query.orderBy ?? [];
    const cursor = query.after
      ? parseQueryCursor(
        query.after,
        queryHash,
        generation.schemaHash,
        resolvedGeneration(definition),
        orderBy.length,
        orderBy.map((clause) =>
          definition.fields.find((field) => field.path === clause.path)!.type),
      )
      : undefined;
    const remaining = cursor
      ? executed.entries.filter((entry) =>
        isAfterQueryCursor(entry, cursor, orderBy, definition))
      : executed.entries;
    const first = query.first ?? remaining.length;
    const pageEntries = remaining.slice(0, first);
    const hasMore = remaining.length > first;
    const last = pageEntries[pageEntries.length - 1];
    return {
      documents: pageEntries.map((entry) => ({
        documentPath: entry.documentPath,
        snapshot: projectFields(entry.fields, query.select),
      })),
      count: query.count === 'exact'
        ? { kind: 'verified', value: executed.totalCount ?? executed.rowsMatched }
        : { kind: 'none' },
      pageInfo: {
        hasMore,
        ...(last ? {
          cursor: createQueryCursor(
            queryHash,
            generation.schemaHash,
            resolvedGeneration(definition),
            last.documentPath,
            last.fields,
            query,
            definition,
          ),
        } : {}),
      },
      execution: {
        source: 'local',
        indexName,
        schemaVersion: definition.version ?? 1,
        schemaHash: generation.schemaHash,
        generation: resolvedGeneration(definition),
        storageMode: resolvedStorageMode(definition),
        physicalIndexes: planPhysicalIndexNames(plan),
        scan: planScanKind(plan),
        sort: executed.sort,
        residualPredicate: plan.residualPredicate,
        rowsVisited: executed.rowsVisited,
        rowsMatched: executed.rowsMatched,
      },
      coverage: { level: 'local-tracked', partial: false, reasons: [] },
    };
  }

  /**
   * Subscribe to live query results. The callback fires when the result set may have changed.
   * Returns an unsubscribe function.
   */
  subscribe(
    options: QueryOptions,
    callback: (result: QueryResult<Record<string, unknown>>) => void,
  ): () => void {
    const id = this._nextSubscriptionId++;
    const subscription: IndexSubscription = { options, callback, queryRevision: 0 };
    this._subscriptions.set(id, subscription);
    this._scheduleSubscriptionQuery(
      id,
      subscription,
      'IndexManager: initial subscription query failed',
    );

    return () => {
      this._subscriptions.delete(id);
    };
  }

  /**
   * Rebuild an index from scratch using all provided documents.
   */
  async rebuildIndex(indexName: string, documents: Map<string, DocType>): Promise<void> {
    const definition = this._definitions.get(indexName);
    const generation = this._indexGenerations.get(indexName);
    if (!definition || !generation) return;

    const rows: Array<{ documentPath: string; fields: Record<string, unknown> }> = [];
    for (const [documentPath, document] of documents) {
      validateDocumentPath(documentPath);
      if (!documentPath.startsWith(definition.collectionPrefix)) continue;
      const snapshot = this._extractor(document);
      const fields: Record<string, unknown> = {};
      let invalid: { fieldPath: string; reason: InvalidIndexedValueReason } | undefined;
      for (const fieldDef of definition.fields) {
        const value = extractField(snapshot, fieldDef.path);
        if ((definition.version ?? 1) === 2) {
          const reason = invalidIndexedValueReason(value, fieldDef);
          if (reason) {
            invalid = { fieldPath: fieldDef.path, reason };
            break;
          }
        }
        this._setNestedField(fields, fieldDef.path, value);
      }
      if (invalid) {
        if (resolvedInvalidValuePolicy(definition) === 'reject') {
          throw new InvalidIndexedDocumentError(
            indexName,
            documentPath,
            invalid.fieldPath,
            invalid.reason,
          );
        }
        this._recordDiagnostic(indexName, documentPath, invalid.fieldPath, invalid.reason);
        continue;
      }
      rows.push({ documentPath, fields });
    }

    await this._runExclusiveIndexOperation(indexName, generation, async () => {
      await this._storage.clear(indexName);
      for (const { documentPath, fields } of rows) {
        if (this._indexGenerations.get(indexName) !== generation) {
          return;
        }
        await this._storage.put(indexName, documentPath, fields);
      }

      this._notifySubscribers();
    });
  }

  /**
   * Resolve which index to query based on options.
   * If indexName is specified, use it directly. Otherwise find an index
   * matching the collectionPrefix.
   */
  private _resolveIndexName(options: QueryOptions | QueryAst): string | undefined {
    if (options.indexName) {
      return this._definitions.has(options.indexName) ? options.indexName : undefined;
    }
    if (options.collectionPrefix) {
      for (const [name, def] of this._definitions) {
        if (def.collectionPrefix === options.collectionPrefix) {
          return name;
        }
      }
    }
    // Return the first defined index as fallback
    const first = this._definitions.keys().next();
    return first.done ? undefined : first.value;
  }

  private _fieldsEqual(a: Record<string, unknown>, b: Record<string, unknown>): boolean {
    const keysA = Object.keys(a);
    const keysB = Object.keys(b);
    if (keysA.length !== keysB.length) return false;
    for (const key of keysA) {
      const va = a[key];
      const vb = b[key];
      if (va === vb) continue;
      // Handle Date objects explicitly -- they have no enumerable keys
      if (va instanceof Date && vb instanceof Date) {
        if (va.getTime() !== vb.getTime()) return false;
        continue;
      }
      if (
        va !== null && vb !== null &&
        typeof va === 'object' && typeof vb === 'object'
      ) {
        if (!this._fieldsEqual(va as Record<string, unknown>, vb as Record<string, unknown>)) {
          return false;
        }
      } else {
        return false;
      }
    }
    return true;
  }

  private _enqueueDocumentOperation(
    documentPath: string,
    operation: () => Promise<void>,
  ): Promise<void> {
    const previous = this._documentOperations.get(documentPath);
    const current = previous
      ? previous.then(operation, operation)
      : Promise.resolve().then(operation);
    this._documentOperations.set(documentPath, current);

    const cleanup = (): void => {
      if (this._documentOperations.get(documentPath) === current) {
        this._documentOperations.delete(documentPath);
      }
    };
    void current.then(cleanup, cleanup);

    return current;
  }

  private _runIndexOperation(
    indexName: string,
    generation: IndexGeneration,
    operation: () => Promise<void>,
  ): Promise<void> {
    if (this._indexGenerations.get(indexName) !== generation) {
      return Promise.resolve();
    }

    const barrier = generation.barrier;
    const current = Promise.all([generation.ready, barrier]).then(async () => {
      if (this._indexGenerations.get(indexName) === generation) {
        await operation();
      }
    });
    generation.operations.add(current);

    const cleanup = (): void => {
      generation.operations.delete(current);
    };
    void current.then(cleanup, cleanup);

    return current;
  }

  private _runExclusiveIndexOperation(
    indexName: string,
    generation: IndexGeneration,
    operation: () => Promise<void>,
  ): Promise<void> {
    if (this._indexGenerations.get(indexName) !== generation) {
      return Promise.resolve();
    }

    const priorOperations = Array.from(generation.operations);
    const current = Promise.all([
      generation.ready,
      generation.barrier,
      Promise.allSettled(priorOperations),
    ]).then(async () => {
      if (this._indexGenerations.get(indexName) === generation) {
        await operation();
      }
    });
    generation.barrier = current.then(() => undefined, () => undefined);
    generation.operations.add(current);

    const cleanup = (): void => {
      generation.operations.delete(current);
    };
    void current.then(cleanup, cleanup);

    return current;
  }

  private _enqueueIndexLifecycleOperation(
    indexName: string,
    operation: () => Promise<void>,
    options: {
      runAfterPreviousFailure: boolean;
      cleanupAfterStartedFailure: boolean;
    },
  ): Promise<void> {
    const previous = this._indexLifecycleOperations.get(indexName);
    let operationStarted = false;
    const trackedOperation = async (): Promise<void> => {
      operationStarted = true;
      await operation();
    };
    const current = previous
      ? options.runAfterPreviousFailure
        ? previous.then(trackedOperation, trackedOperation)
        : previous.then(trackedOperation)
      : Promise.resolve().then(trackedOperation);
    this._indexLifecycleOperations.set(indexName, current);

    const cleanup = (): void => {
      if (this._indexLifecycleOperations.get(indexName) === current) {
        this._indexLifecycleOperations.delete(indexName);
      }
    };
    void current.then(cleanup, () => {
      if (operationStarted && options.cleanupAfterStartedFailure) {
        cleanup();
      }
    });

    return current;
  }

  /**
   * Set a value in a nested object structure using a dot-notation path.
   * e.g. _setNestedField(obj, 'a.b', 42) creates { a: { b: 42 } }
   */
  private _setNestedField(obj: Record<string, unknown>, path: string, value: unknown): void {
    const segments = path.split('.');
    let current: Record<string, unknown> = obj;
    for (let i = 0; i < segments.length - 1; i++) {
      const seg = segments[i];
      const existing = Object.prototype.hasOwnProperty.call(current, seg)
        ? current[seg]
        : undefined;
      if (typeof existing !== 'object' || existing === null) {
        Object.defineProperty(current, seg, {
          value: {},
          configurable: true,
          enumerable: true,
          writable: true,
        });
      }
      current = current[seg] as Record<string, unknown>;
    }
    Object.defineProperty(current, segments[segments.length - 1], {
      value,
      configurable: true,
      enumerable: true,
      writable: true,
    });
  }

  private _recordDiagnostic(
    indexName: string,
    documentPath: string,
    fieldPath: string,
    reason: InvalidIndexedValueReason,
  ): void {
    this._diagnostics.push({ indexName, documentPath, fieldPath, reason, recordedAt: Date.now() });
    if (this._diagnostics.length > MAX_DIAGNOSTICS) this._diagnostics.shift();
  }

  private _notifySubscribers(): void {
    for (const [id, subscription] of this._subscriptions) {
      this._scheduleSubscriptionQuery(
        id,
        subscription,
        'IndexManager: subscription notification query failed',
      );
    }
  }

  private _scheduleSubscriptionQuery(
    id: number,
    subscription: IndexSubscription,
    errorMessage: string,
  ): void {
    const revision = ++subscription.queryRevision;
    this.query(subscription.options).then((result) => {
      if (
        this._subscriptions.get(id) === subscription &&
        subscription.queryRevision === revision
      ) {
        subscription.callback(result);
      }
    }).catch((err) => {
      if (
        this._subscriptions.get(id) === subscription &&
        subscription.queryRevision === revision
      ) {
        console.warn(errorMessage, err);
      }
    });
  }
}
