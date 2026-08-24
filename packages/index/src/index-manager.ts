import {
  IndexDefinition,
  QueryOptions,
  QueryResult,
  DocumentSnapshotExtractor,
} from './types.js';
import { IndexStorage } from './index-storage.js';
import { extractField } from './field-extractor.js';

interface IndexGeneration {
  ready: Promise<void>;
  operations: Set<Promise<void>>;
}

interface IndexSubscription {
  options: QueryOptions;
  callback: (result: QueryResult<Record<string, unknown>>) => void;
  queryRevision: number;
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
    const existing = this._definitions.get(definition.name);
    if (existing) {
      // Allow idempotent re-definition with same config
      if (JSON.stringify(existing) === JSON.stringify(definition)) {
        await this._indexGenerations.get(definition.name)?.ready;
        return;
      }
      throw new Error(
        `Index "${definition.name}" is already defined with a different configuration. ` +
        `Call removeIndex() first to redefine it.`,
      );
    }
    const generation: IndexGeneration = {
      ready: Promise.resolve(),
      operations: new Set(),
    };
    this._definitions.set(definition.name, definition);
    this._indexGenerations.set(definition.name, generation);
    generation.ready = this._enqueueIndexLifecycleOperation(
      definition.name,
      async () => {
        await this._storage.initialize(definition.name, definition.fields);
      },
      {
        runAfterPreviousFailure: false,
        cleanupAfterStartedFailure: true,
      },
    );
    try {
      await generation.ready;
    } catch (err) {
      if (this._indexGenerations.get(definition.name) === generation) {
        this._indexGenerations.delete(definition.name);
        this._definitions.delete(definition.name);
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
    return Array.from(this._definitions.values());
  }

  /**
   * Update the index entries for a document.
   * Extracts a snapshot, determines which indexes match the document path,
   * extracts indexed fields, and writes to storage.
   * Skips the write if the extracted fields are unchanged from the previous entry.
   */
  async updateIndex(documentPath: string, document: DocType): Promise<void> {
    const snapshot = this._extractor(document);
    const entries: Array<{
      indexName: string;
      generation: IndexGeneration;
      fields: Record<string, unknown>;
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
      for (const fieldDef of definition.fields) {
        this._setNestedField(fields, fieldDef.path, extractField(snapshot, fieldDef.path));
      }

      entries.push({ indexName, generation, fields });
    }

    await this._enqueueDocumentOperation(documentPath, async () => {
      let changed = false;

      for (const { indexName, generation, fields } of entries) {
        if (this._indexGenerations.get(indexName) !== generation) {
          continue;
        }

        await this._runIndexOperation(indexName, generation, async () => {
          // Diff against previous entry -- skip write if unchanged
          const existing = await this._storage.get(indexName, documentPath);
          if (existing && this._fieldsEqual(existing, fields)) {
            return;
          }

          await this._storage.put(indexName, documentPath, fields);
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
  async query(options: QueryOptions): Promise<QueryResult<Record<string, unknown>>> {
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

    await this._runIndexOperation(indexName, generation, async () => {
      await this._storage.clear(indexName);

      for (const [documentPath, document] of documents) {
        if (this._indexGenerations.get(indexName) !== generation) {
          return;
        }
        if (!documentPath.startsWith(definition.collectionPrefix)) {
          continue;
        }

        const snapshot = this._extractor(document);
        const fields: Record<string, unknown> = {};
        for (const fieldDef of definition.fields) {
          this._setNestedField(fields, fieldDef.path, extractField(snapshot, fieldDef.path));
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
  private _resolveIndexName(options: QueryOptions): string | undefined {
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

    const current = generation.ready.then(async () => {
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
      if (!(seg in current) || typeof current[seg] !== 'object' || current[seg] === null) {
        current[seg] = {};
      }
      current = current[seg] as Record<string, unknown>;
    }
    current[segments[segments.length - 1]] = value;
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
