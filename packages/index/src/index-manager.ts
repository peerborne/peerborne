import {
  IndexDefinition,
  QueryOptions,
  QueryResult,
  DocumentSnapshotExtractor,
} from './types.js';
import { IndexStorage } from './index-storage.js';
import { extractField } from './field-extractor.js';

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
  private _subscriptions: Map<
    number,
    { options: QueryOptions; callback: (result: QueryResult<Record<string, unknown>>) => void }
  > = new Map();
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
        return;
      }
      throw new Error(
        `Index "${definition.name}" is already defined with a different configuration. ` +
        `Call removeIndex() first to redefine it.`,
      );
    }
    this._definitions.set(definition.name, definition);
    await this._storage.initialize(definition.name, definition.fields);
  }

  /**
   * Remove an index definition and clear its stored data.
   */
  async removeIndex(indexName: string): Promise<void> {
    this._definitions.delete(indexName);
    await this._storage.clear(indexName);
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
    const entries: Array<{ indexName: string; fields: Record<string, unknown> }> = [];

    for (const [indexName, definition] of this._definitions) {
      if (!documentPath.startsWith(definition.collectionPrefix)) {
        continue;
      }

      const fields: Record<string, unknown> = {};
      for (const fieldDef of definition.fields) {
        this._setNestedField(fields, fieldDef.path, extractField(snapshot, fieldDef.path));
      }

      entries.push({ indexName, fields });
    }

    await this._enqueueDocumentOperation(documentPath, async () => {
      let changed = false;

      for (const { indexName, fields } of entries) {
        // Diff against previous entry -- skip write if unchanged
        const existing = await this._storage.get(indexName, documentPath);
        if (existing && this._fieldsEqual(existing, fields)) {
          continue;
        }

        await this._storage.put(indexName, documentPath, fields);
        changed = true;
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
    await this._enqueueDocumentOperation(documentPath, async () => {
      for (const indexName of this._definitions.keys()) {
        await this._storage.delete(indexName, documentPath);
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
    this._subscriptions.set(id, { options, callback });

    // Fire initial query -- guard against delivery after unsubscribe
    this.query(options).then((result) => {
      if (this._subscriptions.has(id)) {
        callback(result);
      }
    }).catch((err) => {
      console.warn('IndexManager: initial subscription query failed', err);
    });

    return () => {
      this._subscriptions.delete(id);
    };
  }

  /**
   * Rebuild an index from scratch using all provided documents.
   */
  async rebuildIndex(indexName: string, documents: Map<string, DocType>): Promise<void> {
    const definition = this._definitions.get(indexName);
    if (!definition) return;

    await this._storage.clear(indexName);

    for (const [documentPath, document] of documents) {
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
    for (const [id, sub] of this._subscriptions) {
      this.query(sub.options).then((result) => {
        // Guard: subscription may have been removed while query was in flight
        if (this._subscriptions.has(id)) {
          sub.callback(result);
        }
      }).catch((err) => {
        console.warn('IndexManager: subscription notification query failed', err);
      });
    }
  }
}
