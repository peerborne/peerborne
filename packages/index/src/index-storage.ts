import { IndexFieldDefinition, FieldFilter, SortClause } from './types.js';

/**
 * A single stored index entry: document path mapped to its indexed field values.
 */
export interface IndexEntry {
  documentPath: string;
  fields: Record<string, unknown>;
}

/**
 * Storage backend interface for the indexing system.
 * Implementations back the local materialized index with different storage engines.
 */
export interface IndexStorage {
  /**
   * Initialize storage for a named index with the given field definitions.
   * Called once when an index is first defined. Implementations should create
   * any necessary stores, tables, or data structures.
   */
  initialize(indexName: string, fields: IndexFieldDefinition[]): Promise<void>;

  /**
   * Insert or update an index entry for a document.
   */
  put(indexName: string, documentPath: string, fields: Record<string, unknown>): Promise<void>;

  /**
   * Remove an index entry for a document.
   */
  delete(indexName: string, documentPath: string): Promise<void>;

  /**
   * Query the index with filters, sorting, and pagination.
   * Returns matching entries ordered and paginated as specified.
   */
  query(
    indexName: string,
    filters: FieldFilter[],
    sort?: SortClause[],
    limit?: number,
    offset?: number,
  ): Promise<IndexEntry[]>;

  /**
   * Get a single entry by document path.
   * Returns undefined if the document is not in the index.
   */
  get(indexName: string, documentPath: string): Promise<Record<string, unknown> | undefined>;

  /**
   * Remove all entries from a named index.
   */
  clear(indexName: string): Promise<void>;

  /**
   * Close the storage backend and release resources.
   */
  close(): Promise<void>;
}
