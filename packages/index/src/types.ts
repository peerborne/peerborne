/**
 * Supported field types for index definitions.
 */
export type IndexFieldType = 'string' | 'number' | 'date' | 'boolean';

/**
 * Defines a single field to be indexed.
 */
export interface IndexFieldDefinition {
  /** Dot-notation path to the field in the document snapshot. */
  path: string;
  /** The expected type of the field value. */
  type: IndexFieldType;
}

/**
 * Declarative definition for an index over a collection of documents.
 */
export interface IndexDefinition {
  /** Unique name for this index. */
  name: string;
  /** Document path prefix that determines which documents belong to this index. */
  collectionPrefix: string;
  /** Fields to extract and index from matching documents. */
  fields: IndexFieldDefinition[];
}

/**
 * Supported query filter operators.
 */
export type FilterOperator =
  | 'eq'
  | 'neq'
  | 'gt'
  | 'gte'
  | 'lt'
  | 'lte'
  | 'prefix'
  | 'in'
  | 'contains';

/**
 * A single filter condition on an indexed field.
 */
export interface FieldFilter {
  /** Dot-notation path to the field. */
  path: string;
  /** Comparison operator. */
  operator: FilterOperator;
  /** Value to compare against. */
  value: unknown;
}

/**
 * Sorting clause for query results.
 */
export interface SortClause {
  /** Dot-notation path to the field to sort by. */
  path: string;
  /** Sort direction. */
  direction: 'asc' | 'desc';
}

/**
 * Options for querying an index.
 */
export interface QueryOptions {
  /** Target a specific named index. */
  indexName?: string;
  /** Filter to documents matching this path prefix. */
  collectionPrefix?: string;
  /** Filter conditions to apply. */
  filters: FieldFilter[];
  /** Sort clauses (applied in order). */
  sort?: SortClause[];
  /** Maximum number of results to return. */
  limit?: number;
  /** Number of results to skip (for pagination). */
  offset?: number;
}

/**
 * A single document in a query result.
 */
export interface QueryResultEntry<T> {
  /** The document's path/ID. */
  documentPath: string;
  /** The extracted snapshot of the document. */
  snapshot: T;
}

/**
 * Result of a query against the index.
 */
export interface QueryResult<T> {
  /** Matching documents (after filters, sort, limit, offset). */
  documents: QueryResultEntry<T>[];
  /** Total count of matching documents before limit/offset. */
  totalCount: number;
}

/**
 * Extracts a plain-object snapshot from a CRDT document type.
 * For example, for Y.js: `(doc: Y.Doc) => doc.getMap('root').toJSON()`
 */
export type DocumentSnapshotExtractor<DocType> = (doc: DocType) => Record<string, unknown>;

/**
 * Result of a single benchmark run.
 */
export interface BenchmarkResult {
  /** Name of the benchmark scenario. */
  name: string;
  /** Average execution time in milliseconds. */
  avgMs: number;
  /** 50th percentile (median) execution time in milliseconds. */
  p50Ms: number;
  /** 99th percentile execution time in milliseconds. */
  p99Ms: number;
  /** Memory usage change in bytes (if measured). */
  memoryDeltaBytes?: number;
  /** Storage size in bytes (if measured). */
  storageSizeBytes?: number;
}
