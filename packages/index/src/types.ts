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
  /** Whether absence or null excludes the document from this index. */
  required?: boolean;
  /** Maximum UTF-16 length accepted for strings. Defaults to 16,384. */
  maxStringLength?: number;
}

/** Ordered fields forming one physical secondary index. */
export interface IndexKeyDefinition {
  name: string;
  fields: string[];
}

/**
 * Declarative definition for an index over a collection of documents.
 */
export interface IndexDefinition {
  /** Definitions without a version retain the v1 API and storage behavior. */
  version?: 1 | 2;
  /** Unique name for this index. */
  name: string;
  /** Document path prefix that determines which documents belong to this index. */
  collectionPrefix: string;
  /** Fields to extract and index from matching documents. */
  fields: IndexFieldDefinition[];
  /** Omission creates one physical index per required field. */
  indexes?: IndexKeyDefinition[];
  /** Application-controlled identifier for blue/green rebuilds. */
  generation?: string;
  /** V2 defaults to memory-only. Persistence requires explicit opt-in. */
  storageMode?: 'memory' | 'cleartext-local';
  /** V2 defaults to excluding malformed documents. */
  invalidValuePolicy?: 'skip-document' | 'reject';
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
 * Legacy local query API.
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

export interface QueryFieldExpression {
  kind: 'field';
  path: string;
  operator: FilterOperator;
  value: unknown;
}

export interface QueryAndExpression {
  kind: 'and';
  expressions: QueryExpression[];
}

export interface QueryOrExpression {
  kind: 'or';
  expressions: QueryExpression[];
}

export type QueryExpression = QueryFieldExpression | QueryAndExpression | QueryOrExpression;
export type QueryCountMode = 'exact' | 'none';
export type QueryConsistency = 'eventual' | 'indexed';

/** Versioned, serializable query contract shared by local and distributed search. */
export interface QueryAst {
  version: 2;
  indexName?: string;
  collectionPrefix?: string;
  where?: QueryExpression;
  orderBy?: SortClause[];
  first?: number;
  after?: string;
  select?: string[];
  count?: QueryCountMode;
  allowScan?: boolean;
  consistency?: QueryConsistency;
}

export type QueryScanKind = 'none' | 'bounded' | 'full';

export interface QueryExecutionInfo {
  source: 'local';
  indexName: string;
  schemaVersion: 1 | 2;
  schemaHash: string;
  generation: string;
  storageMode: 'memory' | 'cleartext-local';
  physicalIndexes: string[];
  scan: QueryScanKind;
  sort: 'index' | 'memory' | 'none';
  residualPredicate: boolean;
  rowsVisited: number;
  rowsMatched: number;
}

export interface QueryCoverage {
  level: 'local-tracked';
  partial: boolean;
  reasons: string[];
}

export interface QueryPageInfo {
  cursor?: string;
  hasMore: boolean;
}

export type QueryCount = { kind: 'none' } | { kind: 'verified'; value: number };

export interface QueryAstResult<T> {
  documents: QueryResultEntry<T>[];
  count: QueryCount;
  pageInfo: QueryPageInfo;
  execution: QueryExecutionInfo;
  coverage: QueryCoverage;
}

/** Bounded diagnostic which deliberately excludes the offending value. */
export interface IndexDiagnostic {
  indexName: string;
  documentPath: string;
  fieldPath: string;
  reason: InvalidIndexedValueReason;
  recordedAt: number;
}

export type InvalidIndexedValueReason =
  | 'missing-required'
  | 'wrong-type'
  | 'value-too-large';

export type IndexScalar = string | number | boolean;

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
