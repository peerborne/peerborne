// Types
export type {
  IndexFieldType,
  IndexFieldDefinition,
  IndexDefinition,
  FilterOperator,
  FieldFilter,
  SortClause,
  QueryOptions,
  QueryResultEntry,
  QueryResult,
  DocumentSnapshotExtractor,
  BenchmarkResult,
} from './types.js';

// Field extraction
export { extractField } from './field-extractor.js';

// Storage layer
export type { IndexStorage, IndexEntry } from './index-storage.js';
export { MemoryIndexStorage } from './memory-index-storage.js';
export { IDBIndexStorage } from './idb-index-storage.js';

// Index manager
export { IndexManager } from './index-manager.js';

// Integration with PeerborneDocument
export {
  PeerborneIndexIntegration,
} from './peerborne-index-integration.js';
export type { SubscribableDocument } from './peerborne-index-integration.js';

// Blind index (encrypted search)
export type { BlindIndexProvider } from './blind-index-provider.js';
export { SubtleBlindIndexProvider } from './subtle-blind-index-provider.js';
export { BlindIndexQuery } from './blind-index-query.js';
export type { BlindIndexEntry } from './blind-index-query.js';

// Bloom filter (distributed discovery)
export { BloomFilterCRDT } from './bloom-filter-crdt.js';
export { BloomFilterGossip } from './bloom-filter-gossip.js';
export type { PeerFilterState, BloomFilterGossipConfig } from './bloom-filter-gossip.js';

