// Types
export type {
  IndexFieldType,
  IndexFieldDefinition,
  IndexKeyDefinition,
  IndexDefinition,
  FilterOperator,
  FieldFilter,
  SortClause,
  QueryOptions,
  QueryResultEntry,
  QueryResult,
  QueryExpression,
  QueryFieldExpression,
  QueryAndExpression,
  QueryOrExpression,
  QueryAst,
  QueryAstResult,
  QueryExecutionInfo,
  QueryCoverage,
  QueryPageInfo,
  QueryCount,
  QueryCountMode,
  QueryScanKind,
  QueryConsistency,
  IndexDiagnostic,
  InvalidIndexedValueReason,
  IndexScalar,
  DocumentSnapshotExtractor,
  BenchmarkResult,
} from './types.js';

// Field extraction
export { extractField } from './field-extractor.js';

// Storage layer
export type {
  IndexStorage,
  IndexEntry,
  StorageSchemaIdentity,
  StorageQueryRequest,
  StorageQueryResult,
} from './index-storage.js';
export { MemoryIndexStorage } from './memory-index-storage.js';
export { IDBIndexStorage } from './idb-index-storage.js';

// Index manager
export {
  IndexManager,
  IndexSecurityPolicyError,
  InvalidIndexedDocumentError,
  QueryRequiresScanError,
} from './index-manager.js';

export {
  InvalidIndexSchemaError,
  InvalidQueryError,
  validateIndexDefinition,
  validateQueryAst,
  legacyQueryToAst,
  physicalIndexesFor,
  resolvedStorageMode,
  resolvedInvalidValuePolicy,
  invalidIndexedValueReason,
  canonicalJsonString,
  canonicalIndexDefinitionString,
  canonicalQueryString,
  hashIndexDefinition,
  hashQuery,
} from './query-ast.js';
export { planQuery, planScanKind, planPhysicalIndexNames } from './query-planner.js';
export type {
  QueryPlan,
  PhysicalQueryPlan,
  FullScanQueryPlan,
  UnionQueryPlan,
  QueryIndexLookup,
  QueryRangeConstraint,
} from './query-planner.js';
export {
  createQueryCursor,
  parseQueryCursor,
  isAfterQueryCursor,
} from './query-cursor.js';
export type { QueryCursorPosition } from './query-cursor.js';

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

// Distributed candidate and authorization boundary
export type {
  QueryCandidateReference,
  CandidateSearchRequest,
  CandidateSearchResult,
  QueryCandidateSource,
  AuthorizedDocumentSnapshot,
  AuthorizedDocumentResolver,
} from './candidate-source.js';
export type {
  DistributedSearchPermission,
  DistributedSearchSigner,
  DistributedSearchAuthorizer,
} from './distributed-auth.js';
export {
  FederatedSearchCoordinator,
} from './federated-search.js';
export type {
  FederatedCoverageReason,
  FederatedQueryCoverage,
  FederatedQueryCount,
  FederatedSourceExecution,
  FederatedQueryResult,
  FederatedSearchConfig,
} from './federated-search.js';

// Signed distributed control plane and wire protocol
export {
  DistributedManifestError,
  DistributedManifestRegistry,
  validateDistributedIndexManifest,
  signDistributedIndexManifest,
  verifyDistributedIndexManifest,
} from './distributed-manifest.js';
export type {
  DistributedIndexManifestV1,
  SignedDistributedIndexManifestV1,
  VerifiedDistributedIndexManifest,
  ManifestAcceptResult,
} from './distributed-manifest.js';
export { RoutingAdvertisementRegistry, signRoutingAdvertisement } from './routing-advertisement.js';
export type {
  RoutingAdvertisementV1,
  SignedRoutingAdvertisementV1,
  RoutingPeerState,
  RoutingAdvertisementRegistryConfig,
  RoutingAdvertisementRejectReason,
  RoutingAdvertisementAcceptResult,
} from './routing-advertisement.js';
export {
  SearchWireError,
  DistributedSearchRequestReplayGuard,
  createDistributedSearchRequestId,
  signDistributedSearchRequest,
  verifyDistributedSearchRequest,
  signDistributedSearchResponse,
  verifyDistributedSearchResponse,
  encodeDistributedSearchRequest,
  encodeDistributedSearchResponse,
} from './distributed-search-wire.js';
export type {
  DistributedSearchRequestPayload,
  DistributedSearchRequestV1,
  SignedDistributedSearchRequestV1,
  VerifiedDistributedSearchRequest,
  DistributedSearchCandidateV1,
  DistributedSearchResponseV1,
  SignedDistributedSearchResponseV1,
  VerifiedDistributedSearchResponse,
  SearchWireRejectReason,
} from './distributed-search-wire.js';
export {
  DistributedPeerCandidateSource,
  PlaintextDistributedQueryEncoder,
  BlindEqualityRequestEncoder,
} from './distributed-peer-source.js';
export type {
  DistributedSearchTransport,
  DistributedSearchRequestEncoder,
  DistributedPeerCandidateSourceOptions,
} from './distributed-peer-source.js';
