import {
  DEFAULT_INVITATION_TTL_MS,
  Peerborne,
  PeerbornePeersHandler,
} from './peerborne.js';
import {
  PeerborneConfig,
  DEFAULT_WEBRTC_ICE_SERVERS,
  IceServer,
  defaultConfig,
  defaultBootstrapConfig,
  getDefaultConfig,
} from './peerborne-config.js';
import {
  PeerborneDocument,
  PeerborneDocumentChangeHandler,
  HistoryVisibility,
} from './peerborne-document.js';
import { CRDTSyncMessage } from './crdt-sync-message.js';
// PeerborneNode is intentionally excluded from this barrel export.
// It is a Node-only module (imports `fs`, `@libp2p/mdns` which depends on
// `dgram`) and must not be bundled by browser consumers. Import it from the
// dedicated Node subpath export:
//   import { PeerborneNode, defaultNodeConfig } from '@peerborne/core/node';
import { CRDTProvider } from './crdt-provider.js';
import { SyncMessageSerializer } from './sync-message-serializer.js';
import { ChangesSerializer } from './changes-serializer.js';
import {
  JSONSerializer,
  validateChangeBlockMetadata,
} from './json-serializer.js';
import { SubtleCrypto } from './auth-subtlecrypto.js';
import { ACLProvider } from './acl-provider.js';
import { KeychainProvider } from './keychain-provider.js';
import { ACL } from './acl.js';
import {
  Keychain,
  TransactionalKeychain,
  PreparedKeychainAddition,
  PreparedKeychainEpoch,
  PreparedKeychainMerge,
  KeychainAppendIntent,
  MAX_KEYCHAIN_EPOCHS,
  computeKeychainStateCommitment,
  isTransactionalKeychain,
  keychainHistorySinceOrFull,
} from './keychain.js';
import {
  requireDeserializePublicKey,
  requireSerializePublicKey,
} from './auth-provider.js';
import {
  LoadMessageSerializer,
  LoadRequestCompletionDetector,
} from './load-request-serializer.js';
import { CRDTChangeBlock } from './crdt-change-block.js';
import {
  CRDTChangeNodeKind,
  CRDTChangeNodeDeferred,
  CRDTChangeNode,
  crdtChangeNodeDeferred,
} from './crdt-change-node.js';
import {
  CRDTChangeNodeWire,
  MAX_MERKLE_DAG_DEPTH,
  describeValue,
  serializeChangeNodeForJSON,
  deserializeChangeNodeFromJSON,
} from './merkle-dag-serialization.js';
import {
  EPOCH_ID_LENGTH,
  GCM_NONCE_LENGTH,
  EPOCH_SECRET_INFO,
  ENCRYPTION_KEY_INFO,
  Epoch,
  EpochTransition,
  toHex,
  generateEpochId,
  deriveEpochSecret,
  deriveEncryptionKey,
  createEpoch,
  EpochManager,
} from './epoch.js';
import {
  GroupKeyAgreementOutput,
  WelcomeMessage,
  MembershipProposal,
  GroupKeyProvider,
} from './group-key-provider.js';
import {
  CAP_DOC_ADMIN,
  CAP_DOC_WRITE,
  CAP_DOC_READ,
  CAP_DOC_HISTORY,
  CAPABILITY_HIERARCHY,
  NON_HIERARCHICAL_CAPABILITIES,
  capabilityImplies,
  isFieldCapability,
  getFieldPath,
} from './capabilities.js';
import {
  createUCAN,
  verifyUCANSignature,
  validateUCANChain,
  serializeUCAN,
  deserializeUCAN,
} from './ucan.js';
import { UCANACL, UCANACLProvider } from './ucan-acl.js';
import {
  ACLChain,
  canonicalEntryPayload,
  computeEntryHash,
} from './acl-chain.js';
import { NetworkStats } from './network-stats.js';
import { LRUCache } from './lru-cache.js';
import {
  beekemPathUpdateV1,
  beekemPathUpdateV2,
  beekemWelcomeV1,
  beekemWelcomeV2,
  bloomFilterUpdateV1,
  searchIndexAdvertiseV1,
  searchQueryV1,
  invitationJoinV1,
  tipAdvertiseV1,
} from './wire-protocols.js';
import {
  DOC_KEY_INFO,
  deriveDocumentKeyFromRootSecret,
  deriveEpochIdFromRootSecret,
} from './derive-doc-key.js';
import {
  SerializedPathNodeUpdate,
  SerializedPathUpdate,
  deserializePathUpdateFromWire,
  deserializePathUpdateV2FromWire,
  serializePathUpdateForWire,
  serializePathUpdateV2ForWire,
} from './path-update-wire.js';
import {
  deserializeBeeKEMWelcomeFromWire,
  deserializeBeeKEMWelcomeV2FromWire,
  serializeBeeKEMWelcomeForWire,
  serializeBeeKEMWelcomeV2ForWire,
} from './beekem-welcome-wire.js';
import {
  decodeWelcomeSealedPayload,
  decodeWelcomeSealedPayloadV2,
  encodeWelcomeSealedPayload,
  encodeWelcomeSealedPayloadV2,
} from './welcome-sealed-payload.js';
import { tipsHash, tipsHashToHex, TIPS_HASH_LENGTH } from './tips-hash.js';
import {
  decideLoadQuorum,
  effectiveK,
  effectiveQ,
  LoadQuorumFailedError,
  validateLoadQuorumConfig,
} from './load-quorum.js';
import {
  documentTopic,
  DEFAULT_DOCUMENT_TOPIC_PREFIX,
} from './document-topic.js';
import type { CRDTSnapshotNode } from './snapshot-node.js';
import type { CompactionConfig } from './compaction-config.js';
import {
  defaultCompactionConfig,
  mergeCompactionConfig,
} from './compaction-config.js';

export * from './beekem/index.js';
export * from './invitation-capacity.js';
export * from './invitation-wire.js';
export * from './invitation-replay-guard.js';
export * from './ecies.js';
export * from './welcome-sealed-payload.js';
export * from './group-security-provider.js';
export * from './membership-control-record.js';
export * from './group-state-store.js';
export * from './group-security-rollback-anchor.js';
export * from './group-security-store-commitment.js';
export * from './group-security-durable-acceptance.js';
export * from './group-security-coordinator.js';
export * from './webcrypto-group-state-protector.js';

export {
  ACL,
  ACLProvider,
  SubtleCrypto,
  Peerborne,
  PeerbornePeersHandler,
  DEFAULT_INVITATION_TTL_MS,
  PeerborneConfig,
  PeerborneDocument,
  PeerborneDocumentChangeHandler,
  HistoryVisibility,
  CRDTChangeBlock,
  CRDTChangeNodeKind,
  CRDTChangeNodeDeferred,
  CRDTChangeNode,
  crdtChangeNodeDeferred,
  CRDTChangeNodeWire,
  MAX_MERKLE_DAG_DEPTH,
  describeValue,
  serializeChangeNodeForJSON,
  deserializeChangeNodeFromJSON,
  CRDTSyncMessage,
  CRDTProvider,
  ChangesSerializer,
  EPOCH_ID_LENGTH,
  GCM_NONCE_LENGTH,
  EPOCH_SECRET_INFO,
  ENCRYPTION_KEY_INFO,
  Epoch,
  EpochTransition,
  toHex,
  generateEpochId,
  deriveEpochSecret,
  deriveEncryptionKey,
  createEpoch,
  EpochManager,
  GroupKeyAgreementOutput,
  WelcomeMessage,
  MembershipProposal,
  GroupKeyProvider,
  Keychain,
  TransactionalKeychain,
  PreparedKeychainAddition,
  PreparedKeychainEpoch,
  PreparedKeychainMerge,
  KeychainAppendIntent,
  MAX_KEYCHAIN_EPOCHS,
  computeKeychainStateCommitment,
  isTransactionalKeychain,
  keychainHistorySinceOrFull,
  KeychainProvider,
  requireDeserializePublicKey,
  requireSerializePublicKey,
  SyncMessageSerializer,
  LoadMessageSerializer,
  LoadRequestCompletionDetector,
  JSONSerializer,
  validateChangeBlockMetadata,
  defaultConfig,
  defaultBootstrapConfig,
  getDefaultConfig,
  DEFAULT_WEBRTC_ICE_SERVERS,
  IceServer,
  // Capabilities
  CAP_DOC_ADMIN,
  CAP_DOC_WRITE,
  CAP_DOC_READ,
  CAP_DOC_HISTORY,
  CAPABILITY_HIERARCHY,
  NON_HIERARCHICAL_CAPABILITIES,
  capabilityImplies,
  isFieldCapability,
  getFieldPath,
  // UCAN
  createUCAN,
  verifyUCANSignature,
  validateUCANChain,
  serializeUCAN,
  deserializeUCAN,
  // UCAN ACL
  UCANACL,
  UCANACLProvider,
  // ACL chain-of-trust
  ACLChain,
  canonicalEntryPayload,
  computeEntryHash,
  // Wire protocols
  bloomFilterUpdateV1,
  beekemWelcomeV1,
  beekemWelcomeV2,
  beekemPathUpdateV1,
  beekemPathUpdateV2,
  searchIndexAdvertiseV1,
  searchQueryV1,
  invitationJoinV1,
  tipAdvertiseV1,
  // BeeKEM document-key derivation
  DOC_KEY_INFO,
  deriveDocumentKeyFromRootSecret,
  deriveEpochIdFromRootSecret,
  // BeeKEM PathUpdate wire serialization
  serializePathUpdateForWire,
  deserializePathUpdateFromWire,
  serializePathUpdateV2ForWire,
  deserializePathUpdateV2FromWire,
  serializeBeeKEMWelcomeForWire,
  deserializeBeeKEMWelcomeFromWire,
  serializeBeeKEMWelcomeV2ForWire,
  deserializeBeeKEMWelcomeV2FromWire,
  encodeWelcomeSealedPayload,
  decodeWelcomeSealedPayload,
  encodeWelcomeSealedPayloadV2,
  decodeWelcomeSealedPayloadV2,
  // Initial-load quorum (#189 §5.4.2)
  tipsHash,
  tipsHashToHex,
  TIPS_HASH_LENGTH,
  decideLoadQuorum,
  effectiveK,
  effectiveQ,
  LoadQuorumFailedError,
  validateLoadQuorumConfig,
  // Compaction
  defaultCompactionConfig,
  mergeCompactionConfig,
  // Network statistics
  NetworkStats,
  // Utilities
  documentTopic,
  DEFAULT_DOCUMENT_TOPIC_PREFIX,
  LRUCache,
};

export type { NetworkStatsSnapshot } from './network-stats.js';
export type { CreateInvitationOptions } from './peerborne.js';
export type { InvitationBootstrapBundle } from './peerborne-document.js';
export type {
  PeerTipAdvertisement,
  LoadQuorumDecision,
  LoadQuorumFailedReason,
} from './load-quorum.js';

// Re-export types
export type {
  AuthProvider,
  AesAlgorithmName,
  EncryptionResult,
} from './auth-provider.js';
export type { SubtleCryptoEncryptionResult } from './auth-subtlecrypto.js';
export type { CRDTLoadRequest } from './crdt-load-request.js';
export type {
  CRDTDocumentChangeNode,
  CRDTWriterChangeNode,
  CRDTReaderChangeNode,
} from './crdt-change-node.js';
export type {
  SerializedPathUpdate,
  SerializedPathNodeUpdate,
} from './path-update-wire.js';
export type {
  SerializedEncryptedPathKeyBundle,
  SerializedPathNodeUpdateV2,
  SerializedPathTreeNodePublicKey,
  SerializedPathUpdateV2,
} from './path-update-wire.js';
export type {
  SerializedBeeKEMWelcome,
  SerializedBeeKEMWelcomeV2,
  SerializedWelcomeNodePublicKey,
  SerializedWelcomePathNodeUpdate,
} from './beekem-welcome-wire.js';
export type {
  WelcomeSealedPayload,
  WelcomeSealedPayloadV2,
} from './welcome-sealed-payload.js';
export type { DocumentCapability } from './capabilities.js';
export type { UCAN, UCANCapability, UCANPayload } from './ucan.js';
export type { UCANACLEntry } from './ucan-acl.js';
export type { CRDTSnapshotNode } from './snapshot-node.js';
export type { CompactionConfig } from './compaction-config.js';
export {
  LOAD_SECURITY_STATE_VERSION,
  LOAD_SECURITY_HASH_LENGTH,
  MAX_LOAD_SECURITY_GROUP_ID_BYTES,
  MAX_LOAD_SECURITY_EPOCH,
  TrustedLoadSecurityCommitmentsError,
  captureTrustedLoadSecurityCommitments,
  cloneLoadSecurityCommitments,
  encodeLoadSecurityState,
  loadSecurityCommitmentsEqual,
  loadSecurityStateHash,
  loadSecurityStateHashToHex,
  validateLoadSecurityCommitments,
  validateLoadSecurityState,
} from './load-security-state.js';
export type {
  LoadSecurityCommitments,
  LoadSecurityCommitmentsResolver,
  LoadSecurityState,
} from './load-security-state.js';
export {
  serializeLoadSecurityCommitmentsForWire,
  deserializeLoadSecurityCommitmentsFromWire,
} from './load-security-state-wire.js';
export type { LoadSecurityCommitmentsWire } from './load-security-state-wire.js';
export {
  loadAdvertisementHash,
  loadAdvertisementHashToHex,
} from './load-advertisement-hash.js';
export {
  LOAD_RESPONSE_MANIFEST_HASH_LENGTH,
  MAX_LOAD_RESPONSE_MANIFEST_EDGES,
  MAX_LOAD_RESPONSE_MANIFEST_ID_BYTES,
  MAX_LOAD_RESPONSE_MANIFEST_NODES,
  MAX_LOAD_RESPONSE_MANIFEST_OCCURRENCES,
  MAX_LOAD_RESPONSE_MANIFEST_PAYLOAD_BYTES,
  loadResponseManifestHash,
} from './load-response-manifest.js';
export type {
  LoadResponseManifestInput,
  LoadResponseManifestSnapshot,
} from './load-response-manifest.js';
export {
  identifyInitialLoadSigner,
  verifyInitialLoadAuthentication,
} from './initial-load-auth.js';
export type {
  IdentifiedInitialLoadSigner,
  InitialLoadAuthenticationOptions,
} from './initial-load-auth.js';
export {
  allowsUnauthenticatedUnknownDocumentSentinel,
  isUnknownDocumentAdvertisement,
  unknownDocumentAdvertisement,
} from './initial-load-sentinel-policy.js';
export type { InitialLoadSentinelPolicy } from './initial-load-sentinel-policy.js';
export {
  INITIAL_LOAD_CHALLENGE_LENGTH,
  MAX_INITIAL_LOAD_CHALLENGE_DOCUMENT_ID_BYTES,
  cloneInitialLoadChallenge,
  createInitialLoadChallenge,
  deserializeInitialLoadChallengeFromWire,
  initialLoadChallengeEquals,
  initialLoadRequestSignaturePayload,
  serializeInitialLoadChallengeForWire,
  validateInitialLoadChallenge,
} from './initial-load-challenge.js';
export {
  documentLoadV3,
  documentLoadV4,
  snapshotLoadV3,
  snapshotLoadV4,
  securityAdvertiseV1,
} from './wire-protocols.js';
export type {
  ACLChainConfig,
  ACLChainOps,
  ACLChainVerifyError,
  ACLChainVerifyResult,
  ACLEntry,
  ACLState,
  SerializePublicKey,
} from './acl-chain.js';
export {
  MAX_SHARED_PROTOCOL_REQUEST_BYTES,
  assertSharedProtocolRequestSize,
  copyUnsharedUint8Array,
  snapshotDeepEnumerableData,
} from './utils.js';
export type { DeepDataSnapshotLimits } from './utils.js';
