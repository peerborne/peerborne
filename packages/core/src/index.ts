import { Peerborne, PeerbornePeersHandler } from './peerborne.js';
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
import { JSONSerializer, validateChangeBlockMetadata } from './json-serializer.js';
import { SubtleCrypto } from './auth-subtlecrypto.js';
import { ACLProvider } from './acl-provider.js';
import { KeychainProvider } from './keychain-provider.js';
import { ACL } from './acl.js';
import { Keychain, keychainHistorySinceOrFull } from './keychain.js';
import { requireSerializePublicKey } from './auth-provider.js';
import { LoadMessageSerializer } from './load-request-serializer.js';
import { CRDTChangeBlock } from './crdt-change-block.js';
import {
  CRDTChangeNodeKind,
  CRDTChangeNodeDeferred,
  CRDTChangeNode,
  crdtChangeNodeDeferred,
} from './crdt-change-node.js';
import {
  CRDTChangeNodeWire,
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
import {
  UCANACL,
  UCANACLProvider,
} from './ucan-acl.js';
import {
  ACLChain,
  canonicalEntryPayload,
  computeEntryHash,
} from './acl-chain.js';
import { NetworkStats } from './network-stats.js';
import { LRUCache } from './lru-cache.js';
import {
  beekemPathUpdateV1,
  beekemWelcomeV1,
  bloomFilterUpdateV1,
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
  serializePathUpdateForWire,
} from './path-update-wire.js';
import { tipsHash, tipsHashToHex, TIPS_HASH_LENGTH } from './tips-hash.js';
import {
  decideLoadQuorum,
  effectiveK,
  effectiveQ,
  LoadQuorumFailedError,
  validateLoadQuorumConfig,
} from './load-quorum.js';
import { documentTopic, DEFAULT_DOCUMENT_TOPIC_PREFIX } from './document-topic.js';
import type { CRDTSnapshotNode } from './snapshot-node.js';
import type { CompactionConfig } from './compaction-config.js';
import { defaultCompactionConfig } from './compaction-config.js';

export * from './beekem/index.js';

export {
  ACL,
  ACLProvider,
  SubtleCrypto,
  Peerborne,
  PeerbornePeersHandler,
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
  keychainHistorySinceOrFull,
  KeychainProvider,
  requireSerializePublicKey,
  SyncMessageSerializer,
  LoadMessageSerializer,
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
  beekemPathUpdateV1,
  tipAdvertiseV1,
  // BeeKEM document-key derivation
  DOC_KEY_INFO,
  deriveDocumentKeyFromRootSecret,
  deriveEpochIdFromRootSecret,
  // BeeKEM PathUpdate wire serialization
  serializePathUpdateForWire,
  deserializePathUpdateFromWire,
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
  // Network statistics
  NetworkStats,
  // Utilities
  documentTopic,
  DEFAULT_DOCUMENT_TOPIC_PREFIX,
  LRUCache,
};

export type { NetworkStatsSnapshot } from './network-stats.js';
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
export type { SerializedPathUpdate, SerializedPathNodeUpdate } from './path-update-wire.js';
export type { DocumentCapability } from './capabilities.js';
export type { UCAN, UCANCapability, UCANPayload } from './ucan.js';
export type { UCANACLEntry } from './ucan-acl.js';
export type { CRDTSnapshotNode } from './snapshot-node.js';
export type { CompactionConfig } from './compaction-config.js';
export type {
  ACLChainConfig,
  ACLChainOps,
  ACLChainVerifyError,
  ACLChainVerifyResult,
  ACLEntry,
  ACLState,
  SerializePublicKey,
} from './acl-chain.js';
