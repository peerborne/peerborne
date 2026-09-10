/**
 * Document  is just for opening documents right now
 * @remarks
 *   A document is part of a Swarm.
 *   Document keys are attached to a single document.
 */

import { pipe } from 'it-pipe';
import { Libp2p } from 'libp2p';
import { Peerborne, MAX_DOCUMENT_PATH_LENGTH } from './peerborne.js';
import type { CreateInvitationOptions } from './peerborne.js';
import {
  concatUint8Arrays,
  copyUnsharedUint8Array,
  readUint8Iterable,
  shuffleArray,
  snapshotDeepEnumerableData,
  snapshotEnumerableOwnDataObject,
} from './utils.js';
import { wrapStream } from './stream-adapter.js';
import { CRDTProvider } from './crdt-provider.js';
import { AuthProvider, requireSerializePublicKey } from './auth-provider.js';
import {
  CRDTChangeNode,
  crdtChangeNodeDeferred,
  CRDTChangeNodeKind,
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
} from './crdt-change-node.js';
import {
  collectReferencedAncestors,
  collectAllCidsInTree,
  computeServedFrontier,
  stripInlineChanges,
  MAX_CROSS_LINKS,
  MAX_RECENT_TIPS,
  mergeRemoteSyncTree,
  RecentTip,
  selectCrossLinks,
  trackTipInList,
  treeContainsCid,
} from './merkle-cross-links.js';
import { CRDTSyncMessage } from './crdt-sync-message.js';
import { ChangesSerializer } from './changes-serializer.js';
import { SyncMessageSerializer } from './sync-message-serializer.js';
import {
  evaluateBeeKEMWelcome,
  evaluateBeeKEMWelcomeTransition,
} from './beekem-welcome-handler.js';
import { validateAndExportKemKeyPair } from './kem-key-pair.js';
import {
  eciesSeal,
  eciesOpen,
  importEciesPublicKey,
  ECIES_P256_PUBLIC_KEY_LENGTH,
} from './ecies.js';
import {
  beekemPathUpdateV2,
  beekemWelcomeV1,
  beekemWelcomeV2,
  documentKeyUpdateV2,
} from './wire-protocols.js';
import type { BeeKEMWireVersion } from './wire-protocols.js';
import {
  initialLoadProtocols,
  MAX_INITIAL_LOAD_RESPONSE_SIZE,
  MAX_SECURITY_ADVERTISE_RESPONSE_SIZE,
  MAX_SHARED_PROTOCOL_REQUEST_SIZE,
  MAX_TIP_ADVERTISE_RESPONSE_SIZE,
  shouldServeInitialLoadProtocol,
} from './initial-load-protocols.js';
import type { InitialLoadProtocolFamily } from './initial-load-protocols.js';
import { isUnknownDocumentAdvertisement } from './initial-load-sentinel-policy.js';
import {
  cloneInitialLoadChallenge,
  createInitialLoadChallenge,
  initialLoadChallengeEquals,
  initialLoadRequestSignaturePayload,
} from './initial-load-challenge.js';
import {
  loadAdvertisementHash,
  loadAdvertisementHashToHex,
} from './load-advertisement-hash.js';
import { loadResponseManifestHash } from './load-response-manifest.js';
import {
  identifyInitialLoadSigner,
  verifyInitialLoadAuthentication,
} from './initial-load-auth.js';
import type { LoadSecurityCommitments } from './load-security-state.js';
import {
  captureTrustedLoadSecurityCommitments,
  cloneLoadSecurityCommitments,
  loadSecurityCommitmentsEqual,
} from './load-security-state.js';
import {
  captureInitialLoadSignerAuthorities,
  InitialLoadSignerAuthority,
} from './initial-load-trust.js';
import { BeeKEM } from './beekem/beekem.js';
import {
  BeeKEMWelcome,
  BeeKEMWelcomeV2,
  PathUpdate,
  PathUpdateV2,
} from './beekem/types.js';
import {
  deserializePathUpdateFromWire,
  deserializePathUpdateV2FromWire,
  serializePathUpdateForWire,
  serializePathUpdateV2ForWire,
} from './path-update-wire.js';
import {
  applyBeeKEMPathUpdateWithEpoch,
  isBeeKEMMessageForDocument,
} from './beekem-path-update-apply.js';
import {
  decodeWelcomeSealedPayload,
  decodeWelcomeSealedPayloadV2,
  encodeWelcomeSealedPayload,
  encodeWelcomeSealedPayloadV2,
} from './welcome-sealed-payload.js';
import {
  deriveDocumentKeyFromRootSecret,
  deriveEpochIdFromRootSecret,
} from './derive-doc-key.js';
import { EPOCH_ID_LENGTH } from './epoch.js';
import { tipsHash, tipsHashToHex, TIPS_HASH_LENGTH } from './tips-hash.js';
import {
  constantTimeHexEquals,
  dedupePeersByPeerId,
  LoadQuorumFailedError,
} from './load-quorum.js';
import {
  SignerAttributedLoadQuorumVote,
  runLoadQuorum,
} from './load-quorum-orchestrator.js';
import { CRDTSnapshotNode } from './snapshot-node.js';
import type { CompactionConfig } from './compaction-config.js';
import { mergeCompactionConfig } from './compaction-config.js';
import { isTransactionalKeychain } from './keychain.js';
import {
  filterDeletableCIDs,
  loadChangeBlock as lazyLoadChangeBlock,
} from './blockstore-gc.js';
import { documentTopic } from './document-topic.js';
import { ACLProvider } from './acl-provider.js';
import { KeychainProvider } from './keychain-provider.js';
import { LoadMessageSerializer } from './load-request-serializer.js';
import { CRDTLoadRequest } from './crdt-load-request.js';
import { Base64 } from 'js-base64';
import { Uint8ArrayList } from 'uint8arraylist';
import { CID } from 'multiformats';
import { UnixFS, unixfs } from '@helia/unixfs';
// libp2p v3 moved the `PubSubBaseProtocol` shim out of `@libp2p/pubsub` (the
// package has been removed). Use the concrete `GossipSub` service interface
// from `@libp2p/gossipsub` instead -- it is what `helia` actually wires up via
// `services.pubsub` and exposes the same publish/subscribe/event surface we
// rely on. `Message` (the pubsub message shape) likewise moved here.
import { TopicValidatorResult } from '@libp2p/gossipsub';
import type {
  GossipSub,
  Message,
  TopicValidatorFn,
} from '@libp2p/gossipsub';
import { EventHandler, PeerId } from '@libp2p/interface';
import { multiaddr } from '@multiformats/multiaddr';
import {
  syncInvitationMessageCompletely,
  withIssuerPinnedInvitationStream,
} from './invitation-catch-up.js';
import {
  MAX_INVITATION_MESSAGE_BYTES,
  assertInvitationBootstrapEpochBinding,
  type InvitationOfferV1,
} from './invitation-wire.js';
import {
  assertInitialInvitationBeeKEMCapacity,
  assertInitialInvitationBeeKEMWelcomeShape,
  assertInitialInvitationCapacityProfile,
  assertInvitationOpaquePayloadCapacity,
  assertProjectedInitialInvitationBootstrapCapacity,
  assertProjectedInitialInvitationWelcomeCapacity,
  INITIAL_INVITATION_MAX_ENCRYPTED_BOOTSTRAP_OVERHEAD_BYTES,
  INITIAL_INVITATION_MAX_MEMBERSHIP_GROWTH_BYTES,
  INITIAL_INVITATION_MAX_SEALED_WELCOME_GROWTH_BYTES,
  INITIAL_INVITATION_MAX_SIGNATURE_BYTES,
  projectInitialInvitationBootstrapCapacity,
} from './invitation-capacity.js';
import {
  assertInitialInvitationHistoryVisibility,
  type HistoryVisibility,
} from './invitation-policy.js';
import {
  assertAcceptedInvitationMembershipTopology,
  createInvitationMutationAdmission,
  InvitationMembershipQueue,
  prepareInitialInvitationMembership,
  type InitialInvitationMembershipState,
} from './invitation-membership.js';
export type { HistoryVisibility } from './invitation-policy.js';

type AuthenticatedBeeKEMPathUpdate<ChangesType, PublicKey> = {
  message: CRDTSyncMessage<ChangesType, PublicKey> & {
    signature: string;
    pathUpdateEpochId: Uint8Array;
  };
  pathUpdate: PathUpdate | PathUpdateV2;
};

type PreparedLocalChange<ChangesType, PublicKey> = {
  hash: string;
  kind: CRDTChangeNodeKind;
  encryptedPayload: Uint8Array;
  updateMessage: CRDTSyncMessage<ChangesType, PublicKey>;
  referencedAncestorCids: readonly string[];
  committed: boolean;
};

type PreparedBeeKEMDelivery = {
  protocol: string;
  payload: Uint8Array;
  label: 'Welcome' | 'PathUpdate';
};

type PreparedKeyUpdateDelivery = {
  payload: Uint8Array;
};

type SyncAuthorizationLease = {
  isCurrent(): boolean;
  advanceAfterWriterMutation(): boolean;
};

type InitialLoadSyncAuthorization<PublicKey> = {
  writerKeys: readonly PublicKey[];
  writerVersion: number;
  /** Internal gate invoked immediately before every live mutation. */
  onStateMutation?: () => void;
  deferredBlockBudget?: InitialLoadDeferredBlockBudget;
  /** Complete strict apply checks before the mutation queue slot is released. */
  finalizeInMutationSlot?: (applied: boolean) => Promise<boolean>;
  /** Convert a post-mutation rejection to terminal retirement in that slot. */
  failInMutationSlot?: (cause: unknown) => void;
};

type InitialLoadDeferredBlockBudget = {
  readonly maxEncryptedBlockBytes: number;
  readonly maxEncryptedAggregateBytes: number;
  readonly maxDecodedBlockBytes: number;
  readonly maxDecodedAggregateBytes: number;
  encryptedBytes: number;
  decodedBytes: number;
  /** Candidate-wide deadline for all deferred blockstore reads. */
  signal: AbortSignal;
  /** Arm the shared deadline lazily when the first deferred read begins. */
  begin(): void;
};

type InitialLoadSignerAuthoritySnapshot<PublicKey> = {
  authorities: readonly InitialLoadSignerAuthority<PublicKey>[];
  writerVersion: number;
};

type BeeKEMReaderRegistration = {
  welcome: BeeKEMWelcome | null;
  pathUpdate?: PathUpdateV2;
  rootSecret?: Uint8Array;
};

type PendingBeeKEMAdd<ChangesType, PublicKey> = {
  readerKemPublicKey?: Uint8Array;
  aclAddState: 'not-needed' | 'started' | 'succeeded';
  readerChanges?: ChangesType;
  registration?: BeeKEMReaderRegistration;
  pathDelivery?: PreparedBeeKEMDelivery;
  welcomeDelivery?: PreparedBeeKEMDelivery;
  preparedReaderChange?: PreparedLocalChange<ChangesType, PublicKey>;
};

type PendingBeeKEMRemoval<ChangesType, PublicKey> = {
  leafIndex: number;
  aclRemoveState: 'started' | 'succeeded';
  readerChanges?: ChangesType;
  pathDelivery?: PreparedBeeKEMDelivery;
  preparedReaderChange?: PreparedLocalChange<ChangesType, PublicKey>;
};

type PendingFounderInitialization<ChangesType> = {
  writerAddState: 'started' | 'succeeded';
  writerChanges?: ChangesType;
  keyAddState: 'not-started' | 'started' | 'succeeded';
};

type PendingWriterAdd<ChangesType, PublicKey> = {
  aclAddState: 'started' | 'succeeded';
  writerChanges?: ChangesType;
  preparedChange?: PreparedLocalChange<ChangesType, PublicKey>;
};

type PendingWriterRemoval<ChangesType, PublicKey, DocumentKey> = {
  authorizedActor: string;
  selfRemoval: boolean;
  aclRemoveState: 'started' | 'succeeded';
  writerChanges?: ChangesType;
  preparedChange?: PreparedLocalChange<ChangesType, PublicKey>;
  keyAddState: 'not-started' | 'started' | 'succeeded';
  previousKey?: [Uint8Array, DocumentKey];
  keychainChanges?: ChangesType;
  keyUpdateDelivery?: PreparedKeyUpdateDelivery;
  publicationState: 'not-started' | 'started' | 'succeeded';
  distributionState: 'not-started' | 'started' | 'succeeded';
};

type BeeKEMWriterAuthoritySnapshot<PublicKey> = {
  source: 'acl' | 'bootstrap';
  writerKeysVersion: number;
  authorities: readonly InitialLoadSignerAuthority<PublicKey>[];
};

type AuthenticatedBeeKEMWelcome<ChangesType, PublicKey> = {
  message: CRDTSyncMessage<ChangesType, PublicKey>;
  writerAuthorities: BeeKEMWriterAuthoritySnapshot<PublicKey>;
};

function snapshotKemKeyPair(keyPair: CryptoKeyPair): CryptoKeyPair {
  if (typeof keyPair !== 'object' || keyPair === null) {
    throw new TypeError('setKemKeyPair: key pair must be an object');
  }
  const publicKey = Object.getOwnPropertyDescriptor(keyPair, 'publicKey');
  const privateKey = Object.getOwnPropertyDescriptor(keyPair, 'privateKey');
  if (
    publicKey === undefined ||
    !Object.prototype.hasOwnProperty.call(publicKey, 'value') ||
    privateKey === undefined ||
    !Object.prototype.hasOwnProperty.call(privateKey, 'value')
  ) {
    throw new TypeError(
      'setKemKeyPair: publicKey and privateKey must be own data properties',
    );
  }
  return {
    publicKey: publicKey.value as CryptoKey,
    privateKey: privateKey.value as CryptoKey,
  };
}

function snapshotExactTuple(
  value: unknown,
  length: number,
  label: string,
): unknown[] {
  let isArray: boolean;
  let prototype: object | null;
  let keys: PropertyKey[];
  try {
    isArray = Array.isArray(value);
    prototype =
      value !== null && typeof value === 'object'
        ? Object.getPrototypeOf(value)
        : null;
    keys =
      value !== null && typeof value === 'object' ? Reflect.ownKeys(value) : [];
  } catch {
    throw new TypeError(`${label} must be a plain dense tuple`);
  }
  if (
    !isArray ||
    prototype !== Array.prototype ||
    keys.length !== length + 1 ||
    !keys.includes('length')
  ) {
    throw new TypeError(`${label} must be a plain dense ${length}-tuple`);
  }
  const result = new Array<unknown>(length);
  for (let index = 0; index < length; index++) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    } catch {
      throw new TypeError(`${label} must contain only own data entries`);
    }
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !('value' in descriptor)
    ) {
      throw new TypeError(`${label} must contain only own data entries`);
    }
    result[index] = descriptor.value;
  }
  return result;
}

/** Opaque, recipient-bound material returned by the invitation join handler. */
export interface InvitationBootstrapBundle {
  welcomeEpochId: Uint8Array;
  sealedWelcome: Uint8Array;
  encryptedBootstrap: Uint8Array;
}

interface InvitationBootstrapCapacityPlan<ChangesType, PublicKey> {
  readonly currentMessage: CRDTSyncMessage<ChangesType, PublicKey>;
  readonly keychainChanges: ChangesType;
  readonly snapshot?: CRDTSnapshotNode<ChangesType, PublicKey>;
  readonly serializedBootstrapBaselineBytes: number;
  readonly welcomeWithoutBeeKEMBytes: number;
}

/**
 * Handler type for local-change (changes made on the current computer) and remote-change (changes made by a remote peer) events.
 *
 * Subscribe functions that match this type signature to track local-change/remote-change events.
 */
export type PeerborneDocumentChangeHandler<DocType, PublicKey> = (
  current: DocType,
  readers: PublicKey[],
  writers: PublicKey[],
  hashes: string[],
) => void;

/**
 * A peerborne "document" represents a single CRDT document.
 *
 * A new peerborne document undergoes the following process when it is first opened:
 * - Connect to the document pubsub topic
 * - Send a load-document request to any peer (and keep trying with different peers if one fails) (`.load()`)
 * - Use load-document response from peer (if any) to update existing document with any new hashes (`.sync()`)
 *
 * A new local change (made on the current computer) causes the following:
 * - The delta between the current document and the new document is calculated
 * - A sync message is constructed and sent to all peers on the document pubsub topic (`.change(...)`)
 *
 * A new remote change (made on a peer's computer) causes the following:
 * - New change hashes are used to update exising document with any new changes (`.sync()`)
 *
 * Any edits made to the document should go through its corresponding PeerborneDocument's
 * `.change(...)` method:
 *
 * @example Automerge usage
 * ```ts
 * // Open a document (Automerge-based peerborne instance).
 * const doc1 = peerborne.doc("/my-doc1-path");
 * await doc1.open();
 *
 * await doc1.change(doc => {
 *   doc.field1 = "new-value";
 * });
 * ```
 *
 * @example Yjs usage
 * ```ts
 * // Open a document (Yjs-based peerborne instance).
 * const doc2 = peerborneYjs.doc("/my-doc2-path");
 * await doc2.open();
 *
 * await doc2.change(doc => {
 *   doc.getMap('data').set('field1', 'new-value');
 * });
 * ```
 * @typeParam DocType The CRDT document type
 * @typeParam ChangesType A block of CRDT change(s)
 * @typeParam ChangeFnType A function for applying changes to a document
 * @typeParam PrivateKey The type of secret key used to identify a user (for writing)
 * @typeParam PublicKey The type of key used to identify a user publicly
 * @typeParam DocumentKey The type of key used to encrypt/decrypt document changes
 */

/**
 * Bound on parallel Helia `blockstore.get(cid)` work in quorum-bound prefetch
 * and ordinary deferred fetch/decrypt/apply. Initial-load deferred apply is
 * serialized so aggregate plaintext accounting cannot be overshot by several
 * concurrent decryptions.
 *
 * A bound is needed because the served `changes` tree can be large
 * under an adversary-shaped response (the agreeing peer voted for the
 * expected frontier but stuffed the tree with many additional CIDs that
 * must still be retrieved to satisfy the post-sync coverage check).
 * Without a cap, the prefetch would issue every fetch in parallel and
 * each fetch holds a libp2p bitswap stream + buffers the retrieved
 * payload via `readUint8Iterable`; for very large responses this can
 * exhaust per-connection stream quotas and pressure memory. The cap is
 * chosen large enough to overlap WAN-latency-bound bitswap fetches and
 * keep the load fast (8 inflight is comfortably more than typical mesh
 * peer counts) but small enough to bound peak resource use on the
 * loader.
 */
const LOAD_BLOCK_MAX_CONCURRENCY = 8;

/**
 * Every deferred change block has the same 16 MiB decoded compatibility limit
 * as a V4 manifest's inline-change payload. The encrypted allowance adds
 * 64 KiB as a wire-compatibility allowance for key IDs, nonces, tags, and
 * provider expansion. AuthProvider has no expansion contract; custom providers
 * that exceed this allowance are rejected symmetrically on send and receive.
 * Initial load additionally applies aggregate encrypted and decoded ceilings
 * across the complete candidate response.
 */
const MAX_DEFERRED_BLOCK_DECODED_BYTES = 16 * 1024 * 1024;
const MAX_DEFERRED_BLOCK_ENCRYPTED_BYTES =
  MAX_DEFERRED_BLOCK_DECODED_BYTES + 64 * 1024;
const MAX_INITIAL_LOAD_DEFERRED_DECODED_BYTES = 16 * 1024 * 1024;
const MAX_INITIAL_LOAD_DEFERRED_ENCRYPTED_BYTES = 32 * 1024 * 1024;
const MAX_INITIAL_LOAD_BLOCK_STREAM_CHUNKS = 65_536;

class _DeferredBlockBudgetExceededError extends RangeError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = '_DeferredBlockBudgetExceededError';
  }
}

/** Maximum decoded signature accepted on JSON wire envelopes. */
const MAX_WIRE_SIGNATURE_BYTES = 4096;
const MAX_WIRE_SIGNATURE_BASE64_LENGTH =
  4 * Math.ceil(MAX_WIRE_SIGNATURE_BYTES / 3);

/**
 * Module-private sentinel thrown by `_sendLoadRequestAndSync` when the
 * quorum frontier binding check fails on a single peer's load response
 * (either the responder omitted `tips` or the served `tips` hashed to a
 * value other than the agreed `winningHashHex`). Caught by the `load()`
 * loop, which records the failure against the responsible peer and
 * proceeds to the NEXT peer in the agreeing cohort.
 *
 * A per-peer error lets `load()` continue through the agreeing cohort. Bind
 * failure can reflect concurrent responder state advance, incomplete block
 * retrieval, inconsistent serialization, protocol violation, or equivocation;
 * none of those responses may reach local state mutation.
 *
 * Public callers never see this type; `load()` catches it internally
 * and only escalates to `LoadQuorumFailedError(reason:
 * 'bind-check-failed-all-agreeing-peers')` once EVERY peer in the
 * narrowed cohort has bind-failed.
 *
 * The historical `advertisedHex` field carries an observed digest when one is
 * available, or a parenthesized diagnostic marker for failures such as a
 * missing attestation or untrusted tuple. The outer loop threads it into the
 * final error's `agreeingPeerBindFailures` map.
 */
class _QuorumBindCheckFailedError extends Error {
  public readonly advertisedHex: string;
  constructor(advertisedHex: string, message: string) {
    super(message);
    this.name = '_QuorumBindCheckFailedError';
    this.advertisedHex = advertisedHex;
  }
}

/**
 * An encrypted, local-first CRDT document managed by a {@link Peerborne}
 * instance.
 *
 * Membership operations journal each ACL/keychain provider call before
 * awaiting it. A completed call can be resumed after a later preparation or
 * delivery failure, but a provider rejection is an ambiguous possible
 * mutation: the document is permanently retired in-process and starts
 * best-effort cleanup. Callers must discard the document and its ACL/keychain
 * provider instances; `close()` is not rollback, and the retirement journal is
 * not durable across process restart. An initial load is also
 * retired if it fails after its first live mutation, because CRDT, snapshot,
 * ACL, and keychain providers do not share a cross-provider rollback contract.
 */
export class PeerborneDocument<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
> {
  /**
   * CORE STATE ===============================================================
   */

  // Only store/cache the full automerge document.
  private _document: DocType;
  get document(): DocType {
    return this._document;
  }

  // Document readers ACL.
  private _readers;

  // Document writers ACL.
  private _writers;

  // Cached snapshot of `_writers.users()` for hot-path signature verification.
  // Document-scoped (not per-DAG-node): every signature check needs the current
  // trusted writer set, so a single lazy cache is sufficient. Invalidated by
  // bumping `_writerKeysVersion` whenever `_writers` is mutated via
  // `_mergeWriters` / `_addWriter` / `_removeWriter`. All ACL mutations must
  // go through those helpers. The version counter is what makes invalidation
  // race-safe: `_getWriterKeys` captures the version before awaiting and only
  // commits the result if the version is still current, so an in-flight fetch
  // that races with an invalidation cannot overwrite the new null state with
  // a stale list (which could otherwise admit signatures from a revoked writer).
  // Typed `ReadonlyArray` so an accidental mutation by an internal caller is
  // a type error rather than a silent cache corruption that would affect
  // later signature verification.
  private _cachedWriterKeys: ReadonlyArray<PublicKey> | null = null;
  private _writerKeysVersion = 0;
  // Counter of in-flight `_writers` mutations (add/remove/merge). Some ACL
  // implementations (e.g. UCANACL.remove, YjsACL.remove) mutate their
  // backing state *before* their returned Promise resolves, so during the
  // mutation window `_writers.users()` may already reflect the new state
  // even though the helper has not yet reached its post-await invalidation
  // line. While this counter is nonzero, `_getWriterKeys` bypasses the
  // cache entirely and always re-fetches, so a signature check that races
  // a mutation cannot observe the stale pre-mutation list.
  private _writerMutationsInFlight = 0;

  // List of document encryption keys. Lower index numbers mean more recent.
  // Since the document is created from change history, all keys are needed.
  private _keychain;

  // Controls which document-key epochs peers supply during onboarding/load.
  private _historyVisibility: HistoryVisibility = 'current_only';

  // Tracks the epoch at which this node was invited to the document. It is a
  // local monotonic audit/ordering anchor; ordinary load cannot safely use a
  // responder's local value as the requester's `since_invited` boundary and
  // therefore sends current-only until the wire authenticates a
  // requester-specific boundary. Set after an authenticated Welcome and left
  // `undefined` for the founding member.
  private _invitationEpoch: Uint8Array | undefined;

  // Bound serialized Welcome and PathUpdate messages before parsing or
  // signature verification.
  private static readonly _MAX_BEEKEM_WIRE_PAYLOAD_BYTES = 10 * 1024 * 1024;

  // Recipient-side ECIES (P-256 ECDH) key pair for opening BeeKEM Welcome
  // sealed payloads. The inviter sends `eciesSealed` -- the keychain delta
  // encrypted to this public key (see `_prepareBeeKEMWelcome`); the recipient
  // opens it with the matching private key (see
  // `_evaluateAndApplyBeeKEMWelcome`). When `undefined`, sealed Welcomes
  // addressed to us cannot be opened and are dropped. An ordinary load is
  // encrypted under the unknown document key and cannot repair this; the
  // recipient must reinstall the intended KEM key and receive a fresh signed,
  // identity+KEM-bound Welcome. The
  // application is responsible for plumbing in a stable KEM key pair via
  // `setKemKeyPair` and sharing the matching raw public key with inviters
  // out-of-band so they can pass it to `addReader`.
  private _kemKeyPair: CryptoKeyPair | undefined;

  // Cached raw SEC1-uncompressed bytes for `_kemKeyPair.publicKey`,
  // populated eagerly inside `setKemKeyPair` so the receive path
  // (`_evaluateAndApplyBeeKEMWelcome`) never has to await an `exportKey`
  // call -- and so a non-exportable public key surfaces as a clear
  // error at installation time rather than as a generic WebCrypto
  // exception inside the Welcome handler.
  private _kemPublicKeyRaw: Uint8Array | undefined;

  /**
   * Install the recipient-side ECDH (P-256) key pair used to open
   * incoming BeeKEM Welcome sealed payloads. The application is
   * responsible for persisting and re-supplying this key pair across
   * sessions; the matching raw public key (see
   * `getKemPublicKeyRaw`) must be communicated out-of-band to any
   * writer who will invite this user, so they can pass it to
   * `addReader(reader, readerKemPublicKey)`.
   *
   * Idempotent: calling with the same key pair more than once is fine.
   * Pass `undefined` to clear only before BeeKEM membership setup begins. Once
   * ratchet or pending membership state exists, clearing or replacing the key
   * requires a future authenticated rotation protocol and is rejected;
   * reinstalling the same public-key identity remains allowed.
   *
   * Validation: the key pair MUST be an ECDH P-256 pair, and the
   * private key MUST have `'deriveBits'` in its key usages so
   * `eciesOpen` can perform the ECDH step. The public key MUST be
   * raw-exportable (the inviter-side flow ships those bytes as the
   * `welcomeRecipientKemPublicKey` field). Mismatches are rejected
   * here with a descriptive error rather than silently accepted and
   * surfaced as a generic WebCrypto failure later in the Welcome
   * receive path.
   *
   * Async because it eagerly exports the public key to raw bytes via
   * `crypto.subtle.exportKey` and caches them for the receive path.
   */
  public async setKemKeyPair(
    keyPair: CryptoKeyPair | undefined,
  ): Promise<void> {
    // Snapshot synchronously before queueing. A caller-owned CryptoKeyPair is
    // an ordinary mutable record even though its CryptoKey handles are not.
    const snapshot = keyPair && snapshotKemKeyPair(keyPair);
    return this._runInMutationQueue(() =>
      this._setKemKeyPairUnlocked(snapshot),
    );
  }

  private async _setKemKeyPairUnlocked(
    stableKeyPair: CryptoKeyPair | undefined,
  ): Promise<void> {
    this._throwIfSecurityProviderMutationFailed();
    let rawPublic: Uint8Array | undefined;
    if (stableKeyPair !== undefined) {
      if (!isTransactionalKeychain(this._keychain)) {
        throw new TypeError(
          'setKemKeyPair: BeeKEM requires a TransactionalKeychain that ' +
            'implements prepareEpochKey and prepareMerge',
        );
      }
      // Capture each caller-controlled pair field exactly once before the
      // first await. The object itself is an ordinary mutable dictionary even
      // though genuine CryptoKey values are immutable host objects.
      rawPublic = copyUnsharedUint8Array(
        await validateAndExportKemKeyPair(stableKeyPair),
        ECIES_P256_PUBLIC_KEY_LENGTH,
        ECIES_P256_PUBLIC_KEY_LENGTH,
        'setKemKeyPair public key',
      );
      this._throwIfSecurityProviderMutationFailed();
    }

    await this._runBeeKEMTransition(async () => {
      this._throwIfSecurityProviderMutationFailed();
      const hasRatchetState =
        this._beekemInitialized ||
        this._beekem !== null ||
        this._beekemInitPromise !== null ||
        (this._pendingBeeKEMAdds?.size ?? 0) > 0 ||
        (this._pendingBeeKEMRemovals?.size ?? 0) > 0 ||
        this._readerKemPublicKeys.size > 0 ||
        this._readerLeafIndices.size > 0;

      if (stableKeyPair === undefined || rawPublic === undefined) {
        if (hasRatchetState) {
          throw new Error(
            `setKemKeyPair: cannot clear the KEM key while BeeKEM membership ` +
              `state exists; authenticated KEM rotation is not supported`,
          );
        }
        this._kemKeyPair = undefined;
        this._kemPublicKeyRaw = undefined;
        this.swarm.unregisterWelcomeRecipient?.(this.documentPath, this);
        return;
      }

      if (
        hasRatchetState &&
        (this._kemPublicKeyRaw === undefined ||
          !this._constantTimeEquals(this._kemPublicKeyRaw, rawPublic))
      ) {
        throw new Error(
          `setKemKeyPair: cannot replace the active KEM key while BeeKEM ` +
            `membership state exists; authenticated KEM rotation is not supported`,
        );
      }

      // Register before exposing the key locally so a duplicate document path
      // fails without leaving an unreachable half-installed invitation key.
      this.swarm.registerWelcomeRecipient?.(this.documentPath, this);
      this._kemKeyPair = stableKeyPair;
      this._kemPublicKeyRaw = rawPublic;
    });
  }

  /**
   * Returns the raw SEC1-uncompressed bytes (65 bytes) of the
   * installed ECDH public key, or `undefined` if no key pair has been
   * set via `setKemKeyPair`. The bytes are what inviters pass to
   * `addReader(reader, readerKemPublicKey)`.
   *
   * The raw bytes are cached on `setKemKeyPair`, so this is a
   * synchronous lookup. A defensive copy of the cached `Uint8Array` is
   * returned so callers cannot accidentally mutate the document's
   * internal state (e.g. `raw[0] = ...`), which would otherwise cause
   * hard-to-debug Welcome drops/mismatches on the receive path.
   */
  public getKemPublicKeyRaw(): Uint8Array | undefined {
    return this._kemPublicKeyRaw && new Uint8Array(this._kemPublicKeyRaw);
  }

  /**
   * Create a signed public offer for an online, distinct-identity join.
   * The offer contains only public metadata and is safe to encode in a URL
   * fragment. The inviter must remain online until the recipient accepts it.
   */
  public async createInvitation(
    options: CreateInvitationOptions,
  ): Promise<InvitationOfferV1> {
    return this.swarm.createInvitationForDocument(this, options);
  }

  /** @internal Validate the deliberately narrow initial membership topology. */
  public async assertCanCreateInitialInvitation(): Promise<void> {
    this._assertInitialInvitationCapacityProfile();
    await this._ensureCurrentUserCanWrite();
    if (!this._createdLocally) {
      throw new Error(
        `Invitation creation for ${this.documentPath} is limited to the ` +
          'founder process that created the document',
      );
    }
    const [readers, writers] = await Promise.all([
      this._readers.users(),
      this._writers.users(),
    ]);
    if (writers.length !== 1) {
      throw new Error(
        `Invitation creation for ${this.documentPath} requires exactly one ` +
          'founder writer before onboarding',
      );
    }
    if (readers.length > 0) {
      throw new Error(
        `Invitation creation for ${this.documentPath} requires an empty ` +
          'reader slot; the initial release supports one active collaborator',
      );
    }
    assertInitialInvitationBeeKEMCapacity(
      this._beekem?.memberCount,
      false,
      this.documentPath,
    );
  }

  private _assertInitialInvitationCapacityProfile(): void {
    assertInitialInvitationCapacityProfile({
      crdtProvider: this._crdtProvider,
      aclProvider: this._aclProvider,
      keychainProvider: this._keychainProvider,
      changesSerializer: this._changesSerializer,
      syncMessageSerializer: this._syncMessageSerializer,
      authProvider: this._authProvider,
      privateKey: this._userKey,
      publicKey: this._userPublicKey,
    });
  }

  // BeeKEM ratchet-tree state for cryptographic reader revocation.
  //
  // `removeReader` blanks the removed reader's BeeKEM leaf, re-keys the
  // path, and broadcasts the next parent-tree-bound v2 `PathUpdate`.
  // Surviving readers feed the update into `processPathUpdate` and
  // re-derive the document encryption key from the fresh root secret
  // (see `derive-doc-key.ts`). The removed reader's leaf is blanked,
  // so they cannot recompute the root secret -- this closes the
  // revocation-latency gap of the previous "encrypt the new key under
  // the old key" rotation scheme.
  //
  // The tree is initialized in one of two ways:
  //
  //  1. **Founder**: a writer who creates a new document calls
  //     `_initializeBeeKEMAsFounder()` (driven by `addReader` the first
  //     time it runs on a fresh document, or eagerly by a future
  //     "create document" API). This seeds leaf 0 with the local KEM
  //     key pair from `setKemKeyPair`.
  //
  //  2. **Joiner**: a peer that receives an `eciesSealed` BeeKEM
  //     Welcome from an inviting writer calls `processWelcome` on a
  //     fresh `BeeKEM` instance, populating their leaf and the path
  //     keys from the inviter's tree state.
  //
  // The PathUpdate receive handler MUST NOT initialize a fresh founder
  // tree on a peer that has not gone through either path: a
  // freshly-initialized tree would produce a different root secret
  // than the writer's, and the epoch-ID mismatch gate would drop the
  // PathUpdate anyway. Surface that as a clean drop-with-warning; recovery
  // requires persisted current ratchet state or an authenticated remove/rejoin.
  private _beekem: BeeKEM | null = null;
  private _beekemInitPromise: Promise<BeeKEM> | null = null;
  // Local membership changes, ACL-bearing remote sync, and invitation
  // bootstrap construction share one queue. This keeps the ACL topology,
  // BeeKEM tree, keychain, and signed bootstrap attestation coherent.
  // One FIFO freezes every state writer while an invitation sizes and builds
  // its bootstrap. Internal helpers called from an admitted operation remain
  // unlocked to avoid reentrant waits on the same queue.
  private _mutationQueue = new InvitationMembershipQueue();
  // `true` iff `_beekem` was set via `_initializeBeeKEMAsFounder` or
  // `processWelcome`. Distinguishes a legitimate local BeeKEM state
  // from "we have never received a Welcome and we are not the
  // founder", which is the gate `handleBeeKEMPathUpdateRequestData`
  // uses to drop PathUpdates that arrive before bootstrap.
  private _beekemInitialized = false;
  // Monotonic in-process creation provenance. Set only after the complete
  // founder ACL/key/change initialization succeeds under the BeeKEM mutex.
  // Loaded or invited replicas never set it; a restarted founder must restore
  // ratchet state rather than infer founder authority from document hashes.
  private _localFounderEstablished = false;
  // Record each founder provider step before awaiting it and retain the first
  // completed writer-ACL delta across an in-process retry. ACL providers may
  // return an empty delta when asked to add an already-present founder; a
  // started-but-not-completed step is therefore terminally ambiguous rather
  // than safe to repeat.
  private _pendingFounderInitialization?: PendingFounderInitialization<ChangesType>;
  // Terminal in-process retirement marker. ACL/keychain provider ambiguity and
  // an incomplete initial load after its first live mutation
  // both make this instance unsafe to reuse.
  private _securityProviderMutationFailure?: Error;
  private _pendingWriterAdds = new Map<
    string,
    PendingWriterAdd<ChangesType, PublicKey>
  >();
  private _pendingWriterRemovals = new Map<
    string,
    PendingWriterRemoval<ChangesType, PublicKey, DocumentKey>
  >();

  // pubkey (serialized) -> BeeKEM leaf index, populated by local `addReader`
  // registrations so `removeReader` can look up the leaf to blank.
  // **Fast-path cache only**: `removeReader` falls back to a BeeKEM
  // tree scan (`BeeKEM.findLeafByPublicKey`) on cache miss, so explicitly
  // evicting this fast-path entry does not block revocation while the same
  // live instance still retains the reader's KEM public key (see
  // `_readerKemPublicKeys`).
  // Processing a Welcome reconstructs the anonymous ratchet tree but does not
  // reconstruct identity-to-KEM/leaf bindings for pre-existing members. A
  // joined writer can therefore remove only readers it registered locally;
  // broader binding persistence/state transfer remains unimplemented.
  private _readerLeafIndices = new Map<string, number>();

  // pubkey (serialized identity) -> raw SEC1-uncompressed P-256 ECDH
  // public key bytes (the reader's KEM public key as passed to local
  // `addReader`). Used by `removeReader` as the lookup key when the
  // `_readerLeafIndices` fast-path cache misses: we know the
  // identity but need the KEM key to query the BeeKEM tree via
  // `BeeKEM.findLeafByPublicKey`. Persistence and Welcome-side reconstruction
  // are not implemented, so a restart or joined writer lacks bindings for
  // pre-existing readers and `removeReader` surfaces the gap with a clear
  // error.
  private _readerKemPublicKeys = new Map<string, Uint8Array>();

  // Serializes every document-level BeeKEM transition, including local
  // founder/add/remove operations, inbound Welcome swaps, PathUpdate ratchets,
  // and the matching keychain commit. BeeKEM's own lock is per instance and
  // cannot protect a document while a Welcome replaces that instance.
  private _beekemTransitionTail: Promise<void> = Promise.resolve();
  private _beekemTransitionsPending = 0;
  private _beekemRemoteTransitionsPending = 0;
  private _beekemRemoteIngressPending = 0;
  private static readonly _MAX_PENDING_REMOTE_BEEKEM_INGRESS = 4;
  private static readonly _MAX_PENDING_REMOTE_BEEKEM_TRANSITIONS = 3;
  private _beekemFanoutTail: Promise<void> = Promise.resolve();
  // Writer ACL/key-rotation retries need their own serialization boundary.
  // Keeping network publication off the BeeKEM transition mutex preserves
  // priority for inbound Welcome/PathUpdate and urgent reader revocation.
  private _writerMembershipTail: Promise<void> = Promise.resolve();
  private static readonly _MEMBERSHIP_DELIVERY_TIMEOUT_MS = 5_000;
  private static readonly _MAX_CONCURRENT_MEMBERSHIP_DELIVERIES = 8;

  // BeeKEM leaf node index -> the `BeeKEMWelcome` produced when that
  // leaf was first registered via `_registerBeeKEMReader`. Used by
  // `addReader` to re-emit a Welcome when a previous invitation was
  // dropped: re-invoking `addReader(reader, kemPub)` for an existing
  // reader is now a re-send, not a silent no-op.
  //
  // Cleared when the leaf is blanked via `removeReader`, so a
  // recipient that was revoked cannot later re-derive the original
  // Welcome (which would re-deliver the keychain delta at the leaf's
  // original epoch).
  //
  // In-memory only; on writer restart this map is empty. A normal encrypted
  // load cannot synthesize the missing tree state; safe recovery requires
  // persisted current ratchet state or an authenticated remove/rejoin.
  private _beekemWelcomeByLeaf = new Map<number, BeeKEMWelcome>();
  // Exact in-memory transition records retained across retryable local
  // preparation failures. They prevent an ACL provider that already mutated
  // from causing a retry to allocate a second BeeKEM generation or lose the
  // original ACL delta. BeeKEM/keychain persistence remains a documented
  // process-restart limitation.
  private _pendingBeeKEMAdds = new Map<
    string,
    PendingBeeKEMAdd<ChangesType, PublicKey>
  >();
  private _pendingBeeKEMRemovals = new Map<
    string,
    PendingBeeKEMRemoval<ChangesType, PublicKey>
  >();
  // Per-deserialized-message trust and ACL-version lease used only by the
  // authenticated load path. WeakMap scoping keeps concurrent loads isolated
  // without exposing a public API through which callers could supply an
  // authorization token or arbitrary snapshot authorities.
  private _initialLoadSyncAuthorizations = new WeakMap<
    object,
    InitialLoadSyncAuthorization<PublicKey>
  >();
  private _canonicalSyncMessages = new WeakSet<object>();

  /**
   * Set the history visibility for this document.
   * This filters distributed epoch keys; it does not redact retained CRDT
   * operations or provide a historical-content confidentiality boundary.
   */
  public set historyVisibility(value: HistoryVisibility) {
    this._historyVisibility = value;
  }

  public get historyVisibility(): HistoryVisibility {
    return this._historyVisibility;
  }

  /**
   * /CORE STATE ==============================================================
   */

  // Last sync message (for populating load requests).
  private _lastSyncMessage?: CRDTSyncMessage<ChangesType, PublicKey>;

  // Set of already-merged change blocks.
  private _hashes = new Set<string>();

  // Set of CIDs that have been seen as a `children` key in any sync tree we
  // have processed (locally created or remotely received) -- i.e. every CID
  // some node references as a parent / cross-link target. These are
  // *referenced ancestors*: by definition they are NOT heads of the local
  // DAG, because at least one node points to them as a predecessor.
  //
  // `_currentFrontier()` returns `_hashes \ _referencedAncestors` -- the set
  // of CIDs that no node we've ever seen has referenced. That is the actual
  // "frontier" / "heads" of the merged-changes DAG, which is what the
  // initial-load quorum tip-set advertisement is supposed to attest to.
  //
  // Critically, this set converges across honest peers: two peers with the
  // same logical state but different sync histories (e.g. one loaded from a
  // snapshot, the other has been merging changes since founding) will have
  // *different* `_hashes` cardinality but the same head set, hence the same
  // `_hashes \ _referencedAncestors`. Drawing the quorum probe from
  // `_hashes` alone (the prior buggy implementation) would have made the
  // probe pessimistically diverge on irrelevant sync history.
  //
  // Populated in:
  //   - `_makeChange()`: every newly-attached `changeNode.children` key
  //     is recorded -- the new change references those parents.
  //   - `_syncDocumentChanges()`: every received sync tree is walked once
  //     and its `children` keys are recorded -- the receiver now knows the
  //     same parent relationships the sender did.
  //
  // Snapshot boundaries: when a snapshot is applied, `lastChangeNodeCID` is
  // added to `_hashes` as a sentinel for dedup, but its ancestor chain is
  // pruned -- those ancestors are not added to `_referencedAncestors`,
  // which is correct: the snapshot boundary IS the local "oldest" head
  // from the loader's view of the DAG.
  private _referencedAncestors = new Set<string>();

  // Bounded list of recently-known change CIDs paired with their node kind.
  // Used by `_makeChange()` to attach Merkle-CRDT cross-links (paper §VI.B.e)
  // in addition to the primary parent link. Cross-links improve consistency
  // and availability when peers have partial views of the DAG: a peer that
  // missed an earlier message can still discover and fetch the corresponding
  // block via a later change that references it.
  //
  // Populated by both local changes (in `_makeChange`) and remote-applied
  // changes (in `_syncDocumentChanges`), since cross-linking to a freshly-
  // received remote tip helps third peers that haven't yet received it.
  //
  // Kept small (`MAX_RECENT_TIPS`) to bound per-message overhead. Insertion-
  // ordered so the oldest entry is at index 0 and the newest at the end;
  // eviction uses `Array.prototype.shift()` (O(n) on n=`MAX_RECENT_TIPS`,
  // which is a small constant -- effectively O(1) in practice).
  private _recentTips: RecentTip[] = [];

  // Compaction state.
  private _compactionConfig: CompactionConfig;
  private _latestSnapshot?: CRDTSnapshotNode<ChangesType, PublicKey>;
  private _changesSinceSnapshot = 0;
  private _compactionInProgress = false;
  private _snapshotUnsupported = false;
  // Counts only document-kind changes (excludes ACL reader/writer changes).
  // Used by _maybeCompact() for the minChangesBeforeSnapshot threshold.
  // Incremented for both local changes (in _makeChange) and remote changes
  // (in _syncDocumentChanges). Compaction triggers from both paths, so relay-only
  // nodes that never make local changes will still compact via remote change processing.
  private _documentChangeCount = 0;

  // Handler for listening for sync messages on the document topic. Is `undefined` until
  // the document is `.open()`-ed.
  private _pubsubHandler: EventHandler<CustomEvent<Message>> | undefined;

  // Whether this instance has successfully subscribed to the pubsub topic.
  // Used in close() to avoid unsubscribing when open() failed before subscribing,
  // which would break other instances listening on the same topic.
  private _subscribed = false;

  // Exact validator installed by this instance. Cleanup compares by identity
  // so a stale/failed document cannot delete another instance's validator.
  private _topicValidator: TopicValidatorFn | undefined;

  // Set only after a signed invitation bootstrap has been fully verified and
  // applied. The following open() activates handlers without falling through
  // the ambiguous network-load/new-document branch.
  private _invitationBootstrapReady = false;

  // Explicit creation provenance for BeeKEM founder initialization. Change
  // count is not a valid proxy because open() replicates the founder-writer
  // ACL before the first invitation is created.
  private _createdLocally = false;

  // Cached pubsub topic string. Initialized in constructor via _computeTopic()
  // so that callers that invoke _makeChange() before open() (e.g. via load())
  // publish to a valid topic. open() recomputes this with the configured prefix.
  private _topic: string;

  // Transaction state for batching multiple changes atomically.
  private _pendingChangeFns: ChangeFnType[] = [];
  private _inTransaction = false;
  private _committing = false;

  // Handlers registered by users of `PeerborneDocument` that fire on remote changes.
  private _remoteHandlers: {
    [id: string]: PeerborneDocumentChangeHandler<DocType, PublicKey>;
  } = {};

  // Handlers registered by users of `PeerborneDocument` that fire on local changes.
  private _localHandlers: {
    [id: string]: PeerborneDocumentChangeHandler<DocType, PublicKey>;
  } = {};

  public get libp2p(): Libp2p {
    return this.swarm.heliaNode.libp2p;
  }

  private heliaFs: UnixFS;

  constructor(
    /**
     * Peerborne swarm that this document belongs to.
     */
    public readonly swarm: Peerborne<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >,

    /**
     * Path of the document.
     */
    public readonly documentPath: string,

    /**
     * Private key identifying the current user.
     */
    private readonly _userKey: PrivateKey,

    /**
     * Private key identifying the current user.
     */
    private readonly _userPublicKey: PublicKey,

    /**
     * CRDTProvider handles reading/writing CRDT document data and metadata.
     */
    private readonly _crdtProvider: CRDTProvider<
      DocType,
      ChangesType,
      ChangeFnType
    >,

    /**
     * AuthProvider handles signing/verification and encryption/decryption.
     */
    private readonly _authProvider: AuthProvider<
      PrivateKey,
      PublicKey,
      DocumentKey
    >,

    /**
     * ACLProvider handles read/write ACL operations.
     */
    private readonly _aclProvider: ACLProvider<ChangesType, PublicKey>,

    /**
     * KeychainProvider handles read/write ACL operations.
     */
    private readonly _keychainProvider: KeychainProvider<
      ChangesType,
      DocumentKey
    >,

    /**
     * ChangesSerializer is responsible for serializing/deserializing CRDTChangeBlocks.
     */
    private readonly _changesSerializer: ChangesSerializer<ChangesType>,

    /**
     * SyncMessageSerializer is responsible for serializing/deserializing CRDTSyncMessages.
     */
    private readonly _syncMessageSerializer: SyncMessageSerializer<
      ChangesType,
      PublicKey
    >,

    /**
     * LoadMessageSerializer is responsible for serializing/deserializing CRDTLoadMessages.
     */
    private readonly _loadMessageSerializer: LoadMessageSerializer,
  ) {
    this.heliaFs = unixfs(this.swarm.heliaNode);

    this._document = this._crdtProvider.newDocument();
    this._readers = this._aclProvider.initialize();
    this._writers = this._aclProvider.initialize();
    this._keychain = this._keychainProvider.initialize();
    this._compactionConfig = mergeCompactionConfig(
      this.swarm.config?.compaction,
    );

    // Provide a valid default topic so that _makeChange() works even before
    // open() is called (e.g. when load() triggers a change). open() will
    // recompute this with the configured prefix.
    this._topic = this._computeTopic();
  }

  // Helpers ------------------------------------------------------------------

  /**
   * Computes the pubsub topic for this document by applying the configured
   * prefix to the document path. Called once in open() to populate the
   * cached _topic field.
   */
  private _computeTopic(): string {
    const prefix = this.swarm.config?.pubsubDocumentPrefix;
    return prefix !== undefined
      ? documentTopic(this.documentPath, prefix)
      : documentTopic(this.documentPath);
  }

  private async _shuffledPeers() {
    const connected =
      this.swarm.heliaNode.libp2p
        .getConnections()
        ?.map((connection) => connection.remoteAddr) ?? [];
    const peers = Array.from(
      new Map(connected.map((peer) => [peer.toString(), peer])).values(),
    );
    if (peers.length === 0) {
      return peers;
    }

    // Shuffle peer array.
    const shuffledPeers = [...peers];
    shuffleArray(shuffledPeers);
    return shuffledPeers;
  }

  private async _decryptBlock(
    blockKeyID: Uint8Array,
    nonce: Uint8Array,
    data: Uint8Array,
  ) {
    try {
      const key = this._keychain.getKey(blockKeyID);
      if (key) {
        // Await inside the try so asynchronous AEAD failures are converted to
        // an ordinary decryption miss instead of escaping as an unhandled
        // rejection from event-driven receive paths.
        return await this._authProvider.decrypt(data, key, nonce);
      } else {
        console.warn(`Failed to find a document key for ${this.documentPath}`);
      }
    } catch {
      console.warn(`Failed to decrypt block for ${this.documentPath}`);
    }
  }

  private async _prefetchInitialLoadBlock(
    hash: CID,
    signal: AbortSignal,
    maxEncryptedBlockBytes: number,
    accountEncryptedBytes: (byteLength: number) => void,
  ): Promise<void> {
    let blockBytes = 0;
    let chunkCount = 0;
    for await (const chunk of this.swarm.heliaNode.blockstore.get(hash, {
      signal,
    })) {
      chunkCount++;
      if (chunkCount > MAX_INITIAL_LOAD_BLOCK_STREAM_CHUNKS) {
        throw new _DeferredBlockBudgetExceededError(
          `Initial-load deferred block exceeded ${MAX_INITIAL_LOAD_BLOCK_STREAM_CHUNKS} chunks`,
        );
      }
      if (chunk.length === 0) continue;
      const nextBlockBytes = blockBytes + chunk.length;
      if (nextBlockBytes > maxEncryptedBlockBytes) {
        throw new _DeferredBlockBudgetExceededError(
          `Initial-load deferred block exceeded ${maxEncryptedBlockBytes} encrypted bytes`,
        );
      }
      accountEncryptedBytes(chunk.length);
      blockBytes = nextBlockBytes;
    }
  }

  private async *_accountInitialLoadEncryptedBlockBytes(
    source: Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
    budget: InitialLoadDeferredBlockBudget,
  ): AsyncGenerator<Uint8Array> {
    for await (const chunk of source) {
      if (budget.signal.aborted) throw budget.signal.reason;
      const nextEncryptedBytes = budget.encryptedBytes + chunk.byteLength;
      if (nextEncryptedBytes > budget.maxEncryptedAggregateBytes) {
        throw new _DeferredBlockBudgetExceededError(
          `Initial-load deferred blocks exceeded ${budget.maxEncryptedAggregateBytes} aggregate encrypted bytes`,
        );
      }
      budget.encryptedBytes = nextEncryptedBytes;
      yield chunk;
    }
    if (budget.signal.aborted) throw budget.signal.reason;
  }

  private async _getBlock(
    hash: CID,
    initialLoadBudget?: InitialLoadDeferredBlockBudget,
  ): Promise<ChangesType> {
    // Helia v6 / interface-blockstore v6 changed `Blockstore#get(cid)` to
    // return an `AwaitGenerator<Uint8Array>` (a generator of byte chunks)
    // rather than a single `Uint8Array`. Consume the generator into a
    // contiguous buffer here before slicing the encryption header off.
    // Compatibility limit: all sync paths reject deferred blocks larger than
    // 16 MiB decoded (or 16 MiB + 64 KiB encrypted). Initial load may impose a
    // lower per-block cap and also tracks aggregate bytes across its candidate.
    const maxEncryptedBlockBytes =
      initialLoadBudget?.maxEncryptedBlockBytes ??
      MAX_DEFERRED_BLOCK_ENCRYPTED_BYTES;
    let block: Uint8Array;
    try {
      if (initialLoadBudget?.signal.aborted) {
        throw initialLoadBudget.signal.reason;
      }
      initialLoadBudget?.begin();
      if (initialLoadBudget?.signal.aborted) {
        throw initialLoadBudget.signal.reason;
      }
      const source =
        initialLoadBudget === undefined
          ? this.swarm.heliaNode.blockstore.get(hash)
          : this.swarm.heliaNode.blockstore.get(hash, {
              signal: initialLoadBudget.signal,
            });
      block = await readUint8Iterable(
        initialLoadBudget === undefined
          ? source
          : this._accountInitialLoadEncryptedBlockBytes(
              source,
              initialLoadBudget,
            ),
        maxEncryptedBlockBytes,
      );
    } catch (cause) {
      if (cause instanceof _DeferredBlockBudgetExceededError) {
        throw cause;
      }
      if (cause instanceof RangeError) {
        throw new _DeferredBlockBudgetExceededError(
          `Deferred change block exceeded ${maxEncryptedBlockBytes} encrypted bytes`,
          { cause },
        );
      }
      throw cause;
    }
    if (initialLoadBudget?.signal.aborted) {
      throw initialLoadBudget.signal.reason;
    }
    const headerLength =
      this._keychainProvider.keyIDLength + this._authProvider.nonceBits;
    if (block.length <= headerLength) {
      throw new Error(`Encrypted block has an incomplete header (CID: ${hash})`);
    }
    const blockKeyID = block.slice(0, this._keychainProvider.keyIDLength);
    const blockNonce = block.slice(
      this._keychainProvider.keyIDLength,
      headerLength,
    );
    const blockData = block.slice(headerLength);
    const content = await this._decryptBlock(blockKeyID, blockNonce, blockData);
    if (initialLoadBudget?.signal.aborted) {
      throw initialLoadBudget.signal.reason;
    }
    if (!content) {
      throw new Error(`Failed to decrypt block (CID: ${hash})`);
    }
    const maxDecodedBlockBytes =
      initialLoadBudget?.maxDecodedBlockBytes ?? MAX_DEFERRED_BLOCK_DECODED_BYTES;
    if (content.byteLength > maxDecodedBlockBytes) {
      throw new _DeferredBlockBudgetExceededError(
        `Deferred change block exceeded ${maxDecodedBlockBytes} decoded bytes`,
      );
    }
    if (initialLoadBudget !== undefined) {
      const nextDecodedBytes =
        initialLoadBudget.decodedBytes + content.byteLength;
      if (nextDecodedBytes > initialLoadBudget.maxDecodedAggregateBytes) {
        throw new _DeferredBlockBudgetExceededError(
          `Initial-load deferred blocks exceeded ${initialLoadBudget.maxDecodedAggregateBytes} aggregate decoded bytes`,
        );
      }
      initialLoadBudget.decodedBytes = nextDecodedBytes;
    }
    return this._changesSerializer.deserializeChanges(content);
  }

  private async _putBlock(
    block: ChangesType,
    encryptionKey?: readonly [Uint8Array, DocumentKey],
  ): Promise<string> {
    const [documentKeyID, documentKey] =
      encryptionKey ?? (await this._keychain.current());
    if (!documentKey) {
      throw new Error(`Document ${this.documentPath} has an empty keychain!`);
    }
    const content = this._changesSerializer.serializeChanges(block);
    if (content.byteLength > MAX_DEFERRED_BLOCK_DECODED_BYTES) {
      throw new RangeError(
        `Deferred change block exceeded ${MAX_DEFERRED_BLOCK_DECODED_BYTES} decoded bytes`,
      );
    }
    const { nonce, data } = await this._authProvider.encrypt(
      content,
      documentKey,
    );
    if (!nonce) {
      throw new Error(`Failed to encrypt change block! Nonce cannot be empty`);
    }
    const encryptedBlockLength =
      documentKeyID.byteLength + nonce.byteLength + data.byteLength;
    if (encryptedBlockLength > MAX_DEFERRED_BLOCK_ENCRYPTED_BYTES) {
      throw new RangeError(
        `Deferred change block exceeded ${MAX_DEFERRED_BLOCK_ENCRYPTED_BYTES} encrypted bytes; custom AuthProvider expansion beyond the 64 KiB wire allowance is unsupported`,
      );
    }
    const blockData = concatUint8Arrays(documentKeyID, nonce, data);
    const newFileResult = await this.heliaFs.addBytes(blockData);
    return newFileResult.toString();
  }

  /**
   * Walk the remote sync tree and return entries that are new relative to
   * `localHashes` / `localRootId`. Delegates to the pure `mergeRemoteSyncTree`
   * helper, which also performs per-message dedup so a cross-link CID that
   * coincides with an inline ancestor in the same sync tree is not applied
   * (or fetched + applied) twice -- see paper §VI.B.e.
   */
  private async _mergeSyncTree(
    remoteRootId: string | undefined,
    remoteRoot: CRDTChangeNode<ChangesType>,

    localRootId: string | undefined,
    localHashes: Set<string>,
  ): Promise<[string, CRDTChangeNodeKind, ChangesType | undefined][]> {
    return mergeRemoteSyncTree<ChangesType>(
      remoteRootId,
      remoteRoot,
      localRootId,
      localHashes,
    );
  }

  private async _fireRemoteUpdateHandlers(hashes: string[]) {
    for (const handler of Object.values(this._remoteHandlers)) {
      handler(
        this.document,
        await this.getReaders(),
        await this.getWriters(),
        hashes,
      );
    }
  }
  private async _fireLocalUpdateHandlers(hashes: string[]) {
    for (const handler of Object.values(this._localHandlers)) {
      handler(
        this.document,
        await this.getReaders(),
        await this.getWriters(),
        hashes,
      );
    }
  }

  private _createSyncMessage(): CRDTSyncMessage<ChangesType, PublicKey> {
    const message: CRDTSyncMessage<ChangesType, PublicKey> = {
      ...(this._lastSyncMessage || {
        documentId: this.documentPath,
      }),
    };
    return message;
  }

  /**
   * Returns this peer's structural local-DAG frontier as a plain
   * string[] of CIDs -- the heads of EVERYTHING this peer has seen.
   *
   * NOTE: this is NOT the value advertised in a `tipAdvertiseV1` probe
   * and NOT the value the responder commits to on a v3 load response.
   * Both of those use `_servedFrontier()` instead -- the heads of the
   * change tree this peer can actually ship in a single load round.
   * See `_servedFrontier()`'s docstring for why the two differ (short
   * version: a load response only carries the tree rooted at
   * `_lastSyncMessage.changeId`, so concurrent local heads that aren't
   * cross-linked into that tree don't appear in what's served).
   *
   * `_currentFrontier()` is retained for callers that need the
   * structural truth of "what heads do I have locally?" rather than
   * "what would I advertise / serve?":
   *
   *   - `_makeChange()` cross-link selection (so a new local change
   *     can reference concurrent remote heads that landed since the
   *     last cached sync message).
   *   - Diagnostics / introspection paths.
   *
   * The frontier is the set of heads of the local merged-changes DAG:
   * CIDs that this peer has seen but that no other change references
   * as a parent or cross-link target. Computed as `_hashes \
   * _referencedAncestors`. See the `_referencedAncestors` field
   * docstring for why this matters: it is the part of the local DAG
   * that converges across honest peers regardless of differing sync
   * histories or pruning levels.
   *
   * Edge cases:
   *   - Empty DAG (founding member, brand-new document): `_hashes` is
   *     empty, the returned frontier is `[]`.
   *   - Just-loaded from snapshot: `_hashes` holds the snapshot
   *     boundary CID (and any post-snapshot changes). The boundary CID
   *     is NOT in `_referencedAncestors`, so it correctly appears as a
   *     head.
   *   - Pruned ancestors: irrelevant. Pruning removes CIDs from the
   *     in-memory change tree but leaves them in `_hashes` for dedup;
   *     they were already in `_referencedAncestors`, so they remain
   *     marked as non-heads.
   *
   * Returns a fresh array so callers can't mutate internal state;
   * `tipsHash` sorts independently, so we don't sort here.
   *
   * @internal
   */
  private _currentFrontier(): string[] {
    const out: string[] = [];
    for (const cid of this._hashes) {
      if (!this._referencedAncestors.has(cid)) {
        out.push(cid);
      }
    }
    return out;
  }

  /**
   * Returns the frontier this peer would *advertise as part of a load
   * response* -- the heads of the change tree this peer can actually ship
   * in a single `documentLoadV3` / `snapshotLoadV3` round.
   *
   * # Why this is NOT the same as `_currentFrontier()`
   *
   * `_currentFrontier()` returns the heads of the local DAG (`_hashes \
   * _referencedAncestors`) -- the structural truth of EVERYTHING this peer
   * has seen. That set is the right answer for "what is the logical state
   * of my local document?", but it is the WRONG answer for "what hash
   * should I advertise in a `tipAdvertiseV1` probe?".
   *
   * A load response only carries ONE change tree (rooted at
   * `_lastSyncMessage.changeId`), plus optionally `_latestSnapshot`.
   * `_lastSyncMessage` is refreshed by `_makeChange()` (its tree is
   * rooted at *this peer's* last locally-produced change) AND by
   * `_syncDocumentChanges()` (when an incoming remote tree subsumes the
   * cached root, including on relay peers that never make local changes;
   * see `_refreshLastSyncMessageFromSync()`). When the
   * incoming root is concurrent with the cached root, the cache is left
   * alone so served-frontier coverage cannot shrink; the next local
   * change re-bundles concurrent heads via cross-links from
   * `_recentTips` (`selectCrossLinks`).
   *
   * So when a peer has multiple concurrent heads (e.g. its own last local
   * change H1 plus remotely-applied changes H2, H3 that aren't yet
   * cross-linked from any local change), `_currentFrontier()` returns
   * `{H1, H2, H3}` but the load response only contains H1's subtree.
   * That creates an inconsistency: the tip-advertise probe would hash
   * `{H1, H2, H3}` and win the quorum vote, but the served payload's
   * structural frontier (`computeServedFrontier(...)` on the loader side)
   * hashes only `{H1}`, causing the loader's bind check to reject the
   * honest peer.
   *
   * # What this returns
   *
   * The heads of the served payload, computed via `computeServedFrontier`
   * over EXACTLY the same inputs the load response will carry:
   *   - `_lastSyncMessage?.changeId` -- root CID of the served tree (if any);
   *   - `_lastSyncMessage?.changes` -- the served tree itself (if any);
   *   - `_latestSnapshot?.lastChangeNodeCID` -- snapshot boundary CID (if any).
   *
   * This mirrors the loader's `_sendLoadRequestAndSync` binding check:
   * both sides hash the structurally-derived served frontier, so an
   * honest responder advertises a hash the loader can reproduce from the
   * payload it received. Two honest peers in the same logical state with
   * the same `_lastSyncMessage` / `_latestSnapshot` advertise the same
   * hash regardless of any unrelated concurrent heads they happen to be
   * holding in `_currentFrontier()`.
   *
   * # Trade-off (acknowledged)
   *
   * The quorum no longer verifies that a responder has all of its
   * logical heads -- only the ones it would actually serve. A peer with
   * un-served concurrent heads can pass quorum on the subset it ships
   * via load. This matches the existing load semantics (the load only
   * ever ships what `_lastSyncMessage` covers anyway) and is reconciled
   * by post-load GossipSub sync; the alternative (Option B in the design
   * notes) would require the load response itself to carry every head's
   * subtree, a larger protocol change.
   *
   * @internal
   */
  private _servedFrontier(): string[] {
    return computeServedFrontier(
      this._lastSyncMessage?.changeId,
      this._lastSyncMessage?.changes,
      this._latestSnapshot?.lastChangeNodeCID,
    );
  }

  /**
   * Construct the exact state-mutating payload shared by V4 advertisement,
   * document-load, and snapshot-load handlers. Keeping this in one helper
   * prevents the lightweight probe from committing to a different candidate
   * than the selected full response later serves.
   */
  private async _createLoadResponsePlan(
    loadChallenge?: Uint8Array,
  ): Promise<CRDTSyncMessage<ChangesType, PublicKey>> {
    const message = this._createSyncMessage();
    message.signature = undefined;
    message.tips = undefined;
    message.tipsHash = undefined;
    message.loadSecurityState = undefined;
    message.loadChallenge =
      loadChallenge === undefined
        ? undefined
        : cloneInitialLoadChallenge(loadChallenge);
    message.keychainChanges = this._requireWireChanges(
      await this._keychainChangesForVisibility(),
      'load-response keychain change',
    );
    if (this._latestSnapshot === undefined) {
      message.snapshot = undefined;
    } else {
      message.snapshot = this._latestSnapshot;
    }
    return message;
  }

  private _initialLoadRequestSignaturePayload(
    message: CRDTLoadRequest,
    securityAware: boolean,
  ): Uint8Array | null {
    if (!securityAware) return this._encoder.encode(message.documentId);
    try {
      return initialLoadRequestSignaturePayload(
        message.documentId,
        message.loadChallenge!,
      );
    } catch {
      return null;
    }
  }

  /** Derive the V4 commitment from the actual response fields sync() applies. */
  private async _loadResponseManifestHash(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): Promise<Uint8Array> {
    return loadResponseManifestHash({
      changeId: message.changeId,
      changes: message.changes,
      serializeChange: (change) =>
        this._changesSerializer.serializeChanges(change),
      snapshot:
        message.snapshot === undefined
          ? undefined
          : {
              stateBytes: this._changesSerializer.serializeChanges(
                message.snapshot.state,
              ),
              lastChangeNodeCID: message.snapshot.lastChangeNodeCID,
              compactedCount: message.snapshot.compactedCount,
              timestamp: message.snapshot.timestamp,
            },
      keychainChangesBytes:
        message.keychainChanges === undefined
          ? undefined
          : this._changesSerializer.serializeChanges(message.keychainChanges),
    });
  }

  private _loadResponsePlanFrontier(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): string[] {
    return computeServedFrontier(
      message.changeId,
      message.changes,
      message.snapshot?.lastChangeNodeCID,
    );
  }

  /**
   * Record a CID as a recently-known tip for Merkle-CRDT cross-linking
   * (paper §VI.B.e). Called for both locally-generated and remote-applied
   * change nodes -- a peer A that just received B's change can cross-link
   * to it on A's next outgoing change, helping a third peer C that missed
   * B's broadcast discover the missing block. Cross-links to deferred CIDs
   * are emitted as leaf nodes with only `kind` set; the receiver fetches
   * the block from Helia when needed (see `_syncDocumentChanges`).
   *
   * Bounded to `MAX_RECENT_TIPS` entries (oldest evicted). If the CID is
   * already tracked, move it to the back so it remains a high-priority
   * cross-link candidate.
   */
  private _trackTip(cid: string, kind: CRDTChangeNodeKind): void {
    trackTipInList(this._recentTips, { cid, kind }, MAX_RECENT_TIPS);
  }

  private async _syncDocumentChanges(
    changeId: string | undefined,
    changes: CRDTChangeNode<ChangesType>,
    authorizationLease?: SyncAuthorizationLease,
    initialLoadBudget?: InitialLoadDeferredBlockBudget,
    admitStateMutation?: () => void,
  ): Promise<boolean> {
    // Validate and flatten before mutating frontier bookkeeping. In
    // particular, a conflicting repeated-CID representation must not be able
    // to poison `_referencedAncestors` merely because the merge is rejected.
    const newChangeEntries = await this._mergeSyncTree(
      changeId,
      changes,
      this._lastSyncMessage && this._lastSyncMessage.changeId,
      this._hashes,
    );
    if (
      authorizationLease !== undefined &&
      authorizationLease.isCurrent() !== true
    ) {
      return false;
    }

    // Walk the incoming sync tree once and record every CID that appears
    // as a `children` key. Those CIDs are referenced ancestors -- by
    // definition no longer heads of the local DAG. Doing this BEFORE the
    // merge keeps `_currentFrontier()` correct regardless of whether the
    // referenced parent ends up applied inline or fetched lazily from the
    // blockstore: either way, the receiver now knows the parent relationship
    // the sender had.
    //
    // Idempotent and inexpensive: the helper walks at most the size of the
    // delivered tree (bounded by the sender's compaction config); duplicates
    // are no-ops in a Set.
    const incomingReferencedAncestors = new Set<string>();
    collectReferencedAncestors(changeId, changes, incomingReferencedAncestors);
    for (const cid of incomingReferencedAncestors) {
      if (!this._referencedAncestors.has(cid)) {
        admitStateMutation?.();
        this._referencedAncestors.add(cid);
      }
    }

    // First apply changes that were sent directly.
    let newDocument = this.document;
    const newDocumentHashes: string[] = [];
    const newDocumentTips: Array<[string, CRDTChangeNodeKind]> = [];
    const missingDocumentHashes: [string, CRDTChangeNodeKind][] = [];
    for (const [sentHash, sentChangeKind, sentChanges] of newChangeEntries) {
      if (sentChanges !== undefined) {
        switch (sentChangeKind) {
          case crdtDocumentChangeNode: {
            // Apply the changes that were sent directly.
            admitStateMutation?.();
            newDocument = this._crdtProvider.remoteChange(
              newDocument,
              sentChanges,
            );
            newDocumentHashes.push(sentHash);
            newDocumentTips.push([sentHash, sentChangeKind]);
            this._documentChangeCount++;
            this._changesSinceSnapshot++;
            break;
          }
          case crdtReaderChangeNode: {
            // Apply through the sanctioned wrapper so a provider rejection
            // terminally retires ambiguous ACL state.
            admitStateMutation?.();
            this._mergeReaders(sentChanges);
            newDocumentHashes.push(sentHash);
            newDocumentTips.push([sentHash, sentChangeKind]);
            break;
          }
          case crdtWriterChangeNode: {
            // Apply the changes that were sent directly.
            admitStateMutation?.();
            this._mergeWriters(sentChanges);
            if (
              authorizationLease !== undefined &&
              authorizationLease.advanceAfterWriterMutation() !== true
            ) {
              return false;
            }
            newDocumentHashes.push(sentHash);
            newDocumentTips.push([sentHash, sentChangeKind]);
            break;
          }
        }
      } else {
        missingDocumentHashes.push([sentHash, sentChangeKind]);
      }
    }
    if (newDocumentHashes.length) {
      this._document = newDocument;
      for (const newHash of newDocumentHashes) {
        this._hashes.add(newHash);
      }
      // Track applied tips for Merkle-CRDT cross-linking (paper §VI.B.e)
      // *before* firing remote update handlers. Recording remote-applied
      // CIDs lets this peer cross-link to them on its next outgoing change,
      // helping other peers that may have missed the original broadcast.
      // The ordering matters: if a handler synchronously triggers a local
      // `change()`, `_makeChange()` must see the just-received remote tips
      // in `_recentTips` to cross-link to them. This matches the ordering
      // used in the missing-block fetch path below.
      //
      // `newDocumentTips` is populated in `mergeRemoteSyncTree`'s traversal
      // order, which is root-first (the remote head is the first entry, its
      // ancestors follow). `_trackTip` appends to the back of `_recentTips`
      // with LRU semantics, so pushing in root-first order would make the
      // head the *oldest* entry -- and when more than MAX_RECENT_TIPS new
      // entries arrive in one sync, the head would be evicted first. Walk
      // in reverse so the remote head ends up at the back (most-recent),
      // matching the intent of LRU tracking.
      for (let i = newDocumentTips.length - 1; i >= 0; i--) {
        const [cid, kind] = newDocumentTips[i]!;
        this._trackTip(cid, kind);
      }
      await this._fireRemoteUpdateHandlers(newDocumentHashes);
    }

    if (
      authorizationLease !== undefined &&
      authorizationLease.isCurrent() !== true
    ) {
      return false;
    }

    // Then apply missing hashes by fetching them from the blockstore. A bounded
    // worker pool prevents an adversarial 4096-node manifest from starting one
    // decrypt/apply promise per CID at once. Aggregate-budgeted initial loads
    // use one worker so concurrent decryptions cannot overshoot the decoded
    // aggregate ceiling; ordinary sync retains bounded parallel fetching.
    let authorizationRevoked = false;
    let blockFetchFailed = false;
    let stopFetchWorkers = false;
    let nextMissingIndex = 0;
    const fetchWorker = async (): Promise<void> => {
      while (true) {
        if (stopFetchWorkers) return;
        const index = nextMissingIndex++;
        if (index >= missingDocumentHashes.length) return;
        const [missingHash, missingHashKind] = missingDocumentHashes[index]!;
        let missingChanges: ChangesType;
        try {
          missingChanges = await this._getBlock(
            CID.parse(missingHash),
            initialLoadBudget,
          );
        } catch {
          blockFetchFailed = true;
          if (initialLoadBudget !== undefined) {
            // Initial load requires complete installation. After the first
            // failed deferred fetch, further peer-controlled work cannot make
            // this candidate succeed.
            stopFetchWorkers = true;
          }
          console.error(
            `Failed to fetch a referenced change for ${this.documentPath}`,
          );
          continue;
        }
        if (stopFetchWorkers) return;
        if (!missingChanges) {
          blockFetchFailed = true;
          if (initialLoadBudget !== undefined) stopFetchWorkers = true;
          console.error(
            `A referenced block returned no changes for ${this.documentPath}`,
          );
          continue;
        }
        if (
          authorizationLease !== undefined &&
          authorizationLease.isCurrent() !== true
        ) {
          authorizationRevoked = true;
          if (initialLoadBudget !== undefined) stopFetchWorkers = true;
          continue;
        }
        // Deadline/cancellation admission errors must escape unchanged and
        // must not be misclassified as provider or block-fetch failures.
        admitStateMutation?.();
        try {
          switch (missingHashKind) {
            case crdtDocumentChangeNode: {
              this._document = this._crdtProvider.remoteChange(
                this._document,
                missingChanges,
              );
              this._hashes.add(missingHash);
              this._documentChangeCount++;
              this._changesSinceSnapshot++;
              this._trackTip(missingHash, missingHashKind);
              await this._fireRemoteUpdateHandlers([missingHash]);
              break;
            }
            case crdtReaderChangeNode: {
              this._mergeReaders(missingChanges);
              this._hashes.add(missingHash);
              this._trackTip(missingHash, missingHashKind);
              await this._fireRemoteUpdateHandlers([missingHash]);
              break;
            }
            case crdtWriterChangeNode: {
              this._mergeWriters(missingChanges);
              if (
                authorizationLease !== undefined &&
                authorizationLease.advanceAfterWriterMutation() !== true
              ) {
                authorizationRevoked = true;
                if (initialLoadBudget !== undefined) stopFetchWorkers = true;
                break;
              }
              this._hashes.add(missingHash);
              this._trackTip(missingHash, missingHashKind);
              await this._fireRemoteUpdateHandlers([missingHash]);
              break;
            }
          }
        } catch {
          blockFetchFailed = true;
          if (initialLoadBudget !== undefined) stopFetchWorkers = true;
          if (this._securityProviderMutationFailure !== undefined) {
            this._throwIfSecurityProviderMutationFailed();
          }
          console.error(
            `Failed to apply a referenced change for ${this.documentPath}`,
          );
        }
      }
    };
    const maxFetchWorkers =
      initialLoadBudget === undefined ? LOAD_BLOCK_MAX_CONCURRENCY : 1;
    await Promise.all(
      Array.from(
        {
          length: Math.min(maxFetchWorkers, missingDocumentHashes.length),
        },
        () => fetchWorker(),
      ),
    );
    if (initialLoadBudget !== undefined && blockFetchFailed) {
      return false;
    }
    if (
      authorizationRevoked ||
      (authorizationLease !== undefined &&
        authorizationLease.isCurrent() !== true)
    ) {
      return false;
    }

    // Refresh `_lastSyncMessage` so the served frontier reflects what we now
    // hold. Without this, a relay peer that joined via `load()` (or that has
    // only ever applied remote changes via GossipSub) would keep
    // `_lastSyncMessage` undefined and `_servedFrontier()` would return `[]`,
    // making the peer advertise `tipsHash([])` in the initial-load quorum
    // probe AND ship an empty load response. Two such relay peers would
    // agree on the empty-set hash, satisfying quorum, and an honest newcomer
    // would accept an empty document while the mesh actually had data.
    //
    // We update only when the incoming tree subsumes our prior root --
    // i.e., `_lastSyncMessage.changeId` appears as a CID somewhere in the
    // received tree -- so the served-frontier coverage never shrinks. The
    // undefined-prior and same-root cases are also "subsumes" (vacuously
    // and trivially); concurrent independent roots are intentionally left
    // alone (matches the existing single-tree load semantics documented on
    // `_servedFrontier()`). The next local `_makeChange()` cross-links
    // through `_recentTips` regardless, so concurrent heads are recovered
    // on the next local write.
    admitStateMutation?.();
    this._refreshLastSyncMessageFromSync(changeId, changes);

    await this._maybeCompact(admitStateMutation);
    // Compaction may await ACL and signature providers. Recheck the candidate
    // deadline before reporting a successful initial-load apply.
    admitStateMutation?.();
    return true;
  }

  /**
   * Update `_lastSyncMessage` so it reflects the served frontier of a
   * just-applied remote sync tree. Called by `_syncDocumentChanges()`
   * after the merge has succeeded.
   *
   * Replacement policy: only swap the cached message when the incoming
   * tree *subsumes* the prior cached root, so the served frontier the
   * loader binds against can only grow, never shrink:
   *   - `_lastSyncMessage` is `undefined` (relay peer, no local change
   *     yet): adopt the incoming directly so the relay peer does not serve
   *     an empty frontier.
   *   - prior `changeId` appears anywhere in the incoming tree (root or
   *     descendant): the incoming tree includes the prior root's coverage
   *     by construction, so it is safe to replace.
   *   - prior `changeId` is independent of the incoming tree (concurrent
   *     heads, neither subsumes the other): leave the cached message in
   *     place. The next local `_makeChange()` will bundle both heads via
   *     cross-links from `_recentTips`. This matches the trade-off
   *     documented on `_servedFrontier()` -- a load response only ever
   *     carries one tree, so accepting a single root is the existing
   *     contract.
   *
   * The cached message's `documentId` / `keychainChanges` fields are
   * preserved across the swap. Response-specific fields
   * (`signature`, `tips`, `tipsHash`, `loadSecurityState`) are dropped because they are
   * regenerated per-response by the load / tip-advertise handlers; leaving
   * a stale value would be misleading at best, a wire-protocol violation
   * at worst.
   *
   * Idempotent and inexpensive: the subsumption check walks the incoming
   * tree once (bounded by sender compaction config); the field-level
   * replacement is O(1) reference swaps.
   *
   * @internal
   */
  private _refreshLastSyncMessageFromSync(
    receivedChangeId: string | undefined,
    receivedChanges: CRDTChangeNode<ChangesType>,
  ): void {
    // Defensive: if the incoming carries no root CID we cannot meaningfully
    // refresh the served frontier with it. (`computeServedFrontier` will
    // produce `[]` for the resulting `_lastSyncMessage` and we would simply
    // re-introduce the empty-served-frontier bug.)
    if (!receivedChangeId) return;

    const priorChangeId = this._lastSyncMessage?.changeId;

    // Case 1: no prior cached message -- adopt the incoming. A relay peer
    // with no local changes otherwise serves an empty payload because
    // `_lastSyncMessage` is `undefined`.
    if (!priorChangeId) {
      this._lastSyncMessage = {
        ...(this._lastSyncMessage || { documentId: this.documentPath }),
        changeId: receivedChangeId,
        changes: receivedChanges,
        // Drop response-specific fields; they are regenerated per-response.
        signature: undefined,
        tips: undefined,
        tipsHash: undefined,
        loadSecurityState: undefined,
        loadChallenge: undefined,
      };
      return;
    }

    // Case 2: same root -- already up to date, nothing to do. (CIDs are
    // content-addressed so equal `changeId` implies the same subtree.)
    if (priorChangeId === receivedChangeId) return;

    // Case 3: prior root is embedded in the incoming tree -- the incoming
    // subsumes the prior. Replace.
    if (treeContainsCid(receivedChangeId, receivedChanges, priorChangeId)) {
      this._lastSyncMessage = {
        ...this._lastSyncMessage!,
        changeId: receivedChangeId,
        changes: receivedChanges,
        signature: undefined,
        tips: undefined,
        tipsHash: undefined,
        loadSecurityState: undefined,
        loadChallenge: undefined,
      };
      return;
    }

    // Case 4: concurrent / independent roots. Leave the cached message
    // alone so we do not shrink served-frontier coverage. The next local
    // `_makeChange()` cross-links via `_recentTips`, recovering both heads.
  }

  /** Build an isolated writer-ACL candidate without mutating live state. */
  private async _writerKeysIncludingTree(
    node: CRDTChangeNode<ChangesType> | undefined,
  ): Promise<ReadonlyArray<PublicKey>> {
    const candidate = this._aclProvider.initialize();
    candidate.merge(this._writers.current());
    const pending = node === undefined ? [] : [node];
    while (pending.length > 0) {
      const current = pending.pop()!;
      if (
        current.change !== undefined &&
        current.kind === crdtWriterChangeNode
      ) {
        candidate.merge(current.change);
      }
      if (
        current.children !== undefined &&
        current.children !== crdtChangeNodeDeferred
      ) {
        const children = Object.values(current.children);
        for (let index = children.length - 1; index >= 0; index--) {
          pending.push(children[index]!);
        }
      }
    }
    return candidate.users();
  }

  /** Sanctioned wrapper that retires the document on an ambiguous ACL merge. */
  private _mergeReaders(changes: ChangesType): void {
    try {
      this._readers.merge(changes);
    } catch (error) {
      this._retireAfterAmbiguousSecurityProviderMutation(
        'inbound readers-ACL merge',
        error,
      );
    }
  }

  /**
   * Whether application-level signing is enabled for this document's swarm.
   * Centralizes the `enableSigning` config check to avoid drift across many call sites.
   */
  private _isSigningEnabled(): boolean {
    return this.swarm.enableSigning;
  }

  private _requiresAuthenticatedInitialLoad(): boolean {
    return this.swarm.requireAuthenticatedInitialLoad;
  }

  private async _getBootstrapWriterKeys(): Promise<ReadonlyArray<PublicKey>> {
    const resolver = this.swarm.resolveTrustedDocumentWriters;
    if (!resolver) return [];
    const resolved = await resolver(this.documentPath);
    if (!Array.isArray(resolved)) {
      throw new TypeError(
        'resolveTrustedDocumentWriters must return an array of public keys',
      );
    }
    return resolved as readonly PublicKey[];
  }

  private async _getLoadSecurityCommitments(): Promise<
    LoadSecurityCommitments | undefined
  > {
    const resolver = this.swarm.resolveLoadSecurityCommitments;
    if (!resolver) return undefined;
    const commitments = await resolver(this.documentPath);
    return cloneLoadSecurityCommitments(commitments);
  }

  private _assertInitialLoadWriterAuthorizationCurrent(
    writerVersion: number,
  ): void {
    this._throwIfSecurityProviderMutationFailed();
    if (
      (this._writerMutationsInFlight ?? 0) !== 0 ||
      (this._writerKeysVersion ?? 0) !== writerVersion
    ) {
      throw new Error(
        `Writer authorization changed during the security-aware initial-load ` +
          `round for ${this.documentPath}; retry the load`,
      );
    }
  }

  private async _captureInitialLoadSignerAuthorities(): Promise<
    InitialLoadSignerAuthoritySnapshot<PublicKey>
  > {
    if ((this._writerMutationsInFlight ?? 0) !== 0) {
      throw new Error(
        `Writer authorization changed during the security-aware initial-load ` +
          `round for ${this.documentPath}; retry the load`,
      );
    }
    const writerVersion = this._writerKeysVersion ?? 0;
    const existingWriterKeys = await this._getWriterKeys();
    this._assertInitialLoadWriterAuthorizationCurrent(writerVersion);
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'security-aware initial load',
    );
    const authorities = await captureInitialLoadSignerAuthorities({
      documentPath: this.documentPath,
      existingWriterKeys,
      resolveTrustedDocumentWriters:
        existingWriterKeys.length === 0
          ? (this.swarm.resolveTrustedDocumentWriters as
              | ((
                  documentPath: string,
                ) => readonly PublicKey[] | Promise<readonly PublicKey[]>)
              | undefined)
          : undefined,
      serializePublicKey,
    });
    this._assertInitialLoadWriterAuthorizationCurrent(writerVersion);
    return Object.freeze({ authorities, writerVersion });
  }

  private async _identifyInitialLoadSignerAuthority(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
    authorities: readonly InitialLoadSignerAuthority<PublicKey>[],
  ): Promise<string | null> {
    const { signature, ...messageWithoutSignature } = message;
    let signatureBytes: Uint8Array | undefined;
    if (signature !== undefined) {
      try {
        signatureBytes = this._deserializeSignature(signature);
      } catch {
        return null;
      }
    }
    const identified = await identifyInitialLoadSigner({
      strict: true,
      signingEnabled: this._isSigningEnabled(),
      payload: this._syncMessageSerializer.serializeSyncMessage(
        messageWithoutSignature,
      ),
      signature: signatureBytes,
      existingWriterKeys: authorities.map((entry) => entry.publicKey),
      trustedBootstrapWriterKeys: [],
      verify: (payload, key, candidateSignature) =>
        this._authProvider.verify(payload, key, candidateSignature),
    });
    return identified === null
      ? null
      : authorities[identified.keyIndex].authorityId;
  }

  private async _verifyInitialLoadEnvelope(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
    existingWriterKeys: readonly PublicKey[],
    capturedBootstrapWriterKeys?: readonly PublicKey[],
  ): Promise<boolean> {
    const { signature, ...messageWithoutSignature } = message;
    const signingEnabled = this._isSigningEnabled();
    let signatureBytes: Uint8Array | undefined;
    if (signingEnabled && signature !== undefined) {
      try {
        signatureBytes = this._deserializeSignature(signature);
      } catch {
        return false;
      }
    }
    return verifyInitialLoadAuthentication({
      strict: this._requiresAuthenticatedInitialLoad(),
      signingEnabled,
      payload: this._syncMessageSerializer.serializeSyncMessage(
        messageWithoutSignature,
      ),
      signature: signatureBytes,
      existingWriterKeys,
      trustedBootstrapWriterKeys:
        existingWriterKeys.length === 0
          ? (capturedBootstrapWriterKeys ??
            (await this._getBootstrapWriterKeys()))
          : [],
      verify: (payload, key, candidateSignature) =>
        this._authProvider.verify(payload, key, candidateSignature),
    });
  }

  /**
   * Returns the current list of authorized writer public keys, populating
   * the document-scoped cache on miss. Callers must not mutate the result.
   * The cache is invalidated by `_mergeWriters`, `_addWriter`, and
   * `_removeWriter` -- the only sanctioned mutation paths for `_writers`.
   *
   * Race-safety has two layers:
   *  - Mutation-in-flight bypass: while `_writerMutationsInFlight > 0`,
   *    skip the cache entirely. Some ACLs mutate their backing state
   *    before their `add`/`remove` Promise resolves, so the cached list
   *    can be stale even though the post-await invalidation has not yet
   *    run. Bypassing forces a fresh `users()` read each call until all
   *    mutations have finished and the cache is re-populated by a clean
   *    miss.
   *  - Version check on cache fill: capture `_writerKeysVersion` before
   *    awaiting. If the version advances mid-fetch, the fetched list
   *    reflects the *pre*-invalidation ACL and is unsafe to return --
   *    discard it and loop. The loop converges once a fetch completes
   *    with no intervening invalidation; under continuous invalidation
   *    it would spin, but invalidations are bounded (one per ACL
   *    mutation) and not adversarial.
   */
  private async _getWriterKeys(): Promise<ReadonlyArray<PublicKey>> {
    this._throwIfSecurityProviderMutationFailed();
    while (true) {
      if (
        this._writerMutationsInFlight === 0 &&
        this._cachedWriterKeys !== null
      ) {
        return this._cachedWriterKeys;
      }
      const versionAtStart = this._writerKeysVersion;
      const fetched = await this._writers.users();
      this._throwIfSecurityProviderMutationFailed();
      // Only commit to the cache if (a) the version is still current AND
      // (b) no mutations are in flight. Either condition means the fetch
      // could be racing a still-incomplete mutation; in that case return
      // the freshly fetched list to the caller but leave the cache null
      // so the next caller re-fetches.
      if (
        this._writerKeysVersion === versionAtStart &&
        this._writerMutationsInFlight === 0
      ) {
        this._cachedWriterKeys = fetched;
        return fetched;
      }
      if (this._writerKeysVersion !== versionAtStart) {
        // Version advanced during fetch -- the fetched list reflects the
        // pre-invalidation ACL. Discard it and retry with the post-
        // invalidation state to avoid handing a stale list to signature
        // verification.
        continue;
      }
      // Mutation still in flight but version unchanged: the fetched list
      // reflects whatever the ACL exposed at this moment, which is the
      // best the caller can get. Don't cache (so subsequent reads see
      // the post-mutation state once it lands), but return the value.
      return fetched;
    }
  }

  /** Bump the writer-keys version so any in-flight `_getWriterKeys` aborts
   *  its assignment, and clear the cache for the next caller. */
  private _invalidateWriterKeyCache(): void {
    this._cachedWriterKeys = null;
    this._writerKeysVersion++;
  }

  /**
   * Run a writer-ACL mutation under a guard that closes the gap between
   * "underlying ACL state has changed" and "_getWriterKeys reflects the
   * change." We invalidate the cache *before* the mutation (so any
   * concurrent `_getWriterKeys` re-fetches against whatever state the
   * ACL exposes at that moment) AND set a mutation-in-flight flag that
   * forces `_getWriterKeys` to bypass the cache entirely while the
   * mutation runs. Both bookkeeping operations live in the prelude/
   * finally so they cannot drift out of sync with the underlying call.
   */
  private async _runWriterMutation<T>(op: () => Promise<T> | T): Promise<T> {
    this._writerMutationsInFlight++;
    this._invalidateWriterKeyCache();
    try {
      return await op();
    } finally {
      this._writerMutationsInFlight--;
      // Invalidate again post-mutation: the underlying ACL is now
      // authoritative and any value that landed in the cache during the
      // window must be discarded. Idempotent and cheap.
      this._invalidateWriterKeyCache();
    }
  }

  /** Apply a writer ACL change and invalidate the cached key list. */
  private _mergeWriters(changes: ChangesType): void {
    // Synchronous mutation: increment-mutate-decrement around the
    // `merge()` call so any concurrent `_getWriterKeys` running on
    // another microtask sees the in-flight flag. Both invalidations
    // (pre and post) match the async helper's behavior.
    this._writerMutationsInFlight++;
    this._invalidateWriterKeyCache();
    try {
      this._writers.merge(changes);
    } catch (error) {
      this._retireAfterAmbiguousSecurityProviderMutation(
        'inbound writers-ACL merge',
        error,
      );
    } finally {
      this._writerMutationsInFlight--;
      this._invalidateWriterKeyCache();
    }
  }

  /** Add a writer and invalidate the cached key list. */
  private async _addWriter(publicKey: PublicKey): Promise<ChangesType> {
    return this._runWriterMutation(() => this._writers.add(publicKey));
  }

  /** Remove a writer and invalidate the cached key list. */
  private async _removeWriter(publicKey: PublicKey): Promise<ChangesType> {
    return this._runWriterMutation(() => this._writers.remove(publicKey));
  }

  private async _verifyWriterSignature(raw: Uint8Array, signature: string) {
    return (
      (await this._verifyWriterSignatureAtStableVersion(raw, signature)) !==
      null
    );
  }

  private _writerAuthorizationIsCurrent(version: number): boolean {
    return (
      this._securityProviderMutationFailure === undefined &&
      this._writerMutationsInFlight === 0 &&
      this._writerKeysVersion === version
    );
  }

  /**
   * Verify against one stable ACL-writer snapshot. Rejected verifier promises
   * are ordinary non-matches: one broken provider/key must not suppress a
   * later exact-`true` verification. The returned version is a short-lived
   * authorization lease that callers re-check immediately before their first
   * synchronous state mutation.
   */
  private async _verifyWriterSignatureAtStableVersion(
    raw: Uint8Array,
    signature: string,
  ): Promise<number | null> {
    if (this._securityProviderMutationFailure !== undefined) return null;
    if (!this._isSigningEnabled()) {
      return this._writerKeysVersion;
    }

    if (this._writerMutationsInFlight !== 0) return null;
    const versionAtStart = this._writerKeysVersion;
    const writerKeys = await this._getWriterKeys();
    // Short-circuit: with no writers, no signature can verify. Avoids the
    // base64 decode for an unverifiable input.
    if (writerKeys.length === 0) {
      return null;
    }
    if (!this._writerAuthorizationIsCurrent(versionAtStart)) {
      return null;
    }
    // Malformed base64 throws inside js-base64. A bad signature must surface
    // as a verification failure, not an exception -- the topic validator path
    // turns thrown errors into Ignore (effectively dropping the message
    // silently), which is a DoS surface for malformed input. Treat decode
    // failure as `false`.
    let signatureBytes: Uint8Array;
    try {
      signatureBytes = this._deserializeSignature(signature);
    } catch {
      return null;
    }
    const results = await Promise.allSettled(
      writerKeys.map((writerKey) =>
        this._authProvider.verify(raw, writerKey, signatureBytes),
      ),
    );
    if (!this._writerAuthorizationIsCurrent(versionAtStart)) {
      return null;
    }
    return results.some(
      (result) => result.status === 'fulfilled' && result.value === true,
    )
      ? versionAtStart
      : null;
  }

  /**
   * Verify a snapshot signature by trying all authorized writers.
   * Unlike sync message signatures (which are string-encoded), snapshot
   * signatures are raw Uint8Array. This avoids depending on the snapshot's
   * embedded publicKey field which may not survive serialization for all
   * key types (e.g. CryptoKey).
   */
  private async _verifySnapshotSignature(
    payload: Uint8Array,
    signature: Uint8Array,
    explicitWriterKeys?: readonly PublicKey[],
  ) {
    if (!this._isSigningEnabled()) {
      return true;
    }

    const writerKeys = explicitWriterKeys ?? (await this._getWriterKeys());
    const results = await Promise.allSettled(
      writerKeys.map((writerKey) =>
        this._authProvider.verify(payload, writerKey, signature),
      ),
    );
    return results.some(
      (result) => result.status === 'fulfilled' && result.value === true,
    );
  }

  private async _signAsWriter(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): Promise<string> {
    if (!this._isSigningEnabled()) {
      return '';
    }

    return this._signAsWriterUnconditional(message);
  }

  /**
   * Sign a sync message as a writer **regardless of the swarm-wide
   * `enableSigning` config**. Used exclusively by paths that always
   * require writer-auth (currently BeeKEM Welcomes); see
   * `_signWelcomeAsWriter` below.
   *
   * SECURITY: callers that go through `_signAsWriter` should keep doing
   * so -- it preserves the existing `enableSigning` toggle for normal
   * sync-message signing. Only paths that have a documented "writer-auth
   * is mandatory" requirement should use the unconditional variant.
   */
  private async _signAsWriterUnconditional(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): Promise<string> {
    const { signature: oldSignature, ...messageWithoutSignature } = message;

    const raw = this._syncMessageSerializer.serializeSyncMessage(
      messageWithoutSignature,
    );
    const rawSignature = await this._authProvider.sign(raw, this._userKey);
    return this._serializeSignature(rawSignature);
  }

  /**
   * Sign a BeeKEM Welcome as a writer. Unlike `_signAsWriter`, this is
   * NOT gated on the swarm-wide `enableSigning` config: Welcomes are
   * always writer-authenticated, regardless of whether document-change
   * signing is enabled (see `beekem-welcome-handler.ts` for the receive
   * side and the SECURITY NOTE there for the threat model).
   */
  private async _signWelcomeAsWriter(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): Promise<string> {
    return this._signAsWriterUnconditional(message);
  }

  /**
   * Verify a writer signature on a BeeKEM Welcome. Unlike
   * `_verifyWriterSignature`, this is NOT gated on the swarm-wide
   * `enableSigning` config -- Welcomes are always writer-authenticated.
   */
  private async _verifyWelcomeWriterSignature(
    raw: Uint8Array,
    signature: string,
  ): Promise<boolean> {
    return (
      (await this._verifyWelcomeWriterSignatureAtStableVersion(
        raw,
        signature,
      )) !== null
    );
  }

  private async _verifyWelcomeWriterSignatureAtStableVersion(
    raw: Uint8Array,
    signature: string,
  ): Promise<number | null> {
    if (this._writerMutationsInFlight !== 0) return null;
    const versionAtStart = this._writerKeysVersion;
    const writerKeys = await this._getWriterKeys();
    if (
      writerKeys.length === 0 ||
      this._writerKeysVersion !== versionAtStart ||
      this._writerMutationsInFlight !== 0
    ) {
      return null;
    }
    let signatureBytes: Uint8Array;
    try {
      signatureBytes = this._deserializeSignature(signature);
    } catch {
      return null;
    }
    const verificationResults = await Promise.allSettled(
      writerKeys.map((writerKey) =>
        this._authProvider.verify(raw, writerKey, signatureBytes),
      ),
    );
    if (
      this._writerKeysVersion !== versionAtStart ||
      this._writerMutationsInFlight !== 0
    ) {
      return null;
    }
    return verificationResults.some(
      (result) => result.status === 'fulfilled' && result.value === true,
    )
      ? versionAtStart
      : null;
  }

  /**
   * Capture the complete writer trust set for one inbound Welcome. Existing
   * ACL writers are authoritative. Only when that ACL is empty may the
   * application-pinned resolver provide the onboarding trust root.
   *
   * The resolver is invoked at most once per ingress. Canonical authority IDs
   * collapse duplicate credentials, and the captured array is reused for the
   * pre-authentication pass and the final state commit.
   */
  private async _captureBeeKEMWelcomeWriterAuthorities(): Promise<BeeKEMWriterAuthoritySnapshot<PublicKey> | null> {
    if (this._securityProviderMutationFailure !== undefined) return null;
    if (this._writerMutationsInFlight !== 0) return null;
    const writerKeysVersion = this._writerKeysVersion;
    const existingWriterKeys = await this._getWriterKeys();
    if (
      this._writerKeysVersion !== writerKeysVersion ||
      this._writerMutationsInFlight !== 0
    ) {
      return null;
    }

    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'BeeKEM Welcome writer authorization',
    );
    const resolver = this.swarm.resolveTrustedDocumentWriters as
      | ((
          documentPath: string,
        ) => readonly PublicKey[] | Promise<readonly PublicKey[]>)
      | undefined;
    let authorities: readonly InitialLoadSignerAuthority<PublicKey>[];
    try {
      authorities = await captureInitialLoadSignerAuthorities({
        documentPath: this.documentPath,
        existingWriterKeys,
        resolveTrustedDocumentWriters:
          existingWriterKeys.length === 0 ? resolver : undefined,
        serializePublicKey,
      });
    } catch {
      return null;
    }

    if (
      this._writerKeysVersion !== writerKeysVersion ||
      this._writerMutationsInFlight !== 0
    ) {
      return null;
    }
    return Object.freeze({
      source: existingWriterKeys.length === 0 ? 'bootstrap' : 'acl',
      writerKeysVersion,
      authorities,
    });
  }

  private async _verifyWelcomeWriterSignatureFromSnapshot(
    raw: Uint8Array,
    signature: string,
    snapshot: BeeKEMWriterAuthoritySnapshot<PublicKey>,
  ): Promise<boolean> {
    if (
      this._securityProviderMutationFailure !== undefined ||
      this._writerMutationsInFlight !== 0 ||
      this._writerKeysVersion !== snapshot.writerKeysVersion
    ) {
      return false;
    }
    if (snapshot.source === 'bootstrap') {
      const currentWriterKeys = await this._getWriterKeys();
      if (
        currentWriterKeys.length !== 0 ||
        this._writerMutationsInFlight !== 0 ||
        this._writerKeysVersion !== snapshot.writerKeysVersion
      ) {
        return false;
      }
    }

    let signatureBytes: Uint8Array;
    let stableRaw: Uint8Array;
    try {
      signatureBytes = this._deserializeSignature(signature);
      stableRaw = copyUnsharedUint8Array(
        raw,
        1,
        PeerborneDocument._MAX_BEEKEM_WIRE_PAYLOAD_BYTES,
        'BeeKEM Welcome signature payload',
      );
    } catch {
      return false;
    }
    const verificationResults = await Promise.allSettled(
      snapshot.authorities.map(({ publicKey }) =>
        this._authProvider.verify(stableRaw, publicKey, signatureBytes),
      ),
    );
    if (
      this._securityProviderMutationFailure !== undefined ||
      this._writerMutationsInFlight !== 0 ||
      this._writerKeysVersion !== snapshot.writerKeysVersion
    ) {
      return false;
    }
    if (snapshot.source === 'bootstrap') {
      const currentWriterKeys = await this._getWriterKeys();
      if (
        currentWriterKeys.length !== 0 ||
        this._writerMutationsInFlight !== 0 ||
        this._writerKeysVersion !== snapshot.writerKeysVersion
      ) {
        return false;
      }
    }
    return verificationResults.some(
      (result) => result.status === 'fulfilled' && result.value === true,
    );
  }

  private async _reauthorizeBeeKEMWelcome(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
    snapshot: BeeKEMWriterAuthoritySnapshot<PublicKey>,
  ): Promise<boolean> {
    if (
      typeof message.signature !== 'string' ||
      message.signature.length === 0
    ) {
      return false;
    }
    const signature = message.signature;
    const { signature: _signature, ...messageWithoutSignature } = message;
    let raw: Uint8Array;
    try {
      raw = copyUnsharedUint8Array(
        this._syncMessageSerializer.serializeSyncMessage(
          messageWithoutSignature,
        ),
        1,
        PeerborneDocument._MAX_BEEKEM_WIRE_PAYLOAD_BYTES,
        'BeeKEM Welcome signature payload',
      );
    } catch {
      return false;
    }
    return this._verifyWelcomeWriterSignatureFromSnapshot(
      raw,
      signature,
      snapshot,
    );
  }

  private async _reauthorizeCanonicalBeeKEMMessage(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): Promise<boolean> {
    if (
      typeof message.signature !== 'string' ||
      message.signature.length === 0
    ) {
      return false;
    }
    const signature = message.signature;
    const { signature: _signature, ...messageWithoutSignature } = message;
    let raw: Uint8Array;
    try {
      raw = copyUnsharedUint8Array(
        this._syncMessageSerializer.serializeSyncMessage(
          messageWithoutSignature,
        ),
        1,
        PeerborneDocument._MAX_BEEKEM_WIRE_PAYLOAD_BYTES,
        'BeeKEM signature payload',
      );
    } catch {
      return false;
    }
    return (
      (await this._verifyWelcomeWriterSignatureAtStableVersion(
        raw,
        signature,
      )) !== null
    );
  }

  private _encoder = new TextEncoder();

  private _deserializeSignature(signature: string): Uint8Array {
    if (
      typeof signature !== 'string' ||
      signature.length === 0 ||
      signature.length > MAX_WIRE_SIGNATURE_BASE64_LENGTH ||
      !Base64.isValid(signature)
    ) {
      throw new TypeError('signature must be canonical bounded base64');
    }
    const decoded = Base64.toUint8Array(signature);
    if (
      decoded.length === 0 ||
      decoded.length > MAX_WIRE_SIGNATURE_BYTES ||
      Base64.fromUint8Array(decoded) !== signature
    ) {
      throw new TypeError('signature must be canonical bounded base64');
    }
    return decoded;
  }

  private _serializeSignature(signature: Uint8Array): string {
    return Base64.fromUint8Array(
      copyUnsharedUint8Array(
        signature,
        1,
        MAX_WIRE_SIGNATURE_BYTES,
        'signature',
      ),
    );
  }

  /** Verify one decoded request signature against the reader/writer ACL. */
  private async _authorizeInitialLoadRequest(
    payload: Uint8Array,
    signature: unknown,
  ): Promise<boolean> {
    if (!this._isSigningEnabled()) return true;
    if (typeof signature !== 'string') return false;

    let signatureBytes: Uint8Array;
    try {
      // Decode and canonicalize before reading the ACL. The same bounded byte
      // snapshot is reused for every candidate instead of repeatedly decoding
      // attacker-controlled input inside the verification loop.
      signatureBytes = this._deserializeSignature(signature);
    } catch {
      return false;
    }

    const readers = (
      await Promise.all([this._readers.users(), this._writers.users()])
    ).flat();
    for (const reader of readers) {
      if (
        (await this._authProvider.verify(payload, reader, signatureBytes)) ===
        true
      ) {
        return true;
      }
    }
    return false;
  }

  private _requireWireChanges(
    changes: ChangesType,
    label: string,
  ): ChangesType {
    if (changes === undefined) {
      throw new TypeError(
        `${label} returned undefined, which cannot be represented by the optional sync-message change field`,
      );
    }
    return changes;
  }

  private async _makeChange(
    changes: ChangesType,
    kind: CRDTChangeNodeKind = crdtDocumentChangeNode,
  ): Promise<void> {
    const prepared = await this._prepareChange(changes, kind);
    await this._publishPreparedChange(prepared);
  }

  private async _prepareChange(
    changes: ChangesType,
    kind: CRDTChangeNodeKind = crdtDocumentChangeNode,
    encryptionKey?: readonly [Uint8Array, DocumentKey],
    combinedKeychainChanges?: { value: ChangesType },
  ): Promise<PreparedLocalChange<ChangesType, PublicKey>> {
    this._requireWireChanges(changes, `${kind} change`);
    if (combinedKeychainChanges !== undefined) {
      this._requireWireChanges(
        combinedKeychainChanges.value,
        'combined writer-removal keychain change',
      );
    }
    // Store changes in blockstore.
    const hash = await this._putBlock(changes, encryptionKey);

    // Send new message.
    let updateMessage = this._createSyncMessage();
    if (combinedKeychainChanges !== undefined) {
      // Writer removal carries the replacement key and ACL removal in one
      // old-key-encrypted envelope. When signing is enabled, one signature
      // binds both fields. Direct V2 and GossipSub receive paths both call
      // `sync()`, which merges this keychain field before applying the writer
      // node below. An `undefined` provider delta is rejected above because
      // the optional wire field cannot distinguish it from absence.
      updateMessage.keychainChanges = combinedKeychainChanges.value;
    }
    const changeNode: CRDTChangeNode<ChangesType> = { kind, change: changes };
    const primaryParentId = updateMessage.changeId;
    if (primaryParentId && updateMessage.changes) {
      // Primary back-pointer: include the previous head's subtree inline so
      // peers can apply our change without an extra round-trip for the parent.
      changeNode.children = {};
      changeNode.children[primaryParentId] = updateMessage.changes;

      // Cross-links (Merkle CRDT paper §VI.B.e): additionally reference other
      // recent tips so a peer who missed an intermediate message can still
      // discover the missing CID via a later message. Cross-link entries
      // are emitted as *deferred* nodes (no `change` payload, no `children`)
      // -- they carry only the CID + kind. Receivers that don't already have
      // the block trigger a blockstore fetch in `_syncDocumentChanges`.
      // Receivers that already have the block treat the entry as a no-op
      // (deduplicated via `_hashes`).
      const crossLinkTips = selectCrossLinks(
        this._recentTips,
        primaryParentId,
        hash,
        MAX_CROSS_LINKS,
      );
      for (const tip of crossLinkTips) {
        // Skip if the tip is already a direct child of the new change node.
        if (changeNode.children[tip.cid]) continue;
        // Deferred leaf: no `change` payload, no `children`. Receivers fetch
        // the block from Helia if they don't already have it.
        changeNode.children[tip.cid] = { kind: tip.kind };
      }
    }
    updateMessage.changeId = hash;
    updateMessage.changes = changeNode;

    // Record every CID this new change references as a parent / cross-link
    // target. The primary parent and all cross-link tips become *referenced
    // ancestors* and drop out of `_currentFrontier()`. Walks just the new
    // `changeNode` (not the full inherited subtree below it) because the
    // inherited subtree's ancestor relationships were already recorded
    // when each of those nodes was created or applied.
    const referencedAncestorCids = changeNode.children
      ? Object.keys(changeNode.children)
      : [];

    // Sign new message.
    updateMessage.signature = await this._signAsWriter(updateMessage);

    // Apply the same codec round-trip, byte cap, and aggregate detached-value
    // budgets used by inbound sync before committing local frontier state.
    // This keeps sender and receiver acceptance symmetric for long legacy
    // histories: a locally-built message is never committed/published if an
    // honest peer would reject its wire representation as over budget.
    updateMessage = this._canonicalizeSyncMessage(
      updateMessage,
      'outbound sync message',
    );

    const serializedUpdate = copyUnsharedUint8Array(
      this._syncMessageSerializer.serializeSyncMessage(updateMessage),
      1,
      MAX_SHARED_PROTOCOL_REQUEST_SIZE,
      'outbound sync message encoding',
    );

    // Encrypt sync message.
    const [documentKeyID, documentKey] =
      encryptionKey ?? (await this._keychain.current());
    if (!documentKey) {
      throw new Error(`Document ${this.documentPath} has an empty keychain!`);
    }
    const { nonce, data } = await this._authProvider.encrypt(
      serializedUpdate,
      documentKey,
    );
    if (!nonce) {
      throw new Error(`Failed to encrypt sync message! Nonce cannot be empty`);
    }
    const encryptedPayload = copyUnsharedUint8Array(
      concatUint8Arrays(documentKeyID, nonce, data),
      1,
      MAX_SHARED_PROTOCOL_REQUEST_SIZE,
      'outbound encrypted sync message',
    );
    return {
      hash,
      kind,
      encryptedPayload,
      updateMessage,
      referencedAncestorCids,
      committed: false,
    };
  }

  private _commitPreparedChange(
    prepared: PreparedLocalChange<ChangesType, PublicKey>,
  ): void {
    this._throwIfSecurityProviderMutationFailed();
    if (prepared.committed) return;
    this._hashes.add(prepared.hash);
    for (const childCid of prepared.referencedAncestorCids) {
      this._referencedAncestors.add(childCid);
    }
    this._trackTip(prepared.hash, prepared.kind);
    this._lastSyncMessage = prepared.updateMessage;
    prepared.committed = true;
  }

  private async _publishPreparedChange(
    prepared: PreparedLocalChange<ChangesType, PublicKey>,
  ): Promise<void> {
    this._commitPreparedChange(prepared);
    await this.swarm.heliaNode.libp2p.services.pubsub.publish(
      this._topic,
      prepared.encryptedPayload,
    );
    this._throwIfSecurityProviderMutationFailed();

    // Fire change handlers.
    await this._fireLocalUpdateHandlers([prepared.hash]);
    this._throwIfSecurityProviderMutationFailed();

    // Track document changes for compaction.
    if (prepared.kind === crdtDocumentChangeNode) {
      this._documentChangeCount++;
      this._changesSinceSnapshot++;
      await this._maybeCompact();
    }
  }

  /**
   * Returns the keychain changes to include in a load response based on
   * the document's history visibility setting.
   *
   * Ordinary load requests currently authenticate reader membership but do not
   * bind the requester identity to a persisted invitation epoch. A responder's
   * own `_invitationEpoch` therefore cannot safely define the requester's
   * window: a later joiner could otherwise query an earlier joiner and receive
   * intervening pre-invite keys. Until the protocol carries an authenticated
   * requester-specific boundary, `since_invited` is deliberately current-only
   * on load responses. Operators that explicitly accept historical disclosure
   * can configure `full_history`.
   */
  private async _keychainChangesForVisibility(): Promise<ChangesType> {
    switch (this._historyVisibility) {
      case 'full_history':
        // Send all retained epoch keys.
        return this._keychain.history();
      case 'since_invited':
        return await this._keychain.currentKeyChange();
      case 'current_only':
      default:
        // Only send the current key. This does not redact retained CRDT history.
        return await this._keychain.currentKeyChange();
    }
  }

  /**
   * Returns the keychain changes to include in a BeeKEM Welcome to a
   * newly-added reader.
   *
   * The visibility computation here is from the **recipient's**
   * perspective, not the inviter's:
   *
   * - `current_only`: send only the current key. Identical to the load
   *   response path; this does not redact retained CRDT history.
   * - `since_invited`: send only the current key. The recipient's Welcome
   *   establishes its current invitation epoch; subsequent rotations arrive
   *   via PathUpdates or combined writer-removal envelopes. Ordinary loads
   *   also project this policy to current-only today because they lack an
   *   authenticated requester-specific invitation boundary. The helpers stay
   *   separate because their policy inputs and future evolution differ.
   * - `full_history`: send the full keychain so the recipient can audit
   *   or replay all prior blocks (matches the inviter-side visibility
   *   semantics).
   */
  private async _keychainChangesForWelcome(
    historyVisibility: HistoryVisibility = this._historyVisibility,
  ): Promise<ChangesType> {
    switch (historyVisibility) {
      case 'full_history':
        return this._keychain.history();
      case 'since_invited':
      case 'current_only':
      default:
        return await this._keychain.currentKeyChange();
    }
  }

  /**
   * Check if automatic compaction should be triggered based on the config.
   */
  private async _maybeCompact(admitStateMutation?: () => void) {
    if (!this._compactionConfig.enabled || this._snapshotUnsupported) {
      return;
    }

    // Prevent overlapping snapshot() calls from concurrent async paths.
    if (this._compactionInProgress) {
      return;
    }

    // Check cheap thresholds before the async writer ACL check to avoid
    // repeated crypto/ACL work on every change.
    if (
      this._documentChangeCount <
      this._compactionConfig.minChangesBeforeSnapshot
    ) {
      return;
    }
    if (this._changesSinceSnapshot < this._compactionConfig.snapshotInterval) {
      return;
    }

    // Only writers can create snapshots; read-only peers must not attempt compaction.
    if ((await this._writers.check(this._userPublicKey)) !== true) {
      return;
    }
    admitStateMutation?.();
    this._compactionInProgress = true;
    try {
      await this._snapshotUnlocked(admitStateMutation);
    } finally {
      this._compactionInProgress = false;
    }
  }

  /**
   * Prune the change tree in the last sync message. After a BFS traversal
   * retains `keepCount` document nodes, remaining children are removed.
   * Note: in branching histories, nodes already enqueued in the BFS before
   * the limit is reached are also retained, so the actual count may exceed
   * `keepCount`.
   *
   * @param keepCount Maximum number of change nodes to retain in the sync tree.
   * @returns Set of CID strings for document nodes that were pruned from the tree.
   *   ACL node CIDs are never included (they are always preserved).
   */
  private _pruneChanges(keepCount: number): Set<string> {
    const prunedCIDs = new Set<string>();

    if (keepCount <= 0) {
      // Pruning everything (including root) is destructive and nonsensical; skip.
      return prunedCIDs;
    }
    if (!this._lastSyncMessage?.changes || !this._lastSyncMessage.changeId) {
      return prunedCIDs;
    }

    // Iteratively collect all ACL nodes from a subtree that is about to be pruned.
    // Re-attached ACL nodes are stored as leaf nodes (children stripped) so they
    // don't keep nested children subtrees alive after pruning.
    // Non-ACL (document) node CIDs are added to the prunedCIDs set.
    const collectACLNodes = (
      children: Record<string, CRDTChangeNode<ChangesType>>,
      out: Record<string, CRDTChangeNode<ChangesType>>,
    ) => {
      const pending = Object.entries(children).reverse();
      while (pending.length > 0) {
        const [childHash, childNode] = pending.pop()!;
        if (
          childNode.kind === crdtReaderChangeNode ||
          childNode.kind === crdtWriterChangeNode
        ) {
          // Shallow copy without children to avoid retaining the full subtree.
          const { children: _dropped, ...leafNode } = childNode;
          out[childHash] = leafNode as CRDTChangeNode<ChangesType>;
        } else {
          // Document node being pruned -- record its CID.
          prunedCIDs.add(childHash);
        }
        if (
          childNode.children !== undefined &&
          childNode.children !== crdtChangeNodeDeferred
        ) {
          const descendants = Object.entries(childNode.children);
          for (let index = descendants.length - 1; index >= 0; index--) {
            pending.push(descendants[index]!);
          }
        }
      }
    };

    // BFS traversal to collect nodes up to the limit.
    // ACL nodes (reader/writer) are always preserved regardless of keepCount.
    //
    // When a document node at the boundary is pruned, ACL nodes from the
    // entire pruned subtree are collected and re-attached. This prevents
    // losing ACL state during pruning.
    //
    // For branching histories (DAG with multiple branches), keepCount is applied
    // globally across all branches. Once the limit is reached, all further
    // document nodes in any branch are pruned.
    const queue: Array<CRDTChangeNode<ChangesType>> = [
      this._lastSyncMessage.changes,
    ];
    let documentNodesVisited = 0;
    let qi = 0;

    while (qi < queue.length) {
      const current = queue[qi++]!;

      // ACL nodes are always kept -- never count them toward the limit.
      const isACLNode =
        current.kind === crdtReaderChangeNode ||
        current.kind === crdtWriterChangeNode;

      if (!isACLNode) {
        documentNodesVisited++;
      }

      if (
        current.children !== undefined &&
        current.children !== crdtChangeNodeDeferred
      ) {
        if (!isACLNode && documentNodesVisited >= keepCount) {
          // This document node is at the boundary -- prune its children,
          // but preserve any ACL nodes within the entire subtree.
          const preservedACL: Record<string, CRDTChangeNode<ChangesType>> = {};
          collectACLNodes(current.children, preservedACL);
          if (Object.keys(preservedACL).length > 0) {
            current.children = preservedACL;
          } else {
            delete current.children;
          }
        } else {
          for (const [, childNode] of Object.entries(current.children)) {
            queue.push(childNode);
          }
        }
      }
    }

    console.log(
      `Pruned change tree for ${this.documentPath}: kept ${documentNodesVisited} document nodes, pruned ${prunedCIDs.size} blocks`,
    );

    return prunedCIDs;
  }

  /**
   * Delete pruned blocks from the Helia blockstore. Unpins each block first
   * (if pinned), then deletes the raw block data. CIDs are intentionally
   * kept in `_hashes` so that `_mergeSyncTree()` still deduplicates if a
   * peer re-sends the same change block.
   *
   * Errors on individual blocks are logged but do not abort the overall GC pass.
   */
  private async _gcPrunedBlocks(prunedCIDs: Set<string>): Promise<void> {
    if (prunedCIDs.size === 0) {
      return;
    }

    const blockstore = this.swarm.heliaNode.blockstore;
    const pins = this.swarm.heliaNode.pins;
    let deleted = 0;

    for (const cidStr of prunedCIDs) {
      try {
        const cid = CID.parse(cidStr);

        // Unpin first -- pins.rm is an AsyncGenerator, drain it.
        try {
          for await (const _ of pins.rm(cid)) {
            /* drain */
          }
        } catch (unpinErr) {
          const msg = String(unpinErr);
          if (!msg.includes('not pinned') && !msg.includes('is not pinned')) {
            throw unpinErr;
          }
          console.debug(`Unpin skipped for ${cidStr} (not pinned)`);
        }

        // Delete the raw block from the blockstore.
        // Note: we intentionally keep the CID in _hashes so that
        // _mergeSyncTree() still deduplicates if a peer re-sends
        // the same change block (e.g., a peer that hasn't compacted).
        await blockstore.delete(cid);
        deleted++;
      } catch {
        console.error(`Failed to GC a pruned block for ${this.documentPath}`);
      }
    }

    console.log(
      `Blockstore GC for ${this.documentPath}: deleted ${deleted}/${prunedCIDs.size} blocks`,
    );
  }

  /**
   * Handles a doc-load request with pre-read stream data. Called by the
   * shared protocol handler in Peerborne after reading and routing.
   *
   * @internal
   * @param message The deserialized load request (already parsed by the shared handler).
   * @param stream The stream object for sending the response.
   */
  public async handleLoadRequestData(
    message: CRDTLoadRequest,
    stream: { sink: (data: Iterable<Uint8Array>) => Promise<void> },
    securityAware = false,
  ): Promise<void> {
    try {
      this._throwIfSecurityProviderMutationFailed();
      if (
        !shouldServeInitialLoadProtocol(
          this.swarm.requireSecurityStateQuorum,
          securityAware,
        )
      ) {
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }
      if (!isBeeKEMMessageForDocument(message.documentId, this.documentPath)) {
        console.warn(
          `Received a load request for the wrong local document (${this.documentPath})`,
        );
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }
      const requestSignaturePayload = this._initialLoadRequestSignaturePayload(
        message,
        securityAware,
      );
      if (requestSignaturePayload === null) {
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }

      // Authorize the requestor. When signing is disabled, the shared helper
      // preserves the existing unsigned-load behavior.
      const authorized = await this._authorizeInitialLoadRequest(
        requestSignaturePayload,
        message.signature,
      );

      if (!authorized) {
        console.warn(
          `Rejected an unauthorized or malformed load request for ${this.documentPath}`,
        );
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }

      // Construct load response based on history visibility setting.
      const loadMessage = await this._createLoadResponsePlan(
        securityAware ? message.loadChallenge : undefined,
      );

      // Attach an explicit tip-set advertisement so the loader can apply
      // a defense-in-depth consistency check against this responder's
      // self-attested served frontier (issue #186 / #189 §5.4.2).
      //
      // The loader derives this frontier from the actual response; on V4 it
      // also derives a complete response manifest covering every node/edge,
      // snapshot, and keychain delta. The responder's `tips` array is NOT
      // trusted as the source of truth.
      // `tips` is still emitted by honest responders because the loader
      // ALSO verifies that the responder's own attestation hashes to
      // the same value as the structurally-derived served frontier --
      // a peer whose `tips` contradicts their own served payload is
      // caught at the secondary check.
      //
      // `tips` is the *served* frontier
      // (`_servedFrontier()`) -- i.e. the heads of the change tree this
      // load response actually carries -- NOT the full local DAG
      // frontier (`_currentFrontier()`). The two differ when this peer
      // has multiple concurrent heads but `_lastSyncMessage` only roots
      // at one of them (the load wire shape only ships a single tree).
      // The tip-advertise handler hashes the same served frontier, so
      // the probe and the load round bind against a byte-identical tip
      // set even when the responder is holding remotely-applied heads
      // that aren't yet cross-linked into `_lastSyncMessage.changes`.
      // This field is part of the SIGNED v3 payload; see
      // `wire-protocols.ts` for the version-bump rationale.
      loadMessage.tips = this._loadResponsePlanFrontier(loadMessage);
      if (securityAware) {
        const commitments = await this._getLoadSecurityCommitments();
        if (!commitments) {
          await stream.sink([] as Iterable<Uint8Array>);
          return;
        }
        loadMessage.loadSecurityState = commitments;
      }

      // Sign new message.
      loadMessage.signature = await this._signAsWriter(loadMessage);

      const serializedLoad =
        this._syncMessageSerializer.serializeSyncMessage(loadMessage);

      // Encrypt the load response so keychain is not sent in plaintext.
      // NOTE: This uses the current key, which works for existing peers requesting
      // a reload (they already have the key). For NEW members being onboarded for
      // the first time, the key must be delivered out-of-band via BeeKEM Welcome
      // message -- they cannot decrypt this load response without the key.
      const [documentKeyID, documentKey] = await this._keychain.current();
      if (!documentKey) {
        throw new Error(`Document ${this.documentPath} has an empty keychain!`);
      }
      const { nonce, data } = await this._authProvider.encrypt(
        serializedLoad,
        documentKey,
      );
      if (!nonce) {
        throw new Error(
          `Failed to encrypt sync message! Nonce cannot be empty`,
        );
      }
      const assembled = copyUnsharedUint8Array(
        concatUint8Arrays(documentKeyID, nonce, data),
        1,
        MAX_INITIAL_LOAD_RESPONSE_SIZE,
        'document-load response',
      );
      console.log(
        `sending doc-load response (encrypted) for ${this.documentPath}`,
      );

      this._throwIfSecurityProviderMutationFailed();
      await stream.sink([assembled] as Iterable<Uint8Array>);
    } catch {
      console.error(`Error handling doc-load request for ${this.documentPath}`);
      // Ensure the stream is closed so the requester doesn't hang.
      try {
        await stream.sink([] as Iterable<Uint8Array>);
      } catch {
        /* already closed */
      }
    }
  }

  /**
   * Handles a snapshot-load request with pre-read stream data. Called by
   * the shared protocol handler in Peerborne after reading and routing.
   *
   * @internal
   * @param message The deserialized load request (already parsed by the shared handler).
   * @param stream The stream object for sending the response.
   */
  public async handleSnapshotLoadRequestData(
    message: CRDTLoadRequest,
    stream: { sink: (data: Iterable<Uint8Array>) => Promise<void> },
    securityAware = false,
  ): Promise<void> {
    try {
      this._throwIfSecurityProviderMutationFailed();
      if (
        !shouldServeInitialLoadProtocol(
          this.swarm.requireSecurityStateQuorum,
          securityAware,
        )
      ) {
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }
      if (message.documentId !== this.documentPath) {
        console.warn(
          `Received a snapshot load request for the wrong local document (${this.documentPath})`,
        );
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }
      const requestSignaturePayload = this._initialLoadRequestSignaturePayload(
        message,
        securityAware,
      );
      if (requestSignaturePayload === null) {
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }

      // Authorize the requestor. When signing is disabled, the shared helper
      // preserves the existing unsigned-load behavior.
      const authorized = await this._authorizeInitialLoadRequest(
        requestSignaturePayload,
        message.signature,
      );

      if (!authorized) {
        console.warn(
          `Rejected an unauthorized or malformed snapshot load request for ${this.documentPath}`,
        );
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }

      if (!this._latestSnapshot) {
        // No snapshot available -- respond with empty payload so the peer
        // can fall back to the normal doc-load protocol.
        console.log(
          `No snapshot available for ${this.documentPath}, sending empty response`,
        );
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }

      // Build a complete sync message with the snapshot, post-snapshot
      // changes, and keychain so the peer can fully catch up.
      const snapshotMessage = await this._createLoadResponsePlan(
        securityAware ? message.loadChallenge : undefined,
      );
      // Tip-set advertisement for the pre-apply structural binding check
      // (see the doc-load handler above and the in-line check in
      // `_sendLoadRequestAndSync` for the rationale).
      //
      // This is the *served* frontier (`_servedFrontier()`)
      // -- the heads of the served payload (`_lastSyncMessage.changes`
      // tree plus the snapshot boundary) -- NOT the full local DAG
      // frontier (`_currentFrontier()`). When this peer holds concurrent
      // heads that `_lastSyncMessage` does not yet root over, the
      // load response only carries one head's subtree, so the
      // advertised `tips` must match that subset to satisfy the
      // loader's structural bind check. Part of the signed v3 payload
      // -- the version bump (snapshotLoadV2 -> snapshotLoadV3) is
      // required because `tips` is now covered by the writer signature.
      snapshotMessage.tips = this._loadResponsePlanFrontier(snapshotMessage);
      if (securityAware) {
        const commitments = await this._getLoadSecurityCommitments();
        if (!commitments) {
          await stream.sink([] as Iterable<Uint8Array>);
          return;
        }
        snapshotMessage.loadSecurityState = commitments;
      }
      snapshotMessage.signature = await this._signAsWriter(snapshotMessage);

      const serialized =
        this._syncMessageSerializer.serializeSyncMessage(snapshotMessage);

      // Encrypt the response.
      const [documentKeyID, documentKey] = await this._keychain.current();
      if (!documentKey) {
        throw new Error(`Document ${this.documentPath} has an empty keychain!`);
      }
      const { nonce, data } = await this._authProvider.encrypt(
        serialized,
        documentKey,
      );
      if (!nonce) {
        throw new Error(
          `Failed to encrypt snapshot response! Nonce cannot be empty`,
        );
      }
      const assembled = copyUnsharedUint8Array(
        concatUint8Arrays(documentKeyID, nonce, data),
        1,
        MAX_INITIAL_LOAD_RESPONSE_SIZE,
        'snapshot-load response',
      );
      console.log(
        `sending snapshot-load response (encrypted) for ${this.documentPath}`,
      );

      this._throwIfSecurityProviderMutationFailed();
      await stream.sink([assembled] as Iterable<Uint8Array>);
    } catch {
      console.error(
        `Error handling snapshot-load request for ${this.documentPath}`,
      );
      // Ensure the stream is closed so the requester doesn't hang.
      try {
        await stream.sink([] as Iterable<Uint8Array>);
      } catch {
        /* already closed */
      }
    }
  }

  /**
   * Handles an initial-load quorum tip-advertise request with pre-read
   * stream data. Called by the shared protocol handler in Peerborne
   * after reading and routing.
   *
   * Closes the "no quorum protocol for verifying initial document state"
   * gap tracked under issue #189 §5.4 item 2 (also bulleted in #186).
   * The wire protocol is `tipAdvertiseV1` (see `wire-protocols.ts`);
   * this method returns either an empty payload (decline) or an
   * encrypted `CRDTSyncMessage` whose advertised payload is `tipsHash`
   * (plus V4 security commitments). On V3 the hash represents the served
   * frontier; on V4 it also incorporates a canonical digest of the complete
   * state-mutating load plan. The loader on the other side compares hashes across
   * multiple peers and requires Q-of-K agreement before accepting any
   * peer's full document state. See `load-quorum.ts` for the decision
   * logic.
   *
   * Authorization mirrors the doc-load / snapshot-load handlers: when
   * signing is enabled the requester must sign the document path with
   * a key that appears in the readers or writers ACL. The response is
   * encrypted under the document's current key so a peer that does
   * not already possess the key cannot use the tip hash as an oracle
   * (key delivery is handled by the BeeKEM Welcome path).
   *
   * @internal
   * @param message The deserialized load request (already parsed by the shared handler).
   * @param stream The stream object for sending the response.
   */
  public async handleTipAdvertiseRequestData(
    message: CRDTLoadRequest,
    stream: { sink: (data: Iterable<Uint8Array>) => Promise<void> },
    securityAware = false,
  ): Promise<void> {
    try {
      this._throwIfSecurityProviderMutationFailed();
      if (
        !shouldServeInitialLoadProtocol(
          this.swarm.requireSecurityStateQuorum,
          securityAware,
        )
      ) {
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }
      // Tip-advertise runs on every `open()` from every peer that opens
      // this document, so a per-request log line scales with mesh size.
      // Drop the unconditional log entirely; the only field the handler
      // would have logged is attacker-controlled (`message`), and the
      // mismatch/unauthorized branches below already emit targeted
      // warnings when they fail.

      if (message.documentId !== this.documentPath) {
        console.warn(
          `Received a tip-advertise request for the wrong local document (${this.documentPath})`,
        );
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }
      const requestSignaturePayload = this._initialLoadRequestSignaturePayload(
        message,
        securityAware,
      );
      if (requestSignaturePayload === null) {
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }

      // Authorize the requestor. When signing is disabled, the shared helper
      // preserves the existing unsigned-load behavior.
      const authorized = await this._authorizeInitialLoadRequest(
        requestSignaturePayload,
        message.signature,
      );

      if (!authorized) {
        console.warn(
          `Rejected an unauthorized or malformed tip-advertise request for ${this.documentPath}`,
        );
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }

      // Compute the canonical tip-set hash from the document's *served*
      // frontier — the heads of the payload this peer would actually ship
      // in a `documentLoadV3` / `snapshotLoadV3` round (computed via
      // `computeServedFrontier` over `_lastSyncMessage.changes` plus
      // `_latestSnapshot?.lastChangeNodeCID`, the exact same sources
      // `handleLoadRequestData` / `handleSnapshotLoadRequestData` populate
      // into the load response).
      //
      // This used to hash `_currentFrontier()` -- the full
      // local DAG frontier (`_hashes \ _referencedAncestors`). That
      // produces a hash an honest peer cannot bind against if it holds
      // multiple concurrent heads: `_currentFrontier()` returns every
      // head (including remotely-applied tips not yet cross-linked into
      // `_lastSyncMessage.changes`), but the load response only carries
      // one head's tree, so the loader's structural derivation of the
      // served frontier produces a different (smaller) set. Hashing the
      // served frontier here closes that gap -- a probe-then-load
      // round-trip from this responder always binds against a
      // byte-identical tip set. See `_servedFrontier()` for the
      // full rationale.
      //
      // Two peers with the same `_lastSyncMessage` / `_latestSnapshot`
      // produce byte-identical hashes; see `tips-hash.ts` for the
      // canonicalization (sort + `\n` separator + SHA-256).
      const commitments = securityAware
        ? await this._getLoadSecurityCommitments()
        : undefined;
      if (securityAware && !commitments) {
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }
      const responsePlan = securityAware
        ? await this._createLoadResponsePlan(message.loadChallenge)
        : undefined;
      const servedFrontier = responsePlan
        ? this._loadResponsePlanFrontier(responsePlan)
        : this._servedFrontier();
      const hash = securityAware
        ? await loadAdvertisementHash(
            this.documentPath,
            servedFrontier,
            commitments!,
            await this._loadResponseManifestHash(responsePlan!),
          )
        : await loadAdvertisementHash(this.documentPath, servedFrontier);

      const advertisement: CRDTSyncMessage<ChangesType, PublicKey> = {
        documentId: this.documentPath,
        tipsHash: hash,
        loadSecurityState: commitments,
        loadChallenge:
          securityAware && message.loadChallenge !== undefined
            ? cloneInitialLoadChallenge(message.loadChallenge)
            : undefined,
      };

      // Sign the advertisement so the loader can verify the responder is
      // an authorized writer (the same trust bar applied to load responses
      // above). `_signAsWriter` returns '' when signing is disabled, in
      // which case the loader's pre-load verification block is also a
      // no-op -- mirrors the doc-load / snapshot-load handlers' pattern.
      advertisement.signature = await this._signAsWriter(advertisement);

      const serialized =
        this._syncMessageSerializer.serializeSyncMessage(advertisement);

      // Encrypt the response with the document's current key so that an
      // unauthorized peer that managed to connect to us but does not have
      // the key cannot read (or use as an oracle) the tip hash.
      const [documentKeyID, documentKey] = await this._keychain.current();
      if (!documentKey) {
        throw new Error(`Document ${this.documentPath} has an empty keychain!`);
      }
      const { nonce, data } = await this._authProvider.encrypt(
        serialized,
        documentKey,
      );
      if (!nonce) {
        throw new Error(
          `Failed to encrypt tip-advertise response! Nonce cannot be empty`,
        );
      }
      const assembled = copyUnsharedUint8Array(
        concatUint8Arrays(documentKeyID, nonce, data),
        1,
        securityAware
          ? MAX_SECURITY_ADVERTISE_RESPONSE_SIZE
          : MAX_TIP_ADVERTISE_RESPONSE_SIZE,
        'tip-advertise response',
      );
      console.log(
        `sending tip-advertise response (encrypted) for ${this.documentPath}`,
      );

      this._throwIfSecurityProviderMutationFailed();
      await stream.sink([assembled] as Iterable<Uint8Array>);
    } catch {
      console.error(
        `Error handling tip-advertise request for ${this.documentPath}`,
      );
      // Ensure the stream is closed so the requester doesn't hang.
      try {
        await stream.sink([] as Iterable<Uint8Array>);
      } catch {
        /* already closed */
      }
    }
  }

  /**
   * Build the deterministic binary payload used for snapshot signing/verification.
   *
   * Binary layout (big-endian integers):
   *   [0]       uint8   version (1)
   *   [1..8]    uint64  timestamp
   *   [9..12]   uint32  compactedCount
   *   [13..16]  uint32  cidLen
   *   [17..]    bytes   UTF-8(lastChangeNodeCID)
   *   [..]      uint32  stateLen
   *   [..]      bytes   stateBytes
   */
  private _buildSnapshotSignPayload(
    stateBytes: Uint8Array,
    lastChangeNodeCID: string,
    timestamp: number,
    compactedCount: number,
  ): Uint8Array {
    // Validate inputs to prevent runtime errors (e.g. BigInt(NaN) throws TypeError)
    // and silent uint32 overflow/truncation via DataView.setUint32.
    if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
      throw new Error(`Invalid snapshot timestamp: ${timestamp}`);
    }
    if (
      !Number.isInteger(compactedCount) ||
      compactedCount < 0 ||
      compactedCount > 0xffffffff
    ) {
      throw new Error(`Invalid snapshot compactedCount: ${compactedCount}`);
    }
    const cidBytes = this._encoder.encode(lastChangeNodeCID);
    if (cidBytes.length > 0xffffffff) {
      throw new Error(`lastChangeNodeCID too large: ${cidBytes.length} bytes`);
    }
    if (stateBytes.length > 0xffffffff) {
      throw new Error(`Snapshot state too large: ${stateBytes.length} bytes`);
    }
    // 1 (version) + 8 (timestamp) + 4 (compactedCount) + 4 (cidLen) + cidBytes + 4 (stateLen) + stateBytes
    const totalLen = 1 + 8 + 4 + 4 + cidBytes.length + 4 + stateBytes.length;
    const buf = new ArrayBuffer(totalLen);
    const view = new DataView(buf);
    const out = new Uint8Array(buf);
    let offset = 0;

    // version
    view.setUint8(offset, 1);
    offset += 1;

    // timestamp as uint64
    view.setBigUint64(offset, BigInt(timestamp), false);
    offset += 8;

    // compactedCount as uint32
    view.setUint32(offset, compactedCount, false);
    offset += 4;

    // lastChangeNodeCID (length-prefixed)
    view.setUint32(offset, cidBytes.length, false);
    offset += 4;
    out.set(cidBytes, offset);
    offset += cidBytes.length;

    // stateBytes (length-prefixed)
    view.setUint32(offset, stateBytes.length, false);
    offset += 4;
    out.set(stateBytes, offset);

    return out;
  }

  private async _ensureCurrentUserCanWrite() {
    this._throwIfSecurityProviderMutationFailed();
    // Check that we are a writer (allowed to write to this document).
    const canWrite = await this._writers.check(this._userPublicKey);
    this._throwIfSecurityProviderMutationFailed();
    if (canWrite !== true) {
      throw new Error(
        `Current user does not have write permissions for: ${this.documentPath}`,
      );
    }
  }

  private _throwIfSecurityProviderMutationFailed(): void {
    if (this._securityProviderMutationFailure !== undefined) {
      throw this._securityProviderMutationFailure;
    }
  }

  /** Recheck terminal retirement only after this operation owns the slot. */
  private _runInMutationQueue<Result>(
    operation: () => Promise<Result>,
  ): Promise<Result> {
    return this._mutationQueue.run(async () => {
      this._throwIfSecurityProviderMutationFailed();
      return operation();
    });
  }

  private _retireAfterAmbiguousSecurityProviderMutation(
    operation: string,
    cause?: unknown,
  ): never {
    if (this._securityProviderMutationFailure === undefined) {
      this._securityProviderMutationFailure = new Error(
        `[${this.documentPath}] ${operation} has an ambiguous ACL or keychain ` +
          `provider outcome; discard this document and its ACL/keychain ` +
          `provider instances, then create a fresh instance`,
        cause === undefined ? undefined : { cause },
      );
      // Invalidate before any asynchronous cleanup so an in-flight verifier's
      // captured authorization version cannot commit after retirement.
      this._invalidateWriterKeyCache();
      // Do not await cleanup from inside a membership/BeeKEM transition. The
      // marker is authoritative immediately; close is best-effort resource
      // release for an already-open instance.
      void this.close().catch(() => undefined);
    }
    throw this._securityProviderMutationFailure;
  }

  private _retireAfterIncompleteInitialLoad(
    cause?: unknown,
  ): never {
    if (this._securityProviderMutationFailure === undefined) {
      this._securityProviderMutationFailure = new Error(
        `[${this.documentPath}] initial-load application failed ` +
          `after live document, snapshot, ACL, or keychain state mutation began; ` +
          `discard this document and its ACL/keychain provider instances, then ` +
          `create a fresh instance`,
        cause === undefined ? undefined : { cause },
      );
      this._invalidateWriterKeyCache();
      void this.close().catch(() => undefined);
    }
    throw this._securityProviderMutationFailure;
  }

  private _commitPreparedKeychainState(
    prepared: { commit(): void },
    operation: string,
  ): void {
    this._throwIfSecurityProviderMutationFailed();
    try {
      prepared.commit();
    } catch (error) {
      // The staged-keychain contract requires atomic commit or
      // throw-before-mutation. Retire even when a custom implementation
      // violates that contract: after a rejection the live state cannot be
      // distinguished safely from a partially committed provider state.
      this._retireAfterAmbiguousSecurityProviderMutation(operation, error);
    }
  }

  private _requireMembershipWireChanges(
    changes: ChangesType,
    operation: string,
  ): ChangesType {
    if (changes === undefined) {
      this._retireAfterAmbiguousSecurityProviderMutation(
        operation,
        new TypeError(
          'provider returned an undefined change that the sync wire format cannot represent',
        ),
      );
    }
    return changes;
  }

  /**
   * Send a load request over the given stream and apply the response.
   *
   * @returns `true` if a non-empty response was received and successfully synced.
   *   Returns `false` when:
   *   - The peer responded with an empty payload (e.g., peer has no snapshot).
   *   - The response payload is too short to contain a valid encrypted header.
   *   - The encryption keyID is not recognized (key not in our keychain).
   *   - The response documentId did not match the expected document.
   *   - Writer signature verification failed (when signing is enabled).
   *   - `sync()` rejected the response (e.g., invalid inner signatures or auth failure).
   *
   * @throws When `decrypt()` itself fails (i.e., the keyID was recognized but
   *   decryption produced no output), or on other unexpected protocol errors.
   *   Callers (e.g., `load()`) should wrap calls in a try/catch and handle both a
   *   `false` return value (by trying the next available peer) and thrown errors.
   */
  private async _sendLoadRequestAndSync(
    stream: {
      sink: (data: Iterable<Uint8Array>) => Promise<void>;
      source: AsyncIterable<Uint8ArrayList | Uint8Array>;
      abort?: (err: Error) => void;
    },
    serializedRequest: Uint8Array,
    expectedTipsHashHex: string | null = null,
    securityAware = false,
    trustedLoadSecurityCommitments?: LoadSecurityCommitments,
    signerAuthorization?: InitialLoadSignerAuthoritySnapshot<PublicKey>,
    expectedLoadChallenge?: Uint8Array,
    signal?: AbortSignal,
    responseReceived?: () => void,
    requiredResponseSigner?: PublicKey,
    maxResponseBytes = MAX_INITIAL_LOAD_RESPONSE_SIZE,
    requireCompleteCids = false,
    admitStateMutation?: () => void,
  ): Promise<boolean> {
    if (signal?.aborted) throw signal.reason;
    await pipe([serializedRequest], stream.sink);
    if (signal?.aborted) throw signal.reason;
    return await pipe(
      stream.source,
      async (source: AsyncIterable<Uint8ArrayList | Uint8Array>) => {
        let assembled: Uint8Array;
        const effectiveMaxResponseBytes = Math.min(
          maxResponseBytes,
          MAX_INITIAL_LOAD_RESPONSE_SIZE,
        );
        try {
          assembled = await readUint8Iterable(
            source,
            effectiveMaxResponseBytes,
          );
        } catch (cause) {
          if (cause instanceof RangeError) {
            try {
              stream.abort?.(
                new Error('initial-load response exceeded the wire-size cap'),
              );
            } catch {
              // The underlying stream may already have torn itself down when
              // its async iterator was cancelled.
            }
            throw new _QuorumBindCheckFailedError(
              '(oversized load response)',
              `Initial-load response exceeded ${effectiveMaxResponseBytes} wire bytes`,
            );
          }
          throw cause;
        }

        // The bounded remote-response phase is complete. Check cancellation
        // before disarming so a timeout that won the race cannot fall through
        // into authentication or document mutation on a detached task.
        if (signal?.aborted) throw signal.reason;
        responseReceived?.();

        // Empty response means the peer couldn't serve this request.
        if (assembled.length === 0) {
          return false;
        }

        // Decrypt the response. Extract the keyID from the header and
        // look it up in the keychain. Responses shorter than the encryption
        // header are treated as malformed and rejected.
        const headerLength =
          this._keychainProvider.keyIDLength + this._authProvider.nonceBits;
        let rawContent: Uint8Array;
        if (assembled.length <= headerLength) {
          // Too short to contain a valid encrypted payload -- reject.
          console.warn(
            `Load response for ${this.documentPath}: payload too short (${assembled.length} <= ${headerLength}), skipping peer`,
          );
          return false;
        }

        const blockKeyID = assembled.slice(
          0,
          this._keychainProvider.keyIDLength,
        );
        const key = this._keychain.getKey(blockKeyID);
        if (key) {
          const blockNonce = assembled.slice(
            this._keychainProvider.keyIDLength,
            headerLength,
          );
          const blockData = assembled.slice(headerLength);
          const decrypted = await this._authProvider.decrypt(
            blockData,
            key,
            blockNonce,
          );
          if (!decrypted) {
            throw new Error(
              `Failed to decrypt load response for ${this.documentPath}`,
            );
          }
          rawContent = decrypted;
        } else {
          // KeyID not recognized -- peer sent encrypted data with a key we
          // don't have. Fail and let the caller try the next peer.
          console.warn(
            `Load response for ${this.documentPath}: unrecognized keyID, skipping peer`,
          );
          return false;
        }

        let message: CRDTSyncMessage<ChangesType, PublicKey>;
        try {
          message = this._snapshotDecodedSyncMessage(
            this._syncMessageSerializer.deserializeSyncMessage(rawContent),
            'initial-load response',
          );
        } catch {
          console.warn(
            `Load response for ${this.documentPath} has an unstable or malformed codec value`,
          );
          return false;
        }
        if (message.documentId !== this.documentPath) {
          console.warn(
            `Load response documentId mismatch for ${this.documentPath}, skipping peer`,
          );
          return false;
        }
        if (
          securityAware &&
          !initialLoadChallengeEquals(
            expectedLoadChallenge,
            message.loadChallenge,
          )
        ) {
          throw new _QuorumBindCheckFailedError(
            '(load challenge mismatch)',
            "Security-aware load response did not echo this load round's challenge",
          );
        }
        // Bound and canonicalize the complete untrusted V4 response before
        // signature identification reserializes it. This must precede every
        // recursive/custom serializer boundary: an oversized/deep tree is a
        // bind failure, not a chance to exhaust the verifier's stack first.
        let responseManifestHash: Uint8Array | undefined;
        if (securityAware) {
          try {
            responseManifestHash =
              await this._loadResponseManifestHash(message);
          } catch (cause) {
            throw new _QuorumBindCheckFailedError(
              '(invalid response manifest)',
              `Security-aware load response has a malformed or over-limit ` +
                `state manifest: ${
                  cause instanceof Error ? cause.message : String(cause)
                }`,
            );
          }
        }
        // Verify the outer message signature before applying changes.
        // On subsequent loads (writers already known), verify against the
        // existing trusted writer set BEFORE sync() mutates state. This
        // prevents a malicious peer from injecting ACL changes that add
        // its own key.
        // V4 always verifies against the signer authorities captured before
        // the probe round. The legacy path retains its prior bootstrap
        // behavior for compatibility.
        // Capture the writer ACL generation used for this outer-envelope
        // authentication. `sync(message, false)` below intentionally skips a
        // second signature check because quorum-bound responses have their
        // inline changes stripped after verification. The captured version is
        // therefore the authorization lease: any writer mutation before the
        // first apply step invalidates the load.
        if ((this._writerMutationsInFlight ?? 0) !== 0) return false;
        if (securityAware && signerAuthorization === undefined) return false;
        const preLoadWriterVersion = securityAware
          ? signerAuthorization!.writerVersion
          : (this._writerKeysVersion ?? 0);
        if (
          securityAware &&
          ((this._writerKeysVersion ?? 0) !== preLoadWriterVersion ||
            this._securityProviderMutationFailure !== undefined)
        ) {
          return false;
        }
        const preLoadWriters = await this._getWriterKeys();
        const loadWriterAuthorizationIsCurrent = () =>
          this._securityProviderMutationFailure === undefined &&
          (this._writerMutationsInFlight ?? 0) === 0 &&
          (this._writerKeysVersion ?? 0) === preLoadWriterVersion;
        if (!loadWriterAuthorizationIsCurrent()) {
          return false;
        }

        let requiredSignerAuthenticated = true;
        if (requiredResponseSigner !== undefined) {
          const { signature, ...messageWithoutSignature } = message;
          if (signature === undefined) return false;
          let signatureBytes: Uint8Array;
          try {
            signatureBytes = this._deserializeSignature(signature);
          } catch {
            return false;
          }
          try {
            requiredSignerAuthenticated =
              (await this._authProvider.verify(
                this._syncMessageSerializer.serializeSyncMessage(
                  messageWithoutSignature,
                ),
                requiredResponseSigner,
                signatureBytes,
              )) === true;
          } catch {
            requiredSignerAuthenticated = false;
          }
        }

        let authenticated = false;
        let snapshotWriterKeys: readonly PublicKey[] = preLoadWriters;
        if (securityAware) {
          authenticated =
            signerAuthorization !== undefined &&
            (await this._identifyInitialLoadSignerAuthority(
              message,
              signerAuthorization.authorities,
            )) !== null;
          if (authenticated && preLoadWriters.length > 0) {
            // The quorum round may have captured an authority that was removed
            // before this full response arrived. Existing replicas require a
            // signature from the current ACL as well as the round's pinned
            // authority set.
            authenticated = await this._verifyInitialLoadEnvelope(
              message,
              preLoadWriters,
            );
          } else if (authenticated && signerAuthorization !== undefined) {
            snapshotWriterKeys = signerAuthorization.authorities.map(
              (authority) => authority.publicKey,
            );
          }
        } else {
          const bootstrapWriterKeys =
            preLoadWriters.length === 0
              ? await this._getBootstrapWriterKeys()
              : [];
          authenticated = await this._verifyInitialLoadEnvelope(
            message,
            preLoadWriters,
            bootstrapWriterKeys,
          );
          if (preLoadWriters.length === 0) {
            snapshotWriterKeys = bootstrapWriterKeys;
          }
        }
        authenticated &&= requiredSignerAuthenticated;
        if (
          requiredSignerAuthenticated &&
          requiredResponseSigner !== undefined
        ) {
          snapshotWriterKeys = [requiredResponseSigner];
        }
        if (!authenticated) {
          console.warn(
            `Load response for ${this.documentPath} failed trusted writer authentication, skipping peer`,
          );
          return false;
        }
        if (!loadWriterAuthorizationIsCurrent()) {
          return false;
        }
        if (signal?.aborted) throw signal.reason;
        let initialLoadStateMutationStarted = false;
        const initialLoadAuthorization: InitialLoadSyncAuthorization<PublicKey> =
          {
            writerKeys: snapshotWriterKeys,
            writerVersion: preLoadWriterVersion,
            onStateMutation: () => {
              if (signal?.aborted) throw signal.reason;
              const deferredBlockSignal =
                initialLoadAuthorization.deferredBlockBudget?.signal;
              if (deferredBlockSignal?.aborted) {
                throw deferredBlockSignal.reason;
              }
              if (initialLoadStateMutationStarted) return;
              // Invitation deadlines may be disarmed only once the serialized
              // mutation slot is actually about to change live state.
              admitStateMutation?.();
              initialLoadStateMutationStarted = true;
            },
          };
        const failInitialLoadInMutationSlot = (cause: unknown): void => {
          if (initialLoadStateMutationStarted) {
            this._retireAfterIncompleteInitialLoad(cause);
          }
        };
        const finalizeInitialLoadInMutationSlot = async (
          applied: boolean,
          verifyComplete?: () => void | Promise<void>,
        ): Promise<boolean> => {
          if (!applied) {
            if (initialLoadStateMutationStarted) {
              this._retireAfterIncompleteInitialLoad(
                new Error('authenticated sync returned false'),
              );
            }
            return false;
          }
          await verifyComplete?.();
          return true;
        };
        initialLoadAuthorization.failInMutationSlot =
          failInitialLoadInMutationSlot;
        initialLoadAuthorization.finalizeInMutationSlot = (applied) =>
          finalizeInitialLoadInMutationSlot(applied);
        const maxEncryptedBlockBytes = Math.min(
          MAX_DEFERRED_BLOCK_ENCRYPTED_BYTES,
          effectiveMaxResponseBytes,
        );
        const maxDecodedBlockBytes = Math.min(
          MAX_DEFERRED_BLOCK_DECODED_BYTES,
          effectiveMaxResponseBytes,
        );
        const maxEncryptedAggregateBytes = Math.min(
          MAX_INITIAL_LOAD_DEFERRED_ENCRYPTED_BYTES,
          effectiveMaxResponseBytes,
        );
        const maxDecodedAggregateBytes = Math.min(
          MAX_INITIAL_LOAD_DEFERRED_DECODED_BYTES,
          effectiveMaxResponseBytes,
        );
        const configuredDeferredBlockTimeout = this.swarm?.loadQuorumTimeoutMs;
        const deferredBlockTimeoutMs =
          Number.isSafeInteger(configuredDeferredBlockTimeout) &&
          configuredDeferredBlockTimeout > 0
            ? configuredDeferredBlockTimeout
            : 5_000;
        const createDeferredBlockBudget = (initialEncryptedBytes = 0) => {
          const controller = new AbortController();
          let timer: ReturnType<typeof setTimeout> | undefined;
          let started = false;
          const forwardOuterAbort = (): void => {
            if (!controller.signal.aborted) {
              controller.abort(
                signal?.reason instanceof Error
                  ? signal.reason
                  : new Error('initial-load response aborted'),
              );
            }
          };
          if (signal?.aborted) {
            forwardOuterAbort();
          } else {
            signal?.addEventListener('abort', forwardOuterAbort, {
              once: true,
            });
          }
          return {
            budget: {
              maxEncryptedBlockBytes,
              maxEncryptedAggregateBytes,
              maxDecodedBlockBytes,
              maxDecodedAggregateBytes,
              encryptedBytes: initialEncryptedBytes,
              decodedBytes: 0,
              signal: controller.signal,
              begin: (): void => {
                if (started) return;
                started = true;
                // Blockstore implementations are required to cooperate with
                // AbortSignal. Do not race and detach `_getBlock`: a custom
                // implementation that ignores cancellation may still hang,
                // but a detached task could later mutate authenticated state.
                if (!controller.signal.aborted) {
                  timer = setTimeout(() => {
                    controller.abort(
                      new Error(
                        'initial-load deferred block fetch timed out',
                      ),
                    );
                  }, deferredBlockTimeoutMs);
                }
              },
            } satisfies InitialLoadDeferredBlockBudget,
            dispose: (): void => {
              if (timer !== undefined) clearTimeout(timer);
              signal?.removeEventListener('abort', forwardOuterAbort);
            },
          };
        };

        // A V4 peer does not get to choose the security tuple merely because
        // a quorum of peers repeats it. Match the locally captured trust
        // anchor before examining or staging any served CRDT/snapshot state.
        // This guard applies even if a caller accidentally omits the expected
        // frontier hash, so every V4 full-document and snapshot candidate is
        // fail-closed independently of the later frontier bind.
        if (
          securityAware &&
          !loadSecurityCommitmentsEqual(
            trustedLoadSecurityCommitments,
            message.loadSecurityState,
          )
        ) {
          throw new _QuorumBindCheckFailedError(
            '(untrusted security tuple)',
            'Security-aware load response does not match the locally trusted security tuple',
          );
        }
        // Quorum frontier binding (#186 / #189 §5.4.2). When the loader
        // ran a quorum probe round, the served full-load payload must
        // describe the same value the responder voted for. V3 binds the
        // structurally-derived frontier; V4 additionally binds the complete
        // node/edge, snapshot, and keychain response manifest. Done BEFORE
        // `this.sync(...)`, so mismatch never mutates the document.
        //
        // CRITICAL: the bind decision is derived from the actual served
        // payload, not from the responder-supplied `message.tips`. Trusting
        // only that attestation would permit matching tip CIDs alongside a
        // different `changes` / `snapshot` payload.
        // The advertised-vs-claimed check would pass even though the
        // application would receive divergent content. PR #284 r7
        // Copilot review caught this; the fix delegates frontier
        // computation to `computeServedFrontier`; V4 then combines that
        // frontier with `loadResponseManifestHash`, recomputed from the actual
        // response rather than a responder-supplied manifest field.
        //
        // We additionally REQUIRE `message.tips` on every V3/V4 quorum-
        // enabled load response (PR #284 r9 Copilot review, issue #1).
        // The quorum load-response contract mandates the responder commit
        // to an explicit frontier attestation; a responder that omits
        // `tips` is recorded as a per-peer bind failure so the loader
        // retries the next agreeing peer. The derived bind check above
        // is the primary defense; the explicit `tips` requirement
        // ensures protocol compliance AND that the defense-in-depth
        // check below (verifying `tips` matches the structurally-
        // derived served frontier) actually runs. Catches the
        // responder-equivocation mode where `tips` and `changes` were
        // assembled inconsistently — e.g. a response that claims extra
        // heads in `tips` that are not present in the served tree.
        //
        // Throws the module-private `_QuorumBindCheckFailedError` on
        // mismatch so the surrounding `load()` loop can record this
        // peer as a bind-failure and proceed to the NEXT peer in the
        // agreeing cohort. Previously this site threw
        // `LoadQuorumFailedError` directly, which `load()` re-raised --
        // preventing later agreeing peers from being tried. `load()` only escalates to
        // a structured `LoadQuorumFailedError` with reason
        // `bind-check-failed-all-agreeing-peers`
        // when EVERY narrowed peer fails the bind step.
        if (expectedTipsHashHex !== null) {
          // V4's manifest walk validates node/edge/occurrence/payload bounds
          // before any other traversal of the adversary-controlled tree.
          // It also canonicalizes repeated sparse/full CID descriptions and
          // rejects cycles or conflicts before frontier derivation.
          // Derive the served frontier STRUCTURALLY from the payload
          // the responder is asking us to apply -- not from the
          // responder's own `tips` attestation.
          const servedFrontier = computeServedFrontier(
            message.changeId,
            message.changes,
            message.snapshot?.lastChangeNodeCID,
          );
          // V4 binds the complete state-mutating response plan, not just its
          // heads. Recompute from the received tree/snapshot/keychain before
          // stripping inline changes or invoking sync(). A same-frontier tree
          // with an added child, changed node kind/edge, different snapshot,
          // or different keychain delta therefore cannot preserve the vote.
          const servedBytes = securityAware
            ? await loadAdvertisementHash(
                this.documentPath,
                servedFrontier,
                message.loadSecurityState!,
                responseManifestHash!,
              )
            : await loadAdvertisementHash(this.documentPath, servedFrontier);
          const servedHex = loadAdvertisementHashToHex(servedBytes);
          if (!constantTimeHexEquals(expectedTipsHashHex, servedHex)) {
            console.warn(
              `[${this.documentPath}] Quorum response binding FAILED: ` +
                `expected tipsHash=${expectedTipsHashHex.slice(0, 12)}... but ` +
                `the served response hashes to ${servedHex.slice(0, 12)}.... ` +
                `The response may have advanced or been assembled ` +
                `inconsistently; excluding it from this load round.`,
            );
            throw new _QuorumBindCheckFailedError(
              servedHex,
              `Quorum response binding mismatch (served payload): expected ` +
                `${expectedTipsHashHex.slice(0, 12)}... got ${servedHex.slice(0, 12)}...`,
            );
          }
          // Protocol compliance: under the V3/V4 load-response contract,
          // a quorum-enabled load REQUIRES `message.tips` to be present
          // on the response so the responder commits to an explicit
          // frontier attestation alongside the served payload. The
          // derived response-binding check above is the primary defense; this
          // explicit `Array.isArray(message.tips)` guard ensures a v3
          // responder that omits `tips` is recorded as a per-peer bind
          // failure (so the loader retries the NEXT agreeing peer)
          // rather than silently passing on the structural-hash check
          // alone. Without this guard, a responder could violate the
          // protocol contract — and a defense-in-depth check that
          // catches contradictions between `tips` and the served payload
          // would never run because the `Array.isArray` branch would
          // simply skip.
          if (!Array.isArray(message.tips)) {
            console.warn(
              `[${this.documentPath}] Quorum frontier binding FAILED: ` +
                `quorum-enabled load response omitted required \`tips\` ` +
                `attestation (quorum protocol violation). Recording peer as ` +
                `bind-failed; loader will try the next agreeing peer.`,
            );
            throw new _QuorumBindCheckFailedError(
              '(missing tips)',
              `Quorum frontier binding: responder omitted required \`tips\` ` +
                `attestation on quorum-enabled load response.`,
            );
          }
          // Defense-in-depth: the responder-supplied `tips` must hash
          // to the same value as the structurally-derived served
          // frontier. A peer whose attested `tips` contradicts their
          // own served payload (e.g. claims extra heads that are not
          // present in the served tree) is internally inconsistent.
          const advertisedBytes = securityAware
            ? await loadAdvertisementHash(
                this.documentPath,
                message.tips,
                message.loadSecurityState!,
                responseManifestHash!,
              )
            : await loadAdvertisementHash(this.documentPath, message.tips);
          const advertisedHex = loadAdvertisementHashToHex(advertisedBytes);
          if (!constantTimeHexEquals(servedHex, advertisedHex)) {
            console.warn(
              `[${this.documentPath}] Quorum frontier binding FAILED: ` +
                `served payload frontier hashes to ${servedHex.slice(0, 12)}... ` +
                `but responder advertised tips hashing to ${advertisedHex.slice(0, 12)}.... ` +
                `Responder's own attestation contradicts the served payload.`,
            );
            throw new _QuorumBindCheckFailedError(
              advertisedHex,
              `Quorum frontier binding mismatch (advertised vs served): ` +
                `advertised ${advertisedHex.slice(0, 12)}... served ` +
                `${servedHex.slice(0, 12)}...`,
            );
          }

          // Content-address verification.
          //
          // The structural bind above proves Q peers agree on the
          // FRONTIER CIDs and that those CIDs appear as keys in the
          // served tree. It does NOT prove the inline `change` content
          // for each CID actually hashes back to that CID -- a Byzantine
          // peer could vote for the agreed frontier and then serve a
          // tree whose `children` map uses the agreed CIDs as keys but
          // whose inline `change` values are forged.
          //
          // On a FIRST load (`_writers` empty), per-change signature
          // verification inside the CRDT merge cannot fire -- there are
          // no writer keys to verify against -- so forged inline content
          // would otherwise reach `_crdtProvider.remoteChange`/
          // `_mergeWriters`/`_mergeReaders` unchecked.
          //
          // Defense: strip inline `change` content from every node in
          // the served tree before applying. `sync()` then routes each
          // CID through `missingDocumentHashes -> _getBlock(cid) ->
          // helia.blockstore.get(cid)`, which content-validates the
          // fetched bytes against the CID intrinsically (a Byzantine
          // peer cannot serve bytes that hash to a CID they did not
          // produce, and bitswap will retrieve from an honest peer in
          // the agreeing cohort that does hold the legitimate block).
          //
          // Cost: N bitswap roundtrips instead of one inline load. Paid
          // only on quorum-bound loads; the legacy `winningHashHex ===
          // null` path is untouched.
          //
          // Snapshots: `CRDTSnapshotNode.state` is NOT CID-addressed --
          // the snapshot's `lastChangeNodeCID` only identifies the
          // boundary, not the snapshot bytes. Defense is the writer
          // signature (`_verifySnapshotSignature`), which fails on
          // first load (writers empty) and rejects the snapshot
          // automatically. On subsequent loads writers are known and
          // the signature is the source of truth. We drop the snapshot
          // entirely on first load below so a malicious snapshot
          // signature forged with an attacker-controlled key (which
          // would be admitted if the inline ACL pre-pass were trusted)
          // never reaches `applySnapshot`.
          // Capture every CID before stripping. The strict apply path returns
          // false on any deferred-block failure, and this post-check still
          // verifies complete installation. A failure before mutation remains
          // retryable; once the mutation admission hook fires, any incomplete
          // result terminally retires the instance instead of applying a second
          // candidate to possibly-partial state.
          const expectedCids = collectAllCidsInTree(
            message.changeId,
            message.changes,
          );

          stripInlineChanges(message.changes);
          const preLoadWriterCount = (await this._writers.users()).length;
          if (
            preLoadWriterCount === 0 &&
            message.snapshot &&
            !this._requiresAuthenticatedInitialLoad()
          ) {
            console.warn(
              `[${this.documentPath}] Dropping snapshot from quorum-bound ` +
                `first load: writers ACL is not yet populated so the ` +
                `snapshot signature cannot be verified. The receiver will ` +
                `rebuild state from individual change blocks via Helia ` +
                `(each block content-validated against its CID).`,
            );
            message.snapshot = undefined;
          }

          // Snapshot-only first-load detection: after the snapshot drop
          // above, if the response now carries NO changes tree AND NO
          // snapshot, the responder served us nothing usable. Without
          // this guard the path falls through to `sync(message, false)`
          // (which returns `true` for a vacuously-empty message because
          // there is nothing to merge / reject) and this method reports
          // success — `load()` then returns `true` with neither state
          // applied nor an opportunity to retry. Treat as a per-peer
          // bind failure so the agreeing-cohort load loop tries the
          // next peer (which may serve a real changes tree). See
          // PR #284 r18 Copilot review.
          if (message.changes === undefined && message.snapshot === undefined) {
            console.warn(
              `[${this.documentPath}] Quorum-bound first-load response ` +
                `carries neither a changes tree nor a snapshot after the ` +
                `defensive snapshot drop. Treating as bind failure so the ` +
                `loader tries the next agreeing peer.`,
            );
            throw new _QuorumBindCheckFailedError(
              '(snapshot-only first-load)',
              `Quorum-bound first-load response had only a snapshot (now ` +
                `dropped because writers are not yet populated) and no ` +
                `changes tree; no state can be applied.`,
            );
          }

          // PRE-FETCH gate.
          //
          // A POST-sync `_hashes`-coverage check alone is insufficient because
          // `sync()` mutates the document as each fetched block lands
          // -- so a missing CID would still leave the document
          // partially mutated by the time the post-check threw a bind
          // failure. To keep a failed prefetch from altering local state,
          // pull every required block from Helia
          // here (BEFORE `sync()` is allowed to mutate). Helia's
          // blockstore content-validates each fetch against its CID
          // intrinsically; bitswap retrieves from any peer in the swarm
          // that holds the legitimate block. If ANY fetch fails (CID
          // not retrievable from any peer, content/CID mismatch, or
          // a local deadline), throw a per-peer bind failure before sync --
          // the load loop can cleanly retry the
          // next peer in the agreeing cohort, or escalate to
          // `bind-check-failed-all-agreeing-peers` if every peer
          // exhausts.
          //
          // The worker pool bounds stream fan-out, while per-block and
          // aggregate encrypted byte accounting bounds a candidate's bitswap
          // work. The subsequent sync re-reads locally cached blocks with the
          // same per-block cap, continues the encrypted aggregate counter, and
          // separately accounts decoded plaintext.
          let prefetchedEncryptedBytes = 0;
          if (expectedCids.length > 0) {
            const missingCids: string[] = [];
            let nextIndex = 0;
            let prefetchBudgetFailure:
              | _DeferredBlockBudgetExceededError
              | undefined;
            const prefetchController = new AbortController();
            const configuredPrefetchTimeout = this.swarm.loadQuorumTimeoutMs;
            const prefetchTimeoutMs =
              Number.isSafeInteger(configuredPrefetchTimeout) &&
              configuredPrefetchTimeout > 0
                ? configuredPrefetchTimeout
                : 5_000;
            let prefetchTimer: ReturnType<typeof setTimeout> | undefined;
            let prefetchTimedOut = false;
            const workerCount = Math.min(
              LOAD_BLOCK_MAX_CONCURRENCY,
              expectedCids.length,
            );
            const accountEncryptedBytes = (byteLength: number): void => {
              const nextBytes = prefetchedEncryptedBytes + byteLength;
              if (nextBytes > maxEncryptedAggregateBytes) {
                throw new _DeferredBlockBudgetExceededError(
                  `Initial-load deferred blocks exceeded ${maxEncryptedAggregateBytes} aggregate encrypted bytes`,
                );
              }
              prefetchedEncryptedBytes = nextBytes;
            };
            const worker = async (): Promise<void> => {
              while (true) {
                if (prefetchController.signal.aborted) return;
                const i = nextIndex++;
                if (i >= expectedCids.length) return;
                const cidStr = expectedCids[i]!;
                try {
                  const cid = CID.parse(cidStr);
                  await this._prefetchInitialLoadBlock(
                    cid,
                    prefetchController.signal,
                    maxEncryptedBlockBytes,
                    accountEncryptedBytes,
                  );
                } catch (error) {
                  if (error instanceof _DeferredBlockBudgetExceededError) {
                    prefetchBudgetFailure ??= error;
                    prefetchController.abort(error);
                    return;
                  }
                  if (prefetchController.signal.aborted) return;
                  missingCids.push(cidStr);
                }
              }
            };
            const workers = Promise.all(
              Array.from({ length: workerCount }, () => worker()),
            );
            const deadline = new Promise<never>((_, reject) => {
              prefetchTimer = setTimeout(() => {
                prefetchTimedOut = true;
                const error = new Error(
                  'initial-load block prefetch timed out',
                );
                prefetchController.abort(error);
                reject(error);
              }, prefetchTimeoutMs);
            });
            try {
              await Promise.race([workers, deadline]);
            } catch (error) {
              if (prefetchTimedOut) {
                throw new _QuorumBindCheckFailedError(
                  '(prefetch-timeout)',
                  `Quorum-bound load pre-fetch exceeded ${prefetchTimeoutMs}ms; ` +
                    `aborting before sync() so document state is unchanged`,
                );
              }
              throw error;
            } finally {
              if (prefetchTimer !== undefined) clearTimeout(prefetchTimer);
              if (!prefetchController.signal.aborted) {
                prefetchController.abort();
              }
            }
            if (prefetchBudgetFailure !== undefined) {
              throw new _QuorumBindCheckFailedError(
                '(prefetch-block-budget-exceeded)',
                `${prefetchBudgetFailure.message}; aborting before sync() so document state is unchanged`,
              );
            }
            if (missingCids.length > 0) {
              console.warn(
                `[${this.documentPath}] Quorum-bound load pre-fetch ` +
                  `failed: ${missingCids.length} of ${expectedCids.length} ` +
                  `expected CIDs were not retrievable from Helia (e.g. ` +
                  `${missingCids
                    .slice(0, 3)
                    .map((c) => c.slice(0, 12) + '...')
                    .join(', ')}). Recording peer as bind-failed BEFORE ` +
                  `any state mutation; the loader will try the next ` +
                  `agreeing peer with a clean document.`,
              );
              throw new _QuorumBindCheckFailedError(
                '(prefetch-missing-blocks)',
                `Quorum-bound load pre-fetch could not retrieve ` +
                  `${missingCids.length} of ${expectedCids.length} expected ` +
                  `CIDs from Helia; aborting before sync() so document ` +
                  `state is unchanged.`,
              );
            }
          }

          const verifyQuorumCidCoverage = (): void => {
            const missingCids: string[] = [];
            for (const cid of expectedCids) {
              if (!this._hashes.has(cid)) missingCids.push(cid);
            }
            if (missingCids.length === 0) return;
            if (initialLoadStateMutationStarted) {
              this._retireAfterIncompleteInitialLoad(
                new Error(
                  `post-sync CID coverage failed for ${missingCids.length} blocks`,
                ),
              );
            }
            console.warn(
              `[${this.documentPath}] Quorum-bound load did not complete: ` +
                `${missingCids.length} of ${expectedCids.length} expected ` +
                `CIDs were not fetched from Helia (e.g. ${missingCids
                  .slice(0, 3)
                  .map((c) => c.slice(0, 12) + '...')
                  .join(', ')}). No live state mutation was admitted, so the ` +
                `peer is bind-failed and the loader may try the next agreeing peer.`,
            );
            throw new _QuorumBindCheckFailedError(
              '(missing-blocks)',
              `Quorum-bound load completed sync() but ${missingCids.length} ` +
                `of ${expectedCids.length} expected CIDs were not retrievable; ` +
                `served tree had stripped inline content and bitswap could ` +
                `not retrieve the missing blocks.`,
            );
          };
          initialLoadAuthorization.finalizeInMutationSlot = (applied) =>
            finalizeInitialLoadInMutationSlot(
              applied,
              verifyQuorumCidCoverage,
            );
          const deferredBlockLease = createDeferredBlockBudget(
            prefetchedEncryptedBytes,
          );
          initialLoadAuthorization.deferredBlockBudget =
            deferredBlockLease.budget;
          this._initialLoadSyncAuthorizations ??= new WeakMap();
          this._initialLoadSyncAuthorizations.set(
            message as object,
            initialLoadAuthorization,
          );
          let syncResult: boolean;
          try {
            syncResult = await this.sync(message, false);
          } catch (cause) {
            if (initialLoadStateMutationStarted) {
              this._retireAfterIncompleteInitialLoad(cause);
            }
            throw cause;
          } finally {
            this._initialLoadSyncAuthorizations.delete(message as object);
            deferredBlockLease.dispose();
          }
          if (!syncResult) {
            if (initialLoadStateMutationStarted) {
              this._retireAfterIncompleteInitialLoad(
                new Error('authenticated sync returned false'),
              );
            }
            console.warn(
              `sync rejected message during load for ${this.documentPath}`,
            );
            // Return false so the caller tries the next peer.
            return false;
          }

          // Post-sync verification: every
          // CID we expected from the (stripped) served tree must have
          // landed in `_hashes` via either inline application (for the
          // non-stripped path this branch never reaches) or via the
          // `_getBlock(cid)` Helia fetch path inside
          // `_syncDocumentChanges`. A missing CID means bitswap could
          // not retrieve that block; without surfacing this the load
          // would silently report success with a partial document.
          verifyQuorumCidCoverage();

          return true;
        }

        const deferredBlockLease = createDeferredBlockBudget();
        initialLoadAuthorization.deferredBlockBudget =
          deferredBlockLease.budget;
        const snapshotBoundaryBeforeSync =
          this._latestSnapshot?.lastChangeNodeCID;
        const verifyInvitationCompleteness = async (): Promise<void> => {
          if (!requireCompleteCids) return;
          await syncInvitationMessageCompletely(
            message,
            this._hashes,
            async () => true,
            'catch-up',
            {
              provenSnapshotBoundariesBeforeSync:
                snapshotBoundaryBeforeSync === undefined
                  ? undefined
                  : new Set([snapshotBoundaryBeforeSync]),
              isSnapshotApplied: () =>
                this._latestSnapshot === message.snapshot,
            },
          );
        };
        initialLoadAuthorization.finalizeInMutationSlot = (applied) =>
          finalizeInitialLoadInMutationSlot(
            applied,
            verifyInvitationCompleteness,
          );
        const applyAuthenticatedLoad = async (): Promise<boolean> => {
          if (signal?.aborted) throw signal.reason;
          if (admitStateMutation !== undefined) {
            return this._runInMutationQueue(async () => {
              if (signal?.aborted) throw signal.reason;
              return this._syncUnlocked(
                message,
                false,
                initialLoadAuthorization,
              );
            });
          }
          this._initialLoadSyncAuthorizations ??= new WeakMap();
          this._initialLoadSyncAuthorizations.set(
            message as object,
            initialLoadAuthorization,
          );
          try {
            return await this.sync(message, false);
          } finally {
            this._initialLoadSyncAuthorizations.delete(message as object);
          }
        };
        let syncResult: boolean;
        try {
          syncResult = requireCompleteCids
            ? await syncInvitationMessageCompletely(
                message,
                this._hashes,
                applyAuthenticatedLoad,
                'catch-up',
                {
                  provenSnapshotBoundariesBeforeSync:
                    snapshotBoundaryBeforeSync === undefined
                      ? undefined
                      : new Set([snapshotBoundaryBeforeSync]),
                  isSnapshotApplied: () =>
                    this._latestSnapshot === message.snapshot,
                },
              )
            : await applyAuthenticatedLoad();
        } catch (cause) {
          if (initialLoadStateMutationStarted) {
            this._retireAfterIncompleteInitialLoad(cause);
          }
          throw cause;
        } finally {
          deferredBlockLease.dispose();
        }
        if (!syncResult) {
          if (initialLoadStateMutationStarted) {
            this._retireAfterIncompleteInitialLoad(
              new Error('authenticated sync returned false'),
            );
          }
          console.warn(
            `sync rejected message during load for ${this.documentPath}`,
          );
          // Return false so the caller tries the next peer.
          return false;
        }
        return true;
      },
    );
  }

  /**
   * Send a single `tipAdvertiseV1` probe to one peer and decrypt the
   * response to extract the peer's `tipsHash`. Returns one of:
   *
   *   - `Uint8Array` -- a legacy peer's advertised `tipsHash` (32 bytes).
   *   - `{ hash, signerAuthority }` -- a V4 advertisement whose envelope
   *     verified under exactly one captured trusted writer authority.
   *   - `'unknown-doc'` -- the peer explicitly disclaimed the document
   *     (returned the 1-byte `0xFF` UNKNOWN_DOC sentinel). This is the
   *     signal `Peerborne.tipAdvertiseHandler` emits when no document
   *     is registered for the requested path. Distinguishing this from
   *     `null` lets the orchestrator tally `'unknown-doc'` exactly like
   *     a tip-hash vote so that when the configured Q-of-K threshold of peers
   *     disclaim the document, `load()` returns `false` to let a fresh
   *     `open()` create the document on top of an existing swarm. The
   *     previous design returned `null` for the unknown-doc case, which
   *     was indistinguishable from a partition / timeout and made
   *     new-document creation in an existing mesh fail with
   *     `LoadQuorumFailedError`.
   *   - `null` -- any other non-vote outcome: empty response, decryption
   *     failure with an unknown key (peer has a different keychain),
   *     missing/invalid signature, deserialization failure, document-id
   *     mismatch, missing/short tip hash, or thrown errors. Timeouts are
   *     handled at the caller level via Promise.race.
   *
   * Returns rather than throws so the caller can record this peer as a
   * non-vote (NOT a disagreement) and `decideLoadQuorum` can apply the
   * correct quorum semantics. See `load-quorum.ts` for the
   * timeout-vs-disagreement-vs-unknown-doc distinction.
   *
   * @internal
   */
  private async _probeTipAdvertise(
    peer: import('@multiformats/multiaddr').Multiaddr,
    serializedRequest: Uint8Array,
    signal?: AbortSignal,
    protocolFamily?: InitialLoadProtocolFamily,
    trustedLoadSecurityCommitments?: LoadSecurityCommitments,
    signerAuthorization?: InitialLoadSignerAuthoritySnapshot<PublicKey>,
    expectedLoadChallenge?: Uint8Array,
  ): Promise<Uint8Array | SignerAttributedLoadQuorumVote | 'unknown-doc' | null> {
    const protocols =
      protocolFamily ??
      initialLoadProtocols(this.swarm.requireSecurityStateQuorum);
    if (
      protocols.securityAware &&
      (signerAuthorization === undefined ||
        (this._writerMutationsInFlight ?? 0) !== 0 ||
        (this._writerKeysVersion ?? 0) !== signerAuthorization.writerVersion ||
        this._securityProviderMutationFailure !== undefined)
    ) {
      return null;
    }
    // Capture the underlying v3 Stream so the abort path below can call
    // `abort()` on it directly (the wrapped DuplexStream only exposes the
    // write-side half-close via `close()`, not a full bidirectional tear-
    // down). Without this, a probe that loses the Promise.race to the
    // timeout would leak its stream until the libp2p connection itself
    // closed -- on partitioned/slow peers, each `load()` could leak K
    // streams, exhausting per-connection stream quotas.
    let rawStream: import('@libp2p/interface').Stream;
    let stream: {
      sink: (data: Iterable<Uint8Array>) => Promise<void>;
      source: AsyncIterable<Uint8ArrayList | Uint8Array>;
    };
    try {
      rawStream = await this.libp2p.dialProtocol(peer, [protocols.advertise], {
        runOnLimitedConnection: true,
        signal,
      });
      stream = wrapStream(rawStream);
    } catch {
      // Peer doesn't support tip-advertise or dial failed -- treat as non-vote.
      return null;
    }
    // Abort handler: tear down the v3 stream bidirectionally so a timed-out
    // probe doesn't strand the libp2p resource. `abort()` is the v3 full
    // teardown ("close stream for reading and writing"); `close()` would
    // only half-close the write side. Re-checking `signal?.aborted` after
    // attaching handles the race where the signal fired between dial and
    // listener attach. The handler also resolves `pipe()` / read promises
    // below with `AbortError`, which we swallow in the outer catch.
    const onAbort = () => {
      try {
        rawStream.abort(new Error('tip-advertise probe aborted'));
      } catch {
        // Already torn down -- nothing to do.
      }
    };
    if (signal) {
      if (signal.aborted) {
        try {
          rawStream.abort(new Error('tip-advertise probe aborted'));
        } catch {
          /* already torn down */
        }
        return null;
      }
      signal.addEventListener('abort', onAbort, { once: true });
    }
    try {
      await pipe([serializedRequest], stream.sink);
      // Size-bound the advertisement response read. V4 has tight document
      // and group-ID schema limits; legacy V3 instead preserves document IDs
      // admitted by the shared request ceiling. If the version-specific read
      // overruns its cap,
      // `readUint8Iterable` throws a `RangeError` that is caught by the
      // surrounding `try { ... } catch { return null; }` — surfacing as a
      // non-vote (same outcome as a timeout), NOT a quorum disagreement.
      const assembled = await readUint8Iterable(
        stream.source,
        protocols.securityAware
          ? MAX_SECURITY_ADVERTISE_RESPONSE_SIZE
          : MAX_TIP_ADVERTISE_RESPONSE_SIZE,
      );
      if (assembled.length === 0) {
        // Peer declined (unauthorized, decryption failure, document-id
        // mismatch, etc.). Distinct from the 1-byte UNKNOWN_DOC sentinel
        // handled below, which signals "I don't have this document at all"
        // (a distinguishable case used to let new-doc creation succeed
        // in an existing swarm; see method docstring).
        return null;
      }
      // 1-byte UNKNOWN_DOC sentinel response: `Peerborne.tipAdvertiseHandler`
      // emits this when no document is registered for the requested path.
      // The orchestrator counts these toward a separate "unknown-doc"
      // tally so the configured Q-of-K threshold of disclaims becomes a clean
      // new-doc-creation signal rather than a `LoadQuorumFailedError`.
      // See `_probeTipAdvertise`'s docstring and PR #284 r16 Copilot
      // review for the rationale.
      if (
        isUnknownDocumentAdvertisement(assembled, {
          securityAware: protocols.securityAware,
          requireAuthenticatedInitialLoad:
            this._requiresAuthenticatedInitialLoad(),
        })
      ) {
        return 'unknown-doc';
      }
      const headerLength =
        this._keychainProvider.keyIDLength + this._authProvider.nonceBits;
      if (assembled.length <= headerLength) {
        // Too short to be a valid encrypted payload.
        return null;
      }
      const blockKeyID = assembled.slice(0, this._keychainProvider.keyIDLength);
      const key = this._keychain.getKey(blockKeyID);
      if (!key) {
        // Responder used a key we don't have. Treat as non-vote rather than
        // an attack: a freshly-onboarded reader may legitimately not have
        // every historical key yet. The decryption-side check on the full
        // load that follows will still gate trust on the actual state.
        return null;
      }
      const blockNonce = assembled.slice(
        this._keychainProvider.keyIDLength,
        headerLength,
      );
      const blockData = assembled.slice(headerLength);
      const decrypted = await this._authProvider.decrypt(
        blockData,
        key,
        blockNonce,
      );
      if (!decrypted) {
        return null;
      }
      let message: CRDTSyncMessage<ChangesType, PublicKey>;
      try {
        message = this._snapshotDecodedSyncMessage(
          this._syncMessageSerializer.deserializeSyncMessage(decrypted),
          'tip advertisement',
        );
      } catch {
        return null;
      }
      if (message.documentId !== this.documentPath) {
        return null;
      }
      if (
        protocols.securityAware &&
        !initialLoadChallengeEquals(
          expectedLoadChallenge,
          message.loadChallenge,
        )
      ) {
        return null;
      }
      if (
        protocols.securityAware &&
        !loadSecurityCommitmentsEqual(
          trustedLoadSecurityCommitments,
          message.loadSecurityState,
        )
      ) {
        return null;
      }
      // V4 requires attribution to exactly one signer in the trust set
      // captured before any peer probe. Legacy advertisements retain their
      // prior verification/bootstrap behavior for compatibility.
      let signerAuthority: string | null = null;
      if (protocols.securityAware) {
        if (signerAuthorization === undefined) return null;
        signerAuthority = await this._identifyInitialLoadSignerAuthority(
          message,
          signerAuthorization.authorities,
        );
        if (signerAuthority === null) return null;
      } else {
        const preLoadWriters = await this._getWriterKeys();
        if (!(await this._verifyInitialLoadEnvelope(message, preLoadWriters))) {
          return null;
        }
      }
      if (
        !(message.tipsHash instanceof Uint8Array) ||
        message.tipsHash.length !== TIPS_HASH_LENGTH
      ) {
        return null;
      }
      if (protocols.securityAware) {
        if (
          (this._writerMutationsInFlight ?? 0) !== 0 ||
          (this._writerKeysVersion ?? 0) !==
            signerAuthorization!.writerVersion ||
          this._securityProviderMutationFailure !== undefined
        ) {
          return null;
        }
        if (signerAuthority === null) return null;
        return { hash: message.tipsHash, signerAuthority };
      }
      return message.tipsHash;
    } catch {
      return null;
    } finally {
      // Always detach the abort listener and release the libp2p stream. Once
      // the complete response is consumed, reset the stream synchronously
      // rather than awaiting a remote graceful-close handshake. A hostile
      // peer could otherwise keep `close()` pending after the timeout's abort
      // listener had already been removed, leaking a stream-slot loser behind
      // the completed Promise.race.
      if (signal) {
        signal.removeEventListener('abort', onAbort);
      }
      if (!signal?.aborted) {
        try {
          rawStream.abort(new Error('tip-advertise probe stream complete'));
        } catch {
          /* already torn down */
        }
      }
    }
  }

  /**
   * Run a single tip-advertise probe with a hard timeout. The probe itself
   * never throws (`_probeTipAdvertise` returns `null` on any failure
   * mode); a timeout also resolves to `null` so the caller can treat the
   * peer as a non-vote rather than a disagreement.
   *
   * Stream cancellation: when the timeout wins the race, the underlying
   * probe's libp2p stream is torn down via an AbortController so the
   * pending probe doesn't keep the resource alive in the background. Prior
   * to this fix, every timed-out probe leaked one libp2p stream per
   * `load()` call; under partitions or slow peers, K such leaks per load
   * could exhaust per-connection stream quotas.
   *
   * @internal
   */
  private async _raceTipAdvertiseProbe(
    peer: import('@multiformats/multiaddr').Multiaddr,
    serializedRequest: Uint8Array,
    timeoutMs: number,
    protocolFamily?: InitialLoadProtocolFamily,
    trustedLoadSecurityCommitments?: LoadSecurityCommitments,
    signerAuthorization?: InitialLoadSignerAuthoritySnapshot<PublicKey>,
    expectedLoadChallenge?: Uint8Array,
  ): Promise<Uint8Array | SignerAttributedLoadQuorumVote | 'unknown-doc' | null> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<null>((resolve) => {
      timer = setTimeout(() => resolve(null), timeoutMs);
    });
    try {
      return await Promise.race([
        this._probeTipAdvertise(
          peer,
          serializedRequest,
          controller.signal,
          protocolFamily,
          trustedLoadSecurityCommitments,
          signerAuthorization,
          expectedLoadChallenge,
        ),
        timeout,
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      // Whether the probe won or the timeout won, abort the controller so
      // any in-flight probe (loser of the race, still pending on the event
      // loop) tears down its stream. Aborting AFTER the probe has already
      // resolved is a no-op: the probe's finally block will have already
      // detached the listener and closed the stream itself.
      controller.abort();
    }
  }

  /**
   * Bound the remote-I/O phase of one full initial-load response. The callee
   * disarms the deadline only after the complete bounded response body has
   * arrived; local authentication and state application then finish without a
   * response-body timer racing an in-progress `sync()` mutation. Deferred
   * blockstore reads use their own candidate-wide deadline and abort signal.
   */
  private async _withInitialLoadResponseDeadline<T>(
    timeoutMs: number,
    operation: (
      signal: AbortSignal,
      responseReceived: () => void,
    ) => Promise<T>,
  ): Promise<T> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const disarm = () => {
      if (timer !== undefined) {
        clearTimeout(timer);
        timer = undefined;
      }
    };
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        const error = new Error('initial-load full response timed out');
        controller.abort(error);
        reject(error);
      }, timeoutMs);
    });
    try {
      return await Promise.race([
        operation(controller.signal, disarm),
        timeout,
      ]);
    } finally {
      disarm();
    }
  }

  /**
   * Extract the remote peer-id portion of a Multiaddr in a form suitable
   * for keying the quorum decision map. For relay-circuit multiaddrs (e.g.
   * `.../p2p/<relay>/p2p-circuit/p2p/<remote>`), the remote peer-id is the
   * LAST `/p2p/<id>` segment. Falls back to the full multiaddr string when
   * no `/p2p/<id>` segment is present so two responses from the same peer
   * always collide on the same map key.
   *
   * @internal
   */
  private _peerIdOf(peer: import('@multiformats/multiaddr').Multiaddr): string {
    const str = peer.toString();
    const matches = [...str.matchAll(/\/p2p\/([^/]+)/g)];
    return matches.length > 0 ? matches[matches.length - 1][1] : str;
  }

  // API Methods --------------------------------------------------------------

  /**
   * Close the subscription race after a verified invitation bootstrap by
   * loading directly from the exact endpoint named by the signed offer. This
   * deliberately bypasses the ordinary initial-load quorum only for this
   * issuer-pinned response; normal `load()` behavior is unchanged.
   */
  private async _loadInvitationCatchUp(
    founderAddress: string,
    issuerPublicKey: PublicKey,
  ): Promise<boolean> {
    this._throwIfSecurityProviderMutationFailed();
    const protocols = initialLoadProtocols(
      this.swarm.requireSecurityStateQuorum,
    );
    const trustedLoadSecurityCommitments = protocols.securityAware
      ? await captureTrustedLoadSecurityCommitments(
          this.documentPath,
          this.swarm.resolveLoadSecurityCommitments,
        )
      : undefined;
    const signerAuthorization = protocols.securityAware
      ? await this._captureInitialLoadSignerAuthorities()
      : undefined;
    const loadChallenge = protocols.securityAware
      ? createInitialLoadChallenge()
      : undefined;
    const signatureBytes = await this._authProvider.sign(
      protocols.securityAware
        ? initialLoadRequestSignaturePayload(
            this.documentPath,
            loadChallenge!,
          )
        : this._encoder.encode(this.documentPath),
      this._userKey,
    );
    if (signerAuthorization !== undefined) {
      this._assertInitialLoadWriterAuthorizationCurrent(
        signerAuthorization.writerVersion,
      );
    }
    const serializedRequest =
      this._loadMessageSerializer.serializeLoadRequest({
        documentId: this.documentPath,
        signature: this._serializeSignature(signatureBytes),
        loadChallenge,
      });
    return withIssuerPinnedInvitationStream(
      founderAddress,
      (address, signal) =>
        this.libp2p.dialProtocol(
          multiaddr(address) as any,
          [protocols.documentLoad],
          {
            runOnLimitedConnection: true,
            signal,
          },
        ),
      (rawStream, signal, admitStateMutation) =>
        this._sendLoadRequestAndSync(
          wrapStream(rawStream),
          serializedRequest,
          null,
          protocols.securityAware,
          trustedLoadSecurityCommitments,
          signerAuthorization,
          loadChallenge,
          signal,
          undefined,
          issuerPublicKey,
          MAX_INVITATION_MESSAGE_BYTES,
          true,
          admitStateMutation,
        ),
    );
  }

  // https://gist.github.com/alanshaw/591dc7dd54e4f99338a347ef568d6ee9#duplex-it
  /**
   * Load sends a new load request to any connected peer (each peer is tried one at a time). The expected
   * response from a load request is a sync message containing all document change hashes.
   *
   * Load is used to fetch any new changes that a connecting node is missing.
   *
   * @param preferredPeer Optional peer to try first (typically a PeerId from a
   *   pubsub message sender). Matched against peers by extracting the `/p2p/<id>`
   *   substring from each peer's `Multiaddr.toString()` (the canonical string
   *   form), since `@multiformats/multiaddr` v13 dropped the `getPeerId()`
   *   helper and `getComponents()` may surface the `/p2p` value as bytes.
   * **Initial-load quorum gate.** When
   * `PeerborneConfig.loadQuorumEnabled` is `true` (the default), `load()`
   * first queries up to `loadQuorumK` peers in parallel. Legacy mode uses
   * `tipAdvertiseV1` for a served-frontier hash; strict security-aware mode
   * uses `securityAdvertiseV1` for a digest that also binds the complete V4
   * response manifest and trusted security tuple. The full load proceeds only
   * against a peer in a configured `loadQuorumQ`-of-K agreement. The default Q
   * is a majority; explicitly choosing a lower threshold does not provide a
   * majority-based Byzantine guarantee. The gate runs uniformly
   * regardless of local `_hashes` state (an empty local `_hashes` is the
   * exact state the gate must defend on first `open()` of an existing
   * document — bypassing it then would be unsafe). If quorum is not met,
   * `load()` rejects with a `LoadQuorumFailedError` (see
   * `load-quorum.ts`). The gate can be disabled wholesale via
   * `loadQuorumEnabled: false` for single-peer dev/test scenarios; the
   * single-peer edge case is covered by `loadQuorumAllowSinglePeer`. Tip-
   * advertise responses with an unknown encryption key, missing/invalid
   * writer signature, document-id mismatch, or short/missing tip hash are
   * recorded as non-votes (NOT disagreements) so a stale peer cache does
   * not flip a partition into a Byzantine-failure verdict. The probe
   * round dedupes peers by libp2p PeerId so a single peer with multiple
   * open connections cannot cast multiple votes. The legacy load loop
   * (when `loadQuorumEnabled: false`) keeps the ORIGINAL un-deduped
   * peer list so it can retry across multiple multiaddrs for the same
   * peer id (e.g. a direct connection + a relay-circuit fallback).
   *
   * After quorum passes, the served full state is bound to the agreed digest
   * BEFORE applying the response. V3 derives the responder's served frontier
   * from the actual `changes`/`snapshot` payload. V4 additionally derives a
   * canonical complete manifest covering root/CID/kind/edge structure,
   * deferred markers, snapshot state/metadata, and keychain changes. The
   * responder-supplied `message.tips` array is not the source of truth. It is
   * additionally checked to
   * hash to the same value as the structurally-derived served
   * frontier; this catches an inconsistent response assembly. An
   * agreeing peer whose derived response hash differs from
   * `winningHashHex` is treated as a PER-PEER bind
   * failure: the loader records the peer in
   * `agreeingPeerBindFailures`, skips it, and tries the next peer in
   * the agreeing cohort. A mismatch may result from concurrent responder state
   * advance, retrieval/serialization failure, protocol violation, or
   * equivocation; the bind gate prevents any such response from mutating local
   * state. Only after every peer in the agreeing cohort has bind-failed
   * does the loader throw `LoadQuorumFailedError(reason: 'bind-check-
   * failed-all-agreeing-peers')`, with `agreeingPeerBindFailures`
   * recording per-peer diagnostics.
   * Closes the gap tracked under issue #189 §5.4 item 2 (and bulleted
   * in #186).
   *
   * @returns `true` after a successful sync. Returns `false` when there are no
   *   connected peers, when the quorum explicitly agrees the document is
   *   unknown, or when quorum is disabled and every legacy load attempt is
   *   exhausted. `open()` treats `false` as new only when no existing local or
   *   invitation state is present.
   * @throws {LoadQuorumFailedError} When an enabled quorum has insufficient
   *   agreement, every agreeing peer is unreachable/unusable, or every full
   *   response fails its bind check. Callers can `instanceof`-check this error.
   */
  // Key state can arrive in load responses, BeeKEM Welcome/PathUpdate
  // messages, and combined writer-removal sync envelopes.
  public async load(preferredPeer?: PeerId | string): Promise<boolean> {
    this._throwIfSecurityProviderMutationFailed();
    const protocols = initialLoadProtocols(
      this.swarm.requireSecurityStateQuorum,
    );
    // Pick a peer. All peers come from getConnections() so they already have
    // open connections. dialProtocol reuses existing connections internally,
    // so no additional connection management is needed here.
    const shuffledPeers = await this._shuffledPeers();
    this._throwIfSecurityProviderMutationFailed();
    if (shuffledPeers.length === 0) {
      return false;
    }

    // Capture every local trust anchor once before the first V4 probe. True
    // founders with no connected peers take the new-document return above
    // and do not need a pre-existing tuple. Once a peer can influence the
    // load, however, every advertisement and response must match these
    // immutable snapshots; no peer-facing path re-runs an application
    // resolver (which could otherwise create a TOCTOU split in one round).
    const trustedLoadSecurityCommitments = protocols.securityAware
      ? await captureTrustedLoadSecurityCommitments(
          this.documentPath,
          this.swarm.resolveLoadSecurityCommitments,
        )
      : undefined;
    const initialLoadSignerAuthorization = protocols.securityAware
      ? await this._captureInitialLoadSignerAuthorities()
      : undefined;
    this._throwIfSecurityProviderMutationFailed();
    // One unpredictable nonce scopes every signed V4 request/response in this
    // load round. Historical advertisements or full responses from an earlier
    // round cannot be replayed even when the trusted security tuple is stable.
    const loadChallenge = protocols.securityAware
      ? createInitialLoadChallenge()
      : undefined;

    const orderedPeers = [...shuffledPeers];

    // If a preferred peer is specified, move it to the front.
    // The peer list contains Multiaddrs while preferredPeer is typically a PeerId,
    // so we compare by extracting the PeerId component from each Multiaddr.
    if (preferredPeer) {
      const preferredId = preferredPeer.toString();
      const preferredIdx = orderedPeers.findIndex((p) => {
        // Only compare against the PeerId component of the Multiaddr.
        // Falling back to a full-string equality check would compare against
        // the full multiaddr string (e.g. "/ip4/.../p2p/<id>") which will
        // never match a plain PeerId string.
        //
        // `@multiformats/multiaddr` v13 (bundled by libp2p v3) dropped the
        // `getPeerId()` helper. `getComponents()` exists, but its component
        // `value` field can be either a string or bytes depending on how the
        // multiaddr was parsed, so a direct `=== preferredId` comparison is
        // unreliable. `Multiaddr.toString()` always returns the canonical
        // string form, so extract the `/p2p/<id>` substring from there.
        //
        // For relay-circuit multiaddrs (e.g.
        // `.../p2p/<relay>/p2p-circuit/p2p/<remote>`), there are multiple
        // `/p2p/<id>` segments; the remote peer id is always the LAST one,
        // so iterate all matches and use the final occurrence.
        const matches = [...p.toString().matchAll(/\/p2p\/([^/]+)/g)];
        const peerId =
          matches.length > 0 ? matches[matches.length - 1][1] : null;
        return peerId != null && peerId === preferredId;
      });
      if (preferredIdx > 0) {
        const [preferred] = orderedPeers.splice(preferredIdx, 1);
        orderedPeers.unshift(preferred);
      }
    }

    let signature = '';
    if (this._isSigningEnabled()) {
      const signatureBytes = await this._authProvider.sign(
        protocols.securityAware
          ? initialLoadRequestSignaturePayload(
              this.documentPath,
              loadChallenge!,
            )
          : this._encoder.encode(this.documentPath),
        this._userKey,
      );
      this._throwIfSecurityProviderMutationFailed();
      signature = this._serializeSignature(signatureBytes);
    }
    if (initialLoadSignerAuthorization !== undefined) {
      this._assertInitialLoadWriterAuthorizationCurrent(
        initialLoadSignerAuthorization.writerVersion,
      );
    }
    const loadRequest: CRDTLoadRequest = {
      documentId: this.documentPath,
      signature,
      loadChallenge,
    };
    const serializedRequest =
      this._loadMessageSerializer.serializeLoadRequest(loadRequest);

    // Dedupe peers by peer id ONLY for the quorum probe round.
    // `getConnections()` returns one entry per OPEN connection, and libp2p
    // maintains separate connections per multiaddr / per transport — so a
    // single remote peer with two open connections (e.g. direct +
    // relay-circuit) shows up twice. Without dedup, that peer would cast
    // two votes in the quorum tally, allowing a single malicious peer with
    // multiple connections to dominate the agreement count. Dedup by
    // `_peerIdOf` (which extracts the LAST `/p2p/<id>` segment, i.e. the
    // remote peer's libp2p PeerId for both direct and circuit-relay
    // multiaddrs). Preserves first-seen order so the preferredPeer (placed
    // at index 0 above) remains first.
    //
    // IMPORTANT: dedup applies only to `quorumPeers`. The legacy
    // single-peer load path (when `loadQuorumEnabled: false`) keeps the
    // ORIGINAL `orderedPeers` so it can retry across multiple multiaddrs
    // for the same peer id -- e.g. a direct connection + a relay-circuit
    // fallback. Collapsing those to one entry pre-quorum would silently
    // break the legacy fallback even when the quorum gate is off. See PR
    // #284 r7 Copilot review.
    const quorumPeers = dedupePeersByPeerId(orderedPeers, (p) =>
      this._peerIdOf(p),
    );

    // Initial-load quorum gate (#189 §5.4.2 / #186).
    //
    // Run BEFORE the existing single-peer snapshot/doc-load loop so that a
    // failed quorum aborts the load entirely (the caller cannot accidentally
    // accept a single peer's response). When the gate is disabled we fall
    // through to the legacy loop unchanged so existing callers see the same
    // behaviour.
    //
    // `winningHashHex` (set when quorum passes) is also used below as the
    // per-peer binding check inside `_sendLoadRequestAndSync`. It runs BEFORE
    // the served state is applied: V3 hashes the structurally-derived frontier;
    // V4 also hashes a complete manifest of every sync-mutating field. If the
    // result disagrees, the peer is recorded as a bind failure and the loader
    // retries the next agreeing peer without mutating in-memory state. The
    // mismatch may reflect concurrent state advance, incomplete retrieval,
    // protocol violation, or equivocation; the pre-apply ordering is the
    // load-bearing property.
    // NOTE: previously this block bypassed the gate when `_hashes.size === 0`
    // on the assumption it identified a "founding-member" brand-new document.
    // That bypass was unsafe: `_hashes` is ALSO empty on the first `open()`
    // of an EXISTING document (before load populates it), which is exactly
    // the case the gate is meant to protect. We no longer special-case empty
    // local state; the gate runs uniformly. New-document creation in an
    // EXISTING swarm is handled by the `'unknown-doc'` probe sentinel: each
    // peer that does not have the document responds with the 1-byte UNKNOWN_DOC
    // marker (see `Peerborne.tipAdvertiseHandler`), the orchestrator tallies
    // these alongside tip-hash votes, and a Q-of-K threshold of disclaims
    // surfaces as `{ newDoc: true }` here -- the loader returns `false` and
    // `open()` reaches its new-document branch. Strict-security documents
    // still require an exact-true application `validateDocumentPath` decision
    // before creation. True founders (no peers in the mesh) are handled by the
    // `peers.length === 0` short-circuit at the top of `load()` plus the
    // `k === 0` branch inside `runLoadQuorum` (which returns `{ skipped: true
    // }`); the same explicit creation authorization applies in `open()`.
    //
    // The K-of-Q decision logic itself lives in `runLoadQuorum`
    // (`load-quorum-orchestrator.ts`) so the orchestration can be unit-tested
    // without standing up a libp2p/Helia stack. The orchestrator is given a
    // probe-fn closure that captures this document's `_raceTipAdvertiseProbe`
    // (the only network-touching call); narrowing, agreement counting, and
    // single-peer fallback all happen in pure code with the same control
    // flow as before the extraction. See PR #284 r4 Copilot review for the
    // test-coverage rationale.
    const timeoutMs = this.swarm.loadQuorumTimeoutMs;
    const quorumResult = await runLoadQuorum({
      peers: quorumPeers,
      peerIdOf: (p) => this._peerIdOf(p),
      probeFn: (peer) =>
        this._raceTipAdvertiseProbe(
          peer,
          serializedRequest,
          timeoutMs,
          protocols,
          trustedLoadSecurityCommitments,
          initialLoadSignerAuthorization,
          loadChallenge,
        ),
      documentPath: this.documentPath,
      config: {
        // V4 is fail-closed even if a shared config object is mutated after
        // initialize-time validation. Strict security-aware loading never
        // degrades to the unquorumed loop.
        enabled: protocols.securityAware || this.swarm.loadQuorumEnabled,
        k: this.swarm.loadQuorumK,
        q: this.swarm.loadQuorumQ,
        timeoutMs,
        allowSinglePeer: this.swarm.loadQuorumAllowSinglePeer,
      },
    });
    this._throwIfSecurityProviderMutationFailed();
    if (initialLoadSignerAuthorization !== undefined) {
      this._assertInitialLoadWriterAuthorizationCurrent(
        initialLoadSignerAuthorization.writerVersion,
      );
    }

    let winningHashHex: string | null = null;
    if ('skipped' in quorumResult) {
      // `runLoadQuorum` returns `{ skipped: true }` in two cases: (a) the
      // gate is disabled wholesale (`loadQuorumEnabled: false`), or (b) the
      // effective K resolved to 0 because no peers were known. For (a) we
      // fall through to the legacy single-peer load loop unchanged --
      // `orderedPeers` is intentionally NOT deduped here so the loop can
      // retry across multiple multiaddrs for the same peer id (e.g. a
      // direct connection + a relay-circuit fallback). For (b) there is
      // nothing to load against — treat as new document. The peer-list
      // empty short-circuit at the top of `load()` already covers the
      // trivial "no peers" path; this branch is reached when quorum is
      // enabled with a valid K but the post-dedup `quorumPeers` happens
      // to be empty.
      //
      // Note: a misconfigured `loadQuorumK <= 0` no longer reaches this
      // branch — `runLoadQuorum` throws `LoadQuorumFailedError(invalid-
      // config)` for that case so the misconfiguration is loud at
      // `open()` time instead of silently forking the document. See PR
      // #284 r5 Copilot review.
      const quorumWasEnabled =
        protocols.securityAware || this.swarm.loadQuorumEnabled;
      if (quorumWasEnabled && quorumPeers.length === 0) {
        this._throwIfSecurityProviderMutationFailed();
        return false;
      }
      // Else: gate disabled. Fall through with the original (un-deduped)
      // `orderedPeers` so the legacy loop can retry per-multiaddr.
    } else if ('newDoc' in quorumResult) {
      // The configured Q-of-K threshold of probed peers explicitly disclaimed the
      // document via the `'unknown-doc'` sentinel. Return `false` so
      // `open()` can create the document fresh on top of the existing
      // swarm. Without this branch, the previous design conflated
      // unknown-doc with partition / timeout and surfaced
      // `LoadQuorumFailedError` -- preventing new-document creation in
      // any swarm with online peers. See PR #284 r16 Copilot review.
      this._throwIfSecurityProviderMutationFailed();
      return false;
    } else {
      winningHashHex = quorumResult.winningHashHex;
      // Quorum succeeded: narrow the load loop to the agreeing cohort.
      // The narrowed list is already deduped (it is a filter of
      // `quorumPeers`), so we replace `orderedPeers` wholesale.
      orderedPeers.length = 0;
      orderedPeers.push(...quorumResult.narrowedPeers);
    }

    // Capture the narrowed cohort size so the final error distinguishes every
    // response failing its binding from a mixed bind/transport/protocol
    // exhaustion. A bind failure is deliberately diagnostic rather than an
    // attribution: concurrent state advance, retrieval/serialization failure,
    // protocol violation, and equivocation can all produce it.
    // For the legacy non-quorum path (`winningHashHex === null`), this
    // value is unused -- the failure block guards on `winningHashHex`.
    const narrowedCohortSize = orderedPeers.length;

    // Try snapshot-load first for faster initial sync.
    // If the peer returns an empty response (no snapshot available),
    // fall back to the regular doc-load protocol.
    //
    // Quorum response binding: when `winningHashHex` is non-null,
    // `_sendLoadRequestAndSync` derives the responder's V3 frontier or V4
    // complete response manifest from the actual payload and verifies it equals
    // `winningHashHex` BEFORE applying the sync, so a response that differs
    // from its advertisement never mutates in-memory state. The responder-supplied
    // `message.tips` is checked as a defense-in-depth consistency
    // requirement but is NOT the source of truth -- previous implementations
    // trusting it alone would allow agreed CIDs alongside a divergent
    // `changes` payload.
    //
    // Per-peer bind failures (`_QuorumBindCheckFailedError`) are NOT
    // fatal to the whole load -- they only disqualify the offending
    // peer. The loop records the failure and continues to the next peer in the
    // agreeing cohort. Only after every peer in the
    // narrowed cohort has bind-failed does `load()` escalate to
    // `LoadQuorumFailedError(bind-check-failed-all-agreeing-peers)`.
    //
    // The `agreeingPeerBindFailures` map records, per peer, the hex
    // hash the served payload's structural frontier actually hashed to
    // (or the hex of the responder's contradicting `tips` attestation
    // when the defense-in-depth secondary check fails). This is
    // threaded into the final error so callers / operators can see
    // which peers failed binding and what digest was observed instead.
    const agreeingPeerBindFailures = new Map<string, string>();
    const attemptFullResponse = async (
      peer: import('@multiformats/multiaddr').Multiaddr,
      protocol: string,
    ): Promise<boolean> => {
      if (initialLoadSignerAuthorization !== undefined) {
        this._assertInitialLoadWriterAuthorizationCurrent(
          initialLoadSignerAuthorization.writerVersion,
        );
      }
      const loaded = await this._withInitialLoadResponseDeadline(
        timeoutMs,
        async (signal, responseReceived) => {
          const rawStream = await this.libp2p.dialProtocol(peer, [protocol], {
            runOnLimitedConnection: true,
            signal,
          });
          const abortStream = () => {
            try {
              rawStream.abort(
                signal.reason instanceof Error
                  ? signal.reason
                  : new Error('initial-load full response aborted'),
              );
            } catch {
              // Already closed by the remote or the stream adapter.
            }
          };
          if (signal.aborted) {
            abortStream();
            throw signal.reason;
          }
          signal.addEventListener('abort', abortStream, { once: true });
          try {
            return await this._sendLoadRequestAndSync(
              wrapStream(rawStream),
              serializedRequest,
              winningHashHex,
              protocols.securityAware,
              trustedLoadSecurityCommitments,
              initialLoadSignerAuthorization,
              loadChallenge,
              signal,
              responseReceived,
            );
          } finally {
            signal.removeEventListener('abort', abortStream);
            // The complete response has already been consumed. Tear down the
            // bidirectional stream synchronously instead of awaiting a remote
            // graceful-close handshake that could itself stall and consume a
            // per-connection stream slot. The timeout path already invoked the
            // same abort listener, so avoid a redundant second reset there.
            if (!signal.aborted) {
              try {
                rawStream.abort(
                  new Error('initial-load full response stream complete'),
                );
              } catch {
                // Already closed by the remote or stream adapter.
              }
            }
          }
        },
      );
      if (initialLoadSignerAuthorization !== undefined) {
        this._assertInitialLoadWriterAuthorizationCurrent(
          initialLoadSignerAuthorization.writerVersion,
        );
      }
      return loaded;
    };
    for (const peer of orderedPeers) {
      let peerBindFailed = false;
      // An explicitly disabled compaction policy cannot produce snapshots in
      // this swarm. Avoid an empty request/response round-trip—especially on
      // limited circuit-relay connections—before the real document load.
      if (this._compactionConfig.enabled) {
        try {
          console.log('Trying snapshot-load from peer:', peer.toString());
          const loaded = await attemptFullResponse(
            peer,
            protocols.snapshotLoad,
          );
          this._throwIfSecurityProviderMutationFailed();
          if (loaded) {
            return true;
          }
          // Empty response -- peer has no snapshot, try doc-load below.
        } catch (err) {
          this._throwIfSecurityProviderMutationFailed();
          if (err instanceof _QuorumBindCheckFailedError) {
            // This peer's full response does not bind to its probe digest.
            // Record the failure and skip a second protocol attempt against
            // the same peer in this load round.
            console.warn(
              `[${this.documentPath}] Agreeing peer ${peer.toString()} failed ` +
                `quorum response bind on snapshot-load (observed digest ${err.advertisedHex}); ` +
                `excluding it for this round and trying the next agreeing peer.`,
            );
            agreeingPeerBindFailures.set(
              this._peerIdOf(peer),
              err.advertisedHex,
            );
            peerBindFailed = true;
          }
          // Else: peer doesn't support snapshot-load protocol, or some
          // other transient error -- fall through to doc-load below.
        }
      }

      if (peerBindFailed) {
        // Do not retry doc-load against a peer whose snapshot response already
        // failed binding; continue to the next peer in the cohort.
        continue;
      }

      try {
        console.log('Trying doc-load from peer:', peer.toString());
        const loaded = await attemptFullResponse(peer, protocols.documentLoad);
        this._throwIfSecurityProviderMutationFailed();
        if (loaded) {
          return true;
        }
      } catch (err) {
        this._throwIfSecurityProviderMutationFailed();
        if (err instanceof _QuorumBindCheckFailedError) {
          console.warn(
            `[${this.documentPath}] Agreeing peer ${peer.toString()} failed ` +
              `quorum response bind on doc-load (observed digest ${err.advertisedHex}); ` +
              `excluding it for this round and trying the next agreeing peer.`,
          );
          agreeingPeerBindFailures.set(this._peerIdOf(peer), err.advertisedHex);
          continue;
        }
        console.warn(
          `Failed to load document via ${protocols.documentLoad} from ${peer.toString()}`,
        );
      }
    }

    // If quorum was run (`winningHashHex !== null`) but the load loop is
    // exhausted, the cohort agreed the document exists yet none supplied an
    // applicable response. Three diagnostic sub-cases:
    //
    //   a) `agreeingPeerBindFailures.size === narrowedCohortSize` --
    //      Every full response failed binding. This can result from concurrent
    //      state advance, retrieval/serialization failure, protocol violation,
    //      or equivocation. Use the dedicated historical reason identifier.
    //
    //   b) `agreeingPeerBindFailures.size > 0` but less than the
    //      cohort size -- mixed bind and transport/protocol failure. Report
    //      `'agreeing-peers-unreachable'`; retain the binding map for
    //      diagnostics.
    //
    //   c) `agreeingPeerBindFailures.size === 0` -- every agreeing
    //      peer failed for a transport/protocol reason; we surface
    //      the failure with `'agreeing-peers-unreachable'` so the
    //      caller decides whether to retry or surface to the user.
    //      We MUST NOT fall through to `return false` -- that would
    //      let `open()` initialize a brand-new document despite
    //      quorum just attesting that the document exists.
    //
    // Only after a TRUE no-quorum-was-run outcome (winningHashHex
    // is null -- legacy non-quorum load or quorum disabled / no
    // peers / etc.) is `return false` the right answer.
    if (winningHashHex !== null) {
      if (
        narrowedCohortSize > 0 &&
        agreeingPeerBindFailures.size === narrowedCohortSize
      ) {
        throw new LoadQuorumFailedError({
          documentPath: this.documentPath,
          reason: 'bind-check-failed-all-agreeing-peers',
          respondingCount: 0,
          requiredQ: 0,
          agreement: new Map([[winningHashHex, 0]]),
          agreeingPeerBindFailures,
        });
      }
      throw new LoadQuorumFailedError({
        documentPath: this.documentPath,
        reason: 'agreeing-peers-unreachable',
        respondingCount: 0,
        requiredQ: 0,
        agreement: new Map([[winningHashHex, 0]]),
        agreeingPeerBindFailures,
      });
    }

    // No peer could provide the document -- assume new document.
    console.log(`Failed to open ${this.documentPath} on any connected peer.`);
    this._throwIfSecurityProviderMutationFailed();
    return false;
  }

  /**
   * Opens this peerborne document. The sequence of operations is:
   *
   * 1. Call `.load()` to fetch the document from an existing peer via direct dial.
   * 2. If the document is new (load returned false), run
   *    `validateDocumentPath` to authorize creation. Legacy mode permits an
   *    omitted callback; strict authentication/security-state mode requires a
   *    captured callback and an exact `true` result.
   * 3. Assign the pubsub message handler, subscribe to the document's GossipSub
   *    pubsub topic, and register protocol handlers for load, key-update, and
   *    snapshot-load requests.
   * 4. If `enableTopicValidators` is set, register a GossipSub topic validator
   *    that rejects messages that fail signature verification.
   * 5. For new documents, add the current user as a writer and generate an
   *    initial document encryption key.
   *
   * Once opened, a document can be closed with `.close()`.
   *
   * **Design note:** `load()` runs before protocol handlers are registered, so
   * this node cannot serve incoming load/key-update requests for *this* document
   * during the load window. This is intentional -- validation must complete before
   * subscribing to pubsub to prevent briefly joining an unauthorized topic, and
   * the document is not yet fully open so it has nothing to serve.
   *
   * **Race window:** Messages published by peers between the `load()` response
   * and the `pubsub.subscribe()` call will be missed. This is a deliberate
   * trade-off: validation must complete before subscribing to prevent briefly
   * joining an unauthorized topic. The window is mitigated by the fact that
   * subsequent messages will arrive once subscribed, and the underlying CRDT
   * guarantees eventual consistency. Callers who need to ensure no messages
   * were missed should call `load()` again after `open()` resolves to re-sync
   * the latest state from a peer.
   *
   * @returns `false` when `load()` returned `false` and no existing state had
   *   already been loaded. In that case `open()` treats the document as new by
   *   adding the current user as a writer and generating an initial encryption
   *   key. With quorum enabled, exhausted or unusable agreeing peers throw;
   *   `false` is limited to no peers or an explicit unknown-document outcome.
   * @throws {Error} If `validateDocumentPath` rejects a new path, or if strict
   *   mode attempts creation without a captured validator. Validation runs
   *   before subscribing to pubsub or registering protocol handlers, so no
   *   cleanup is needed on rejection.
   * @throws {Error} If an earlier ACL/keychain provider call rejected after it
   *   may have mutated state. The retired document and provider instances must
   *   be discarded; calling `close()` does not make them reusable.
   * @throws {LoadQuorumFailedError} If an enabled initial-load quorum cannot
   *   agree or its agreeing cohort cannot supply an applicable response.
   */
  public async open(): Promise<boolean> {
    this._throwIfSecurityProviderMutationFailed();
    // Cache the topic once so that subscribe and unsubscribe always target
    // the same string, even if config.pubsubDocumentPrefix changes later.
    this._topic = this._computeTopic();

    // A verified invitation bootstrap already supplied and authenticated the
    // complete state. Skip the normal load in that one-shot case: a failed
    // network load must never make an invited joiner create a divergent new
    // document. The flag is consumed before any await so it cannot leak into a
    // retry after a later failure.
    const bootstrappedFromInvitation = this._invitationBootstrapReady;
    this._invitationBootstrapReady = false;
    const loadedFromPeer = bootstrappedFromInvitation
      ? true
      : await this.load();
    // Any authenticated Welcome establishes that this instance joined an
    // existing document. Legacy v1 may carry only keychain state and leave the
    // ratchet uninitialized; it must still never fall through to founder setup.
    const acceptedInvitation = this._invitationEpoch !== undefined;
    let isExisting =
      loadedFromPeer || this._hashes.size > 0 || acceptedInvitation;
    if (isExisting && this._pendingFounderInitialization !== undefined) {
      // Reuse the transition-owned collision check before validation,
      // subscription, or protocol registration exposes the ambiguous local
      // ACL/keychain state as an opened replica.
      await this._initializeFounderIfStillNew(loadedFromPeer);
    }

    // Validate document path BEFORE subscribing to pubsub or registering
    // protocol handlers. This prevents temporarily joining an unauthorized topic.
    // _pubsubHandler is not yet assigned, so if validation throws, close() will
    // not attempt to unsubscribe from a subscription that was never created.
    if (!isExisting) {
      const validateFn = this.swarm.validateDocumentPath;
      if (
        !validateFn &&
        (this._requiresAuthenticatedInitialLoad() ||
          this.swarm.requireSecurityStateQuorum)
      ) {
        if (await this._hasExistingStateUnderBeeKEMLock(loadedFromPeer)) {
          isExisting = true;
        } else {
          throw new Error(
            `Cannot create strict-security document "${this.documentPath}": ` +
              `validateDocumentPath is required to authorize new document creation`,
          );
        }
      }
      if (!isExisting && validateFn) {
        let allowed: boolean | undefined;
        let validationError: unknown;
        try {
          allowed = await validateFn(this.documentPath, this._userPublicKey);
        } catch (err) {
          validationError = err;
        }
        if (allowed !== true) {
          // The callback authorizes creation, not joining. A valid Welcome may
          // have committed while the arbitrary application callback awaited;
          // recompute under the Welcome/founder mutex before treating its
          // denial or failure as a creator denial.
          if (await this._hasExistingStateUnderBeeKEMLock(loadedFromPeer)) {
            isExisting = true;
          } else if (validationError !== undefined) {
            throw validationError instanceof Error
              ? validationError
              : new Error(String(validationError));
          } else {
            throw new Error(
              `Document path "${this.documentPath}" is not allowed for the current user`,
            );
          }
        }
      }
    }

    // Assign pubsub handler AFTER validation succeeds. This ensures close()
    // won't try to unsubscribe if open() failed during validation.
    this._pubsubHandler = (rawMessage) => {
      // Decrypt sync message.
      const blockKeyID = rawMessage.detail.data.slice(
        0,
        this._keychainProvider.keyIDLength,
      );
      const blockNonce = rawMessage.detail.data.slice(
        this._keychainProvider.keyIDLength,
        this._keychainProvider.keyIDLength + this._authProvider.nonceBits,
      );
      const blockData = rawMessage.detail.data.slice(
        this._keychainProvider.keyIDLength + this._authProvider.nonceBits,
      );
      void this._decryptBlock(blockKeyID, blockNonce, blockData)
        .then((rawContent) => {
          if (!rawContent) {
            console.warn(
              `[${this.documentPath}] Unable to decrypt incoming message. ` +
                `An ordinary encrypted load cannot bootstrap an unknown current ` +
                `document key; recovery requires a fresh writer-authenticated ` +
                `Welcome or authenticated remove/rejoin.`,
            );
            return undefined;
          }

          const message =
            this._syncMessageSerializer.deserializeSyncMessage(rawContent);

          return this.sync(message);
        })
        .catch(() => {
          // Event listeners cannot return an awaitable result to GossipSub.
          // Contain codec/sync/provider failures here so hostile ciphertext or
          // a retired provider cannot become a process-level unhandled
          // rejection. A terminal provider marker remains set on the document.
          console.warn(
            `[${this.documentPath}] Ignoring incoming message after processing failure`,
          );
        });
    };

    // All registration and subscription steps are inside try/catch so that
    // close() cleans up any partially-registered state on failure.
    const pubsub = this.swarm.heliaNode.libp2p.services.pubsub as GossipSub;

    try {
      // Validation and load callbacks above are arbitrary async boundaries. A
      // concurrent membership-provider ambiguity may have retired and closed
      // this instance while they were pending; never re-register it afterward.
      this._throwIfSecurityProviderMutationFailed();
      // Register this document with the swarm BEFORE subscribing to pubsub.
      // registerDocument() throws on duplicate document paths; doing this first
      // avoids subscribing to a topic that would then be unsubscribed by close()
      // on failure, which could disrupt an already-open instance for the same path.
      this.swarm.registerDocument(this.documentPath, this);

      // Subscribe to pubsub topic.
      // Cast required: EventHandler<CustomEvent<Message>> is incompatible with PubSubBaseProtocol's
      // addEventListener due to duplicate @libp2p/interface versions in the dependency tree
      pubsub.addEventListener('message', this._pubsubHandler as EventListener);
      pubsub.subscribe(this._topic);
      this._subscribed = true;

      // Register GossipSub topic validator for authorization enforcement.
      // When enabled, messages from unauthorized peers are rejected at the
      // transport layer with a P4 penalty in peer scoring.
      // Skip entirely when signing is disabled to avoid unnecessary per-message decryption.
      if (this.swarm.enableTopicValidators && this._isSigningEnabled()) {
        if (typeof pubsub.topicValidators?.set === 'function') {
          const topicValidator: TopicValidatorFn = async (
              _peerId: PeerId,
              message: Message,
            ): Promise<TopicValidatorResult> => {
              try {
                // Decrypt the message to access the signature.
                const blockKeyID = message.data.slice(
                  0,
                  this._keychainProvider.keyIDLength,
                );
                const blockNonce = message.data.slice(
                  this._keychainProvider.keyIDLength,
                  this._keychainProvider.keyIDLength +
                    this._authProvider.nonceBits,
                );
                const blockData = message.data.slice(
                  this._keychainProvider.keyIDLength +
                    this._authProvider.nonceBits,
                );
                const rawContent = await this._decryptBlock(
                  blockKeyID,
                  blockNonce,
                  blockData,
                );
                if (!rawContent) {
                  // Decryption failed -- key may not be in keychain yet
                  console.warn(
                    `[${this.documentPath}] Topic validator: decryption failed, ignoring message`,
                  );
                  return TopicValidatorResult.Ignore;
                }

                const syncMessage = this._snapshotDecodedSyncMessage(
                  this._syncMessageSerializer.deserializeSyncMessage(
                    rawContent,
                  ),
                  'topic-validator sync message',
                );

                if (!syncMessage.signature) {
                  return TopicValidatorResult.Reject;
                }

                const { signature, ...messageWithoutSignature } = syncMessage;
                const raw = this._syncMessageSerializer.serializeSyncMessage(
                  messageWithoutSignature,
                );

                // Verify the message was signed by an authorized writer for this document
                if (await this._verifyWriterSignature(raw, signature)) {
                  return TopicValidatorResult.Accept;
                }
                return TopicValidatorResult.Reject;
              } catch {
                console.warn(
                  `[${this.documentPath}] Topic validator: unexpected error, ignoring message`,
                );
                return TopicValidatorResult.Ignore;
              }
            };
          this._topicValidator = topicValidator;
          pubsub.topicValidators.set(this._topic, topicValidator);
        }
      }

      if (!isExisting || this._pendingFounderInitialization !== undefined) {
        isExisting = await this._initializeFounderIfStillNew(loadedFromPeer);
      }
    } catch (err) {
      // Clean up any partially-registered state to avoid leaked handlers,
      // subscriptions, or registry entries.
      await this.close().catch(() => {});
      throw err;
    }

    this._throwIfSecurityProviderMutationFailed();
    return isExisting;
  }

  private _initializeFounderIfStillNew(
    loadedFromPeer: boolean,
  ): Promise<boolean> {
    return this._runBeeKEMTransition(async () => {
      this._throwIfSecurityProviderMutationFailed();
      // A pre-open Welcome may have committed while path validation and
      // protocol registration were awaiting. Recompute under the same
      // transition mutex that owns Welcome commits; never initialize a
      // founder from the stale pre-validation classification.
      const hasExistingOrInvitedState =
        loadedFromPeer ||
        this._hashes.size > 0 ||
        this._invitationEpoch !== undefined;
      if (
        hasExistingOrInvitedState &&
        this._pendingFounderInitialization !== undefined
      ) {
        // The failed founder attempt has already mutated the local writer ACL
        // (and may have installed a key), while the newly observed state has a
        // different authenticated origin. Silently adopting it would retain a
        // local self-writer fork. None of those provider mutations has a
        // generic rollback contract, so this instance is terminally ambiguous.
        this._retireAfterAmbiguousSecurityProviderMutation(
          'incomplete founder initialization collided with loaded or invited document state',
        );
      }
      if (hasExistingOrInvitedState) {
        return true;
      }

      let pendingFounder = this._pendingFounderInitialization;
      if (
        pendingFounder?.writerAddState === 'started' ||
        pendingFounder?.keyAddState === 'started'
      ) {
        // The ACL/keychain interfaces do not promise throw-before-mutation.
        // A rejected call may therefore already have changed its provider,
        // while there is no authenticated delta/commit proving the outcome.
        // Never repeat or adopt state on this ambiguous provider instance.
        this._retireAfterAmbiguousSecurityProviderMutation(
          'founder initialization',
        );
      }
      if (pendingFounder === undefined) {
        pendingFounder = {
          writerAddState: 'started',
          keyAddState: 'not-started',
        };
        this._pendingFounderInitialization = pendingFounder;
        try {
          pendingFounder.writerChanges = this._requireMembershipWireChanges(
            await this._addWriter(this._userPublicKey),
            'founder writer-ACL initialization returned an unrepresentable change',
          );
        } catch (error) {
          this._retireAfterAmbiguousSecurityProviderMutation(
            'founder writer-ACL initialization',
            error,
          );
        }
        pendingFounder.writerAddState = 'succeeded';
      }
      if (pendingFounder.keyAddState === 'not-started') {
        console.log(`Adding a key to ${this.documentPath}`);
        pendingFounder.keyAddState = 'started';
        try {
          await this._keychain.add();
        } catch (error) {
          this._retireAfterAmbiguousSecurityProviderMutation(
            'founder keychain initialization',
            error,
          );
        }
        pendingFounder.keyAddState = 'succeeded';
      }

      // The founder ACL must be part of the replicated change DAG. Keeping it
      // only in the creator's in-memory ACL lets first-load peers decrypt state
      // but leaves them unable to authenticate later writer updates.
      const preparedFounderChange = await this._prepareChange(
        pendingFounder.writerChanges as ChangesType,
        crdtWriterChangeNode,
      );
      // `_publishPreparedChange` commits before its first network/handler
      // await. Record founder provenance in the same synchronous local commit
      // so a later publish, handler, or compaction failure cannot leave hashes
      // that classify this replica as existing while permanently disabling its
      // first BeeKEM add. The publish helper's repeated commit is idempotent.
      this._commitPreparedChange(preparedFounderChange);
      this._localFounderEstablished = true;
      this._createdLocally = true;
      this._pendingFounderInitialization = undefined;
      await this._publishPreparedChange(preparedFounderChange);
      return false;
    });
  }

  private _hasExistingStateUnderBeeKEMLock(
    loadedFromPeer: boolean,
  ): Promise<boolean> {
    return this._runBeeKEMTransition(async () =>
      Boolean(
        loadedFromPeer ||
          this._hashes.size > 0 ||
          this._invitationEpoch !== undefined,
      ),
    );
  }

  /**
   * Disconnects from this peerborne document. Running this method disconnects from the
   * document pubsub topic.
   *
   * Multiple open `PeerborneDocument` instances sharing the same
   * `documentPath` are not supported. Cleanup is instance-safe, so a failed or
   * stale instance does not unregister a newer live document.
   *
   * Cleanup is best-effort. In particular, closing a document retired after an
   * ambiguous ACL/keychain provider rejection does not roll back provider state
   * or make that document/provider set safe to reuse.
   */
  public async close() {
    // Use the cached topic for cleanup; it is initialized in the constructor.
    const topic = this._topic;

    if (this._pubsubHandler) {
      const pubsub = this.swarm.heliaNode.libp2p.services.pubsub as GossipSub;

      // Only unsubscribe if this instance actually subscribed. If open()
      // failed before pubsub.subscribe() completed, unsubscribing here
      // would remove a subscription belonging to another instance.
      if (this._subscribed) {
        pubsub.unsubscribe(topic);
        this._subscribed = false;
      }

      // Cast required: see addEventListener comment above
      pubsub.removeEventListener(
        'message',
        this._pubsubHandler as EventListener,
      );

      if (
        this._topicValidator &&
        pubsub.topicValidators?.get(topic) === this._topicValidator
      ) {
        pubsub.topicValidators.delete(topic);
      }
      this._topicValidator = undefined;
    }

    // Unregister this document from the shared V2 protocol handler registry.
    // Pass `this` so only this instance is removed (instance-safe).
    this.swarm.unregisterDocument(this.documentPath, this);
    this.swarm.unregisterWelcomeRecipient?.(this.documentPath, this);
  }

  /**
   * Round-trip and detach a codec-produced sync message once. All routing,
   * authentication, and mutation for an ingress operation must use this exact
   * snapshot; re-reading the original codec object after an await would permit
   * accessor/Proxy time-of-check/time-of-use substitution.
   */
  private _canonicalizeSyncMessage(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
    label: string,
    maximumWireBytes = MAX_SHARED_PROTOCOL_REQUEST_SIZE,
  ): CRDTSyncMessage<ChangesType, PublicKey> {
    const canonicalBytes = copyUnsharedUint8Array(
      this._syncMessageSerializer.serializeSyncMessage(message),
      1,
      maximumWireBytes,
      `${label} encoding`,
    );
    return this._snapshotDecodedSyncMessage(
      this._syncMessageSerializer.deserializeSyncMessage(canonicalBytes),
      label,
    );
  }

  private _snapshotDecodedSyncMessage(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
    label: string,
  ): CRDTSyncMessage<ChangesType, PublicKey> {
    const snapshot = snapshotDeepEnumerableData<
      CRDTSyncMessage<ChangesType, PublicKey>
    >(message, label);
    (this._canonicalSyncMessages ??= new WeakSet()).add(snapshot as object);
    return snapshot;
  }

  /**
   * Given a sync message containing a list of hashes:
   * - Fetch new changes that are only hashes (missing change itself) from the blockstore (using the hash).
   * - Apply new changes to the existing CRDT document.
   *
   * @param message A sync message to apply.
   * @param verifySignature Whether to perform normal writer verification
   *   (default: true). Passing `false` does not bypass authentication when
   *   signing is enabled; it is accepted only for an exact message carrying a
   *   private, version-bound authorization from the authenticated load path.
   * @returns `true` if the message was applied successfully, `false` if rejected due to auth failure.
   *
   * **BREAKING CHANGE:** Return type changed from `Promise<void>` to
   * `Promise<boolean>`. TypeScript callers with explicit `Promise<void>` type
   * annotations will need to update. Callers should now check the returned
   * boolean to determine whether the message was applied successfully.
   */
  public async sync(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
    verifySignature = true,
  ): Promise<boolean> {
    this._throwIfSecurityProviderMutationFailed();
    const initialLoadAuthorization = this._initialLoadSyncAuthorizations?.get(
      message as object,
    );
    this._initialLoadSyncAuthorizations?.delete(message as object);
    let stableMessage: CRDTSyncMessage<ChangesType, PublicKey>;
    try {
      stableMessage = this._canonicalSyncMessages?.has(message as object)
        ? message
        : this._canonicalizeSyncMessage(message, 'sync message');
    } catch {
      this._throwIfSecurityProviderMutationFailed();
      console.warn(`Rejected malformed sync message for ${this.documentPath}`);
      return false;
    }
    return this._runInMutationQueue(() =>
      this._syncUnlocked(
        stableMessage,
        verifySignature,
        initialLoadAuthorization,
      ),
    );
  }

  /** Apply a sync message after any required membership-queue admission. */
  private async _syncUnlocked(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
    verifySignature: boolean,
    initialLoadAuthorization?: InitialLoadSyncAuthorization<PublicKey>,
  ): Promise<boolean> {
    try {
      const applied = await this._sync(
        message,
        verifySignature,
        initialLoadAuthorization,
      );
      // `_sync()` deliberately uses `false` for ordinary authentication and
      // validation failures. A provider outcome that became ambiguous across
      // one of its awaits is terminal instead and must remain observable to
      // the caller as the exact retirement error.
      this._throwIfSecurityProviderMutationFailed();
      const finalized =
        initialLoadAuthorization?.finalizeInMutationSlot === undefined
          ? applied
          : await initialLoadAuthorization.finalizeInMutationSlot(applied);
      this._throwIfSecurityProviderMutationFailed();
      return finalized;
    } catch (cause) {
      // `sync()` and direct invitation catch-up both hold `_mutationQueue`
      // around this method. Terminalize before returning or rejecting so the
      // next queued writer can never observe possibly-partial load state.
      initialLoadAuthorization?.failInMutationSlot?.(cause);
      throw cause;
    }
  }

  private async _sync(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
    verifySignature: boolean,
    initialLoadAuthorization?: InitialLoadSyncAuthorization<PublicKey>,
  ): Promise<boolean> {
    if (this._securityProviderMutationFailure !== undefined) return false;
    // The initial-load gate runs before every mutation so a deferred-block
    // deadline that expires after an earlier apply still blocks subsequent
    // state changes. Its implementation one-shots the external invitation
    // admission and mutation-started marker internally.
    const admitStateMutation = initialLoadAuthorization?.onStateMutation;
    if (message.documentId !== this.documentPath) {
      console.warn(
        `Rejected sync message for the wrong local document (${this.documentPath})`,
      );
      return false;
    }
    const { signature, ...messageWithoutSignature } = message;
    const signingEnabled = this._isSigningEnabled();
    if (signingEnabled && !signature) {
      return false;
    }
    if (
      signingEnabled &&
      !verifySignature &&
      initialLoadAuthorization === undefined
    ) {
      return false;
    }

    // Only serialize for signature verification -- skip when signing is disabled
    // to avoid expensive serialization of large messages.
    let writerAuthorizationVersion: number | undefined;
    if (signingEnabled && verifySignature) {
      const raw = this._syncMessageSerializer.serializeSyncMessage(
        messageWithoutSignature,
      );
      const verifiedVersion = await this._verifyWriterSignatureAtStableVersion(
        raw,
        signature!,
      );
      if (verifiedVersion === null) {
        console.warn(
          `Received a sync message with an invalid signature for ${this.documentPath}`,
        );
        return false;
      }
      writerAuthorizationVersion = verifiedVersion;
    } else if (signingEnabled && initialLoadAuthorization !== undefined) {
      if (
        !this._writerAuthorizationIsCurrent(
          initialLoadAuthorization.writerVersion,
        )
      ) {
        return false;
      }
      writerAuthorizationVersion = initialLoadAuthorization.writerVersion;
    }

    // Validate a newer snapshot before mutating the keychain, ACLs, or CRDT.
    // Candidate writer changes are applied to an isolated ACL instance so a
    // self-authorizing snapshot cannot poison live authorization state.
    let snapshotToApply: CRDTSnapshotNode<ChangesType, PublicKey> | undefined;
    if (message.snapshot) {
      const incoming = message.snapshot;
      const isNewer =
        !this._latestSnapshot ||
        incoming.compactedCount > this._latestSnapshot.compactedCount ||
        (incoming.compactedCount === this._latestSnapshot.compactedCount &&
          String(incoming.lastChangeNodeCID ?? '') >
            String(this._latestSnapshot.lastChangeNodeCID ?? ''));
      if (isNewer) {
        let snapshotSignatureValid = !signingEnabled;
        if (signingEnabled) {
          try {
            const currentWriters = await this._getWriterKeys();
            const candidateWriters = await this._writerKeysIncludingTree(
              message.changes,
            );
            const bootstrapWriters =
              currentWriters.length === 0 &&
              this._requiresAuthenticatedInitialLoad()
                ? (initialLoadAuthorization?.writerKeys ??
                  (await this._getBootstrapWriterKeys()))
                : [];
            const trustedSnapshotWriters =
              currentWriters.length > 0
                ? candidateWriters
                : [...bootstrapWriters, ...candidateWriters];
            const stateBytes = this._changesSerializer.serializeChanges(
              incoming.state,
            );
            const signPayload = this._buildSnapshotSignPayload(
              stateBytes,
              incoming.lastChangeNodeCID,
              incoming.timestamp,
              incoming.compactedCount,
            );
            snapshotSignatureValid = await this._verifySnapshotSignature(
              signPayload,
              incoming.signature,
              trustedSnapshotWriters,
            );
          } catch {
            console.warn(
              `Rejected snapshot for ${this.documentPath}: malformed snapshot fields`,
            );
          }
        }
        if (!snapshotSignatureValid) {
          console.warn(
            `Rejected snapshot for ${this.documentPath}: no trusted writer produced a valid signature`,
          );
          return false;
        }
        snapshotToApply = incoming;
      }
    }

    // Linearize the authorization immediately before the first synchronous
    // mutation. A writer removed while signature/snapshot verification was
    // awaiting must not retain a stale authority lease. Once this check and a
    // mutation complete, a concurrent later removal is ordered after this
    // already-authorized message.
    const mutatesBeforeTree =
      message.keychainChanges !== undefined || snapshotToApply !== undefined;
    if (
      mutatesBeforeTree &&
      (this._securityProviderMutationFailure !== undefined ||
        (writerAuthorizationVersion !== undefined &&
          !this._writerAuthorizationIsCurrent(writerAuthorizationVersion)))
    ) {
      return false;
    }

    if (message.keychainChanges !== undefined) {
      admitStateMutation?.();
      try {
        this._keychain.merge(message.keychainChanges);
        console.log(`Updated keychain in ${this.documentPath}`);
      } catch (e) {
        this._retireAfterAmbiguousSecurityProviderMutation(
          'inbound keychain merge',
          e,
        );
      }
    }

    if (snapshotToApply) {
      admitStateMutation?.();
      this._document = this._crdtProvider.applySnapshot
        ? this._crdtProvider.applySnapshot(
            this._document,
            snapshotToApply.state,
          )
        : this._crdtProvider.remoteChange(
            this._document,
            snapshotToApply.state,
          );
      this._latestSnapshot = snapshotToApply;
      this._documentChangeCount = Math.max(
        this._documentChangeCount,
        snapshotToApply.compactedCount,
      );
      this._changesSinceSnapshot = 0;
      if (snapshotToApply.lastChangeNodeCID) {
        this._hashes.add(snapshotToApply.lastChangeNodeCID);
      }
      console.log(
        `Applied remote snapshot for ${this.documentPath}: ${snapshotToApply.compactedCount} nodes compacted`,
      );
    }

    // Full change sync: process all nodes (document + ACL) only after the
    // snapshot gate succeeds.
    if (message.changes) {
      let expectedWriterVersion =
        writerAuthorizationVersion ?? this._writerKeysVersion;
      const authorizationLease: SyncAuthorizationLease = {
        isCurrent: () =>
          this._securityProviderMutationFailure === undefined &&
          this._writerMutationsInFlight === 0 &&
          this._writerKeysVersion === expectedWriterVersion,
        advanceAfterWriterMutation: () => {
          // `_mergeWriters` is synchronous. Advancing immediately afterward
          // admits only its exact pre/post invalidation pair. Never adopt the
          // current version generically: a re-entrant or unrelated mutation
          // must invalidate the authenticated lease rather than being folded
          // into it.
          const nextExpectedVersion = expectedWriterVersion + 2;
          if (
            this._securityProviderMutationFailure !== undefined ||
            this._writerMutationsInFlight !== 0 ||
            this._writerKeysVersion !== nextExpectedVersion
          ) {
            return false;
          }
          expectedWriterVersion = nextExpectedVersion;
          return true;
        },
      };
      const changesApplied = await this._syncDocumentChanges(
        message.changeId,
        message.changes,
        authorizationLease,
        initialLoadAuthorization?.deferredBlockBudget,
        admitStateMutation,
      );
      if (!changesApplied) {
        this._throwIfSecurityProviderMutationFailed();
        return false;
      }
    }

    this._throwIfSecurityProviderMutationFailed();
    return true;
  }

  /**
   * Subscribes a change handler to the document. Use this method to receive real-time
   * updates to the document.
   *
   * @param id A unique id for this handler. Used to unsubscribe this handler.
   * @param handler A function that is called when a change is received.
   * @param originFilter Determines what kinds of change events trigger the handler.
   *     'remote' indicates that the change was received from a remote peer.
   *     'local' indicates that the change was received from the local document.
   *     'all' indicates that all changes should be handled.
   */
  public subscribe(
    id: string,
    handler: PeerborneDocumentChangeHandler<DocType, PublicKey>,
    originFilter: 'all' | 'remote' | 'local' = 'all',
  ) {
    switch (originFilter) {
      case 'all': {
        this._remoteHandlers[id] = handler;
        this._localHandlers[id] = handler;
        break;
      }
      case 'remote': {
        this._remoteHandlers[id] = handler;
        break;
      }
      case 'local': {
        this._localHandlers[id] = handler;
        break;
      }
    }
  }

  /**
   * Unsubscribes a change handler from the document.
   *
   * @param id The id of the handler to unsubscribe.
   */
  public unsubscribe(id: string) {
    if (this._remoteHandlers[id]) {
      delete this._remoteHandlers[id];
    }
    if (this._localHandlers[id]) {
      delete this._localHandlers[id];
    }
  }

  // TODO: Unit tests for PeerborneDocument require mocking libp2p, Helia,
  // and all providers -- deferred to integration testing (see e2e/).

  /**
   * Start a change transaction. Changes made via `addChange()` will be batched
   * and applied atomically when `endChange()` is called.
   */
  public startChange() {
    if (this._inTransaction) {
      throw new Error('Transaction already in progress');
    }
    this._inTransaction = true;
    this._pendingChangeFns = [];
  }

  /**
   * Queue a change function within an active transaction.
   * Must be called between `startChange()` and `endChange()`.
   */
  public addChange(changeFn: ChangeFnType) {
    if (!this._inTransaction) {
      throw new Error('No transaction in progress. Call startChange() first.');
    }
    if (this._committing) {
      throw new Error('Cannot add changes while endChange() is committing.');
    }
    this._pendingChangeFns.push(changeFn);
  }

  /**
   * End the transaction and apply all queued changes atomically.
   * This sends a single sync message for all batched changes.
   *
   * On failure (from any step: write check, CRDT apply, or network publish),
   * the transaction is aborted and the document reference is rolled back.
   * For immutable CRDT providers (e.g. Automerge), rollback is reliable
   * because `localChange()` returns a new document object.
   *
   * **Known limitation -- in-place mutating providers:** For CRDT providers
   * that mutate in place (e.g. Yjs), rollback does NOT undo mutations.
   * Yjs's `localChange()` mutates the document object directly and returns
   * the same reference, so restoring the saved reference after failure has
   * no effect -- the mutations have already been applied to the shared
   * Y.Doc. Callers using Yjs should treat a failed transaction as leaving
   * the local document in a potentially inconsistent state and consider
   * re-syncing from peers.
   *
   * **Known limitation -- concurrent remote changes during rollback:** The
   * rollback sets `_document` back to the snapshot captured when
   * `endChange()` is called (before applying the pending change functions).
   * Because `_makeChange()` is async and the node remains
   * subscribed to pubsub throughout, remote sync messages may arrive and be
   * applied to `_document` between the start of the transaction and the
   * point of failure. Rolling back to the original snapshot **reverts those
   * remote changes as well**, not just the local batch. This is acceptable
   * because the CRDT layer guarantees eventual consistency -- the reverted
   * remote changes will be re-applied on the next sync cycle or document
   * load. If transaction failure is critical, callers should re-sync the
   * document after a failed transaction (e.g. call `load()` or wait for
   * the next pubsub round) to ensure remote state is promptly restored.
   *
   * **Known limitation -- partial internal state on failure:** If
   * `_makeChange()` fails partway through (e.g. encryption succeeds but
   * pubsub publish throws), `_hashes` may retain CIDs for the rolled-back
   * change (see below). Other counters and bookkeeping fields
   * (`_lastSyncMessage`, `_documentChangeCount`, `_changesSinceSnapshot`,
   * `_recentTips`) ARE restored from snapshots captured before
   * `_makeChange()` -- see the "Internal metadata rollback" section below
   * for details.
   *
   * **Specifically, `_hashes` may retain CIDs for the rolled-back change.**
   * Because `_hashes` is used to skip already-seen changes during sync,
   * any CID added before the failure will cause that change to be silently
   * skipped if it arrives again via pubsub or `load()`. This means the
   * rolled-back change is effectively "lost" from this peer's perspective
   * until `_hashes` is rebuilt. **Callers should call `load()` after a
   * failed transaction** to re-sync the full document state from a peer
   * and restore consistency. A new transaction must be started after a
   * failure.
   *
   * **Internal metadata rollback:** On failure, `_lastSyncMessage`,
   * `_documentChangeCount`, `_changesSinceSnapshot`, and `_recentTips`
   * are restored from snapshots captured before `_makeChange()`.
   * (`_recentTips` is bounded to `MAX_RECENT_TIPS` entries so the snapshot
   * is a cheap shallow array copy.) For `_hashes` and
   * `_referencedAncestors`, all entries added to each Set after its
   * pre-attempt size are removed. Because the node remains
   * subscribed to pubsub during the async transaction, this may include
   * CIDs appended by concurrent remote syncs, not just local ones.
   * This is acceptable because CRDT convergence guarantees those remote
   * CIDs will be re-added on the next sync cycle or document load.
   * The approach is O(n) iteration but O(delta) memory -- no full
   * array clone -- and avoids disrupting any concurrent sync iteration
   * that `clear()` would break. A new transaction must be started after
   * a failure.
   *
   * @throws {Error} If any step in the commit pipeline fails.
   */
  public async endChange(message?: string) {
    return this._runInMutationQueue(() => this._endChangeUnlocked(message));
  }

  private async _endChangeUnlocked(message?: string) {
    if (!this._inTransaction) {
      throw new Error('No transaction in progress. Call startChange() first.');
    }
    if (this._committing) {
      throw new Error(
        'endChange() is already in progress. Await the previous call.',
      );
    }

    // Snapshot pending fns so late addChange() calls during await don't
    // unpredictably modify the batch being committed.
    const pendingFns = [...this._pendingChangeFns];
    if (pendingFns.length === 0) {
      this._inTransaction = false;
      this._pendingChangeFns = [];
      return;
    }

    const originalDocument = this.document;
    // Snapshot internal metadata so we can restore on failure.
    // Only track the Set size (O(1)) instead of cloning the entire Set (O(n)):
    // _makeChange adds at most one CID, and JS Sets iterate in insertion order,
    // so on rollback we remove only entries appended after this point.
    const hashSizeBefore = this._hashes.size;
    const referencedAncestorsSizeBefore = this._referencedAncestors.size;
    const lastSyncSnapshot = this._lastSyncMessage;
    const changeCountSnapshot = this._documentChangeCount;
    const compactionCountSnapshot = this._changesSinceSnapshot;
    // Bounded copy (max MAX_RECENT_TIPS entries) -- cheap to snapshot.
    const recentTipsSnapshot = [...this._recentTips];

    this._committing = true;
    try {
      await this._ensureCurrentUserCanWrite();

      // Compose all queued change functions into a single localChange call
      // to produce one atomic delta. This ensures providers like Automerge
      // (which return incremental deltas) don't drop earlier changes.
      const composedFn = ((doc: any) => {
        for (const fn of pendingFns) {
          (fn as any)(doc);
        }
      }) as ChangeFnType;

      // Note: YjsProvider.localChange mutates the document in-place and returns
      // the same reference, so rollback on failure is best-effort for Yjs.
      // Automerge returns a new immutable document, so rollback is reliable.
      const [newDocument, changes] = this._crdtProvider.localChange(
        this.document,
        message || '',
        composedFn,
      );
      this._document = newDocument;

      await this._makeChange(changes);

      // Success -- clear transaction state.
      this._inTransaction = false;
      this._pendingChangeFns = [];
    } catch (err) {
      // Abort transaction on ANY error (ensureWrite, localChange, or makeChange).
      // Roll back document and internal metadata (best-effort for in-place
      // mutating providers like Yjs).
      this._document = originalDocument;
      // Remove only the CIDs appended by _makeChange instead of clearing and
      // re-populating the entire Set. This avoids mutating the Set during
      // concurrent sync (clear() would disrupt any in-progress iteration)
      // and is O(delta) instead of O(n).
      // Iterate the Set (O(n)) but only collect entries past the snapshot
      // threshold into a small buffer (O(delta) memory) -- avoids cloning
      // the entire Set into an array via spread.
      if (this._hashes.size > hashSizeBefore) {
        const toRemove: string[] = [];
        let i = 0;
        for (const hash of this._hashes) {
          if (i >= hashSizeBefore) {
            toRemove.push(hash);
          }
          i++;
        }
        for (const hash of toRemove) {
          this._hashes.delete(hash);
        }
      }
      // Mirror the `_hashes` rollback for `_referencedAncestors`: remove
      // only entries appended past the pre-attempt size. Same rationale --
      // insertion-ordered Set iteration plus O(delta) memory -- and same
      // best-effort caveat for concurrent sync that may have inserted into
      // either set in parallel.
      if (this._referencedAncestors.size > referencedAncestorsSizeBefore) {
        const toRemoveRefs: string[] = [];
        let j = 0;
        for (const cid of this._referencedAncestors) {
          if (j >= referencedAncestorsSizeBefore) {
            toRemoveRefs.push(cid);
          }
          j++;
        }
        for (const cid of toRemoveRefs) {
          this._referencedAncestors.delete(cid);
        }
      }
      this._lastSyncMessage = lastSyncSnapshot;
      this._documentChangeCount = changeCountSnapshot;
      this._changesSinceSnapshot = compactionCountSnapshot;
      this._recentTips = recentTipsSnapshot;
      this._inTransaction = false;
      this._pendingChangeFns = [];
      throw err;
    } finally {
      this._committing = false;
    }
  }

  /**
   * Applies a new local change (defined by `changeFn`) to the peerborne document and updates
   * all peers.
   *
   * @param changeFn A function that makes changes to the current CRDT document.
   * @param message An optional change message/description to include.
   */
  public async change(changeFn: ChangeFnType, message?: string) {
    return this._runInMutationQueue(() =>
      this._changeUnlocked(changeFn, message),
    );
  }

  private async _changeUnlocked(changeFn: ChangeFnType, message?: string) {
    if (this._inTransaction) {
      throw new Error(
        'Cannot call change() during an active transaction. Use addChange() instead.',
      );
    }
    await this._ensureCurrentUserCanWrite();

    const [newDocument, changes] = this._crdtProvider.localChange(
      this.document,
      message || '',
      changeFn,
    );
    // Apply local change w/ automerge.
    this._document = newDocument;

    await this._makeChange(changes);
  }

  /**
   * Returns the total number of change nodes (including ACL nodes) tracked
   * in the current document history. This is a count of all known CIDs,
   * not the depth of the longest path in the DAG.
   */
  public historySize(): number {
    return this._hashes.size;
  }

  /**
   * Returns the current snapshot, if one exists.
   */
  public get latestSnapshot():
    | CRDTSnapshotNode<ChangesType, PublicKey>
    | undefined {
    return this._latestSnapshot;
  }

  /**
   * Lazy-load a historical change block by CID.
   *
   * Used to fetch change data on demand for history-visibility consumers (e.g.
   * audit UI, diff viewers) when the change has been pruned from the in-memory
   * sync tree but the block is still present in the Helia blockstore. The
   * returned `ChangesType` is the deserialized, decrypted payload.
   *
   * Returns `undefined` when:
   * - The CID is not in `_hashes` (we have never seen this change).
   * - The block is missing from the blockstore (e.g. it was GC'd locally and
   *   no peer has re-served it yet). Callers that need stronger guarantees can
   *   fall back to dialing peers via the existing sync protocols.
   *
   * Throws when:
   * - The CID is malformed.
   * - The block is present locally but decryption fails (wrong/missing
   *   keychain entry) or the payload fails to deserialize (corrupted data).
   *   These are treated as hard errors so callers can distinguish a recoverable
   *   "missing block" condition from a stronger data-integrity issue.
   *
   * @param cid CID string of the change block to load.
   * @returns The deserialized change payload, or `undefined` if unavailable.
   */
  public async loadChangeBlock(cid: string): Promise<ChangesType | undefined> {
    return lazyLoadChangeBlock<CID, ChangesType>(
      cid,
      this._hashes,
      (c) => CID.parse(c),
      (parsedCID) => this._getBlock(parsedCID),
      // Intentionally no-op onMissing: missing-after-GC is an expected outcome
      // for the lazy-load path (audit UIs, diff viewers) and should not spam
      // logs. Callers that want visibility can detect `undefined` themselves.
    );
  }

  /**
   * Check whether a CID is known to this document (i.e. present in the
   * in-memory `_hashes` set). Useful for callers that want to confirm a
   * change exists before attempting a lazy load.
   *
   * Note: returning `true` only proves the CID has been observed (it is
   * tracked in `_hashes` for sync-message dedup). It does NOT guarantee the
   * underlying block is locally available -- after `gcAfterPrune` runs, the
   * CID remains in `_hashes` even though the block has been removed from the
   * blockstore. Callers should therefore still handle `loadChangeBlock(cid)`
   * resolving to `undefined` (and may need to fall back to dialing peers).
   */
  public hasChange(cid: string): boolean {
    return this._hashes.has(cid);
  }

  /**
   * Creates a snapshot of the current document state.
   *
   * The snapshot compacts all current change nodes into a single state representation.
   * Requires `CRDTProvider.getSnapshot()` to be implemented.
   *
   * @returns The created snapshot node, or undefined if the provider does not support snapshots.
   * @throws {Error} If the current user does not have write access to this document.
   *   Only writers are authorized to create snapshots.
   */
  public async snapshot(): Promise<
    CRDTSnapshotNode<ChangesType, PublicKey> | undefined
  > {
    return this._runInMutationQueue(() => this._snapshotUnlocked());
  }

  private async _snapshotUnlocked(
    admitStateMutation?: () => void,
  ): Promise<CRDTSnapshotNode<ChangesType, PublicKey> | undefined> {
    await this._ensureCurrentUserCanWrite();
    admitStateMutation?.();

    if (!this._crdtProvider.getSnapshot) {
      console.warn(
        'CRDTProvider does not implement getSnapshot(); compaction disabled.',
      );
      this._snapshotUnsupported = true;
      return undefined;
    }

    const state = this._crdtProvider.getSnapshot(this._document);
    const lastChangeNodeCID = this._lastSyncMessage?.changeId ?? '';
    const timestamp = Date.now();

    // Create a deterministic, unambiguous binary payload to sign.
    // Use _documentChangeCount (document-kind changes only) rather than
    // _hashes.size (which includes ACL nodes) to keep the semantic consistent.
    // Binary layout with length prefixes avoids ambiguity and is efficient
    // for large state blobs (no JSON/Array.from overhead).
    const compactedCount = this._documentChangeCount;
    const stateBytes = this._changesSerializer.serializeChanges(state);
    let signature: Uint8Array;
    if (this._isSigningEnabled()) {
      const signPayload = this._buildSnapshotSignPayload(
        stateBytes,
        lastChangeNodeCID,
        timestamp,
        compactedCount,
      );
      signature = await this._authProvider.sign(signPayload, this._userKey);
    } else {
      signature = new Uint8Array(0);
    }

    const snapshotNode: CRDTSnapshotNode<ChangesType, PublicKey> = {
      state,
      lastChangeNodeCID,
      compactedCount,
      signature,
      publicKey: this._userPublicKey,
      timestamp,
    };

    admitStateMutation?.();
    this._latestSnapshot = snapshotNode;
    this._changesSinceSnapshot = 0;

    // Prune old change nodes from the in-memory sync tree if configured.
    // The snapshot is NOT stored on _lastSyncMessage -- it is only included
    // in load/snapshot-load responses via _latestSnapshot, to avoid bloating
    // every incremental pubsub sync message with the full snapshot state.
    if (this._lastSyncMessage && this._compactionConfig.pruneAfterSnapshot) {
      const prunedCIDs = this._pruneChanges(
        this._compactionConfig.keepRecentNodes,
      );

      // Delete pruned blocks from the Helia blockstore asynchronously, but only
      // when explicitly opted-in via `gcAfterPrune`. Filter out any CIDs that
      // remain reachable from the post-prune sync tree (e.g. ACL nodes that
      // were re-attached as leaves) and the snapshot boundary CID itself.
      // Fire-and-forget: GC errors are logged but don't block snapshot creation.
      if (
        this._compactionConfig.gcAfterPrune &&
        prunedCIDs.size > 0 &&
        this._lastSyncMessage?.changes &&
        this._lastSyncMessage.changeId
      ) {
        const protectedCIDs = lastChangeNodeCID ? [lastChangeNodeCID] : [];
        const deletable = filterDeletableCIDs(
          prunedCIDs,
          this._lastSyncMessage.changeId,
          this._lastSyncMessage.changes,
          protectedCIDs,
        );
        if (deletable.size > 0) {
          this._gcPrunedBlocks(deletable).catch(() => {
            console.error(`Blockstore GC failed for ${this.documentPath}`);
          });
        }
      }
    }

    console.log(
      `Created snapshot for ${this.documentPath}: ${snapshotNode.compactedCount} nodes compacted`,
    );

    return snapshotNode;
  }

  /**
   * Get list of writers.
   *
   * @return List of public keys with write access.
   */
  public async getWriters(): Promise<PublicKey[]> {
    this._throwIfSecurityProviderMutationFailed();
    const writers = await this._writers.users();
    this._throwIfSecurityProviderMutationFailed();
    return writers;
  }

  /**
   * Add a new user as a valid writer. Users are identified by their public keys
   *
   * @param writer User's public key
   * @throws {Error} If the writer ACL provider rejects after its mutation may
   *   have started. The document is permanently retired in-process; discard it
   *   and its ACL/keychain provider instances.
   */
  public async addWriter(writer: PublicKey) {
    return this._runInMutationQueue(() => this._addWriterUnlocked(writer));
  }

  private async _addWriterUnlocked(
    writer: PublicKey,
    beginMutation?: () => void,
  ): Promise<void> {
    await this._runWriterMembershipTransition(() =>
      this._addWriterUnderLock(writer, beginMutation),
    );
  }

  private async _addWriterUnderLock(
    writer: PublicKey,
    beginMutation?: () => void,
  ): Promise<void> {
    await this._ensureCurrentUserCanWrite();
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'writer ACL update',
    );
    const serializedWriter = await serializePublicKey(writer);
    let pending = this._pendingWriterAdds.get(serializedWriter);
    if (pending?.aclAddState === 'started') {
      this._retireAfterAmbiguousSecurityProviderMutation(
        `addWriter(${serializedWriter})`,
      );
    }
    if (pending === undefined) {
      // Check that the writer is not already a writer.
      if ((await this._writers.check(writer)) === true) return;
      beginMutation?.();
      pending = {
        aclAddState: 'started',
      };
      this._pendingWriterAdds.set(serializedWriter, pending);
      try {
        pending.writerChanges = this._requireMembershipWireChanges(
          await this._addWriter(writer),
          `addWriter(${serializedWriter}) returned an unrepresentable change`,
        );
      } catch (error) {
        this._retireAfterAmbiguousSecurityProviderMutation(
          `addWriter(${serializedWriter}) writer-ACL update`,
          error,
        );
      }
      pending.aclAddState = 'succeeded';
    }
    if (pending.preparedChange === undefined) {
      pending.preparedChange = await this._prepareChange(
        pending.writerChanges as ChangesType,
        crdtWriterChangeNode,
      );
    }
    await this._publishPreparedChange(pending.preparedChange);
    this._pendingWriterAdds.delete(serializedWriter);
  }

  /**
   * Remove a user as a valid writer. Users are identified by their public keys
   *
   * The replacement-key delta and writer ACL removal share one sync envelope
   * encrypted under the previous document key. With signing enabled (the
   * default), one writer signature binds both fields. Direct V2 and GossipSub
   * receivers authenticate the envelope and use the same key-before-ACL sync
   * order. This is not cross-provider rollback, a delivery guarantee, or
   * confidentiality from a holder of the previous key.
   *
   * @param writer User's public key
   * @throws {Error} If the writer ACL or keychain provider rejects after its
   *   mutation may have started. The document is permanently retired
   *   in-process; discard it and its ACL/keychain provider instances.
   */
  public async removeWriter(writer: PublicKey) {
    return this._runInMutationQueue(() => this._removeWriterUnlocked(writer));
  }

  private async _removeWriterUnlocked(writer: PublicKey): Promise<void> {
    await this._runWriterMembershipTransition(() =>
      this._removeWriterUnderLock(writer),
    );
  }

  private async _removeWriterUnderLock(writer: PublicKey): Promise<void> {
    this._throwIfSecurityProviderMutationFailed();
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'writer ACL removal',
    );
    const serializedWriter = await serializePublicKey(writer);
    let pending = this._pendingWriterRemovals.get(serializedWriter);
    if (
      pending?.aclRemoveState === 'started' ||
      pending?.keyAddState === 'started'
    ) {
      this._retireAfterAmbiguousSecurityProviderMutation(
        `removeWriter(${serializedWriter})`,
      );
    }
    if (pending === undefined) {
      await this._ensureCurrentUserCanWrite();
      const authorizedActor = await serializePublicKey(this._userPublicKey);
      // Check that the writer is already a writer.
      if ((await this._writers.check(writer)) !== true) return;
      pending = {
        authorizedActor,
        selfRemoval: serializedWriter === authorizedActor,
        aclRemoveState: 'started',
        keyAddState: 'not-started',
        publicationState: 'not-started',
        distributionState: 'not-started',
      };
      this._pendingWriterRemovals.set(serializedWriter, pending);
      try {
        pending.writerChanges = this._requireMembershipWireChanges(
          await this._removeWriter(writer),
          `removeWriter(${serializedWriter}) returned an unrepresentable writer change`,
        );
      } catch (error) {
        this._retireAfterAmbiguousSecurityProviderMutation(
          `removeWriter(${serializedWriter}) writer-ACL update`,
          error,
        );
      }
      pending.aclRemoveState = 'succeeded';
    } else {
      const currentActor = await serializePublicKey(this._userPublicKey);
      if (!pending.selfRemoval || currentActor !== pending.authorizedActor) {
        // A retry for somebody else's pending removal remains authorized only
        // while the initiating local actor is still a writer. Self-removal is
        // the sole exception: that exact transition caused the local ACL loss
        // and must be allowed to finish publishing/distributing its retained
        // material.
        await this._ensureCurrentUserCanWrite();
      }
    }
    if (pending.previousKey === undefined) {
      const current = snapshotExactTuple(
        await this._keychain.current(),
        2,
        'removeWriter current key',
      );
      pending.previousKey = [
        copyUnsharedUint8Array(
          current[0],
          this._keychainProvider.keyIDLength,
          this._keychainProvider.keyIDLength,
          'removeWriter previous key ID',
        ),
        current[1] as DocumentKey,
      ];
    }

    if (pending.keyAddState === 'not-started') {
      pending.keyAddState = 'started';
      try {
        const added = snapshotExactTuple(
          await this._keychain.add(),
          3,
          'removeWriter keychain add result',
        );
        copyUnsharedUint8Array(
          added[0],
          this._keychainProvider.keyIDLength,
          this._keychainProvider.keyIDLength,
          'removeWriter replacement key ID',
        );
        pending.keychainChanges = this._requireMembershipWireChanges(
          added[2] as ChangesType,
          `removeWriter(${serializedWriter}) returned an unrepresentable keychain change`,
        );
      } catch (error) {
        this._retireAfterAmbiguousSecurityProviderMutation(
          `removeWriter(${serializedWriter}) keychain rotation`,
          error,
        );
      }
      pending.keyAddState = 'succeeded';
    }

    if (pending.preparedChange === undefined) {
      pending.preparedChange = await this._prepareChange(
        pending.writerChanges as ChangesType,
        crdtWriterChangeNode,
        pending.previousKey,
        { value: pending.keychainChanges as ChangesType },
      );
    }
    if (pending.keyUpdateDelivery === undefined) {
      pending.keyUpdateDelivery = await this._prepareKeyUpdate(
        pending.preparedChange,
      );
    }

    if (pending.selfRemoval) {
      // Publish the authoritative combined envelope before best-effort direct
      // fanout. A connected peer can stall or reject its direct stream, and a
      // completed sink is not a receiver apply ACK; neither may block the
      // GossipSub path. Peers that missed GossipSub can still accept the same
      // signed old-key ciphertext directly while their old ACL is current.
      if (pending.publicationState !== 'succeeded') {
        pending.publicationState = 'started';
        await this._publishPreparedChange(pending.preparedChange);
        pending.publicationState = 'succeeded';
      }
      if (pending.distributionState !== 'succeeded') {
        pending.distributionState = 'started';
        await this._fanoutPreparedKeyUpdate(pending.keyUpdateDelivery);
        pending.distributionState = 'succeeded';
      }
    } else {
      // For another writer, preserve revocation-first semantics: the local
      // actor remains authorized to sign the already-prepared combined
      // writer-removal envelope.
      await this._ensureCurrentUserCanWrite();
      if (pending.publicationState !== 'succeeded') {
        pending.publicationState = 'started';
        await this._publishPreparedChange(pending.preparedChange);
        pending.publicationState = 'succeeded';
      }
      if (pending.distributionState !== 'succeeded') {
        pending.distributionState = 'started';
        await this._fanoutPreparedKeyUpdate(pending.keyUpdateDelivery);
        pending.distributionState = 'succeeded';
      }
    }
    this._pendingWriterRemovals.delete(serializedWriter);
  }

  /**
   * Returns a list of all public keys with read access.
   *
   * Deduplicates users that appear in both reader and writer ACLs,
   * which can occur due to concurrent edits or manual addition to both lists.
   *
   * @return List of public keys with read access.
   */
  public async getReaders(): Promise<PublicKey[]> {
    this._throwIfSecurityProviderMutationFailed();
    const [readers, writers] = await Promise.all([
      this._readers.users(),
      this._writers.users(),
    ]);
    // Filter out any writers that also appear in the readers list to avoid duplicates.
    // Run checks in parallel to avoid sequential async overhead with many writers.
    const checkResults = await Promise.all(
      writers.map((writer) => this._readers.check(writer)),
    );
    this._throwIfSecurityProviderMutationFailed();
    const filteredWriters = writers.filter((_, i) => checkResults[i] !== true);
    return [...readers, ...filteredWriters];
  }

  /**
   * Add a new user as a valid reader. Users are identified by their public keys.
   *
   * After updating the readers ACL, this attempts to send a BeeKEM Welcome
   * to the new reader so they receive (a) the keychain changes appropriate
   * for the document's `historyVisibility` setting (so they can decrypt at
   * least the current state), and (b) the invitation epoch ID they should
   * retain as a monotonic local audit/ordering anchor. The Welcome
   * uses Welcome v2 when a complete generation-bearing tree bootstrap is
   * available; cache-miss/stale retries fail closed rather than downgrade to a
   * key-only v1 payload. It is delivered to every
   * currently-connected peer; the receiving document ignores Welcomes
   * addressed to a different reader.
   *
   * CONFIDENTIALITY: the Welcome's keychain delta is sealed with ECIES
   * (P-256 ECDH + AES-256-GCM) under `readerKemPublicKey`, so only the
   * intended recipient can decrypt it. The recipient binding
   * (`welcomeRecipient`) is the **authorization** gate; the sealed
   * payload is the **confidentiality** gate. See `_prepareBeeKEMWelcome`
   * for the full construction.
   *
   * @param reader User's identity (signing) public key.
   * @param readerKemPublicKey Optional raw SEC1-uncompressed P-256
   *   ECDH public key (65 bytes) of the reader's KEM key pair. The
   *   reader must hold the matching private key (see
   *   `setKemKeyPair`). When this is `undefined`, the readers-ACL
   *   update is still broadcast but **no Welcome is sent**. This is an ACL-only
   *   grant and is not usable for decryption until the writer re-invokes
   *   `addReader` with the recipient's KEM key. A normal encrypted load cannot
   *   bootstrap an unknown current key. (The
   *   library refuses to broadcast an un-sealed Welcome to all peers
   *   because that would leak document key material in plaintext.)
   * @returns The BeeKEM Welcome used for this reader, or `null` when no
   *   recipient KEM key was supplied or recoverable.
   * @throws {Error} If the readers ACL provider rejects after its mutation may
   *   have started. The document is permanently retired in-process; discard it
   *   and its ACL/keychain provider instances.
   */
  public async addReader(
    reader: PublicKey,
    readerKemPublicKey?: Uint8Array,
  ): Promise<BeeKEMWelcome | null> {
    let kemPublicKey: Uint8Array | undefined;
    if (readerKemPublicKey !== undefined) {
      try {
        kemPublicKey = copyUnsharedUint8Array(
          readerKemPublicKey,
          ECIES_P256_PUBLIC_KEY_LENGTH,
          ECIES_P256_PUBLIC_KEY_LENGTH,
          'readerKemPublicKey',
        );
      } catch {
        throw new Error(
          `[${this.documentPath}] addReader: readerKemPublicKey must be ` +
            `${ECIES_P256_PUBLIC_KEY_LENGTH} bytes (SEC1-uncompressed P-256)`,
        );
      }
    }
    return this._runInMutationQueue(() =>
      this._addReaderUnlocked(reader, kemPublicKey),
    );
  }

  private async _addReaderUnlocked(
    reader: PublicKey,
    readerKemPublicKey?: Uint8Array,
    broadcastWelcome = true,
    beginMutation?: () => void,
  ): Promise<BeeKEMWelcome | null> {
    const result = await this._runBeeKEMTransition(() =>
      this._addReaderUnderBeeKEMLock(
        reader,
        readerKemPublicKey,
        broadcastWelcome,
        beginMutation,
      ),
    );
    await result.fanout;
    return result.welcome;
  }

  private async _addReaderUnderBeeKEMLock(
    reader: PublicKey,
    readerKemPublicKey?: Uint8Array,
    broadcastWelcome = true,
    beginMutation?: () => void,
  ): Promise<{
    fanout: Promise<void>;
    welcome: BeeKEMWelcome | null;
  }> {
    await this._ensureCurrentUserCanWrite();

    // Validate prerequisites BEFORE mutating any ACL state. The founder
    // (writer who created the document) MUST have called `setKemKeyPair`
    // before they can seed the BeeKEM tree. The leaf key pair must be a
    // real ECDH key pair the founder controls so future joiners that
    // decrypt path-key encryptions against this node land on consistent
    // key material. A founder that calls `addReader` before
    // `setKemKeyPair` is misconfigured -- surface the error before any
    // ACL change is committed, so a half-applied state (ACL row added
    // but no BeeKEM seeding / Welcome sent) is impossible.
    if (!this._beekemInitialized && !this._kemKeyPair) {
      throw new Error(
        `[${this.documentPath}] addReader: cannot seed the BeeKEM ratchet ` +
          `tree because the local user has not installed a KEM key pair ` +
          `via setKemKeyPair. Call setKemKeyPair with a P-256 ECDH key ` +
          `pair before adding readers.`,
      );
    }

    // Snapshot and validate the complete P-256 point before committing an ACL
    // row. Length alone is insufficient: WebCrypto also rejects off-curve
    // points, and discovering that after `_makeChange` would permanently
    // occupy the founder-plus-one slot without a usable BeeKEM leaf.
    if (
      readerKemPublicKey !== undefined &&
      readerKemPublicKey.byteLength !== ECIES_P256_PUBLIC_KEY_LENGTH
    ) {
      throw new Error(
        `[${this.documentPath}] addReader: readerKemPublicKey must be ` +
          `${ECIES_P256_PUBLIC_KEY_LENGTH} bytes (SEC1-uncompressed P-256), ` +
          `got ${readerKemPublicKey.byteLength}`,
      );
    }
    if (readerKemPublicKey !== undefined) {
      await importEciesPublicKey(readerKemPublicKey);
    }
    const prepareEpochKey = this._keychain.prepareEpochKey;
    if (
      readerKemPublicKey !== undefined &&
      typeof prepareEpochKey !== 'function'
    ) {
      throw new Error(
        `[${this.documentPath}] addReader: this keychain does not implement ` +
          `transactional prepareEpochKey; refusing a non-atomic BeeKEM transition`,
      );
    }

    // Founder-vs-joined-writer gate. The BeeKEM tree is rooted in
    // exactly one of two ways (see the long comment on `_beekem`):
    //   - **Founder**: a writer who completed local document creation in this
    //     instance (`_localFounderEstablished`) and may seed leaf 0 with its
    //     installed KEM key pair via `_initializeBeeKEMAsFounder`.
    //   - **Joined writer**: a writer who was added to an existing document by
    //     another writer. They MUST receive a BeeKEM Welcome before they can
    //     add readers or remove readers registered locally on this replica.
    //     Welcome processing does not reconstruct identity bindings for
    //     pre-existing readers, so those cannot be removed by identity here.
    //
    // Without this gate, a joined writer whose `_beekemInitialized`
    // is still false (no Welcome received yet) would fall through to
    // `_registerBeeKEMReader` -> `_initializeBeeKEMAsFounder`, silently
    // spawning a NEW divergent founder tree from a non-empty document
    // state. Their subsequent PathUpdates and Welcomes would come from
    // a tree shape that no other peer shares, so revocations from this
    // writer would never converge with anyone else's view -- a silent
    // correctness bug that this gate closes.
    //
    // Hash count alone is not a founder discriminator: successful creation
    // replicates the founder writer ACL and therefore has hashes before the
    // first addReader call. The explicit monotonic creation flag distinguishes
    // that case from a loaded/invited writer with no ratchet tree.
    if (
      !this._beekemInitialized &&
      !this._localFounderEstablished &&
      (this._hashes.size > 0 || this._invitationEpoch !== undefined)
    ) {
      throw new Error(
        `[${this.documentPath}] addReader: cannot register a reader -- ` +
          `this writer has document state but no BeeKEM tree bootstrapped ` +
          `from a Welcome. A joined writer must receive a fresh authenticated ` +
          `identity- and KEM-bound Welcome, or complete an authenticated ` +
          `remove/rejoin, before they can change BeeKEM membership. ` +
          `Initializing a fresh founder tree here would ` +
          `silently diverge from every other peer's tree state.`,
      );
    }

    // Idempotent on the ACL side, but if the caller has only now obtained
    // the recipient's KEM public key (e.g. a previous `addReader` call
    // skipped the Welcome because the key was unknown), still emit the
    // Welcome so the existing ACL row can be paired with keychain
    // material. Without this branch the warning emitted below on the
    // first call would point at a recovery path that is itself a no-op.
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'BeeKEM reader registration',
    );
    const serializedReader = await serializePublicKey(reader);
    let pendingAdd = this._pendingBeeKEMAdds.get(serializedReader);
    if (pendingAdd?.aclAddState === 'started') {
      this._retireAfterAmbiguousSecurityProviderMutation(
        `addReader(${serializedReader})`,
      );
    }
    if (
      pendingAdd?.readerKemPublicKey !== undefined &&
      readerKemPublicKey !== undefined &&
      !this._constantTimeEquals(
        pendingAdd.readerKemPublicKey,
        readerKemPublicKey,
      )
    ) {
      throw new Error(
        `[${this.documentPath}] addReader: a retryable transition for this ` +
          `identity is already bound to a different KEM public key`,
      );
    }
    if (pendingAdd?.readerKemPublicKey !== undefined) {
      readerKemPublicKey = pendingAdd.readerKemPublicKey;
    } else if (pendingAdd !== undefined && readerKemPublicKey !== undefined) {
      // Upgrade an exact ACL-only retry to the caller's detached KEM binding.
      // Once retained, every later retry uses these same bytes.
      pendingAdd.readerKemPublicKey = new Uint8Array(readerKemPublicKey);
      readerKemPublicKey = pendingAdd.readerKemPublicKey;
    }
    const existingKemPublicKey =
      this._readerKemPublicKeys.get(serializedReader);
    if (
      existingKemPublicKey !== undefined &&
      readerKemPublicKey !== undefined &&
      !this._constantTimeEquals(existingKemPublicKey, readerKemPublicKey)
    ) {
      throw new Error(
        `[${this.documentPath}] addReader: identity ${serializedReader} is ` +
          `already bound to a different KEM public key`,
      );
    }
    if (readerKemPublicKey !== undefined) {
      if (this._beekemInitialized && this._beekem) {
        const matchingLeaf =
          await this._beekem.findLeafByPublicKey(readerKemPublicKey);
        if (existingKemPublicKey === undefined && matchingLeaf !== undefined) {
          throw new Error(
            `[${this.documentPath}] addReader: KEM public key already belongs ` +
              `to a live BeeKEM leaf for a different identity`,
          );
        }
        const existingLeaf = this._readerLeafIndices.get(serializedReader);
        if (
          existingKemPublicKey !== undefined &&
          (matchingLeaf === undefined ||
            (existingLeaf !== undefined && existingLeaf !== matchingLeaf))
        ) {
          throw new Error(
            `[${this.documentPath}] addReader: the existing identity/KEM ` +
              `binding does not resolve to its unique live BeeKEM leaf`,
          );
        }
      } else if (
        existingKemPublicKey === undefined &&
        this._kemPublicKeyRaw !== undefined &&
        this._constantTimeEquals(this._kemPublicKeyRaw, readerKemPublicKey)
      ) {
        throw new Error(
          `[${this.documentPath}] addReader: KEM public key already belongs ` +
            `to the founder's live BeeKEM leaf`,
        );
      }
    }
    const alreadyReader =
      pendingAdd !== undefined
        ? true
        : (await this._readers.check(reader)) === true;
    if (!alreadyReader) {
      beginMutation?.();
      pendingAdd = {
        readerKemPublicKey:
          readerKemPublicKey === undefined
            ? undefined
            : new Uint8Array(readerKemPublicKey),
        aclAddState: 'started',
      };
      this._pendingBeeKEMAdds.set(serializedReader, pendingAdd);
      try {
        pendingAdd.readerChanges = this._requireMembershipWireChanges(
          await this._readers.add(reader),
          `addReader(${serializedReader}) returned an unrepresentable change`,
        );
      } catch (error) {
        this._retireAfterAmbiguousSecurityProviderMutation(
          `addReader(${serializedReader}) readers-ACL update`,
          error,
        );
      }
      pendingAdd.aclAddState = 'succeeded';
    }
    const hasReaderChanges = pendingAdd?.aclAddState === 'succeeded';
    const readerChanges = pendingAdd?.readerChanges as ChangesType;

    // Record the new reader in the BeeKEM ratchet tree so:
    //   a) a future `removeReader` call can cryptographically revoke
    //      them (their leaf is blanked and the path re-keyed), and
    //   b) the inviter can ship the resulting BeeKEM `Welcome` (the
    //      path keys encrypted under the joiner's leaf public key)
    //      inside the sealed Welcome payload so the joiner can
    //      bootstrap their local BeeKEM state and apply subsequent
    //      PathUpdates.
    //
    // The leaf is seeded with `readerKemPublicKey` -- the reader's own
    // KEM public key, also used as the ECIES recipient for the sealed
    // payload. The reader holds the matching private key, so they can
    // decrypt the path-key chain in the Welcome (see
    // `BeeKEM.processWelcome`).
    //
    // When `readerKemPublicKey` is absent the leaf is left
    // UNALLOCATED: an unrelated placeholder key would let
    // `removeReader` find a leaf to blank, but the joiner could
    // never bootstrap their own BeeKEM state without the private
    // material that matches the placeholder. The library refuses
    // that ambiguous half-onboarded state and surfaces the warning
    // below directing the caller to re-invoke with the KEM key.
    //
    // If registration or any Welcome/PathUpdate/ACL preparation throws, the
    // transactional BeeKEM callback restores the tree and no prepared ACL
    // change is published. We propagate rather than send a key-only Welcome:
    // that would leave the recipient unable to apply the next PathUpdate.
    // Without the recipient's KEM public key we cannot seal the
    // Welcome payload, and we will NEVER send an un-sealed Welcome --
    // that would broadcast `keychainChanges` to every connected peer.
    if (!readerKemPublicKey) {
      if (!alreadyReader) {
        console.warn(
          `[${this.documentPath}] addReader: BeeKEM Welcome skipped because ` +
            `the caller did not provide \`readerKemPublicKey\`. The reader ` +
            `has been added to the readers ACL, but to deliver the document ` +
            `key the caller must either (a) re-invoke \`addReader(reader, ` +
            `readerKemPublicKey)\` once the recipient's raw SEC1 P-256 ECDH ` +
            `public key is available. An ordinary encrypted document load ` +
            `cannot bootstrap a recipient that does not yet know the current key.`,
        );
      }
      const preparedReaderChange = hasReaderChanges
        ? await this._prepareChange(readerChanges, crdtReaderChangeNode)
        : undefined;
      const fanout = this._enqueueBeeKEMFanout(async () => {
        if (preparedReaderChange) {
          await this._publishPreparedChange(preparedReaderChange);
        }
      });
      if (pendingAdd !== undefined) {
        this._pendingBeeKEMAdds.delete(serializedReader);
      }
      return { fanout, welcome: null };
    }

    if (pendingAdd === undefined) {
      pendingAdd = {
        readerKemPublicKey: new Uint8Array(readerKemPublicKey),
        aclAddState: 'not-needed',
      };
      this._pendingBeeKEMAdds.set(serializedReader, pendingAdd);
    }

    let registration = pendingAdd.registration;
    if (registration === undefined) {
      let pathDelivery: PreparedBeeKEMDelivery | undefined;
      let welcomeDelivery: PreparedBeeKEMDelivery | undefined;
      let preparedReaderChange:
        | PreparedLocalChange<ChangesType, PublicKey>
        | undefined;
      registration = await this._registerBeeKEMReaderUnderLock(
        reader,
        readerKemPublicKey,
        async (freshRegistration) => {
          const [newKey, epochId] = await Promise.all([
            deriveDocumentKeyFromRootSecret(freshRegistration.rootSecret),
            deriveEpochIdFromRootSecret(freshRegistration.rootSecret),
          ]);
          const stagedEpoch = await prepareEpochKey!.call(
            this._keychain,
            epochId,
            newKey as unknown as DocumentKey,
          );
          pathDelivery = await this._prepareBeeKEMPathUpdate(
            freshRegistration.pathUpdate,
            epochId,
          );
          preparedReaderChange = hasReaderChanges
            ? await this._prepareChange(readerChanges, crdtReaderChangeNode, [
                epochId,
                newKey as unknown as DocumentKey,
              ])
            : undefined;
          welcomeDelivery = await this._prepareBeeKEMWelcome(
            reader,
            readerKemPublicKey,
            freshRegistration.welcome,
            {
              epochId,
              welcomeKeychainChanges: this._requireWireChanges(
                this._historyVisibility === 'full_history'
                  ? stagedEpoch.history
                  : stagedEpoch.currentKeyChange,
                'BeeKEM Welcome keychain change',
              ),
            },
          );

          // All fallible work is complete. The shipped staged keychains make
          // this synchronous commit atomic and throw-before-mutation if their
          // base state changed. A custom implementation must provide the same
          // contract.
          this._commitPreparedKeychainState(
            stagedEpoch,
            `addReader(${serializedReader}) staged epoch commit`,
          );
          if (preparedReaderChange) {
            this._commitPreparedChange(preparedReaderChange);
          }
        },
        beginMutation,
      );
      if (welcomeDelivery === undefined) {
        const cachedWelcome = registration.welcome;
        const currentGeneration = this._beekem?.generation;
        if (
          cachedWelcome === null ||
          cachedWelcome.version !== 2 ||
          cachedWelcome.generation === undefined ||
          cachedWelcome.generation !== currentGeneration
        ) {
          this._pendingBeeKEMAdds.delete(serializedReader);
          throw new Error(
            `[${this.documentPath}] addReader: the cached Welcome is missing ` +
              `or stale for the live BeeKEM generation; safe recovery requires ` +
              `an authenticated remove/rejoin with current ratchet state`,
          );
        }
        // Same-generation re-send: no tree/key state changed, so sealing and
        // signing a fresh recipient envelope is safely retryable outside a
        // membership transaction.
        welcomeDelivery = await this._prepareBeeKEMWelcome(
          reader,
          readerKemPublicKey,
          cachedWelcome,
        );
      }
      pendingAdd.registration = registration;
      pendingAdd.pathDelivery = pathDelivery;
      pendingAdd.preparedReaderChange = preparedReaderChange;
      if (welcomeDelivery === undefined) {
        throw new Error(
          `[${this.documentPath}] addReader: transition committed without prepared Welcome`,
        );
      }
      pendingAdd.welcomeDelivery = welcomeDelivery;
    }
    const welcomeDelivery = pendingAdd.welcomeDelivery;
    if (welcomeDelivery === undefined) {
      throw new Error(
        `[${this.documentPath}] addReader: retry record has no prepared Welcome`,
      );
    }
    const pathDelivery = pendingAdd.pathDelivery;
    const preparedReaderChange = pendingAdd.preparedReaderChange;
    const fanout = this._enqueueBeeKEMFanout(async () => {
      if (pathDelivery) {
        await this._fanoutPreparedBeeKEMDelivery(pathDelivery);
      }
      if (preparedReaderChange) {
        try {
          await this._publishPreparedChange(preparedReaderChange);
        } catch {
          console.warn(
            `[${this.documentPath}] addReader: readers-ACL broadcast failed`,
          );
        }
      }
      if (broadcastWelcome) {
        await this._fanoutPreparedBeeKEMDelivery(welcomeDelivery);
      }
    });
    this._pendingBeeKEMAdds.delete(serializedReader);
    return { fanout, welcome: registration.welcome };
  }

  /**
   * Grant an invitation recipient access and construct the encrypted material
   * returned by the invitation join protocol. The caller is responsible for
   * signing the outer acceptance and enforcing single-use offer semantics.
   * Membership work is not transactional: an error after mutation begins can
   * leave partial or complete recipient membership without a returned bundle.
   * Only an exact, same-process retry is eligible to repair and attest that
   * state.
   *
   * @internal
   */
  public async buildInvitationBootstrap(
    reader: PublicKey,
    readerKemPublicKey: Uint8Array,
    role: 'reader' | 'editor',
    assertCanMutate?: () => void,
    admitStateMutation?: () => void,
  ): Promise<InvitationBootstrapBundle> {
    const historyVisibility = this._historyVisibility;
    let kemPublicKey: Uint8Array;
    try {
      kemPublicKey = copyUnsharedUint8Array(
        readerKemPublicKey,
        ECIES_P256_PUBLIC_KEY_LENGTH,
        ECIES_P256_PUBLIC_KEY_LENGTH,
        'invitation recipient KEM public key',
      );
    } catch {
      throw new Error(
        `Invitation recipient KEM public key must be ` +
          `${ECIES_P256_PUBLIC_KEY_LENGTH} bytes`,
      );
    }
    return this._runInMutationQueue(() =>
      this._buildInvitationBootstrapUnlocked(
        reader,
        kemPublicKey,
        role,
        assertCanMutate,
        admitStateMutation,
        historyVisibility,
      ),
    );
  }

  private async _initialInvitationMembershipState(
    recipient: PublicKey,
  ): Promise<InitialInvitationMembershipState> {
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'Public invitations',
    );
    const [founder, serializedRecipient, readers, writers] = await Promise.all([
      serializePublicKey(this._userPublicKey),
      serializePublicKey(recipient),
      this._readers.users(),
      this._writers.users(),
    ]);
    const [serializedReaders, serializedWriters] = await Promise.all([
      Promise.all(readers.map((readerKey) => serializePublicKey(readerKey))),
      Promise.all(writers.map((writerKey) => serializePublicKey(writerKey))),
    ]);
    return {
      createdLocally:
        this._createdLocally && this._localFounderEstablished,
      founder,
      recipient: serializedRecipient,
      readers: serializedReaders,
      writers: serializedWriters,
    };
  }

  private async _buildInvitationBootstrapUnlocked(
    reader: PublicKey,
    readerKemPublicKey: Uint8Array,
    role: 'reader' | 'editor',
    assertCanMutate?: () => void,
    admitStateMutation?: () => void,
    historyVisibility: HistoryVisibility = this._historyVisibility,
  ): Promise<InvitationBootstrapBundle> {
    this._throwIfSecurityProviderMutationFailed();
    assertCanMutate?.();
    assertInitialInvitationHistoryVisibility(historyVisibility);
    if (role !== 'reader' && role !== 'editor') {
      throw new Error(`Unsupported invitation role: ${String(role)}`);
    }

    const capacityPlan = await this._prepareInvitationBootstrapCapacity(
      reader,
      historyVisibility,
    );
    this._throwIfSecurityProviderMutationFailed();

    const beginMutation = createInvitationMutationAdmission(() => {
      assertCanMutate?.();
      admitStateMutation?.();
      this._lastSyncMessage = capacityPlan.currentMessage;
    });

    const kemPublicKey = readerKemPublicKey;
    const beekemWelcome = await prepareInitialInvitationMembership({
      role,
      getState: () => this._initialInvitationMembershipState(reader),
      // The public wrappers use this same queue, so internal composition must
      // call the unlocked helpers to avoid a reentrant wait on our own slot.
      addReader: async () => {
        // Recheck after asynchronous capacity and topology preflight. The
        // one-shot guard passed below checks again immediately before the
        // first ACL or BeeKEM state writer, then admits the rest of that commit.
        assertCanMutate?.();
        const welcome = await this._addReaderUnlocked(
          reader,
          kemPublicKey,
          false,
          beginMutation,
        );
        if (!welcome) {
          throw new Error(
            `Cannot build invitation bootstrap for ${this.documentPath}: ` +
              'no BeeKEM Welcome is available for the recipient',
          );
        }
        return welcome;
      },
      addWriter: () => this._addWriterUnlocked(reader, beginMutation),
      repairReaders: () => {
        beginMutation();
        return this._makeChange(
          this._readers.current(),
          crdtReaderChangeNode,
        );
      },
      repairWriters: () => {
        beginMutation();
        return this._makeChange(
          this._writers.current(),
          crdtWriterChangeNode,
        );
      },
    });

    const current = snapshotExactTuple(
      await this._keychain.current(),
      2,
      'invitation current key',
    );
    const welcomeEpochId = copyUnsharedUint8Array(
      current[0],
      this._keychainProvider.keyIDLength,
      this._keychainProvider.keyIDLength,
      'invitation Welcome epoch',
    );
    const documentKey = current[1] as DocumentKey;
    const rawKeychainChanges =
      await this._keychainChangesForWelcome(historyVisibility);
    const keychainChanges = this._changesSerializer.deserializeChanges(
      this._changesSerializer.serializeChanges(rawKeychainChanges),
    );
    if (
      beekemWelcome.version !== 2 ||
      beekemWelcome.generation === undefined ||
      beekemWelcome.numLeaves === undefined
    ) {
      throw new Error(
        `Invitation Welcome for ${this.documentPath} is not generation-bearing`,
      );
    }
    const sealedPayload = encodeWelcomeSealedPayloadV2({
      keychainChanges: this._changesSerializer.serializeChanges(keychainChanges),
      beekemWelcome: beekemWelcome as BeeKEMWelcomeV2,
    });
    const sealedWelcome = await eciesSeal(
      sealedPayload,
      await importEciesPublicKey(kemPublicKey),
    );
    if (
      sealedWelcome.byteLength - capacityPlan.welcomeWithoutBeeKEMBytes >
      INITIAL_INVITATION_MAX_SEALED_WELCOME_GROWTH_BYTES
    ) {
      throw new Error(
        `Invitation Welcome for ${this.documentPath} exceeded the declared attested-profile growth bound`,
      );
    }
    assertInvitationOpaquePayloadCapacity(
      sealedWelcome,
      'Welcome',
      this.documentPath,
    );

    const bootstrapMessage = this._createSyncMessage();
    bootstrapMessage.keychainChanges = keychainChanges;
    if (capacityPlan.snapshot) {
      bootstrapMessage.snapshot = capacityPlan.snapshot;
    }
    bootstrapMessage.tips = computeServedFrontier(
      bootstrapMessage.changeId,
      bootstrapMessage.changes,
      capacityPlan.snapshot?.lastChangeNodeCID,
    );
    bootstrapMessage.signature =
      await this._signAsWriterUnconditional(bootstrapMessage);
    if (
      this._deserializeSignature(bootstrapMessage.signature).byteLength >
      INITIAL_INVITATION_MAX_SIGNATURE_BYTES
    ) {
      throw new Error(
        `Invitation bootstrap for ${this.documentPath} exceeded the declared signature bound`,
      );
    }
    const bootstrapPlaintext =
      this._syncMessageSerializer.serializeSyncMessage(bootstrapMessage);
    if (
      bootstrapPlaintext.byteLength -
        capacityPlan.serializedBootstrapBaselineBytes >
      INITIAL_INVITATION_MAX_MEMBERSHIP_GROWTH_BYTES
    ) {
      throw new Error(
        `Invitation bootstrap for ${this.documentPath} exceeded the declared attested-profile membership-growth bound`,
      );
    }
    const encrypted = await this._authProvider.encrypt(
      bootstrapPlaintext,
      documentKey,
    );
    if (!encrypted.nonce) {
      throw new Error(
        `Cannot build invitation bootstrap for ${this.documentPath}: ` +
          'encryption returned no nonce',
      );
    }

    const encryptedBootstrap = copyUnsharedUint8Array(
      concatUint8Arrays(welcomeEpochId, encrypted.nonce, encrypted.data),
      1,
      MAX_INVITATION_MESSAGE_BYTES,
      'invitation encrypted bootstrap',
    );
    if (
      encryptedBootstrap.byteLength - bootstrapPlaintext.byteLength >
      INITIAL_INVITATION_MAX_ENCRYPTED_BOOTSTRAP_OVERHEAD_BYTES
    ) {
      throw new Error(
        `Invitation bootstrap for ${this.documentPath} exceeded the declared encryption bound`,
      );
    }
    assertInvitationOpaquePayloadCapacity(
      encryptedBootstrap,
      'bootstrap',
      this.documentPath,
    );

    return {
      welcomeEpochId,
      sealedWelcome: new Uint8Array(sealedWelcome),
      encryptedBootstrap: new Uint8Array(encryptedBootstrap),
    };
  }

  /** Freeze and size the complete bootstrap before changing ACL/BeeKEM state. */
  private async _prepareInvitationBootstrapCapacity(
    reader: PublicKey,
    historyVisibility: HistoryVisibility = this._historyVisibility,
  ): Promise<
    InvitationBootstrapCapacityPlan<ChangesType, PublicKey>
  > {
    this._assertInitialInvitationCapacityProfile();

    // Detach provider-owned and caller-supplied aliases synchronously before
    // the first await. The queue excludes Peerborne API writers; these round
    // trips also keep a previously supplied sync tree or returned snapshot
    // reference from changing the bytes underneath the capacity projection.
    const frozenCurrentMessage =
      this._syncMessageSerializer.deserializeSyncMessage(
        this._syncMessageSerializer.serializeSyncMessage(
          this._createSyncMessage(),
        ),
      );
    const snapshot = this._latestSnapshot
      ? {
          ...this._latestSnapshot,
          state: this._changesSerializer.deserializeChanges(
            this._changesSerializer.serializeChanges(
              this._latestSnapshot.state,
            ),
          ),
          signature: new Uint8Array(this._latestSnapshot.signature),
        }
      : undefined;
    const frozenTips = computeServedFrontier(
      frozenCurrentMessage.changeId,
      frozenCurrentMessage.changes,
      snapshot?.lastChangeNodeCID,
    );

    const readerAlreadyPresent = await this._readers.check(reader);
    let hasRetryLeaf = false;
    let hasRetryWelcome = false;
    if (this._beekem?.memberCount === 2 && readerAlreadyPresent) {
      const serializePublicKey = requireSerializePublicKey(
        this._authProvider,
        'Invitation BeeKEM retry validation',
      );
      const serializedReader = await serializePublicKey(reader);
      const leafIndex = this._readerLeafIndices.get(serializedReader);
      hasRetryLeaf = leafIndex !== undefined;
      hasRetryWelcome =
        leafIndex !== undefined && this._beekemWelcomeByLeaf.has(leafIndex);
    }
    assertInitialInvitationBeeKEMCapacity(
      this._beekem?.memberCount,
      readerAlreadyPresent,
      this.documentPath,
      hasRetryLeaf,
      hasRetryWelcome,
    );
    assertInitialInvitationHistoryVisibility(historyVisibility);

    const [rawKeychainChanges, rawFullKeychainChanges] = await Promise.all([
      this._keychainChangesForWelcome(historyVisibility),
      this._keychain.history(),
    ]);
    const keychainChanges = this._changesSerializer.deserializeChanges(
      this._changesSerializer.serializeChanges(rawKeychainChanges),
    );
    const fullKeychainChanges = this._changesSerializer.deserializeChanges(
      this._changesSerializer.serializeChanges(rawFullKeychainChanges),
    );
    const projection = projectInitialInvitationBootstrapCapacity({
      currentMessage: frozenCurrentMessage,
      keychainChanges: fullKeychainChanges,
      snapshot,
      tips: frozenTips,
      serializer: this._syncMessageSerializer,
    });
    assertProjectedInitialInvitationBootstrapCapacity(
      projection,
      this.documentPath,
    );

    const welcomeWithoutBeeKEM = encodeWelcomeSealedPayload({
      keychainChanges:
        this._changesSerializer.serializeChanges(keychainChanges),
      beekemWelcome: null,
    });
    assertProjectedInitialInvitationWelcomeCapacity(
      welcomeWithoutBeeKEM.byteLength,
      this.documentPath,
    );
    return {
      currentMessage: frozenCurrentMessage,
      keychainChanges,
      snapshot,
      serializedBootstrapBaselineBytes: projection.serializedBaselineBytes,
      welcomeWithoutBeeKEMBytes: welcomeWithoutBeeKEM.byteLength,
    };
  }

  private async _assertAcceptedInvitationMembership(
    issuerPublicKey: PublicKey,
    role: 'reader' | 'editor',
  ): Promise<void> {
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'Public invitations',
    );
    const [issuer, recipient, readers, writers] = await Promise.all([
      serializePublicKey(issuerPublicKey),
      serializePublicKey(this._userPublicKey),
      this._readers.users(),
      this._writers.users(),
    ]);
    const [serializedReaders, serializedWriters] = await Promise.all([
      Promise.all(readers.map((readerKey) => serializePublicKey(readerKey))),
      Promise.all(writers.map((writerKey) => serializePublicKey(writerKey))),
    ]);
    assertAcceptedInvitationMembershipTopology(
      {
        issuer,
        recipient,
        readers: serializedReaders,
        writers: serializedWriters,
      },
      role,
    );
  }

  /**
   * Apply a recipient-bound invitation bootstrap and activate the document
   * without invoking normal first-load/new-document detection.
   *
   * The outer invitation acceptance must be verified against
   * `issuerPublicKey` before this method is called. This method independently
   * verifies the enclosed bootstrap signature against that exact key.
   *
   * @internal
   */
  public async acceptInvitationBootstrap(
    bundle: InvitationBootstrapBundle,
    issuerPublicKey: PublicKey,
    role: 'reader' | 'editor',
    founderAddress: string,
  ): Promise<void> {
    if (role !== 'reader' && role !== 'editor') {
      throw new Error(`Unsupported invitation role: ${String(role)}`);
    }
    this._assertInitialInvitationCapacityProfile();
    const rawBundle = snapshotEnumerableOwnDataObject<InvitationBootstrapBundle>(
      bundle,
      'invitation bootstrap bundle',
    );
    const stableBundle: InvitationBootstrapBundle = {
      welcomeEpochId: copyUnsharedUint8Array(
        rawBundle.welcomeEpochId,
        this._keychainProvider.keyIDLength,
        this._keychainProvider.keyIDLength,
        'invitation Welcome epoch',
      ),
      sealedWelcome: copyUnsharedUint8Array(
        rawBundle.sealedWelcome,
        1,
        MAX_INVITATION_MESSAGE_BYTES,
        'invitation sealed Welcome',
      ),
      encryptedBootstrap: copyUnsharedUint8Array(
        rawBundle.encryptedBootstrap,
        this._keychainProvider.keyIDLength + this._authProvider.nonceBits + 1,
        MAX_INVITATION_MESSAGE_BYTES,
        'invitation encrypted bootstrap',
      ),
    };
    assertInvitationOpaquePayloadCapacity(
      stableBundle.sealedWelcome,
      'Welcome',
      this.documentPath,
    );
    assertInvitationOpaquePayloadCapacity(
      stableBundle.encryptedBootstrap,
      'bootstrap',
      this.documentPath,
    );

    try {
      await this._runInMutationQueue(() =>
        this._runBeeKEMTransition(() =>
          this._acceptInvitationBootstrapUnderBeeKEMLock(
            stableBundle,
            issuerPublicKey,
            role,
          ),
        ),
      );
      const existing = await this.open();
      if (!existing) {
        throw new Error('Invitation bootstrap attempted to create a new document');
      }
      if (
        !(await this._loadInvitationCatchUp(
          founderAddress,
          issuerPublicKey,
        ))
      ) {
        throw new Error('Invitation bootstrap catch-up load failed');
      }
      await this._assertAcceptedInvitationMembership(issuerPublicKey, role);
    } catch (error) {
      this._invitationBootstrapReady = false;
      await this.close().catch(() => {});
      throw error;
    }
  }

  private async _acceptInvitationBootstrapUnderBeeKEMLock(
    bundle: InvitationBootstrapBundle,
    issuerPublicKey: PublicKey,
    role: 'reader' | 'editor',
  ): Promise<void> {
    this._throwIfSecurityProviderMutationFailed();
    if (
      this._hashes.size > 0 ||
      this._subscribed ||
      this._invitationEpoch !== undefined ||
      this._beekemInitialized ||
      this._pendingFounderInitialization !== undefined
    ) {
      throw new Error(
        `Invitation bootstrap for ${this.documentPath} requires a fresh document instance`,
      );
    }
    if (!this._kemKeyPair || !this._kemPublicKeyRaw) {
      throw new Error(
        `Invitation bootstrap for ${this.documentPath} requires a KEM key pair ` +
          'installed via setKemKeyPair',
      );
    }
    if (!isTransactionalKeychain(this._keychain)) {
      throw new Error(
        `Invitation bootstrap for ${this.documentPath} requires a ` +
          'transactional keychain',
      );
    }

    let welcomeEnvelope;
    try {
      welcomeEnvelope = decodeWelcomeSealedPayloadV2(
        await eciesOpen(bundle.sealedWelcome, this._kemKeyPair.privateKey),
      );
    } catch {
      throw new Error('Invitation sealed Welcome could not be opened');
    }
    assertInitialInvitationBeeKEMWelcomeShape(
      welcomeEnvelope.beekemWelcome,
    );

    const beekem = new BeeKEM();
    let rootSecret: Uint8Array;
    try {
      rootSecret = await beekem.processWelcome(
        welcomeEnvelope.beekemWelcome,
        this._kemKeyPair.privateKey,
        this._kemKeyPair.publicKey,
      );
    } catch {
      throw new Error('Invitation BeeKEM bootstrap could not be processed');
    }
    if (beekem.memberCount !== 2 || beekem.myLeafIndex !== 2) {
      throw new Error(
        'Invitation BeeKEM bootstrap did not produce the founder-plus-one recipient state',
      );
    }
    const [derivedEpochId, derivedDocumentKey] = await Promise.all([
      deriveEpochIdFromRootSecret(rootSecret),
      deriveDocumentKeyFromRootSecret(rootSecret),
    ]);
    if (!this._constantTimeEquals(derivedEpochId, bundle.welcomeEpochId)) {
      throw new Error(
        'Invitation Welcome epoch is not derived from the BeeKEM root',
      );
    }

    const headerLength =
      this._keychainProvider.keyIDLength + this._authProvider.nonceBits;
    const bootstrapKeyId = bundle.encryptedBootstrap.subarray(
      0,
      this._keychainProvider.keyIDLength,
    );
    assertInvitationBootstrapEpochBinding(
      bundle.welcomeEpochId,
      bootstrapKeyId,
    );
    const nonce = bundle.encryptedBootstrap.subarray(
      this._keychainProvider.keyIDLength,
      headerLength,
    );
    const ciphertext = bundle.encryptedBootstrap.subarray(headerLength);
    let bootstrapPlaintext: Uint8Array;
    try {
      bootstrapPlaintext = copyUnsharedUint8Array(
        await this._authProvider.decrypt(
          ciphertext,
          derivedDocumentKey as unknown as DocumentKey,
          nonce,
        ),
        1,
        MAX_INVITATION_MESSAGE_BYTES,
        'invitation bootstrap plaintext',
      );
    } catch {
      throw new Error('Invitation encrypted bootstrap could not be decrypted');
    }

    let bootstrapMessage: CRDTSyncMessage<ChangesType, PublicKey>;
    try {
      bootstrapMessage = this._canonicalizeSyncMessage(
        this._syncMessageSerializer.deserializeSyncMessage(
          bootstrapPlaintext,
        ),
        'invitation bootstrap message',
        MAX_INVITATION_MESSAGE_BYTES,
      );
    } catch {
      throw new Error('Invitation bootstrap message is malformed');
    }
    if (bootstrapMessage.documentId !== this.documentPath) {
      throw new Error('Invitation bootstrap document binding does not match');
    }
    if (!bootstrapMessage.signature) {
      throw new Error('Invitation bootstrap is missing its issuer signature');
    }
    if (bootstrapMessage.keychainChanges === undefined) {
      throw new Error('Invitation bootstrap is missing its keychain binding');
    }

    const keychainChanges = this._changesSerializer.deserializeChanges(
      welcomeEnvelope.keychainChanges,
    );
    let welcomeKeychainBytes: Uint8Array;
    let bootstrapKeychainBytes: Uint8Array;
    try {
      welcomeKeychainBytes = copyUnsharedUint8Array(
        this._changesSerializer.serializeChanges(keychainChanges),
        1,
        MAX_INVITATION_MESSAGE_BYTES,
        'invitation Welcome keychain changes',
      );
      bootstrapKeychainBytes = copyUnsharedUint8Array(
        this._changesSerializer.serializeChanges(
          bootstrapMessage.keychainChanges,
        ),
        1,
        MAX_INVITATION_MESSAGE_BYTES,
        'invitation bootstrap keychain changes',
      );
    } catch {
      throw new Error('Invitation keychain changes are malformed');
    }
    if (!this._constantTimeEquals(welcomeKeychainBytes, bootstrapKeychainBytes)) {
      throw new Error(
        'Invitation bootstrap keychain does not match its sealed Welcome',
      );
    }

    const { signature, ...unsignedBootstrap } = bootstrapMessage;
    let signatureBytes: Uint8Array;
    try {
      signatureBytes = this._deserializeSignature(signature);
    } catch {
      throw new Error('Invitation bootstrap signature is malformed');
    }
    let signatureValid = false;
    try {
      signatureValid =
        (await this._authProvider.verify(
          this._syncMessageSerializer.serializeSyncMessage(
            unsignedBootstrap,
          ),
          issuerPublicKey,
          signatureBytes,
        )) === true;
    } catch {
      signatureValid = false;
    }
    if (!signatureValid) {
      throw new Error(
        'Invitation bootstrap signature does not match the offer issuer',
      );
    }

    const stagedKeychain = this._keychain.prepareMerge(keychainChanges);
    if (
      !stagedKeychain.keyIds.some((keyId) =>
        this._constantTimeEquals(keyId, bundle.welcomeEpochId),
      )
    ) {
      throw new Error(
        'Invitation Welcome did not stage its advertised epoch key',
      );
    }

    const initialLoadAuthorization: InitialLoadSyncAuthorization<PublicKey> = {
      writerKeys: [issuerPublicKey],
      writerVersion: this._writerKeysVersion,
    };
    const snapshotBoundaryBeforeSync =
      this._latestSnapshot?.lastChangeNodeCID;
    // The exact same keychain state was authenticated and staged above. Avoid
    // asking the live provider to merge it a second time inside `_sync`.
    bootstrapMessage.keychainChanges = undefined;
    let committed = false;
    try {
      this._commitPreparedKeychainState(
        stagedKeychain,
        'invitation bootstrap staged keychain commit',
      );
      committed = true;

      // The shipped keychains keep imported CryptoKeys in a synchronous
      // lookup cache. A staged merge commits the authenticated CRDT state but
      // deliberately does not perform asynchronous key import, so hydrate the
      // committed state before the immediate founder catch-up can call
      // `getKey()` on its encrypted response.
      await this._keychain.keys();
      const installedEpochKey = this._keychain.getKey(
        bundle.welcomeEpochId,
      );
      if (installedEpochKey === undefined) {
        throw new Error(
          'Invitation Welcome did not install its advertised epoch key',
        );
      }

      // Bind the key material carried by the signed keychain changes to the
      // BeeKEM-derived root, not merely to its epoch ID. Both decryptions are
      // bounded snapshots; accepting different plaintext would leave the
      // bootstrap usable under one key while the next load uses another.
      let installedKeyPlaintext: Uint8Array;
      try {
        installedKeyPlaintext = copyUnsharedUint8Array(
          await this._authProvider.decrypt(
            ciphertext,
            installedEpochKey,
            nonce,
          ),
          1,
          MAX_INVITATION_MESSAGE_BYTES,
          'invitation installed-key bootstrap plaintext',
        );
      } catch {
        throw new Error(
          'Invitation staged epoch key does not match its BeeKEM root',
        );
      }
      if (
        !this._constantTimeEquals(
          bootstrapPlaintext,
          installedKeyPlaintext,
        )
      ) {
        throw new Error(
          'Invitation staged epoch key does not match its BeeKEM root',
        );
      }

      this._beekem = beekem;
      this._beekemInitialized = true;
      this._invitationEpoch = new Uint8Array(bundle.welcomeEpochId);

      const applied = await syncInvitationMessageCompletely(
        bootstrapMessage,
        this._hashes,
        () =>
          this._syncUnlocked(
            bootstrapMessage,
            false,
            initialLoadAuthorization,
          ),
        'bootstrap',
        {
          provenSnapshotBoundariesBeforeSync:
            snapshotBoundaryBeforeSync === undefined
              ? undefined
              : new Set([snapshotBoundaryBeforeSync]),
          isSnapshotApplied: () =>
            this._latestSnapshot === bootstrapMessage.snapshot,
        },
      );
      if (!applied) {
        throw new Error('Invitation bootstrap state was rejected');
      }
      await this._assertAcceptedInvitationMembership(issuerPublicKey, role);
    } catch (error) {
      if (
        committed &&
        this._securityProviderMutationFailure === undefined
      ) {
        this._retireAfterAmbiguousSecurityProviderMutation(
          'invitation bootstrap state application',
          error,
        );
      }
      throw error;
    }
    this._invitationBootstrapReady = true;
  }

  /**
   * Build an immutable BeeKEM Welcome delivery for a newly-added reader.
   * Network fanout occurs later on the ordered, deadline-bounded fanout queue.
   *
   * The Welcome payload is a `CRDTSyncMessage` carrying:
   * - `welcomeEpochId`: the current keychain key ID, which the recipient
   *   records as its local monotonic invitation anchor. Ordinary load does
   *   not reuse this responder-local value as another requester's boundary.
   * - `welcomeRecipient`: serialized public key of the intended recipient.
   *   The inviter cannot identify which connected peer is the new reader,
   *   so Welcomes are broadcast to every peer; the recipient binding
   *   ensures a *well-behaved* non-target peer drops the Welcome rather
   *   than installing the document key. The binding is covered by the
   *   writer signature, so a non-writer cannot redirect a Welcome to a
   *   different recipient.
   * - `welcomeRecipientKemPublicKey`: raw SEC1 P-256 ECDH public key of
   *   the recipient. Also covered by the writer signature -- the writer
   *   commits to a specific encryption key for a specific identity, so
   *   an attacker that owns one of those two values alone cannot
   *   redirect the sealed payload.
   * - `eciesSealed`: the inviter-side serialized keychain delta
   *   encrypted under the recipient's ECDH key via ECIES (see
   *   `ecies.ts`). This is the confidentiality control: a
   *   non-recipient peer that receives the broadcast cannot decrypt
   *   the keychain delta. The keychain plaintext is filtered per the
   *   document's `historyVisibility` **from the recipient's
   *   perspective** (see `_keychainChangesForWelcome()`).
   * - `signature`: writer signature over the message so the receiver can
   *   confirm a legitimate writer is the inviter (and ignore forgeries).
   *   The signature covers the **sealed** bytes, not the plaintext, so
   *   alteration fails signature verification. Exact replay retains a valid
   *   signature: V2 generation checks reject stale/duplicate state changes,
   *   while legacy V1 may idempotently reprocess an authenticated payload.
   *
   * Confidentiality: the keychain delta is end-to-end encrypted to the
   * recipient at the application layer. libp2p's Noise/TLS transport
   * still protects on-wire bytes against off-path observers, but the
   * application-layer ECIES seal is the primary confidentiality
   * guarantee against on-path connected peers.
   *
   * Wire format (mirrors `documentKeyUpdateV2`):
   *   [4-byte BE doc-path length] [UTF-8 doc-path] [serialized sync message]
   */
  private async _prepareBeeKEMWelcome(
    reader: PublicKey,
    readerKemPublicKey: Uint8Array,
    beekemWelcome: BeeKEMWelcome | null,
    stagedEpoch?: {
      epochId: Uint8Array;
      welcomeKeychainChanges: ChangesType;
    },
  ): Promise<PreparedBeeKEMDelivery> {
    // Validate the recipient KEM public key length up front so a
    // malformed caller fails fast at the call site rather than deep
    // inside the WebCrypto import.
    if (readerKemPublicKey.byteLength !== ECIES_P256_PUBLIC_KEY_LENGTH) {
      throw new Error(
        `BeeKEM Welcome for ${this.documentPath}: readerKemPublicKey ` +
          `must be ${ECIES_P256_PUBLIC_KEY_LENGTH} raw SEC1 bytes (P-256 ` +
          `uncompressed), got ${readerKemPublicKey.byteLength}`,
      );
    }

    // Defensive copy: snapshot the recipient's KEM public key bytes once
    // at the entry point so a caller that reuses or mutates the same
    // buffer (or shares it across async tasks) after `addReader` returns
    // cannot corrupt the in-flight Welcome. Both the signed message
    // field (`welcomeRecipientKemPublicKey`) and the WebCrypto import
    // must observe the *same* byte sequence; otherwise the receiver
    // would see a signature/payload mismatch.
    const kemPub = copyUnsharedUint8Array(
      readerKemPublicKey,
      ECIES_P256_PUBLIC_KEY_LENGTH,
      ECIES_P256_PUBLIC_KEY_LENGTH,
      'readerKemPublicKey',
    );

    // Build the welcome message.
    const welcomeMessage: CRDTSyncMessage<ChangesType, PublicKey> = {
      documentId: this.documentPath,
    };

    // The invitation epoch is the *current* keychain key ID at the time
    // of invitation -- the boundary between "before I joined" and "from
    // when I joined". `_keychain.current()` throws on an empty keychain;
    // in practice that cannot happen here because the inviter is in the
    // group (and so has at least one key), but if it ever does we surface
    // the error to the caller of `addReader` rather than silently sending
    // a Welcome with no epoch ID.
    const [currentKeyID] = stagedEpoch
      ? [stagedEpoch.epochId]
      : await this._keychain.current();
    welcomeMessage.welcomeEpochId = currentKeyID;

    // Recipient binding: serialize the new reader's public key so
    // recipients that aren't this reader can drop the broadcast Welcome.
    // The signed payload covers this field, so only an authorized writer
    // can claim a specific recipient. `serializePublicKey` is optional
    // on `AuthProvider` for backwards compatibility, but Welcome
    // onboarding cannot function without it.
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'BeeKEM Welcome onboarding',
    );
    welcomeMessage.welcomeRecipient = await serializePublicKey(reader);
    welcomeMessage.welcomeRecipientKemPublicKey = kemPub;

    // Visibility-filtered keychain so the new reader receives the selected
    // epoch-key window. This does not redact retained CRDT operations. Welcome
    // and ordinary-load projections use separate helpers because their policy
    // inputs differ, even though both currently map `since_invited` to the
    // current key only.
    const keychainPlaintext = this._requireWireChanges(
      stagedEpoch?.welcomeKeychainChanges ??
        (await this._keychainChangesForWelcome()),
      'BeeKEM Welcome keychain change',
    );
    const keychainPlaintextBytes =
      this._changesSerializer.serializeChanges(keychainPlaintext);

    // Build the structured sealed-payload envelope. The plaintext
    // inside `eciesSealed` is now a JSON envelope carrying both the
    // keychain delta and (when available) the BeeKEM `Welcome` the
    // joiner needs to bootstrap their local ratchet state. The
    // wire-level field on `CRDTSyncMessage` is still a single
    // `Uint8Array`; only its decoded shape grows. See
    // `welcome-sealed-payload.ts` for the envelope format.
    //
    // The helper retains legacy-v1 encoding support for compatibility tests,
    // but the live add/re-send path requires a complete, current-generation
    // v2 Welcome and fails closed on a missing or stale cache entry.
    let generationBearingWelcome: BeeKEMWelcomeV2 | null = null;
    if (beekemWelcome?.version === 2) {
      if (
        beekemWelcome.generation === undefined ||
        beekemWelcome.numLeaves === undefined
      ) {
        throw new Error(
          'Cannot send incomplete BeeKEM Welcome v2 without generation and numLeaves',
        );
      }
      generationBearingWelcome = beekemWelcome as BeeKEMWelcomeV2;
    } else if (
      beekemWelcome?.generation !== undefined ||
      beekemWelcome?.numLeaves !== undefined
    ) {
      throw new Error('Cannot send BeeKEM Welcome with unversioned v2 fields');
    }
    const welcomeProtocolVersion: BeeKEMWireVersion =
      generationBearingWelcome === null ? 1 : 2;
    const welcomeProtocol =
      welcomeProtocolVersion === 2 ? beekemWelcomeV2 : beekemWelcomeV1;
    const sealedPayloadBytes =
      generationBearingWelcome === null
        ? encodeWelcomeSealedPayload({
            keychainChanges: keychainPlaintextBytes,
            beekemWelcome,
          })
        : encodeWelcomeSealedPayloadV2({
            keychainChanges: keychainPlaintextBytes,
            beekemWelcome: generationBearingWelcome,
          });

    // Seal the envelope to the recipient's ECDH public key. Only the
    // recipient holding the matching ECDH private key can recover the
    // plaintext; every other connected peer that observes the
    // broadcast sees only opaque ciphertext + ephemeral public key +
    // nonce + AES-GCM tag.
    const recipientKemKey = await importEciesPublicKey(kemPub);
    welcomeMessage.eciesSealed = await eciesSeal(
      sealedPayloadBytes,
      recipientKemKey,
    );

    // Sign so the receiver can verify the inviter is an authorized
    // writer. Welcomes are ALWAYS writer-authenticated, regardless of
    // the swarm-wide `enableSigning` toggle that gates normal
    // sync-message signing (see SECURITY NOTE in
    // `beekem-welcome-handler.ts`). The signature covers the sealed
    // bytes (`eciesSealed`) and the recipient bindings
    // (`welcomeRecipient` + `welcomeRecipientKemPublicKey`), so an
    // attacker cannot redirect or substitute the sealed payload
    // without invalidating the signature.
    welcomeMessage.signature = await this._signWelcomeAsWriter(welcomeMessage);

    const serialized =
      this._syncMessageSerializer.serializeSyncMessage(welcomeMessage);

    // Complete generation-bearing Welcomes use v2. A failed v2 dial is never
    // downgraded to a key-only v1 payload.
    const pathBytes = this._encoder.encode(this.documentPath);
    if (pathBytes.length === 0 || pathBytes.length > MAX_DOCUMENT_PATH_LENGTH) {
      throw new Error(
        `Document path "${this.documentPath}" encoded length (${pathBytes.length}) exceeds ` +
          `the maximum allowed path length (${MAX_DOCUMENT_PATH_LENGTH} bytes) for the BeeKEM Welcome v${welcomeProtocolVersion} protocol`,
      );
    }
    const pathHeader = new Uint8Array(4);
    pathHeader[0] = (pathBytes.length >> 24) & 0xff;
    pathHeader[1] = (pathBytes.length >> 16) & 0xff;
    pathHeader[2] = (pathBytes.length >> 8) & 0xff;
    pathHeader[3] = pathBytes.length & 0xff;

    return {
      protocol: welcomeProtocol,
      payload: concatUint8Arrays(pathHeader, pathBytes, serialized),
      label: 'Welcome',
    };
  }

  /**
   * Handles an incoming BeeKEM Welcome message with pre-read payload. Called
   * by the shared protocol handler in Peerborne after the document path
   * header has been stripped and the document looked up in the registry.
   *
   * Verifies the writer signature on the message, merges the included
   * keychain changes so future blocks can be decrypted, and records the
   * `welcomeEpochId` as the local monotonic `_invitationEpoch` anchor.
   *
   * @internal
   * @param payload The serialized sync message (without the document path
   *   header that the shared handler already stripped).
   */
  public async handleBeeKEMWelcomeRequestData(
    payload: Uint8Array,
    protocolVersion: BeeKEMWireVersion = 1,
  ): Promise<void> {
    try {
      await this._runBeeKEMRemoteIngress(async () => {
        const authenticatedMessage =
          await this._preauthenticateBeeKEMWelcome(payload);
        if (authenticatedMessage === null) return;
        await this._runInMutationQueue(() =>
          this._handleBeeKEMWelcomeRequestDataUnlocked(
            authenticatedMessage,
            protocolVersion,
          ),
        );
      });
    } catch {
      console.error(
        `Error handling BeeKEM Welcome for document ${this.documentPath}`,
      );
    }
  }

  private async _handleBeeKEMWelcomeRequestDataUnlocked(
    authenticatedMessage: AuthenticatedBeeKEMWelcome<ChangesType, PublicKey>,
    protocolVersion: BeeKEMWireVersion,
  ): Promise<void> {
    try {
      this._throwIfSecurityProviderMutationFailed();
      await this._runBeeKEMTransition(
        () =>
          this._evaluateAndApplyBeeKEMWelcome(
            authenticatedMessage,
            protocolVersion,
          ),
        true,
      );
    } catch {
      console.error(
        `Error handling BeeKEM Welcome for document ${this.documentPath}`,
      );
    }
  }

  private async _preauthenticateBeeKEMWelcome(
    payload: Uint8Array,
  ): Promise<AuthenticatedBeeKEMWelcome<ChangesType, PublicKey> | null> {
    const stablePayload = copyUnsharedUint8Array(
      payload,
      1,
      PeerborneDocument._MAX_BEEKEM_WIRE_PAYLOAD_BYTES,
      'BeeKEM Welcome payload',
    );
    let message: CRDTSyncMessage<ChangesType, PublicKey>;
    try {
      message =
        this._syncMessageSerializer.deserializeSyncMessage(stablePayload);
    } catch {
      return null;
    }
    const writerAuthorities =
      await this._captureBeeKEMWelcomeWriterAuthorities();
    if (writerAuthorities === null) return null;
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'BeeKEM Welcome onboarding',
    );
    const decision = await evaluateBeeKEMWelcome(message, {
      documentPath: this.documentPath,
      localUserPublicKey: this._userPublicKey,
      serializePublicKey,
      // An identity+KEM-bound Welcome authenticated by the captured writer
      // trust root is the onboarding grant. A new reader may not yet possess
      // the document key needed to decrypt the readers ACL addition.
      isReader: async () => true,
      allowWriterAuthorizedBootstrap: true,
      verifyWriterSignature: (raw, signature) =>
        this._verifyWelcomeWriterSignatureFromSnapshot(
          raw,
          signature,
          writerAuthorities,
        ),
      syncMessageSerializer: this._syncMessageSerializer,
    });
    return decision.kind === 'accept'
      ? { message: decision.message, writerAuthorities }
      : null;
  }

  /**
   * Receive-path body for a preauthenticated Welcome. The detached writer
   * trust snapshot is reused through the final commit check.
   *
   * @returns `true` iff the Welcome was accepted and applied.
   * @internal
   */
  private async _evaluateAndApplyBeeKEMWelcome(
    authenticated: AuthenticatedBeeKEMWelcome<ChangesType, PublicKey>,
    protocolVersion: BeeKEMWireVersion,
  ): Promise<boolean> {
    if (this._securityProviderMutationFailure !== undefined) return false;
    let message = authenticated.message;
    const writerAuthorities = authenticated.writerAuthorities;
    // Run the pure validation gates (extracted to
    // `beekem-welcome-handler.ts` so they can be unit-tested without
    // a full libp2p/Helia stack). On `accept` we apply the keychain
    // merge + invitation-epoch assignment below. `serializePublicKey`
    // is required on the AuthProvider for the recipient-binding gate;
    // we surface a clear error instead of silently dropping
    // every Welcome for misconfigured providers.
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'BeeKEM Welcome onboarding',
    );
    const decision = await evaluateBeeKEMWelcome(message, {
      documentPath: this.documentPath,
      localUserPublicKey: this._userPublicKey,
      serializePublicKey,
      isReader: async () => true,
      allowWriterAuthorizedBootstrap: true,
      // Welcomes always require writer-auth, independent of the
      // swarm-wide `enableSigning` toggle -- wire the unconditional
      // verifier so the validator can't be downgraded by config.
      verifyWriterSignature: (raw, signature) =>
        this._verifyWelcomeWriterSignatureFromSnapshot(
          raw,
          signature,
          writerAuthorities,
        ),
      syncMessageSerializer: this._syncMessageSerializer,
    });

    if (decision.kind !== 'accept') {
      switch (decision.kind) {
        case 'drop-not-for-us':
          // Legitimate Welcome to another peer flowing past our
          // connection -- silently ignore.
          return false;
        case 'drop-malformed':
          console.warn(
            `Dropping malformed BeeKEM Welcome for ${this.documentPath}: ${decision.reason}`,
          );
          return false;
        case 'drop-unauthorized':
          console.warn(
            `Dropping unauthorized BeeKEM Welcome for ${this.documentPath}: ${decision.reason}`,
          );
          return false;
      }
    }

    // The validator returns the detached canonical message whose exact bytes
    // were authenticated. Use only that snapshot for decryption and commit.
    message = decision.message;

    // Open the sealed keychain delta. We must hold the matching ECDH
    // private key (see `setKemKeyPair`); without it, even a Welcome
    // that addresses us by identity and KEM public key cannot be
    // applied. Drop in that case; the recipient must reinstall the intended
    // KEM key and receive a fresh authenticated Welcome.
    //
    // Defense in depth: if the writer-signed `welcomeRecipientKemPublicKey`
    // does NOT match the local installed KEM public key, the writer
    // is claiming a different encryption key than the one we hold.
    // Refuse to attempt decryption: this prevents an attacker who
    // somehow registered a fake KEM key (e.g. via a parallel
    // out-of-band channel) from getting us to silently install
    // keychain state under a key we don't actually control. A
    // legitimate writer who follows the documented onboarding flow
    // will always echo back the recipient's own KEM public key.
    if (!this._kemKeyPair || !this._kemPublicKeyRaw) {
      console.warn(
        `Dropping BeeKEM Welcome for ${this.documentPath}: no local KEM ` +
          `key pair installed via setKemKeyPair; cannot open sealed payload.`,
      );
      return false;
    }
    // Use the eagerly-cached raw bytes from `setKemKeyPair` rather
    // than re-exporting on every Welcome.
    const localKemPublicRaw = this._kemPublicKeyRaw;
    const messageKemPublic = message.welcomeRecipientKemPublicKey;
    if (
      !messageKemPublic ||
      messageKemPublic.byteLength !== localKemPublicRaw.byteLength ||
      !this._constantTimeEquals(messageKemPublic, localKemPublicRaw)
    ) {
      console.warn(
        `Dropping BeeKEM Welcome for ${this.documentPath}: ` +
          `welcomeRecipientKemPublicKey does not match the locally-installed ` +
          `KEM public key.`,
      );
      return false;
    }

    let keychainPlaintext: ChangesType;
    let bootstrapWelcome: BeeKEMWelcome | null = null;
    try {
      const sealed = message.eciesSealed as Uint8Array;
      const plaintextBytes = await eciesOpen(
        sealed,
        this._kemKeyPair.privateKey,
      );
      // The plaintext is now a structured envelope carrying the
      // keychain delta AND (optionally) a BeeKEM `Welcome` so the
      // joiner can bootstrap their local ratchet state. The
      // wire-level field remains a single `Uint8Array`; only the
      // decoded shape grows. See `welcome-sealed-payload.ts`.
      const envelope =
        protocolVersion === 2
          ? decodeWelcomeSealedPayloadV2(plaintextBytes)
          : decodeWelcomeSealedPayload(plaintextBytes);
      keychainPlaintext = this._changesSerializer.deserializeChanges(
        envelope.keychainChanges,
      );
      bootstrapWelcome = envelope.beekemWelcome;
    } catch {
      // ECIES open failure typically means: the sealed payload is
      // tampered (AES-GCM tag check fails), or the writer encrypted
      // under a different ECDH public key than the one we hold (so
      // ECDH produces a different shared secret and the HKDF-derived
      // AES key cannot decrypt). Decode failure means the inviter
      // emitted a malformed envelope (e.g. a legacy unstructured
      // plaintext from a non-upgraded peer). Both are
      // security-relevant; log and drop.
      console.warn(
        `Failed to open sealed BeeKEM Welcome payload for ${this.documentPath}`,
      );
      return false;
    }

    const transitionDecision = evaluateBeeKEMWelcomeTransition(
      this._beekemInitialized && this._beekem
        ? this._beekem.generation
        : undefined,
      protocolVersion,
      bootstrapWelcome?.generation,
    );
    if (transitionDecision.kind === 'reject') {
      console.warn(
        `Dropping BeeKEM Welcome for ${this.documentPath}: ${transitionDecision.reason}`,
      );
      return false;
    }

    // Stage every optional ratchet bootstrap before the final writer
    // authorization check. In particular, legacy v1 must not merge keychain
    // state and then await `processWelcome`: a concurrent writer revocation
    // during that await would leave unauthorized key material installed.
    // V2 treats bootstrap failure as fatal; v1 retains its key-only fallback.
    let stagedBeeKEM: BeeKEM | null = null;
    let stagedWelcomeEpochId: Uint8Array | undefined;
    let legacyBootstrapError: unknown;
    if (protocolVersion === 2) {
      if (
        bootstrapWelcome === null ||
        bootstrapWelcome.version !== 2 ||
        bootstrapWelcome.generation === undefined ||
        bootstrapWelcome.numLeaves === undefined
      ) {
        console.warn(
          `Dropping BeeKEM Welcome v2 for ${this.documentPath}: ` +
            `a non-null generation-bearing Welcome is required.`,
        );
        return false;
      }
    }
    if (bootstrapWelcome !== null) {
      try {
        const beekem = new BeeKEM();
        await beekem.processWelcome(
          bootstrapWelcome,
          this._kemKeyPair.privateKey,
          this._kemKeyPair.publicKey,
        );
        stagedBeeKEM = beekem;
        if (protocolVersion === 2) {
          stagedWelcomeEpochId = await deriveEpochIdFromRootSecret(
            await beekem.getRootSecret(),
          );
        }
      } catch (err) {
        if (protocolVersion === 2) {
          console.warn(
            `Dropping BeeKEM Welcome v2 for ${this.documentPath}: ratchet bootstrap failed.`,
          );
          return false;
        }
        legacyBootstrapError = err;
      }
    }

    const prepareMerge = this._keychain.prepareMerge;
    if (typeof prepareMerge !== 'function') {
      console.error(
        `Cannot apply BeeKEM Welcome for ${this.documentPath}: keychain does ` +
          `not implement transactional prepareMerge`,
      );
      return false;
    }
    let stagedKeychain;
    try {
      stagedKeychain = prepareMerge.call(this._keychain, keychainPlaintext);
    } catch {
      console.error(
        `Failed to stage keychain changes from BeeKEM Welcome for ${this.documentPath}`,
      );
      return false;
    }

    const newEpochId = message.welcomeEpochId as Uint8Array;
    if (
      protocolVersion === 2 &&
      (stagedWelcomeEpochId === undefined ||
        !this._constantTimeEquals(stagedWelcomeEpochId, newEpochId))
    ) {
      console.warn(
        `Dropping BeeKEM Welcome v2 for ${this.documentPath}: ratchet root ` +
          `does not derive the signed welcomeEpochId`,
      );
      return false;
    }
    const incomingEpochPresent = stagedKeychain.keyIds.some((keyId) =>
      this._constantTimeEquals(keyId, newEpochId),
    );
    if (!incomingEpochPresent) {
      console.warn(
        `Dropping BeeKEM Welcome for ${this.documentPath}: staged keychain ` +
          `does not contain welcomeEpochId`,
      );
      return false;
    }
    let nextInvitationEpoch = this._invitationEpoch;
    let invitationEpochAdvanced = false;
    let invitationEpochRegressed = false;
    if (nextInvitationEpoch === undefined) {
      nextInvitationEpoch = newEpochId;
      invitationEpochAdvanced = true;
    } else if (
      this._shouldAdvanceInvitationEpochInOrder(
        nextInvitationEpoch,
        newEpochId,
        stagedKeychain.keyIds,
      )
    ) {
      nextInvitationEpoch = newEpochId;
      invitationEpochAdvanced = true;
    } else if (!this._constantTimeEquals(nextInvitationEpoch, newEpochId)) {
      invitationEpochRegressed = true;
    }

    // Re-check immediately before the synchronous merge-and-swap commit.
    // Another Welcome may have completed while this one was being opened or
    // staged; using only the earlier check would let a slower, older Welcome
    // overwrite the newer ratchet state.
    const commitTransitionDecision = evaluateBeeKEMWelcomeTransition(
      this._beekemInitialized && this._beekem
        ? this._beekem.generation
        : undefined,
      protocolVersion,
      stagedBeeKEM?.generation ?? bootstrapWelcome?.generation,
    );
    if (commitTransitionDecision.kind === 'reject') {
      console.warn(
        `Dropping BeeKEM Welcome for ${this.documentPath}: ${commitTransitionDecision.reason}`,
      );
      return false;
    }

    if (!(await this._reauthorizeBeeKEMWelcome(message, writerAuthorities))) {
      console.warn(
        `Dropping BeeKEM Welcome for ${this.documentPath}: writer authorization changed before commit`,
      );
      return false;
    }
    if (this._securityProviderMutationFailure !== undefined) return false;

    // Commit the detached keychain, ratchet, and invitation anchor without an
    // intervening await. Shipped keychains guarantee commit either succeeds
    // completely or throws before mutation.
    this._commitPreparedKeychainState(
      stagedKeychain,
      'inbound BeeKEM Welcome staged keychain commit',
    );

    // Bootstrap our local BeeKEM ratchet state from the inviter's
    // Welcome payload. Without this step the joiner has no leaf
    // index in the tree and no private key material on their direct
    // path; subsequent PathUpdates broadcast on `removeReader` would
    // fail to apply at `processPathUpdate`, locking the joiner out
    // of the new document key. Initialize-once: a peer that
    // re-receives a Welcome (e.g. a re-invite after being removed)
    // gets a fresh `BeeKEM` instance for the new epoch.
    if (stagedBeeKEM !== null) {
      this._beekem = stagedBeeKEM;
      this._beekemInitialized = true;
    } else if (legacyBootstrapError !== undefined) {
      // BeeKEM bootstrap failure is non-fatal for v1: the authenticated
      // keychain delta still permits current traffic, but the recipient must
      // recover ratchet state before the next chained PathUpdate.
      console.warn(
        `BeeKEM bootstrap via processWelcome failed for ${this.documentPath}: ` +
          `local ratchet state was not installed and future PathUpdates ` +
          `cannot be applied until an authenticated membership remove/rejoin.`,
      );
    }
    this._invitationEpoch = nextInvitationEpoch;
    if (invitationEpochAdvanced) {
      console.log(
        `Recorded BeeKEM Welcome invitation epoch for ${this.documentPath}`,
      );
    } else if (invitationEpochRegressed) {
      console.warn(
        `Ignoring out-of-order BeeKEM Welcome for ${this.documentPath}: ` +
          `incoming epoch is not later than current invitation epoch`,
      );
    }
    return true;
  }

  /**
   * Constant-time byte-equality check. Used by the BeeKEM Welcome
   * receive path to compare the writer-signed
   * `welcomeRecipientKemPublicKey` against the locally-installed KEM
   * public key without leaking byte-position timing on a mismatch.
   * Callers must supply equal-length buffers.
   */
  private _constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }

  /**
   * Test/inspection helper: returns a copy of the recorded invitation
   * epoch, or `undefined` if no Welcome has been processed (e.g.
   * founding member). The returned `Uint8Array` is a defensive copy so
   * external callers cannot mutate the document's internal ordering anchor.
   */
  public get invitationEpoch(): Uint8Array | undefined {
    return this._invitationEpoch === undefined
      ? undefined
      : new Uint8Array(this._invitationEpoch);
  }

  /**
   * Decide whether an incoming BeeKEM Welcome's `welcomeEpochId` is
   * strictly later than the existing `_invitationEpoch`. Used by
   * `handleBeeKEMWelcomeRequestData` to enforce a monotonic-forward
   * update on the invitation-epoch anchor.
   *
   * Comparison is performed by looking up both IDs in the
   * post-merge `_keychain.keys()` ordering. Yjs and Automerge keychain
   * implementations append entries in insertion order, so the array
   * position is the canonical "later means later" ordering -- the
   * same relation `historySince` slices on.
   *
   * Returns `true` iff the new epoch is strictly later than the
   * existing one. Returns `false` if:
   *   - the two IDs are byte-equal (no-op, do not log a regression),
   *   - the new epoch is at an earlier position than the existing one
   *     (would regress the anchor),
   *   - either ID is not present in the keychain after the merge
   *     (we cannot establish ordering; conservatively keep the
   *     known-good existing anchor).
   *
   * @internal exposed only for unit tests.
   */
  public async _shouldAdvanceInvitationEpoch(
    existing: Uint8Array,
    incoming: Uint8Array,
  ): Promise<boolean> {
    let allKeys: [Uint8Array, unknown][];
    try {
      allKeys = await this._keychain.keys();
    } catch {
      // Keychain refused to enumerate keys (empty keychain, transient
      // error). Conservatively keep the known-good anchor.
      return false;
    }

    return this._shouldAdvanceInvitationEpochInOrder(
      existing,
      incoming,
      allKeys.map(([id]) => id),
    );
  }

  private _shouldAdvanceInvitationEpochInOrder(
    existing: Uint8Array,
    incoming: Uint8Array,
    keyIds: readonly Uint8Array[],
  ): boolean {
    if (this._constantTimeEquals(existing, incoming)) return false;
    const existingIdx = keyIds.findIndex((id) =>
      this._constantTimeEquals(id, existing),
    );
    const incomingIdx = keyIds.findIndex((id) =>
      this._constantTimeEquals(id, incoming),
    );
    if (existingIdx === -1 || incomingIdx === -1) {
      // One of the IDs is not in the keychain -- cannot establish
      // ordering. Keep the existing anchor.
      return false;
    }
    return incomingIdx > existingIdx;
  }

  /**
   * Remove a user as a valid reader. Users are identified by their public keys.
   *
   * Authorization, membership, tree, and leaf preconditions run before the
   * BeeKEM transition. The ACL provider delta is also produced before
   * `removeMember`, because providers mutate their local CRDT while producing
   * it. A transactional BeeKEM callback derives and stages the new epoch,
   * prepares the exact signed PathUpdate and ACL ciphertext, and only then
   * performs the synchronous staged keychain/change commits. A preparation
   * failure restores the BeeKEM tree/generation and publishes nothing. It then
   * releases the BeeKEM transition mutex and runs ordered, bounded fanout:
   * PathUpdate first, ACL publication second. Each peer delivery has a strict
   * deadline. The public document mutation queue remains held during this
   * bounded fanout, so later local mutations may wait for its deadlines. A
   * survivor that misses a parent-bound generation requires persisted current
   * ratchet state or an authenticated remove/rejoin; an ordinary encrypted
   * load cannot repair a missing epoch.
   *
   * The removed reader cannot derive the installed epoch because its leaf is
   * blanked before the new path material is generated.
   *
   * Identity-to-KEM/leaf bindings are in-memory and populated only for readers
   * registered locally. Processing a Welcome reconstructs the ratchet tree but
   * not bindings for pre-existing readers, so a joined writer cannot remove
   * those readers by identity until a future authenticated binding
   * persistence/state-transfer mechanism is implemented.
   *
   * @param reader User's public key.
   * @throws If the BeeKEM tree has no record of this reader (e.g.
   *   `addReader` did not seed a leaf for them, or BeeKEM membership
   *   was lost). Callers must surface this rather than silently
   *   degrading: a removeReader that "succeeded" without rotating the
   *   key would leave the removed reader with full ongoing access.
   * @throws If a local transaction prerequisite or preparation fails.
   *   Delivery failures are bounded and logged; recovery requires an
   *   authenticated membership remove/rejoin.
   * @throws If the readers ACL provider rejects after its mutation may have
   *   started. The document is permanently retired in-process; discard it and
   *   its ACL/keychain provider instances.
   */
  public async removeReader(reader: PublicKey) {
    return this._runInMutationQueue(() =>
      this._removeReaderUnlocked(reader),
    );
  }

  private async _removeReaderUnlocked(reader: PublicKey) {
    const result = await this._runBeeKEMTransition(() =>
      this._removeReaderUnderBeeKEMLock(reader),
    );
    if (result) await result.fanout;
  }

  private async _removeReaderUnderBeeKEMLock(reader: PublicKey) {
    // ---------------------------------------------------------------
    // Pre-validation runs before the ACL provider or BeeKEM changes state. An
    // ambiguous ACL-provider rejection retires the document; subsequent
    // BeeKEM work uses snapshot rollback and commits only after preparation.
    // ---------------------------------------------------------------
    await this._ensureCurrentUserCanWrite();

    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'BeeKEM reader revocation',
    );
    const serializedReader = await serializePublicKey(reader);
    let pendingRemoval = this._pendingBeeKEMRemovals.get(serializedReader);
    if (pendingRemoval?.aclRemoveState === 'started') {
      this._retireAfterAmbiguousSecurityProviderMutation(
        `removeReader(${serializedReader})`,
      );
    }

    // A provider may already have applied the ACL removal before a later local
    // preparation failed. The retained transition record makes that exact
    // operation retryable instead of treating the absent ACL row as success.
    if (
      pendingRemoval === undefined &&
      (await this._readers.check(reader)) !== true
    ) {
      return;
    }

    // The BeeKEM tree must be initialized before we can revoke
    // anything: leaf-derivation, key rotation, and PathUpdate
    // generation all require live tree state. A fresh-start replica
    // that has never received a Welcome (and is not the founder)
    // cannot revoke; surface that clearly rather than fail later
    // with a confusing leaf-lookup error.
    if (!this._beekemInitialized || !this._beekem) {
      throw new Error(
        `Cannot remove reader from "${this.documentPath}": BeeKEM tree has ` +
          `not been initialized. This is only possible if the local user is ` +
          `neither the founder nor has received a BeeKEM Welcome -- in either ` +
          `case the user should not be calling removeReader.`,
      );
    }
    const beekem = this._beekem;
    const prepareEpochKey = this._keychain.prepareEpochKey;
    if (typeof prepareEpochKey !== 'function') {
      throw new Error(
        `[${this.documentPath}] removeReader: this keychain does not implement ` +
          `transactional prepareEpochKey; refusing a non-atomic BeeKEM transition`,
      );
    }

    // Look up the BeeKEM leaf for the removed reader. Fast-path: an
    // in-memory cache populated by `addReader` on this same writer
    // process. Slow-path: derive the leaf from BeeKEM tree state by
    // matching the reader's KEM public key against every leaf via
    // `BeeKEM.findLeafByPublicKey`. The slow path is what makes
    // revocation survive an in-process `_readerLeafIndices` cache clear while
    // the separately retained identity-to-KEM map is still available.
    //
    // Both lookups are in-memory only: BeeKEM tree state is not persisted
    // across writer restarts. A fully restarted writer that loses both
    // BeeKEM state and `_readerKemPublicKeys`
    // hits the "BeeKEM tree not initialized" error above OR the
    // "no leaf found" error below, both with actionable messaging.
    let leafIndex =
      pendingRemoval?.leafIndex ??
      this._readerLeafIndices.get(serializedReader);
    if (leafIndex === undefined) {
      const kemPub = this._readerKemPublicKeys.get(serializedReader);
      if (kemPub) {
        leafIndex = await beekem.findLeafByPublicKey(kemPub);
        if (leafIndex !== undefined) {
          // Re-populate the fast-path cache so subsequent
          // revocations for the same reader (within this process)
          // skip the tree scan. Harmless if the reader gets removed
          // immediately below: the entry is deleted again as part
          // of cleanup.
          this._readerLeafIndices.set(serializedReader, leafIndex);
        } else {
          // Pubkey is recorded but the BeeKEM tree has no matching
          // non-blanked leaf. Distinguishing this case from "no
          // pubkey at all" (below) lets operators tell apart a
          // local-state gap (reader never registered) from a
          // tree-state gap (leaf already blanked, or this replica
          // never received the Welcome that placed the reader).
          throw new Error(
            `Cannot remove reader from "${this.documentPath}": the reader's ` +
              `KEM public key is recorded locally but the BeeKEM tree has ` +
              `no matching non-blanked leaf. The tree state may have ` +
              `diverged (leaf already blanked, or this replica never ` +
              `received the Welcome that placed the reader). Recovery requires ` +
              `persisted current ratchet state or an authenticated membership ` +
              `remove/rejoin; an ordinary load cannot reconstruct ` +
              `private tree state.`,
          );
        }
      }
    }
    if (leafIndex === undefined) {
      throw new Error(
        `Cannot remove reader from "${this.documentPath}": no BeeKEM leaf ` +
          `recorded for this reader, and the local replica has no KEM public ` +
          `key recorded to scan the BeeKEM tree with. The reader must have ` +
          `been added via addReader (which seeds the BeeKEM tree and records ` +
          `the KEM public key) before they can be cryptographically revoked.`,
      );
    }

    // Build the local ACL delta before advancing BeeKEM. ACL providers mutate
    // their local CRDT while producing the delta, so this is the last provider
    // await allowed before the cryptographic transition. Nothing is published
    // until the new epoch key has been installed and the exact encrypted ACL
    // message has been prepared below.
    if (pendingRemoval === undefined) {
      pendingRemoval = { leafIndex, aclRemoveState: 'started' };
      this._pendingBeeKEMRemovals.set(serializedReader, pendingRemoval);
      try {
        pendingRemoval.readerChanges = this._requireMembershipWireChanges(
          await this._readers.remove(reader),
          `removeReader(${serializedReader}) returned an unrepresentable change`,
        );
      } catch (error) {
        this._retireAfterAmbiguousSecurityProviderMutation(
          `removeReader(${serializedReader}) readers-ACL update`,
          error,
        );
      }
      pendingRemoval.aclRemoveState = 'succeeded';
    }
    const readerChanges = pendingRemoval.readerChanges as ChangesType;

    // The transactional BeeKEM primitive restores the exact tree/generation if
    // any async preparation below rejects. The staged keychain and prepared
    // change commits are the final synchronous steps.

    // Transactionally blank the leaf and re-key our path. The operation
    //    re-derives key material along the entire path and returns the
    //    `PathUpdate` to broadcast plus the new root secret. We use
    //    those return values directly -- no follow-up `update()` is
    //    needed (it would only discard the removal transition's fresh
    //    material in favour of yet-another rotation).
    if (
      pendingRemoval.pathDelivery === undefined ||
      pendingRemoval.preparedReaderChange === undefined
    ) {
      let pathDelivery: PreparedBeeKEMDelivery | undefined;
      let preparedReaderChange:
        | PreparedLocalChange<ChangesType, PublicKey>
        | undefined;
      await beekem.removeMemberTransactionally(
        leafIndex,
        async ({ pathUpdate, rootSecret }) => {
          const [newKey, derivedEpochId32] = await Promise.all([
            deriveDocumentKeyFromRootSecret(rootSecret),
            deriveEpochIdFromRootSecret(rootSecret),
          ]);
          const stagedEpoch = await prepareEpochKey.call(
            this._keychain,
            derivedEpochId32,
            newKey as unknown as DocumentKey,
          );
          pathDelivery = await this._prepareBeeKEMPathUpdate(
            pathUpdate,
            derivedEpochId32,
          );
          preparedReaderChange = await this._prepareChange(
            readerChanges,
            crdtReaderChangeNode,
            [derivedEpochId32, newKey as unknown as DocumentKey],
          );

          // Final synchronous commits: every fallible outbound step completed
          // while the BeeKEM transaction could still roll back exactly.
          this._commitPreparedKeychainState(
            stagedEpoch,
            `removeReader(${serializedReader}) staged epoch commit`,
          );
          this._commitPreparedChange(preparedReaderChange);
        },
      );
      pendingRemoval.pathDelivery = pathDelivery;
      pendingRemoval.preparedReaderChange = preparedReaderChange;
    }

    const pathDelivery = pendingRemoval.pathDelivery;
    const preparedReaderChange = pendingRemoval.preparedReaderChange;
    if (pathDelivery === undefined || preparedReaderChange === undefined) {
      throw new Error(
        `[${this.documentPath}] removeReader: transition committed without prepared delivery`,
      );
    }

    // Forget the removed reader's per-reader state so subsequent
    //    `removeReader` calls for the same key (idempotency) take
    //    the "already not a reader" early return instead of trying
    //    to re-revoke a blank leaf, and a future `addReader` for
    //    this identity is a fresh registration -- not a re-emit of
    //    the now-invalid pre-revocation Welcome.
    //
    //    Critically, we also clear the cached `BeeKEMWelcome` for
    //    this leaf: leaving the stale entry would let a future
    //    `_registerBeeKEMReader` re-invocation for an unrelated
    //    reader who happens to land on the same blanked slot
    //    re-emit a Welcome that bootstraps the new joiner against
    //    the **revoked reader's** pre-revocation tree state.
    //
    //    Runs unconditionally (independent of the ACL-change branch
    //    above) so the in-memory caches stay consistent with the
    //    advanced BeeKEM tree.
    this._readerLeafIndices.delete(serializedReader);
    this._readerKemPublicKeys.delete(serializedReader);
    this._beekemWelcomeByLeaf.delete(leafIndex);

    const fanout = this._enqueueBeeKEMFanout(async () => {
      await this._fanoutPreparedBeeKEMDelivery(pathDelivery);
      try {
        await this._publishPreparedChange(preparedReaderChange);
      } catch {
        console.warn(
          `[${this.documentPath}] removeReader: readers-ACL broadcast failed`,
        );
      }
    });
    this._pendingBeeKEMRemovals.delete(serializedReader);
    return { fanout };
  }

  /**
   * Lazily initialize the per-document BeeKEM ratchet tree **as the
   * founder**. The founder is the writer who creates a fresh document
   * and runs the first `addReader` call; their leaf-0 KEM key pair
   * roots the tree.
   *
   * Returns the singleton `BeeKEM` instance for this document. The
   * initialization is funnelled through a single in-flight promise
   * (`_beekemInitPromise`) so concurrent callers don't race two
   * `initialize` calls against the same instance.
   *
   * PRECONDITION: the caller must have installed a KEM key pair via
   * `setKemKeyPair` -- the founder's leaf-0 key pair is that same
   * P-256 ECDH pair. A founder that calls `addReader` without first
   * calling `setKemKeyPair` is misconfigured and `addReader` throws
   * before reaching here.
   *
   * Non-founder peers MUST NOT enter this path. They initialize their
   * BeeKEM state by receiving a Welcome from the inviter (see
   * `_evaluateAndApplyBeeKEMWelcome` -> `BeeKEM.processWelcome`).
   */
  private async _initializeBeeKEMAsFounder(): Promise<BeeKEM> {
    if (this._beekem) return this._beekem;
    if (this._beekemInitPromise) return this._beekemInitPromise;

    if (!this._kemKeyPair) {
      throw new Error(
        `[${this.documentPath}] BeeKEM founder initialization requires a KEM ` +
          `key pair installed via setKemKeyPair.`,
      );
    }
    const kemKeyPair = this._kemKeyPair;

    const init = (async () => {
      const beekem = new BeeKEM();
      await beekem.initialize(kemKeyPair.privateKey, kemKeyPair.publicKey);
      this._beekem = beekem;
      this._beekemInitialized = true;
      return beekem;
    })();

    this._beekemInitPromise = init;
    try {
      return await init;
    } finally {
      // Clear the gate whether init succeeded or threw so a retry can
      // re-attempt. On success `_beekem` is set and the next call
      // short-circuits before reading the promise.
      this._beekemInitPromise = null;
    }
  }

  /**
   * Register a newly-added reader in the BeeKEM ratchet tree.
   *
   * Called from `addReader` while the document transition mutex is held.
   * Imports the reader's own KEM public key as the new leaf, records the
   * resulting leaf index in `_readerLeafIndices` so `removeReader`
   * can later look up the leaf to blank, caches the
   * `BeeKEMWelcome` produced by `BeeKEM.addMember` so it can be
   * re-emitted on a subsequent `addReader` call (covering the case
   * where the initial Welcome was dropped on the wire), and returns
   * the Welcome so the inviter can ship it inside the sealed
   * Welcome envelope to the joiner.
   *
   * **Idempotency / re-send**: if the same reader is registered
   * again (`addReader` invoked twice with the same KEM key), the
   * method does NOT re-call `BeeKEM.addMember` (which would mutate
   * the tree and produce a Welcome that no longer matches the
   * joiner's actual leaf index). Instead it returns the cached
   * Welcome from `_beekemWelcomeByLeaf`, so `addReader` can re-send
   * the same Welcome bytes without advancing generation. If the cache is empty
   * for the existing leaf, `null` is returned and the caller fails closed; an
   * authenticated remove/rejoin is required.
   *
   * A fresh registration also returns the exact parent-bound PathUpdate and
   * root secret from `BeeKEM.addMember`. The caller installs the derived local
   * epoch before any remote I/O, then distributes that update to existing
   * members before publishing the ACL change and targeted Welcome. Chained v2
   * updates must be delivered in order; a missed generation requires persisted
   * current ratchet state or an authenticated membership remove/rejoin and
   * cannot be healed by a later update or ordinary encrypted load.
   */
  private async _registerBeeKEMReaderUnderLock(
    reader: PublicKey,
    readerKemPublicKey: Uint8Array,
    commitFresh?: (result: {
      pathUpdate: PathUpdateV2;
      welcome: BeeKEMWelcomeV2;
      rootSecret: Uint8Array;
    }) => Promise<void>,
    beginMutation?: () => void,
  ): Promise<BeeKEMReaderRegistration> {
    let kemPublicKey: Uint8Array;
    try {
      kemPublicKey = copyUnsharedUint8Array(
        readerKemPublicKey,
        ECIES_P256_PUBLIC_KEY_LENGTH,
        ECIES_P256_PUBLIC_KEY_LENGTH,
        'readerKemPublicKey',
      );
    } catch {
      throw new Error(
        `[${this.documentPath}] _registerBeeKEMReader: readerKemPublicKey ` +
          `must be ${ECIES_P256_PUBLIC_KEY_LENGTH} bytes (SEC1-uncompressed P-256)`,
      );
    }
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'BeeKEM reader revocation',
    );
    const serializedReader = await serializePublicKey(reader);

    const existingKemPublicKey =
      this._readerKemPublicKeys.get(serializedReader);
    if (
      existingKemPublicKey !== undefined &&
      !this._constantTimeEquals(existingKemPublicKey, kemPublicKey)
    ) {
      throw new Error(
        `[${this.documentPath}] _registerBeeKEMReader: identity ` +
          `${serializedReader} is already bound to a different KEM public ` +
          `key. In-place KEM key rotation is not supported; remove and ` +
          `re-add the reader through an authenticated membership change.`,
      );
    }

    // Idempotency: if a leaf is already recorded (e.g. addReader was
    // re-invoked because the initial Welcome was dropped), we do NOT
    // call `BeeKEM.addMember` again -- that would mutate the tree
    // and produce a Welcome that no longer matches the joiner's
    // actual leaf index. Instead we return the cached Welcome (if
    // any) so the caller can re-send. A cache miss has no supported
    // reconstruction path; surface it as `null` so the caller fails closed
    // with the existing recovery guidance.
    const existingLeaf = this._readerLeafIndices.get(serializedReader);
    if (existingLeaf !== undefined) {
      if (existingKemPublicKey === undefined) {
        throw new Error(
          `[${this.documentPath}] _registerBeeKEMReader: identity ` +
            `${serializedReader} has an existing BeeKEM leaf without a ` +
            `bound KEM public key; refusing an unverifiable re-registration.`,
        );
      }
      return {
        welcome: this._beekemWelcomeByLeaf.get(existingLeaf) ?? null,
      };
    }

    // `_readerLeafIndices` is explicitly a fast-path cache and may be
    // cleared while the KEM binding and BeeKEM tree remain live. Recover
    // that cache instead of allocating another leaf for the same identity.
    if (existingKemPublicKey !== undefined) {
      if (!this._beekemInitialized || !this._beekem) {
        throw new Error(
          `[${this.documentPath}] _registerBeeKEMReader: identity ` +
            `${serializedReader} has a KEM binding but the BeeKEM tree is ` +
            `not initialized; refusing to create a duplicate membership.`,
        );
      }
      const recoveredLeaf =
        await this._beekem.findLeafByPublicKey(existingKemPublicKey);
      if (recoveredLeaf === undefined) {
        throw new Error(
          `[${this.documentPath}] _registerBeeKEMReader: identity ` +
            `${serializedReader} has a KEM binding but no matching live ` +
            `BeeKEM leaf; refusing to create a duplicate membership.`,
        );
      }
      this._readerLeafIndices.set(serializedReader, recoveredLeaf);
      return {
        welcome: this._beekemWelcomeByLeaf.get(recoveredLeaf) ?? null,
      };
    }

    // Bootstrap the local BeeKEM tree if needed. On the founder's
    // first `addReader` this initializes leaf 0 with the founder's
    // KEM key pair. On a non-founder writer this branch is invalid
    // (writers other than the founder must themselves have been
    // bootstrapped via a Welcome before they can call `addReader`).
    //
    // Defense-in-depth: only a locally-created founder (or the legacy
    // pre-open empty-state path) may initialize leaf 0. A loaded/invited
    // replica must never infer founder status from the current hash count.
    if (!this._beekemInitialized) {
      if (
        !this._localFounderEstablished &&
        (this._hashes.size > 0 || this._invitationEpoch !== undefined)
      ) {
        throw new Error(
          `[${this.documentPath}] _registerBeeKEMReader: cannot ` +
            `initialize a fresh founder BeeKEM tree because the local ` +
            `replica has existing or invited state without local creation ` +
            `provenance. A ` +
            `joined writer must bootstrap via a fresh authenticated BeeKEM ` +
            `Welcome before they can register ` +
            `readers cryptographically.`,
        );
      }
      beginMutation?.();
      await this._initializeBeeKEMAsFounder();
    }
    const beekem = this._beekem;
    if (!beekem) {
      throw new Error(
        `[${this.documentPath}] BeeKEM tree is not initialized; ` +
          `cannot register a new reader.`,
      );
    }
    // Import the reader's own KEM public key as their leaf. This is
    // critical for joiner-side decryption: `BeeKEM.processWelcome`
    // uses the leaf private key (held by the joiner) to decrypt the
    // first path-key encryption in the Welcome. If the leaf were
    // seeded with a placeholder key the joiner could never bootstrap.
    //
    // Imported as `extractable=true`: BeeKEM's tree-hash computation
    // (`_computeTreeHash`) calls `exportKey('raw', publicKey)` over
    // every non-blanked tree node, so a non-extractable leaf public
    // key would crash subsequent `addMember` / `removeMember` calls.
    // `importEciesPublicKey` defaults to non-extractable for ECIES
    // recipient-key use, where extractability is wasted; for BeeKEM
    // leaf use we need the extractable variant.
    const memberPublicKey = await crypto.subtle.importKey(
      'raw',
      kemPublicKey as unknown as BufferSource,
      { name: 'ECDH', namedCurve: 'P-256' },
      true, // extractable
      [],
    );
    beginMutation?.();
    const result = await beekem.addMemberTransactionally(
      memberPublicKey,
      async (freshResult) => {
        await commitFresh?.(freshResult);
        return freshResult;
      },
    );

    // Publish the identity binding and all related caches only after the
    // BeeKEM transition succeeds. This keeps a failed import/add retryable
    // and makes the cache tuple visible atomically to the next registration.
    this._readerKemPublicKeys.set(serializedReader, kemPublicKey);
    this._readerLeafIndices.set(serializedReader, result.welcome.leafIndex);
    this._beekemWelcomeByLeaf.set(result.welcome.leafIndex, result.welcome);
    return result;
  }

  private async _runBeeKEMRemoteIngress<T>(
    operation: () => Promise<T>,
  ): Promise<T> {
    const pending = this._beekemRemoteIngressPending ?? 0;
    if (pending >= PeerborneDocument._MAX_PENDING_REMOTE_BEEKEM_INGRESS) {
      return Promise.reject(new Error('BeeKEM remote ingress is at capacity'));
    }
    this._beekemRemoteIngressPending = pending + 1;
    try {
      return await operation();
    } finally {
      this._beekemRemoteIngressPending--;
    }
  }

  private _runBeeKEMTransition<T>(
    operation: () => Promise<T>,
    remote = false,
  ): Promise<T> {
    const remotePending = this._beekemRemoteTransitionsPending ?? 0;
    if (
      remote &&
      remotePending >= PeerborneDocument._MAX_PENDING_REMOTE_BEEKEM_TRANSITIONS
    ) {
      return Promise.reject(
        new Error(
          'BeeKEM authenticated remote transition queue is at capacity',
        ),
      );
    }
    if (remote) {
      this._beekemRemoteTransitionsPending = remotePending + 1;
    }
    this._beekemTransitionsPending = (this._beekemTransitionsPending ?? 0) + 1;
    const tail = this._beekemTransitionTail ?? Promise.resolve();
    const result = tail.then(operation, operation);
    this._beekemTransitionTail = result.then(
      () => undefined,
      () => undefined,
    );
    return result.finally(() => {
      this._beekemTransitionsPending--;
      if (remote) this._beekemRemoteTransitionsPending--;
    });
  }

  private _runWriterMembershipTransition<T>(
    operation: () => Promise<T>,
  ): Promise<T> {
    const tail = this._writerMembershipTail ?? Promise.resolve();
    const result = tail.then(operation, operation);
    this._writerMembershipTail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private _enqueueBeeKEMFanout(operation: () => Promise<void>): Promise<void> {
    const tail = this._beekemFanoutTail ?? Promise.resolve();
    const result = tail.then(operation, operation);
    this._beekemFanoutTail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private async _withMembershipDeliveryDeadline<T>(
    operation: (signal: AbortSignal) => Promise<T>,
    onTimeout?: (error: Error) => void,
  ): Promise<T> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        const error = new Error('membership peer delivery timed out');
        controller.abort(error);
        try {
          onTimeout?.(error);
        } catch {
          // Stream teardown is best-effort; the deadline must still reject.
        } finally {
          reject(error);
        }
      }, PeerborneDocument._MEMBERSHIP_DELIVERY_TIMEOUT_MS);
    });
    try {
      return await Promise.race([operation(controller.signal), timeout]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  private async _fanoutPreparedBeeKEMDelivery(
    delivery: PreparedBeeKEMDelivery,
  ): Promise<void> {
    const connected =
      this.swarm.heliaNode.libp2p
        .getConnections()
        ?.map((connection) => connection.remoteAddr) ?? [];
    const peers = Array.from(
      new Map(connected.map((peer) => [peer.toString(), peer])).values(),
    );
    let failedPeerCount = 0;
    let nextPeer = 0;
    const workerCount = Math.min(
      peers.length,
      PeerborneDocument._MAX_CONCURRENT_MEMBERSHIP_DELIVERIES,
    );
    const workers = Array.from({ length: workerCount }, async () => {
      while (nextPeer < peers.length) {
        const peer = peers[nextPeer++];
        let stream: ReturnType<typeof wrapStream> | undefined;
        try {
          await this._withMembershipDeliveryDeadline(
            async (signal) => {
              const rawStream = await this.libp2p.dialProtocol(
                peer,
                [delivery.protocol],
                { runOnLimitedConnection: true, signal },
              );
              if (signal.aborted) {
                rawStream.abort(
                  signal.reason instanceof Error
                    ? signal.reason
                    : new Error('BeeKEM peer delivery aborted'),
                );
                throw signal.reason;
              }
              stream = wrapStream(rawStream);
              await pipe([delivery.payload], stream.sink);
            },
            (error) => stream?.abort(error),
          );
        } catch {
          failedPeerCount++;
          console.warn(`Failed to send BeeKEM ${delivery.label} to a peer`);
        }
      }
    });
    await Promise.all(workers);
    if (failedPeerCount > 0) {
      console.warn(
        `BeeKEM ${delivery.label} for ${this.documentPath} failed to reach ${failedPeerCount} peer(s)`,
      );
    }
  }

  /**
   * Prepare an immutable BeeKEM `PathUpdate` delivery for the
   * `beekemPathUpdateV2` protocol. The caller owns the transactional
   * `removeMemberTransactionally` state change, local key commit, and later
   * fanout; this helper performs no tree mutation or network I/O.
   *
   * Wire format mirrors `documentKeyUpdateV2`: a 4-byte big-endian
   * document-path length, the UTF-8 path bytes, then the serialized
   * sync message body (which carries the `pathUpdate` /
   * `pathUpdateEpochId` / `signature` fields). The message is
   * **writer-signed unconditionally** (independent of the swarm-wide
   * `enableSigning` toggle) so a malicious peer cannot inject a
   * forged PathUpdate that steers surviving readers onto an
   * attacker-controlled ratchet state.
   *
   */
  private async _prepareBeeKEMPathUpdate(
    pathUpdate: PathUpdateV2,
    pathUpdateEpochId: Uint8Array,
  ): Promise<PreparedBeeKEMDelivery> {
    const message: CRDTSyncMessage<ChangesType, PublicKey> = {
      documentId: this.documentPath,
      pathUpdate: serializePathUpdateV2ForWire(pathUpdate),
      pathUpdateEpochId,
    };

    // Always writer-sign (mirrors the BeeKEM Welcome flow). Signing
    // is mandatory here: an unsigned PathUpdate would let any
    // connected peer rewrite every surviving reader's BeeKEM state.
    message.signature = await this._signAsWriterUnconditional(message);

    const serialized =
      this._syncMessageSerializer.serializeSyncMessage(message);

    const pathBytes = this._encoder.encode(this.documentPath);
    if (pathBytes.length === 0 || pathBytes.length > MAX_DOCUMENT_PATH_LENGTH) {
      throw new Error(
        `Document path "${this.documentPath}" encoded length (${pathBytes.length}) exceeds ` +
          `the maximum allowed path length (${MAX_DOCUMENT_PATH_LENGTH} bytes) for the BeeKEM PathUpdate v2 protocol`,
      );
    }
    const pathHeader = new Uint8Array(4);
    pathHeader[0] = (pathBytes.length >> 24) & 0xff;
    pathHeader[1] = (pathBytes.length >> 16) & 0xff;
    pathHeader[2] = (pathBytes.length >> 8) & 0xff;
    pathHeader[3] = pathBytes.length & 0xff;

    return {
      protocol: beekemPathUpdateV2,
      payload: concatUint8Arrays(pathHeader, pathBytes, serialized),
      label: 'PathUpdate',
    };
  }

  /**
   * Handle an inbound BeeKEM PathUpdate v1 or v2 payload (already
   * de-framed of the path-prefix header by the shared handler in
   * `peerborne.ts`).
   *
   * Validates the writer signature, deserializes the carried
   * `PathUpdate`, applies it and the staged key install through the
   * transactional BeeKEM helper, and installs the resulting document key under
   * the supplied epoch ID. Mirrors the wire framing used by
   * `handleKeyUpdateRequestData` and `handleBeeKEMWelcomeRequestData`.
   *
   * SECURITY: the writer signature is **always** verified, regardless
   * of the swarm-wide `enableSigning` toggle. An unsigned or
   * invalid-signature PathUpdate is dropped without applying any
   * state change. The receiver also validates that the epoch ID it
   * derives locally matches the sender's `pathUpdateEpochId` -- a
   * mismatch indicates either a peer with stale local BeeKEM state
   * or a tampered payload, and is treated as a hard error.
   *
   * @internal Invoked by the shared protocol handler in `peerborne.ts`.
   */
  public async handleBeeKEMPathUpdateRequestData(
    payload: Uint8Array,
    protocolVersion: BeeKEMWireVersion = 1,
  ): Promise<void> {
    try {
      const legacyV1Allowed =
        protocolVersion === 1 &&
        this.swarm.allowInsecureLegacyBeeKEMPathUpdateV1;
      if (protocolVersion !== 2 && !legacyV1Allowed) {
        console.warn(
          `Dropping disabled or unsupported BeeKEM PathUpdate for ${this.documentPath}`,
        );
        return;
      }
      await this._runBeeKEMRemoteIngress(async () => {
        const authenticated = await this._preauthenticateBeeKEMPathUpdate(
          payload,
          protocolVersion,
        );
        if (authenticated === null) return;
        await this._runInMutationQueue(() =>
          this._handleBeeKEMPathUpdateRequestDataUnlocked(
            authenticated,
            protocolVersion,
          ),
        );
      });
    } catch {
      console.warn(
        `Dropping malformed BeeKEM PathUpdate for ${this.documentPath}`,
      );
    }
  }

  private async _handleBeeKEMPathUpdateRequestDataUnlocked(
    authenticated: AuthenticatedBeeKEMPathUpdate<ChangesType, PublicKey>,
    protocolVersion: BeeKEMWireVersion,
  ): Promise<void> {
    try {
      this._throwIfSecurityProviderMutationFailed();
      await this._runBeeKEMTransition(
        () =>
          this._handleBeeKEMPathUpdateUnderLock(authenticated, protocolVersion),
        true,
      );
    } catch {
      console.warn(
        `Dropping malformed BeeKEM PathUpdate for ${this.documentPath}`,
      );
    }
  }

  private async _preauthenticateBeeKEMPathUpdate(
    payload: Uint8Array,
    protocolVersion: BeeKEMWireVersion,
  ): Promise<AuthenticatedBeeKEMPathUpdate<ChangesType, PublicKey> | null> {
    const stablePayload = copyUnsharedUint8Array(
      payload,
      1,
      PeerborneDocument._MAX_BEEKEM_WIRE_PAYLOAD_BYTES,
      'BeeKEM PathUpdate payload',
    );
    let message: CRDTSyncMessage<ChangesType, PublicKey>;
    try {
      const parsed =
        this._syncMessageSerializer.deserializeSyncMessage(stablePayload);
      const canonical = copyUnsharedUint8Array(
        this._syncMessageSerializer.serializeSyncMessage(parsed),
        1,
        PeerborneDocument._MAX_BEEKEM_WIRE_PAYLOAD_BYTES,
        'BeeKEM PathUpdate encoding',
      );
      message = snapshotEnumerableOwnDataObject<
        CRDTSyncMessage<ChangesType, PublicKey>
      >(
        this._syncMessageSerializer.deserializeSyncMessage(canonical),
        'BeeKEM PathUpdate message',
      );
    } catch {
      return null;
    }

    if (!isBeeKEMMessageForDocument(message.documentId, this.documentPath)) {
      return null;
    }
    if (
      typeof message.signature !== 'string' ||
      message.signature.length === 0
    ) {
      return null;
    }
    if (message.pathUpdate === undefined) return null;

    let pathUpdate: PathUpdate | PathUpdateV2;
    try {
      pathUpdate =
        protocolVersion === 2
          ? deserializePathUpdateV2FromWire(message.pathUpdate)
          : deserializePathUpdateFromWire(message.pathUpdate);
      message = {
        ...message,
        pathUpdate:
          protocolVersion === 2
            ? serializePathUpdateV2ForWire(pathUpdate as PathUpdateV2)
            : serializePathUpdateForWire(pathUpdate as PathUpdate),
      };
    } catch {
      return null;
    }

    let pathUpdateEpochId: Uint8Array;
    try {
      pathUpdateEpochId = copyUnsharedUint8Array(
        message.pathUpdateEpochId,
        EPOCH_ID_LENGTH,
        EPOCH_ID_LENGTH,
        'pathUpdateEpochId',
      );
    } catch {
      return null;
    }
    message = { ...message, pathUpdateEpochId };

    const signature = message.signature!;
    const { signature: _signature, ...messageWithoutSignature } = message;
    const raw = copyUnsharedUint8Array(
      this._syncMessageSerializer.serializeSyncMessage(messageWithoutSignature),
      1,
      PeerborneDocument._MAX_BEEKEM_WIRE_PAYLOAD_BYTES,
      'BeeKEM PathUpdate signature payload',
    );
    if ((await this._verifyWelcomeWriterSignature(raw, signature)) !== true) {
      return null;
    }

    return {
      message: message as CRDTSyncMessage<ChangesType, PublicKey> & {
        signature: string;
        pathUpdateEpochId: Uint8Array;
      },
      pathUpdate,
    };
  }

  private async _handleBeeKEMPathUpdateUnderLock(
    authenticated: AuthenticatedBeeKEMPathUpdate<ChangesType, PublicKey>,
    protocolVersion: BeeKEMWireVersion,
  ): Promise<void> {
    try {
      const legacyV1Allowed =
        protocolVersion === 1 &&
        this.swarm.allowInsecureLegacyBeeKEMPathUpdateV1;
      if (protocolVersion !== 2 && !legacyV1Allowed) {
        return;
      }
      this._throwIfSecurityProviderMutationFailed();
      const { message, pathUpdate } = authenticated;

      // Re-authorize against the current writer ACL at the state-commit
      // boundary. Only messages that already passed this check in the bounded
      // ingress stage can reach the transition queue.
      const signature = message.signature!;
      const { signature: _authenticatedSignature, ...messageWithoutSignature } =
        message;
      const raw = copyUnsharedUint8Array(
        this._syncMessageSerializer.serializeSyncMessage(
          messageWithoutSignature,
        ),
        1,
        PeerborneDocument._MAX_BEEKEM_WIRE_PAYLOAD_BYTES,
        'BeeKEM PathUpdate signature payload',
      );
      if ((await this._verifyWelcomeWriterSignature(raw, signature)) !== true) {
        console.warn(
          `Dropping BeeKEM PathUpdate for ${this.documentPath}: invalid signature`,
        );
        return;
      }

      // Apply the path update to the local BeeKEM tree. Two failure
      // modes need different handling here:
      //
      //  - **No local BeeKEM state at all**: this peer has not gone
      //    through founder bootstrap or processed a Welcome yet, so
      //    initializing a fresh founder tree on the fly would only
      //    produce a different root than the sender's. The
      //    epoch-ID gate further down would reject it, but that
      //    would also do unnecessary cryptographic work and (worse)
      //    leave a stranded fresh tree behind for the next
      //    PathUpdate to confuse. Drop the message explicitly and
      //    log: recovery requires persisted current ratchet state or an
      //    authenticated remove/rejoin.
      //
      //  - **Stale local state**: `processPathUpdate` throws (the
      //    sender's path doesn't intersect our blanked path, or
      //    our tree state has drifted). Surface the failure but
      //    do not crash the inbound handler.
      if (!this._beekemInitialized || !this._beekem) {
        console.warn(
          `Dropping BeeKEM PathUpdate for ${this.documentPath}: local BeeKEM ` +
          `state is not initialized (no Welcome received). Recovery requires ` +
            `an authenticated membership remove/rejoin, not an ordinary encrypted load.`,
        );
        return;
      }
      const beekem = this._beekem;
      const applyResult = await applyBeeKEMPathUpdateWithEpoch<DocumentKey>(
        beekem,
        pathUpdate,
        protocolVersion,
        message.pathUpdateEpochId,
        {
          deriveEpochId: deriveEpochIdFromRootSecret,
          deriveDocumentKey: async (rootSecret) =>
            (await deriveDocumentKeyFromRootSecret(
              rootSecret,
            )) as unknown as DocumentKey,
          installEpochKey: async (epochId, key) => {
            const prepareEpochKey = this._keychain.prepareEpochKey;
            if (typeof prepareEpochKey !== 'function') {
              throw new Error(
                'Keychain does not implement transactional prepareEpochKey',
              );
            }
            const stagedEpoch = await prepareEpochKey.call(
              this._keychain,
              epochId,
              key,
            );
            if (!(await this._reauthorizeCanonicalBeeKEMMessage(message))) {
              throw new Error(
                'BeeKEM PathUpdate writer authorization changed before key commit',
              );
            }
            this._throwIfSecurityProviderMutationFailed();
            this._commitPreparedKeychainState(
              stagedEpoch,
              'inbound BeeKEM PathUpdate staged epoch commit',
            );
          },
        },
      );

      if (applyResult.kind === 'applied') {
        console.log(
          `Installed BeeKEM-derived epoch key for ${this.documentPath} via PathUpdate`,
        );
        return;
      }
      if (applyResult.kind === 'duplicate') {
        // The ratchet already applied these exact signed v2 bytes. The helper
        // still verifies the epoch binding, but deliberately skips appending
        // the same epoch key to CRDT-backed keychains a second time.
        return;
      }

      if (applyResult.reason === 'legacy-downgrade') {
        console.warn(
          `Dropping legacy BeeKEM PathUpdate for ${this.documentPath}: ` +
            `local state is generation-bearing and cannot be downgraded to v1.`,
        );
        return;
      }

      if (applyResult.reason === 'epoch-mismatch') {
        console.warn(
          `BeeKEM PathUpdate epoch-ID mismatch for ${this.documentPath}: ` +
            `local derivation diverged from sender. PathUpdate dropped.`,
        );
        return;
      }
      if (applyResult.reason === 'key-install') {
        console.error(
          `Failed to install BeeKEM-derived epoch key in keychain for ${this.documentPath}`,
        );
        return;
      }
      console.warn(
        `Failed to apply BeeKEM PathUpdate for ${this.documentPath}: ` +
          `local tree state could not process the update. ` +
          `Persisted current ratchet state or an authenticated remove/rejoin ` +
          `is required for recovery.`,
      );
    } catch {
      console.error(
        `Error handling BeeKEM PathUpdate for document ${this.documentPath}`,
      );
    }
  }

  /**
   * Frames an already-prepared combined writer-removal sync envelope for
   * direct delivery over legacy `documentKeyUpdateV2`.
   *
   * `prepared.encryptedPayload` already contains the replacement-key delta and
   * ACL removal encrypted under the previous key and, when signing is enabled,
   * bound by one signature. This method adds only the length-prefixed path.
   * Both transports feed the same envelope through `sync()`. When signing is
   * enabled, `sync()` authenticates it; in either mode it merges keychain state
   * before applying the ACL node. Retries reuse identical bytes. This ordering
   * is not cross-provider rollback, a delivery guarantee, or confidentiality
   * from a previous-key holder.
   *
   * @param prepared The immutable combined sync envelope prepared by
   *   `_prepareChange`.
   */
  private async _prepareKeyUpdate(
    prepared: PreparedLocalChange<ChangesType, PublicKey>,
  ): Promise<PreparedKeyUpdateDelivery> {
    // V2 payload format: 4-byte big-endian path length + UTF-8 path + encrypted payload
    const pathBytes = this._encoder.encode(this.documentPath);
    if (pathBytes.length === 0 || pathBytes.length > MAX_DOCUMENT_PATH_LENGTH) {
      throw new Error(
        `Document path "${this.documentPath}" encoded length (${pathBytes.length}) exceeds ` +
          `the maximum allowed path length (${MAX_DOCUMENT_PATH_LENGTH} bytes) for the V2 key-update protocol`,
      );
    }
    const pathHeader = new Uint8Array(4);
    pathHeader[0] = (pathBytes.length >> 24) & 0xff;
    pathHeader[1] = (pathBytes.length >> 16) & 0xff;
    pathHeader[2] = (pathBytes.length >> 8) & 0xff;
    pathHeader[3] = pathBytes.length & 0xff;

    return {
      payload: copyUnsharedUint8Array(
        concatUint8Arrays(pathHeader, pathBytes, prepared.encryptedPayload),
        1,
        MAX_SHARED_PROTOCOL_REQUEST_SIZE,
        'V2 key-update request',
      ),
    };
  }

  private async _fanoutPreparedKeyUpdate(
    delivery: PreparedKeyUpdateDelivery,
  ): Promise<void> {
    const v2Payload = delivery.payload;

    // Send to all connected peers via the V2 key-update protocol.
    const connected =
      this.swarm.heliaNode.libp2p
        .getConnections()
        ?.map((connection) => connection.remoteAddr) ?? [];
    const peers = Array.from(
      new Map(connected.map((peer) => [peer.toString(), peer])).values(),
    );

    // WARNING: If some peers fail to receive this update, they will be unable
    // to decrypt future messages encrypted with the new key. They will need to
    // recover through an authenticated membership remove/rejoin.
    // An ordinary load is encrypted under the unknown current key.
    let failedPeerCount = 0;
    let nextPeer = 0;
    const workerCount = Math.min(
      peers.length,
      PeerborneDocument._MAX_CONCURRENT_MEMBERSHIP_DELIVERIES,
    );
    const workers = Array.from({ length: workerCount }, async () => {
      while (nextPeer < peers.length) {
        const peer = peers[nextPeer++];
        let stream: ReturnType<typeof wrapStream> | undefined;
        try {
          await this._withMembershipDeliveryDeadline(
            async (signal) => {
              const rawStream = await this.libp2p.dialProtocol(
                peer,
                [documentKeyUpdateV2],
                { runOnLimitedConnection: true, signal },
              );
              if (signal.aborted) {
                rawStream.abort(
                  signal.reason instanceof Error
                    ? signal.reason
                    : new Error('key-update peer delivery aborted'),
                );
                throw signal.reason;
              }
              stream = wrapStream(rawStream);
              await pipe([v2Payload], stream.sink);
            },
            (error) => stream?.abort(error),
          );
        } catch {
          failedPeerCount++;
          console.warn('Failed to send key update to a peer');
        }
      }
    });
    await Promise.all(workers);

    if (failedPeerCount > 0) {
      console.warn(
        `Key update for ${this.documentPath} failed to reach ${failedPeerCount} peer(s). ` +
        'These peers may be unable to decrypt future messages; recovery requires an authenticated membership remove/rejoin, not an ordinary encrypted load.',
      );
    }
  }

  /**
   * Handles a key-update request with pre-read payload data. Called by
   * the shared protocol handler in Peerborne after reading the document
   * path header and routing.
   *
   * @internal
   * @param payload The encrypted key-update payload (without the document
   *   path header that was already stripped by the shared handler).
   */
  public async handleKeyUpdateRequestData(
    payload: Uint8Array,
  ): Promise<void> {
    let stablePayload: Uint8Array;
    try {
      stablePayload = copyUnsharedUint8Array(
        payload,
        this._keychainProvider.keyIDLength + this._authProvider.nonceBits + 1,
        MAX_SHARED_PROTOCOL_REQUEST_SIZE,
        'key-update payload',
      );
    } catch {
      console.warn(`Ignoring malformed key-update for ${this.documentPath}`);
      return;
    }
    try {
      await this._runInMutationQueue(() =>
        this._handleKeyUpdateRequestDataUnlocked(stablePayload),
      );
    } catch {
      // Ingress handlers intentionally drop failures. Keep that contract when
      // the acquired-slot retirement check rejects before the unlocked body.
      console.error(
        `Error handling key update request for document ${this.documentPath}`,
      );
    }
  }

  private async _handleKeyUpdateRequestDataUnlocked(
    payload: Uint8Array,
  ): Promise<void> {
    try {
      this._throwIfSecurityProviderMutationFailed();
      // Decrypt the key update message.
      const blockKeyID = payload.slice(0, this._keychainProvider.keyIDLength);
      const blockNonce = payload.slice(
        this._keychainProvider.keyIDLength,
        this._keychainProvider.keyIDLength + this._authProvider.nonceBits,
      );
      const blockData = payload.slice(
        this._keychainProvider.keyIDLength + this._authProvider.nonceBits,
      );

      let rawContent: Uint8Array | undefined;
      try {
        rawContent = await this._decryptBlock(
          blockKeyID,
          blockNonce,
          blockData,
        );
      } catch {
        console.warn(`Failed to decrypt key update for ${this.documentPath}`);
      }

      this._throwIfSecurityProviderMutationFailed();

      if (!rawContent) {
        console.warn(`Unable to decrypt key update for ${this.documentPath}`);
        return;
      }

      let message: CRDTSyncMessage<ChangesType, PublicKey>;
      try {
        message = this._snapshotDecodedSyncMessage(
          this._syncMessageSerializer.deserializeSyncMessage(rawContent),
          'key-update message',
        );
      } catch {
        console.warn(`Ignoring malformed key-update for ${this.documentPath}`);
        return;
      }

      // The shared V2 key-update handler already routes by the
      // length-prefixed document-path header and drops invalid headers;
      // this check is kept as a defense-in-depth guard against malformed
      // or misrouted messages.
      if (message.documentId !== this.documentPath) {
        console.warn(
          `Ignoring key-update for the wrong local document (${this.documentPath})`,
        );
        return;
      }

      console.log(`received key-update for ${this.documentPath}`);

      // A V2 writer-removal delivery is the same sync envelope published on
      // GossipSub (writer-signed when signing is enabled): it may contain both
      // the replacement-key delta and writer ACL node. Reuse the normal sync
      // path so signing-mode-specific authentication, key-before-ACL ordering,
      // and authorization leasing cannot drift between transports. Legacy
      // key-only envelopes remain compatible because `changes` is optional.
      if ((await this._syncUnlocked(message, true)) !== true) {
        console.warn(`Discarding rejected key update for ${this.documentPath}`);
      }
    } catch {
      console.error(
        `Error handling key update request for document ${this.documentPath}`,
      );
    }
  }
}
