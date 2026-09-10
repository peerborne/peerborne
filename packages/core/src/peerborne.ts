/**
 * A Swarm is for opening documents
 * and it allows you to store your configuration in a single line when you use it as a library
 *
 * Conceptually a "swarm" is a connected group of nodes
 * Not all peerborne nodes will be connected to each other
 *
 * basic config
 *   what the swarm name is
 *   at least one address to join
 */

import { pipe } from 'it-pipe';
import {
  AuthProvider,
  requireDeserializePublicKey,
  requireSerializePublicKey,
} from './auth-provider.js';
import { CRDTProvider } from './crdt-provider.js';
import {
  PeerborneConfig,
  defaultConfig,
  defaultBootstrapConfig,
} from './peerborne-config.js';
import { PeerborneDocument } from './peerborne-document.js';
import {
  assertInvitationOfferLifetime,
  assertInitialInvitationHistoryVisibility,
  firstSuccessfulInvitationRendezvous,
  InMemoryInvitationAcceptanceCoordinator,
  invitationAcceptanceExpiresAt,
  assertInvitationProcessingWindow,
} from './invitation-policy.js';
import { withInvitationProtocolStream } from './invitation-catch-up.js';
import {
  encodeInvitationProtocolFrame,
  readInvitationProtocolMessage,
} from './invitation-framing.js';
import { NetworkStats } from './network-stats.js';
import { SyncMessageSerializer } from './sync-message-serializer.js';
import { ChangesSerializer } from './changes-serializer.js';
import { ACLProvider } from './acl-provider.js';
import { KeychainProvider } from './keychain-provider.js';
import { LoadMessageSerializer } from './load-request-serializer.js';
import { validateLoadQuorumConfig } from './load-quorum.js';
import {
  type PeerborneSecurityPolicyConfig,
  snapshotPeerborneSecurityPolicy,
  validateSecurityConfiguration,
} from './security-config.js';
import { unknownDocumentAdvertisement } from './initial-load-sentinel-policy.js';
import {
  beekemPathUpdateV1,
  beekemPathUpdateV2,
  beekemWelcomeV1,
  beekemWelcomeV2,
  documentLoadV3,
  documentLoadV4,
  documentKeyUpdateV2,
  invitationJoinV1,
  securityAdvertiseV1,
  snapshotLoadV3,
  snapshotLoadV4,
  tipAdvertiseV1,
} from './wire-protocols.js';
import type { BeeKEMWireVersion } from './wire-protocols.js';
import {
  readFirstDeserializable,
  readPathPrefixedProtocolHeader,
} from './utils.js';
import { wrapStream } from './stream-adapter.js';
import { closeLegacyHeliaStores } from './store-lifecycle.js';
import type { OpenableStore } from './store-lifecycle.js';
import { createAndStartHeliaNode } from './helia-node.js';
import type { PeerborneHeliaNode } from './helia-node.js';
import type { HeliaWithLibp2p } from '@helia/libp2p';
import { Libp2p } from 'libp2p';
import { PeerId } from '@libp2p/interface';
import type { ServiceMap, Stream } from '@libp2p/interface';
import type { GossipSub } from '@libp2p/gossipsub';
import { peerIdFromString } from '@libp2p/peer-id';
import { multiaddr } from '@multiformats/multiaddr';
import type { Uint8ArrayList } from 'uint8arraylist';
import { importEciesPublicKey } from './ecies.js';
import { snapshotKemKeyPair } from './kem-key-pair.js';
import {
  INVITATION_ID_LENGTH,
  MAX_INVITATION_JOIN_REQUEST_BYTES,
  MAX_INVITATION_MESSAGE_BYTES,
  InvitationAcceptanceV1,
  InvitationJoinRequestV1,
  InvitationOfferV1,
  InvitationRole,
  InvitationSignatureProvider,
  UnsignedInvitationAcceptanceV1,
  UnsignedInvitationJoinRequestV1,
  UnsignedInvitationOfferV1,
  assertInvitationAcceptanceMatches,
  assertInvitationAcceptanceUsable,
  assertInvitationJoinMatchesOffer,
  assertInvitationOfferUsable,
  decodeInvitationAcceptance,
  decodeInvitationJoinRequest,
  decodeInvitationOffer,
  digestInvitationJoinRequest,
  digestInvitationOffer,
  encodeInvitationAcceptance,
  encodeInvitationJoinRequest,
  encodeInvitationOffer,
  signInvitationAcceptance,
  signInvitationJoinRequest,
  signInvitationOffer,
  verifyInvitationAcceptance,
  verifyInvitationJoinRequest,
  verifyInvitationOffer,
} from './invitation-wire.js';
import {
  InMemoryInvitationReplayGuard,
} from './invitation-replay-guard.js';
import { MAX_SHARED_PROTOCOL_REQUEST_SIZE } from './initial-load-protocols.js';

/** Maximum allowed document path length in key-update V2 wire format. */
export const MAX_DOCUMENT_PATH_LENGTH = 4096;

/** Maximum time an inbound shared-protocol reader may wait for its next chunk. */
const SHARED_PROTOCOL_READ_IDLE_TIMEOUT_MS = 5_000;

/** Maximum wall-clock time allowed to assemble one shared-protocol request. */
const SHARED_PROTOCOL_READ_TOTAL_TIMEOUT_MS = 30_000;

/** Default lifetime for a user-facing invitation offer. */
export const DEFAULT_INVITATION_TTL_MS = 15 * 60 * 1000;

/** Bound in-memory offer and retry state instead of accepting unbounded links. */
const MAX_ACTIVE_INVITATION_OFFERS = 128;

export interface CreateInvitationOptions {
  /** Least-privilege role granted to the first valid claimant. */
  role: InvitationRole;
  /** One to eight observed addresses that end at the founder peer. */
  rendezvous: readonly string[];
  /** Offer lifetime: 60 seconds to seven days; defaults to 15 minutes. */
  expiresInMs?: number;
}

function bytesToHex(bytes: Uint8Array): string {
  let result = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    result += bytes[i].toString(16).padStart(2, '0');
  }
  return result;
}

/** Minimal stream shape used by shared protocol handlers. */
interface ProtocolStream {
  source: AsyncIterable<Uint8ArrayList | Uint8Array>;
  sink: (data: Iterable<Uint8Array>) => Promise<void>;
  close: () => Promise<void>;
  abort: (err: Error) => void;
}

/**
 * Bound both idle time and total assembly time for unauthenticated inbound
 * shared-protocol requests. The aggregate byte cap remains enforced by the
 * existing request readers; these deadlines prevent a peer from retaining a
 * stream slot indefinitely with an incomplete, below-cap request.
 */
async function* withSharedProtocolReadDeadline(
  source: ProtocolStream['source'],
  abort: ProtocolStream['abort'],
  protocolName: string,
): AsyncGenerator<Uint8ArrayList | Uint8Array> {
  const iterator = source[Symbol.asyncIterator]();
  const totalDeadline = Date.now() + SHARED_PROTOCOL_READ_TOTAL_TIMEOUT_MS;
  let reachedEnd = false;

  const abortForDeadline = (kind: 'idle' | 'total'): Error => {
    const error = new Error(
      `Inbound ${protocolName} request exceeded its ${kind} read deadline`,
    );
    try {
      abort(error);
    } catch {
      // The remote may have reset the stream at the same time as the timer.
    }
    return error;
  };

  try {
    while (true) {
      const remainingTotalMs = totalDeadline - Date.now();
      if (remainingTotalMs <= 0) {
        throw abortForDeadline('total');
      }

      const deadlineKind: 'idle' | 'total' =
        remainingTotalMs <= SHARED_PROTOCOL_READ_IDLE_TIMEOUT_MS
          ? 'total'
          : 'idle';
      const waitMs = Math.min(
        remainingTotalMs,
        SHARED_PROTOCOL_READ_IDLE_TIMEOUT_MS,
      );
      let timer: ReturnType<typeof setTimeout> | undefined;
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(abortForDeadline(deadlineKind)),
          waitMs,
        );
      });

      let next: IteratorResult<Uint8ArrayList | Uint8Array>;
      try {
        next = await Promise.race([iterator.next(), timeout]);
      } finally {
        if (timer !== undefined) {
          clearTimeout(timer);
        }
      }

      if (next.done) {
        reachedEnd = true;
        return;
      }
      yield next.value;
    }
  } finally {
    if (!reachedEnd) {
      try {
        const returned = iterator.return?.();
        if (returned !== undefined) {
          void returned.catch(() => undefined);
        }
      } catch {
        // Full stream teardown is already owned by the enclosing handler.
      }
    }
  }
}

/**
 * Handler type for peer-connect and peer-disconnect events.
 *
 * Subscribe functions that match this type signature to track peer-connection/peer-disconnection events.
 */
export type PeerbornePeersHandler = (
  peerId: string,
  connection: CustomEvent<PeerId>,
) => void;

const objectHasOwnProperty = Object.prototype.hasOwnProperty;

/**
 * Build the top-level configuration view exposed after initialization.
 * Security fields come exclusively from the already validated, normalized
 * policy, while other own properties are captured without re-reading security
 * fields through a caller-supplied Proxy.
 */
function createEffectiveConfigView(
  source: PeerborneConfig,
  securityPolicy: Readonly<PeerborneSecurityPolicyConfig>,
): Readonly<PeerborneConfig> {
  const view: Record<PropertyKey, unknown> = {};

  for (const key of Reflect.ownKeys(source)) {
    if (
      typeof key === 'string' &&
      objectHasOwnProperty.call(securityPolicy, key)
    ) {
      continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(source, key);
    if (!descriptor) {
      throw new TypeError('Peerborne config changed during initialization');
    }
    const value =
      'value' in descriptor ? descriptor.value : Reflect.get(source, key);
    Object.defineProperty(view, key, {
      value,
      enumerable: descriptor.enumerable,
      configurable: false,
      writable: false,
    });
  }

  for (const key of Reflect.ownKeys(securityPolicy)) {
    Object.defineProperty(view, key, {
      value: Reflect.get(securityPolicy, key),
      enumerable: true,
      configurable: false,
      writable: false,
    });
  }

  return Object.freeze(view) as Readonly<PeerborneConfig>;
}

/**
 * The peerborne object is the main entry point for the peerborne library.
 *
 * @example
 * import {
 *   Peerborne,
 *   SubtleCrypto,
 *   defaultBootstrapConfig,
 *   defaultConfig,
 * } from '@peerborne/core';
 * import {
 *   AutomergeACLProvider,
 *   AutomergeJSONSerializer,
 *   AutomergeKeychainProvider,
 *   AutomergeProvider,
 * } from '@peerborne/automerge';
 *
 * // Create the necessary providers and pass them to the peerborne constructor.
 * const userKeyPair = await crypto.subtle.generateKey(
 *   { name: 'ECDSA', namedCurve: 'P-384' },
 *   true,
 *   ['sign', 'verify'],
 * ) as CryptoKeyPair;
 * const crdt = new AutomergeProvider();
 * const serializer = new AutomergeJSONSerializer();
 * const peerborne = new Peerborne(
 *   userKeyPair.privateKey,
 *   userKeyPair.publicKey,
 *   crdt,
 *   serializer,
 *   serializer,
 *   serializer,
 *   new SubtleCrypto(),
 *   new AutomergeACLProvider(),
 *   new AutomergeKeychainProvider(),
 * );
 *
 * // Set the config for your peerborne object and startup a Helia node.
 * await peerborne.initialize(defaultConfig(defaultBootstrapConfig([])));
 *
 * // Optionally connect to a known peer.
 * // await peerborne.connect(['/dns4/relay.example.com/tcp/443/wss/p2p/12D3...']);
 *
 * // Open a document.
 * const doc = peerborne.doc('/my-doc-path');
 * await doc.open();
 * @typeParam DocType The CRDT document type
 * @typeParam ChangesType A block of CRDT change(s)
 * @typeParam ChangeFnType A function for applying changes to a document
 */
export class Peerborne<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
> {
  constructor(
    private readonly _userKey: PrivateKey,
    private readonly _userPublicKey: PublicKey,
    private readonly _crdtProvider: CRDTProvider<
      DocType,
      ChangesType,
      ChangeFnType
    >,
    private readonly _changesSerializer: ChangesSerializer<ChangesType>,
    private readonly _syncMessageSerializer: SyncMessageSerializer<
      ChangesType,
      PublicKey
    >,
    private readonly _loadMessageSerializer: LoadMessageSerializer,
    private readonly _authProvider: AuthProvider<
      PrivateKey,
      PublicKey,
      DocumentKey
    >,
    private readonly _aclProvider: ACLProvider<ChangesType, PublicKey>,
    private readonly _keychainProvider: KeychainProvider<
      ChangesType,
      DocumentKey
    >,
  ) {}

  private _invitationSignatureProvider(): InvitationSignatureProvider<
    PrivateKey,
    PublicKey
  > {
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'Public invitations',
    );
    return {
      sign: (data, privateKey) =>
        this._authProvider.sign(data, privateKey),
      verify: (data, publicKey, signature) =>
        this._authProvider.verify(data, publicKey, signature),
      serializePublicKey,
    };
  }

  // Effective configuration captured for documents opened in this swarm.
  protected _config: Readonly<PeerborneConfig> | null = null;
  private _enableSigning = true;
  private _enableTopicValidators = false;
  private _allowInsecureLegacyBeeKEMPathUpdateV1 = false;
  private _loadQuorumEnabled = true;
  private _loadQuorumK = 3;
  private _loadQuorumQ: number | undefined;
  private _loadQuorumTimeoutMs = 5000;
  private _loadQuorumAllowSinglePeer = false;
  private _requireAuthenticatedInitialLoad = false;
  private _requireSecurityStateQuorum = false;
  private _resolveTrustedDocumentWriters: PeerborneConfig['resolveTrustedDocumentWriters'] =
    undefined;
  private _resolveLoadSecurityCommitments: PeerborneConfig['resolveLoadSecurityCommitments'] =
    undefined;
  private _validateDocumentPath: PeerborneConfig['validateDocumentPath'] =
    undefined;
  private _heliaNode: PeerborneHeliaNode | undefined;
  private _peerId: PeerId | undefined;
  private _peerIds: string[] = [];
  private _peerConnectHandlers: Map<string, PeerbornePeersHandler> = new Map<
    string,
    PeerbornePeersHandler
  >();
  private _peerDisconnectHandlers: Map<string, PeerbornePeersHandler> = new Map<
    string,
    PeerbornePeersHandler
  >();
  private _networkStats?: NetworkStats;

  private _sharedHandlersRegistration: Promise<void> | undefined;
  private _openedLegacyStores: OpenableStore[] = [];
  private _initializationInFlight = false;

  // Registry of open documents keyed by document path. Shared protocol
  // handlers use this to route incoming stream requests to the correct
  // PeerborneDocument instance.
  private _documentRegistry = new Map<
    string,
    PeerborneDocument<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >
  >();
  // Welcome-only routing for invitation recipients that installed a KEM key
  // before `open()`. These instances are deliberately invisible to load,
  // key-update, PathUpdate, and tip-advertisement handlers.
  private _welcomeRecipientRegistry = new Map<
    string,
    PeerborneDocument<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >
  >();
  private static readonly _MAX_WELCOME_RECIPIENT_REGISTRATIONS = 1024;

  // Online invitation offers are intentionally in-memory for the initial
  // founder-plus-one flow. A durable store is required before invitations can
  // survive an inviter restart; until then, restart invalidates outstanding
  // links instead of risking replay after replay memory was lost.
  private _invitationRegistry = new Map<
    string,
    {
      offer: InvitationOfferV1;
      document: PeerborneDocument<
        DocType,
        ChangesType,
        ChangeFnType,
        PrivateKey,
        PublicKey,
        DocumentKey
      >;
      replayGuard: InMemoryInvitationReplayGuard;
      acceptanceCoordinator:
        InMemoryInvitationAcceptanceCoordinator<InvitationAcceptanceV1>;
    }
  >();
  private _recipientInvitationReplayGuard =
    new InMemoryInvitationReplayGuard();
  // Keep the exact signed request for an offer so an application retry after
  // a lost response presents the same request digest and can receive the
  // inviter's cached acceptance. This state is intentionally process-local.
  private _outboundInvitationRequests = new Map<
    string,
    { request: InvitationJoinRequestV1; expiresAtMs: number }
  >();
  // Reserve a document path from offer decode through post-subscribe catch-up.
  // The exact instance is allowed to register; any competing open is rejected.
  private _pendingInvitationDocuments = new Map<
    string,
    PeerborneDocument<DocType, ChangesType, ChangeFnType, PrivateKey, PublicKey, DocumentKey>
  >();

  /**
   * Network statistics tracker. Only available when `enableNetworkStats`
   * is set to `true` in the config passed to `initialize()`.
   */
  public get networkStats(): NetworkStats | undefined {
    return this._networkStats;
  }

  /**
   * Gets the current libp2p node instance.
   *
   * Only works after `.initialize()` has been called.
   */
  public get libp2p(): Libp2p {
    return this.heliaNode.libp2p;
  }

  /**
   * Gets the current Helia node instance.
   *
   * Only works after `.initialize()` has been called.
   */
  public get heliaNode(): HeliaWithLibp2p<ServiceMap & { pubsub: GossipSub }> {
    if (this._heliaNode) {
      return this._heliaNode;
    }

    throw new Error('Helia node not initialized yet!');
  }

  /**
   * Gets the current peer ID.
   *
   * Only works after `.initialize()` has been called.
   */
  public get peerId(): PeerId {
    if (this._peerId) {
      return this._peerId;
    }

    throw new Error('Helia node not initialized yet!');
  }

  /**
   * Gets the current list of peer IDs that this peerborne node is connected to.
   */
  public get peerIds(): string[] {
    return this._peerIds;
  }

  /**
   * Gets the detached, top-level immutable effective configuration captured by
   * the latest initialization. Security-policy fields contain their normalized
   * runtime values and cannot diverge from the dedicated policy getters when
   * the caller later mutates its source object.
   */
  public get config(): Readonly<PeerborneConfig> | null {
    return this._config;
  }

  /** Whether application-level signing is enabled for this initialization. */
  public get enableSigning(): boolean {
    return this._enableSigning;
  }

  /** Whether GossipSub validators are enabled for this initialization. */
  public get enableTopicValidators(): boolean {
    return this._enableTopicValidators;
  }

  /** Whether the insecure legacy BeeKEM PathUpdate v1 migration path is active. */
  public get allowInsecureLegacyBeeKEMPathUpdateV1(): boolean {
    return this._allowInsecureLegacyBeeKEMPathUpdateV1;
  }

  /** Immutable initial-load quorum policy captured during initialization. */
  public get loadQuorumEnabled(): boolean {
    return this._loadQuorumEnabled;
  }

  public get loadQuorumK(): number {
    return this._loadQuorumK;
  }

  public get loadQuorumQ(): number | undefined {
    return this._loadQuorumQ;
  }

  public get loadQuorumTimeoutMs(): number {
    return this._loadQuorumTimeoutMs;
  }

  public get loadQuorumAllowSinglePeer(): boolean {
    return this._loadQuorumAllowSinglePeer;
  }

  /**
   * Whether initial loads must be authenticated by an application-pinned
   * writer. Captured during initialization so later mutation of the caller's
   * config object cannot downgrade the load policy.
   */
  public get requireAuthenticatedInitialLoad(): boolean {
    return this._requireAuthenticatedInitialLoad;
  }

  /**
   * Whether initial loads must use the security-state-aware quorum protocol.
   * Captured during initialization so later mutation of the caller's config
   * object cannot select a legacy protocol.
   */
  public get requireSecurityStateQuorum(): boolean {
    return this._requireSecurityStateQuorum;
  }

  /** Trusted-writer resolver captured during initialization. */
  public get resolveTrustedDocumentWriters(): PeerborneConfig['resolveTrustedDocumentWriters'] {
    return this._resolveTrustedDocumentWriters;
  }

  /** Load-security commitment resolver captured during initialization. */
  public get resolveLoadSecurityCommitments(): PeerborneConfig['resolveLoadSecurityCommitments'] {
    return this._resolveLoadSecurityCommitments;
  }

  /** Document-creation policy callback captured during initialization. */
  public get validateDocumentPath(): PeerborneConfig['validateDocumentPath'] {
    return this._validateDocumentPath;
  }

  /**
   * Sets up the peerborne node and starts its underlying Helia/libp2p node.
   *
   * @param config General settings for peerborne.
   */
  public async initialize(config?: PeerborneConfig) {
    if (this._initializationInFlight) {
      throw new Error('Cannot initialize while initialization is already active');
    }
    if (
      this._documentRegistry.size > 0 ||
      this._pendingInvitationDocuments.size > 0 ||
      this._welcomeRecipientRegistry.size > 0
    ) {
      throw new Error(
        'Cannot reinitialize while documents are open, invitation acceptance ' +
        'is active, or a document is awaiting a Welcome. Close all document ' +
        'instances and wait for invitation acceptance before calling initialize() again.',
      );
    }

    this._initializationInFlight = true;
    try {
      await this._initializeUnlocked(config);
    } finally {
      this._initializationInFlight = false;
    }
  }

  private async _initializeUnlocked(config?: PeerborneConfig) {
    if (!config) {
      config = defaultConfig(defaultBootstrapConfig([]));
    }

    // Validate and snapshot every authentication/quorum policy value before
    // the first await. Even during reinitialization, a caller cannot race a
    // mutation of the shared config object against transport teardown to
    // change the policy that this initialization installs.
    const securityPolicyConfig = snapshotPeerborneSecurityPolicy(config);
    validateLoadQuorumConfig(securityPolicyConfig);
    validateSecurityConfiguration(securityPolicyConfig as PeerborneConfig);
    const securityPolicy = {
      enableSigning: securityPolicyConfig.enableSigning !== false,
      enableTopicValidators:
        securityPolicyConfig.enableSigning !== false &&
        securityPolicyConfig.enableTopicValidators === true,
      allowInsecureLegacyBeeKEMPathUpdateV1:
        securityPolicyConfig.allowInsecureLegacyBeeKEMPathUpdateV1 === true,
      loadQuorumEnabled: securityPolicyConfig.loadQuorumEnabled !== false,
      loadQuorumK: securityPolicyConfig.loadQuorumK ?? 3,
      loadQuorumQ: securityPolicyConfig.loadQuorumQ,
      loadQuorumTimeoutMs: securityPolicyConfig.loadQuorumTimeoutMs ?? 5000,
      loadQuorumAllowSinglePeer:
        securityPolicyConfig.loadQuorumAllowSinglePeer === true,
      requireAuthenticatedInitialLoad:
        securityPolicyConfig.requireAuthenticatedInitialLoad === true,
      requireSecurityStateQuorum:
        securityPolicyConfig.requireSecurityStateQuorum === true,
      resolveTrustedDocumentWriters:
        securityPolicyConfig.resolveTrustedDocumentWriters,
      resolveLoadSecurityCommitments:
        securityPolicyConfig.resolveLoadSecurityCommitments,
      validateDocumentPath: securityPolicyConfig.validateDocumentPath,
    } as const;
    const effectiveConfig = createEffectiveConfigView(config, securityPolicy);

    // Outstanding online invitations are bound to the current libp2p
    // endpoint and in-memory replay state. Reinitialization invalidates them.
    this._invitationRegistry.clear();
    this._recipientInvitationReplayGuard =
      new InMemoryInvitationReplayGuard();
    this._outboundInvitationRequests.clear();
    this._pendingInvitationDocuments.clear();

    // Tear down the previous Helia/libp2p instance if reinitializing,
    // preventing leaked background resources (connections, timers, etc.).
    if (this._heliaNode) {
      try {
        await this._heliaNode.stop();
      } catch {
        /* best-effort */
      }
      await closeLegacyHeliaStores(this._openedLegacyStores);
      this._openedLegacyStores = [];
      this._heliaNode = undefined;
      this._peerId = undefined;
      this._peerIds = [];
    }

    this._enableSigning = securityPolicy.enableSigning;
    this._enableTopicValidators = securityPolicy.enableTopicValidators;
    this._allowInsecureLegacyBeeKEMPathUpdateV1 =
      securityPolicy.allowInsecureLegacyBeeKEMPathUpdateV1;
    this._loadQuorumEnabled = securityPolicy.loadQuorumEnabled;
    this._loadQuorumK = securityPolicy.loadQuorumK;
    this._loadQuorumQ = securityPolicy.loadQuorumQ;
    this._loadQuorumTimeoutMs = securityPolicy.loadQuorumTimeoutMs;
    this._loadQuorumAllowSinglePeer = securityPolicy.loadQuorumAllowSinglePeer;
    this._requireAuthenticatedInitialLoad =
      securityPolicy.requireAuthenticatedInitialLoad;
    this._requireSecurityStateQuorum =
      securityPolicy.requireSecurityStateQuorum;
    this._resolveTrustedDocumentWriters =
      securityPolicy.resolveTrustedDocumentWriters;
    this._resolveLoadSecurityCommitments =
      securityPolicy.resolveLoadSecurityCommitments;
    this._validateDocumentPath = securityPolicy.validateDocumentPath;
    this._config = effectiveConfig;

    this._sharedHandlersRegistration = undefined;

    this._networkStats = effectiveConfig.enableNetworkStats
      ? new NetworkStats()
      : undefined;

    // Setup Helia node.
    const { heliaNode, openedLegacyStores } = await createAndStartHeliaNode(
      effectiveConfig.helia,
    );
    this._heliaNode = heliaNode;
    this._openedLegacyStores = openedLegacyStores;

    this.libp2p.addEventListener('peer:connect', (event) => {
      const peerId = event.detail.toString();
      this._peerIds.push(peerId);
      for (const [, handler] of this._peerConnectHandlers) {
        handler(peerId, event);
      }
    });
    this.libp2p.addEventListener('peer:disconnect', (event) => {
      const peerId = event.detail.toString();
      const peerIndex = this._peerIds.indexOf(peerId);
      if (peerIndex >= 0) {
        this._peerIds.splice(peerIndex, 1);
      }
      for (const [, handler] of this._peerDisconnectHandlers) {
        handler(peerId, event);
      }
    });
    this._peerId = this._heliaNode?.libp2p?.peerId;

    // Register shared protocol handlers that route incoming requests to
    // the appropriate document via the document registry. This replaces
    // per-document protocol handler registration, reducing protocol
    // handler overhead for multi-document applications.
    await this._registerSharedProtocolHandlers();

    console.log('Helia node initialized:', this._peerId);
  }

  /**
   * Registers a document in the shared handler registry so incoming
   * protocol requests can be routed to it.
   *
   * Called by PeerborneDocument.open().
   *
   * @internal
   */
  registerDocument(
    documentPath: string,
    document: PeerborneDocument<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >,
  ): void {
    const pendingInvitation =
      this._pendingInvitationDocuments.get(documentPath);
    if (pendingInvitation && pendingInvitation !== document) {
      throw new Error(
        `Document "${documentPath}" is reserved by an invitation acceptance`,
      );
    }
    if (this._documentRegistry.has(documentPath)) {
      throw new Error(
        `A document is already registered for "${documentPath}". ` +
          'Multiple instances per path are not supported. Close the existing document first.',
      );
    }
    const welcomeRecipient = this._welcomeRecipientRegistry.get(documentPath);
    if (welcomeRecipient !== undefined && welcomeRecipient !== document) {
      throw new Error(
        `A Welcome recipient is already registered for "${documentPath}". ` +
          'Multiple instances per path are not supported.',
      );
    }
    this._documentRegistry.set(documentPath, document);
    if (welcomeRecipient === document) {
      this._welcomeRecipientRegistry.delete(documentPath);
    }
  }

  /** Register one unopened document for recipient-targeted Welcome routing. */
  registerWelcomeRecipient(
    documentPath: string,
    document: PeerborneDocument<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >,
  ): void {
    const openDocument = this._documentRegistry.get(documentPath);
    if (openDocument !== undefined) {
      if (openDocument !== document) {
        throw new Error(
          `A document is already registered for "${documentPath}". ` +
            'Multiple instances per path are not supported.',
        );
      }
      return;
    }
    const existing = this._welcomeRecipientRegistry.get(documentPath);
    if (existing !== undefined) {
      if (existing !== document) {
        throw new Error(
          `A Welcome recipient is already registered for "${documentPath}". ` +
            'Multiple instances per path are not supported.',
        );
      }
      return;
    }
    if (
      this._welcomeRecipientRegistry.size >=
      Peerborne._MAX_WELCOME_RECIPIENT_REGISTRATIONS
    ) {
      throw new Error(
        `Welcome-recipient registry limit of ${Peerborne._MAX_WELCOME_RECIPIENT_REGISTRATIONS} reached`,
      );
    }
    this._welcomeRecipientRegistry.set(documentPath, document);
  }

  /** Instance-safe removal of a pre-open Welcome-only registration. */
  unregisterWelcomeRecipient(
    documentPath: string,
    document: PeerborneDocument<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >,
  ): void {
    if (this._welcomeRecipientRegistry.get(documentPath) === document) {
      this._welcomeRecipientRegistry.delete(documentPath);
    }
  }

  /**
   * Removes a document from the shared handler registry.
   *
   * Instance-safe: only removes the entry if the registered document
   * matches the provided reference. This prevents a stale close()
   * from removing a live document that was re-opened at the same path.
   *
   * Called by PeerborneDocument.close().
   *
   * @internal
   */
  unregisterDocument(
    documentPath: string,
    document: PeerborneDocument<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >,
  ): void {
    if (this._documentRegistry.get(documentPath) === document) {
      this._documentRegistry.delete(documentPath);
      for (const [offerKey, registration] of this._invitationRegistry) {
        if (registration.document === document) {
          this._invitationRegistry.delete(offerKey);
        }
      }
    }
  }

  private _pruneExpiredInvitationState(now = Date.now()): void {
    for (const [offerKey, registration] of this._invitationRegistry) {
      if (
        registration.offer.expiresAtMs <= now ||
        this._documentRegistry.get(registration.document.documentPath) !==
          registration.document
      ) {
        this._invitationRegistry.delete(offerKey);
      }
    }
    for (const [offerKey, cached] of this._outboundInvitationRequests) {
      if (cached.expiresAtMs <= now) {
        this._outboundInvitationRequests.delete(offerKey);
      }
    }
  }

  private async _processInvitationJoin(
    request: InvitationJoinRequestV1,
    signal?: AbortSignal,
    admitStateMutation?: () => void,
  ): Promise<InvitationAcceptanceV1> {
    const offerKey = bytesToHex(request.offerDigest);
    const registration = this._invitationRegistry.get(offerKey);
    if (!registration) {
      throw new Error('Invitation offer is unavailable');
    }

    const { offer } = registration;
    const assertRegistrationAvailable = (): void => {
      if (
        this._invitationRegistry.get(offerKey) !== registration ||
        this._documentRegistry.get(registration.document.documentPath) !==
          registration.document
      ) {
        if (this._invitationRegistry.get(offerKey) === registration) {
          this._invitationRegistry.delete(offerKey);
        }
        throw new Error('Invitation offer is unavailable');
      }
    };
    assertRegistrationAvailable();
    assertInvitationOfferUsable(offer);
    await assertInvitationJoinMatchesOffer(request, offer);

    const deserializePublicKey = requireDeserializePublicKey(
      this._authProvider,
      'Public invitations',
    );
    const signatureProvider = this._invitationSignatureProvider();
    const recipientPublicKey = await deserializePublicKey(request.recipient);
    if (
      !(await verifyInvitationJoinRequest(
        request,
        recipientPublicKey,
        signatureProvider,
      ))
    ) {
      throw new Error('Invitation join signature is invalid');
    }
    if (request.recipient === offer.issuer) {
      throw new Error('Invitation recipient must use a distinct identity');
    }

    const requestDigest = await digestInvitationJoinRequest(request);
    const requestKey = bytesToHex(requestDigest);

    // Validate the SEC1 point before recording the one-time offer claim. A
    // malformed-but-correctly-signed KEM key must not burn a bearer link.
    await importEciesPublicKey(request.recipientKemPublicKey);
    return registration.acceptanceCoordinator.run(
      requestKey,
      offer.expiresAtMs,
      signal,
      async () => {
        assertRegistrationAvailable();
        assertInvitationOfferUsable(offer);
        await registration.replayGuard.observeJoin(offer, request);
      },
      () => {
        // The claim awaits cryptographic checks, so close()/stop() can run in
        // between. Re-check synchronously at the mutation boundary.
        assertRegistrationAvailable();
        assertInvitationOfferUsable(offer);
      },
      async () => {
        const assertCanMutate = (): void => {
          assertRegistrationAvailable();
          assertInvitationOfferUsable(offer);
          assertInvitationProcessingWindow(offer.expiresAtMs);
          if (signal?.aborted) {
            throw signal.reason instanceof Error
              ? signal.reason
              : new Error('Invitation stream closed before onboarding started');
          }
        };
        const bootstrap =
          await registration.document.buildInvitationBootstrap(
            recipientPublicKey,
            request.recipientKemPublicKey,
            offer.role,
            assertCanMutate,
            admitStateMutation,
          );
        const now = Date.now();
        const expiresAtMs = invitationAcceptanceExpiresAt(
          offer.expiresAtMs,
          now,
        );
        const unsignedAcceptance: UnsignedInvitationAcceptanceV1 = {
          version: 1,
          acceptanceId: crypto.getRandomValues(
            new Uint8Array(INVITATION_ID_LENGTH),
          ),
          offerDigest: request.offerDigest,
          requestDigest,
          documentId: offer.documentId,
          issuer: offer.issuer,
          recipient: request.recipient,
          recipientKemPublicKey: new Uint8Array(
            request.recipientKemPublicKey,
          ),
          role: offer.role,
          welcomeEpochId: bootstrap.welcomeEpochId,
          sealedWelcome: bootstrap.sealedWelcome,
          encryptedBootstrap: bootstrap.encryptedBootstrap,
          issuedAtMs: now,
          expiresAtMs,
        };
        const acceptance = await signInvitationAcceptance(
          unsignedAcceptance,
          this._userKey,
          this._userPublicKey,
          signatureProvider,
        );
        await registration.replayGuard.observeAcceptance(
          offer,
          request,
          acceptance,
        );
        return acceptance;
      },
    );
  }

  /**
   * Registers shared protocol handlers on libp2p for all three
   * protocols (doc-load, snapshot-load, key-update). Each handler reads
   * the incoming stream, extracts the document path, and routes to the
   * matching PeerborneDocument instance in the registry.
   *
   * For doc-load and snapshot-load, the document path is extracted by
   * deserializing the CRDTLoadRequest from the stream data. For
   * key-update, a 4-byte length-prefixed document path header precedes
   * the encrypted payload.
   */
  private async _registerSharedProtocolHandlers(): Promise<void> {
    if (this._sharedHandlersRegistration) {
      return this._sharedHandlersRegistration;
    }

    // Handler implementation for doc-load requests.
    //
    // libp2p v3 changed the `StreamHandler` signature from
    // `({ stream, connection }) => void` to `(stream, connection) => void`.
    // The raw stream is also now event-driven instead of `{ source, sink }`,
    // so we wrap it with the stream-adapter shim before passing it to the
    // legacy pipe-based protocol logic below.
    const docLoadHandler = (securityAware: boolean) => (rawStream: Stream) => {
      const stream: ProtocolStream = wrapStream(rawStream);
      return pipe(
        withSharedProtocolReadDeadline(
          stream.source,
          stream.abort,
          securityAware ? 'document-load v4' : 'document-load v3',
        ),
        async (source: AsyncIterable<Uint8ArrayList | Uint8Array>) => {
          let request;
          try {
            request = await readFirstDeserializable(
              source,
              (data) =>
                this._loadMessageSerializer.deserializeLoadRequest(data),
              MAX_SHARED_PROTOCOL_REQUEST_SIZE,
              this._loadMessageSerializer.createLoadRequestCompletionDetector?.(),
            );
          } catch (err) {
            const reason =
              err instanceof RangeError
                ? 'request too large'
                : 'failed to read request';
            console.warn(`Shared doc-load handler: ${reason}, dropping`);
            await stream.sink([] as Iterable<Uint8Array>);
            return [];
          }
          const doc = this._documentRegistry.get(request.documentId);
          if (!doc) {
            console.warn(
              'Shared doc-load handler: no document registered, dropping',
            );
            await stream.sink([] as Iterable<Uint8Array>);
            return [];
          }
          await doc.handleLoadRequestData(request, stream, securityAware);
          return [];
        },
      )
        .then(() => undefined)
        .catch(() => {
          console.error('Error in shared doc-load handler');
        });
    };

    // Handler implementation for snapshot-load requests.
    // See note on `docLoadHandler` above re: the v3 StreamHandler signature.
    const snapshotLoadHandler =
      (securityAware: boolean) => (rawStream: Stream) => {
        const stream: ProtocolStream = wrapStream(rawStream);
        return pipe(
          withSharedProtocolReadDeadline(
            stream.source,
            stream.abort,
            securityAware ? 'snapshot-load v4' : 'snapshot-load v3',
          ),
          async (source: AsyncIterable<Uint8ArrayList | Uint8Array>) => {
            let request;
            try {
              request = await readFirstDeserializable(
                source,
                (data) =>
                  this._loadMessageSerializer.deserializeLoadRequest(data),
                MAX_SHARED_PROTOCOL_REQUEST_SIZE,
                this._loadMessageSerializer.createLoadRequestCompletionDetector?.(),
              );
            } catch (err) {
              const reason =
                err instanceof RangeError
                  ? 'request too large'
                  : 'failed to read request';
              console.warn(`Shared snapshot-load handler: ${reason}, dropping`);
              await stream.sink([] as Iterable<Uint8Array>);
              return [];
            }
            const doc = this._documentRegistry.get(request.documentId);
            if (!doc) {
              console.warn(
                'Shared snapshot-load handler: no document registered, dropping',
              );
              await stream.sink([] as Iterable<Uint8Array>);
              return [];
            }
            await doc.handleSnapshotLoadRequestData(
              request,
              stream,
              securityAware,
            );
            return [];
          },
        )
          .then(() => undefined)
          .catch(() => {
            console.error('Error in shared snapshot-load handler');
          });
      };

    // Handler implementation for key-update requests. The stream data
    // is prefixed with a 4-byte big-endian length followed by the
    // UTF-8 document path. The remaining bytes are the encrypted
    // key-update payload.
    // See note on `docLoadHandler` above re: the v3 StreamHandler signature.
    //
    // The header parse (read assembled bytes, validate the 4-byte
    // length, decode the UTF-8 path, look up the doc in the registry)
    // is shared with the BeeKEM Welcome handler below via
    // `readPathPrefixedProtocolHeader`. Both protocols use the same
    // wire-format prefix; keeping the validation in one place means a
    // tightened bound only needs to land once.
    const keyUpdateHandler = (rawStream: Stream) => {
      const stream: ProtocolStream = wrapStream(rawStream);
      return pipe(
        withSharedProtocolReadDeadline(
          stream.source,
          stream.abort,
          'key-update v2',
        ),
        async (source: AsyncIterable<Uint8ArrayList | Uint8Array>) => {
          try {
            const header = await readPathPrefixedProtocolHeader(
              source,
              this._documentRegistry,
              'key-update',
              MAX_SHARED_PROTOCOL_REQUEST_SIZE,
              MAX_DOCUMENT_PATH_LENGTH,
            );
            if (header.kind !== 'ok') {
              return [];
            }
            await header.doc.handleKeyUpdateRequestData(header.payload);
            return [];
          } finally {
            // Key-update is fire-and-forget (no response via stream.sink),
            // but the inbound stream must still be closed to release resources.
            await stream.close();
          }
        },
      )
        .then(() => undefined)
        .catch(() => {
          console.error('Error in shared key-update handler');
        });
    };

    // Handlers for BeeKEM Welcome v1/v2. Wire framing mirrors key-update v2:
    // 4-byte big-endian path length, then UTF-8 path, then the serialized
    // welcome sync-message body. After routing by path, the per-document
    // handler verifies the writer signature, merges the keychain delta,
    // and records the invitation epoch.
    // See note on `docLoadHandler` above re: the v3 StreamHandler signature.
    //
    // Header parse shared with the key-update handler above via
    // `readPathPrefixedProtocolHeader`.
    const createBeeKEMWelcomeHandler =
      (version: BeeKEMWireVersion) => (rawStream: Stream) => {
        const stream: ProtocolStream = wrapStream(rawStream);
        return pipe(
          withSharedProtocolReadDeadline(
            stream.source,
            stream.abort,
            `beekem-welcome v${version}`,
          ),
          async (source: AsyncIterable<Uint8ArrayList | Uint8Array>) => {
            try {
              const header = await readPathPrefixedProtocolHeader(
                source,
                {
                  get: (documentPath: string) =>
                    this._documentRegistry.get(documentPath) ??
                    this._welcomeRecipientRegistry.get(documentPath),
                },
                'beekem-welcome',
                MAX_SHARED_PROTOCOL_REQUEST_SIZE,
                MAX_DOCUMENT_PATH_LENGTH,
              );
              if (header.kind !== 'ok') {
                return [];
              }
              await header.doc.handleBeeKEMWelcomeRequestData(
                header.payload,
                version,
              );
              return [];
            } finally {
              // Welcome is fire-and-forget (no response over stream.sink),
              // but the inbound stream still needs to be closed to release
              // resources.
              await stream.close();
            }
          },
        )
          .then(() => undefined)
          .catch(() => {
            console.error(`Error in shared beekem-welcome v${version} handler`);
          });
      };
    const beekemWelcomeV1Handler = createBeeKEMWelcomeHandler(1);
    const beekemWelcomeV2Handler = createBeeKEMWelcomeHandler(2);

    // Handlers for BeeKEM PathUpdate v1/v2 (reader-revocation rotations).
    // Wire format mirrors key-update v2 / BeeKEM Welcome: 4-byte
    // big-endian path length, then UTF-8 path, then the serialized
    // sync-message body carrying the `pathUpdate` /
    // `pathUpdateEpochId` / `signature` fields. After routing by path
    // the per-document handler verifies the writer signature, applies
    // the PathUpdate via `BeeKEM.processPathUpdate`, and installs the
    // freshly-derived document key in the keychain.
    // See note on `docLoadHandler` above re: the v3 StreamHandler
    // signature.
    //
    // Header parse shared with the key-update + Welcome handlers via
    // `readPathPrefixedProtocolHeader`.
    const createBeeKEMPathUpdateHandler =
      (version: BeeKEMWireVersion) => (rawStream: Stream) => {
        const stream: ProtocolStream = wrapStream(rawStream);
        return pipe(
          withSharedProtocolReadDeadline(
            stream.source,
            stream.abort,
            `beekem-pathupdate v${version}`,
          ),
          async (source: AsyncIterable<Uint8ArrayList | Uint8Array>) => {
            try {
              const header = await readPathPrefixedProtocolHeader(
                source,
                this._documentRegistry,
                'beekem-pathupdate',
                MAX_SHARED_PROTOCOL_REQUEST_SIZE,
                MAX_DOCUMENT_PATH_LENGTH,
              );
              if (header.kind !== 'ok') {
                return [];
              }
              await header.doc.handleBeeKEMPathUpdateRequestData(
                header.payload,
                version,
              );
              return [];
            } finally {
              // PathUpdate is fire-and-forget (no response over
              // stream.sink), but the inbound stream still needs to be
              // closed to release resources.
              await stream.close();
            }
          },
        )
          .then(() => undefined)
          .catch(() => {
            console.error(
              `Error in shared beekem-pathupdate v${version} handler`,
            );
          });
      };
    const beekemPathUpdateV1Handler = createBeeKEMPathUpdateHandler(1);
    const beekemPathUpdateV2Handler = createBeeKEMPathUpdateHandler(2);

    // Handler implementation for tip-advertise requests (initial-load
    // quorum probe; see `wire-protocols.ts::tipAdvertiseV1`). Wire format
    // mirrors documentLoadV3: a single serialized CRDTLoadRequest in,
    // a single (small) encrypted/serialized CRDTSyncMessage out (whose
    // only populated payload field is `tipsHash`), or an empty response
    // on decline.
    // See note on `docLoadHandler` above re: the v3 StreamHandler signature.
    const tipAdvertiseHandler =
      (securityAware: boolean) => (rawStream: Stream) => {
        const stream: ProtocolStream = wrapStream(rawStream);
        return pipe(
          withSharedProtocolReadDeadline(
            stream.source,
            stream.abort,
            securityAware ? 'security-advertise v1' : 'tip-advertise v1',
          ),
          async (source: AsyncIterable<Uint8ArrayList | Uint8Array>) => {
            try {
              let request;
              try {
                request = await readFirstDeserializable(
                  source,
                  (data) =>
                    this._loadMessageSerializer.deserializeLoadRequest(data),
                  MAX_SHARED_PROTOCOL_REQUEST_SIZE,
                  this._loadMessageSerializer.createLoadRequestCompletionDetector?.(),
                );
              } catch (err) {
                const reason =
                  err instanceof RangeError
                    ? 'request too large'
                    : 'failed to read request';
                console.warn(
                  `Shared tip-advertise handler: ${reason}, dropping`,
                );
                await stream.sink([] as Iterable<Uint8Array>);
                return [];
              }
              const doc = this._documentRegistry.get(request.documentId);
              if (!doc) {
                // Unknown document -- respond with the 1-byte UNKNOWN_DOC
                // sentinel (`0xFF`) so the loader can DISTINGUISH "I don't
                // have this document" from generic probe failures (timeout,
                // auth failure, decryption failure, malformed response). The
                // loader uses this signal so that when EVERY queried peer in
                // the swarm explicitly disclaims the document, `load()`
                // returns `false` to let a fresh `open()` create the document
                // on top of an existing swarm -- the previous empty-response
                // decline was indistinguishable from a partition / timeout
                // and made new-document creation in an existing mesh fail
                // with `LoadQuorumFailedError`.
                //
                // Unauthenticated: this signal carries no signature. A
                // Byzantine peer can lie and claim "unknown" even when other
                // honest peers have the document. Defense: quorum tallies
                // `'unknown-doc'` exactly like a tip-hash vote -- if Q of K
                // peers all agree on `'unknown-doc'` the loader trusts the
                // disclaimer, but a single lying peer in a 3-of-3 mesh whose
                // other 2 peers have the doc cannot force new-doc creation
                // (the honest hash X wins the tally). The protection is the
                // configured Q-of-K agreement threshold and depends on peer
                // independence; it is not Byzantine consensus or Sybil
                // resistance. See `decideLoadQuorum` for the tally semantics
                // and PR #284 r16 Copilot review for the original bug report.
                //
                // Information-disclosure tradeoff (PR #284 r27): replying with
                // `0xff` lets any peer that can dial this node learn whether
                // `documentId` is registered here. We accept this because the
                // quorum protocol REQUIRES a distinguishable "unknown-doc"
                // signal to allow new-document creation on an existing swarm;
                // suppressing the signal would block legitimate `open()` calls
                // for fresh paths. Two mitigations are wired in: (1) no
                // unauthenticated-probe log line so attacker-controlled
                // `documentId` values don't reach the host log, and (2) the
                // sentinel is a single byte with no per-document content, so
                // it leaks only the existence bit -- nothing about contents,
                // membership, or history.
                await stream.sink(
                  unknownDocumentAdvertisement({
                    securityAware,
                    requireAuthenticatedInitialLoad:
                      this.requireAuthenticatedInitialLoad,
                  }),
                );
                return [];
              }
              await doc.handleTipAdvertiseRequestData(
                request,
                stream,
                securityAware,
              );
              return [];
            } finally {
              // Tip-advertise runs on every `open()` quorum probe, so every
              // connected peer hits this handler. Always close the inbound
              // stream (even on the sink-already-completed happy path) so
              // per-connection stream quota doesn't leak under load or when
              // a downstream call throws after sink. Safe to call after
              // `stream.sink`: libp2p stream.close() is idempotent on a
              // already-half-closed stream.
              await stream.close().catch(() => {
                // swallow: close-after-error is best-effort cleanup
              });
            }
          },
        )
          .then(() => undefined)
          .catch(() => {
            console.error('Error in shared tip-advertise handler');
          });
      };

    // Public invitation join handler. Unlike document protocols, routing is
    // by the signed offer digest, so a recipient can join before it has a
    // local document instance or document key. One bounded canonical request
    // receives one bounded, recipient-encrypted acceptance.
    const invitationJoinHandler = async (rawStream: Stream) => {
      try {
        await withInvitationProtocolStream(
          async () => rawStream,
          async (openedStream, signal, admitStateMutation) => {
            const stream: ProtocolStream = wrapStream(openedStream);
            const request = await readInvitationProtocolMessage(
              stream.source,
              decodeInvitationJoinRequest,
              MAX_INVITATION_JOIN_REQUEST_BYTES,
            );
            const acceptance = await this._processInvitationJoin(
              request,
              signal,
              admitStateMutation,
            );
            await stream.sink([
              encodeInvitationProtocolFrame(
                encodeInvitationAcceptance(acceptance),
                MAX_INVITATION_MESSAGE_BYTES,
              ),
            ] as Iterable<Uint8Array>);
          },
        );
      } catch {
        // Unknown, expired, malformed, unauthorized, replayed, failed, and
        // timed-out requests all receive the same connection-level decline.
      }
    };

    // Register shared protocol handlers. Each protocol ID uses a single
    // handler for all documents; the document path is extracted from the
    // stream payload for routing.
    const relayProtocolOptions = { runOnLimitedConnection: true };
    const registration = Promise.all([
      this.libp2p.handle(
        documentLoadV3,
        docLoadHandler(false),
        relayProtocolOptions,
      ),
      this.libp2p.handle(
        documentLoadV4,
        docLoadHandler(true),
        relayProtocolOptions,
      ),
      this.libp2p.handle(
        snapshotLoadV3,
        snapshotLoadHandler(false),
        relayProtocolOptions,
      ),
      this.libp2p.handle(
        snapshotLoadV4,
        snapshotLoadHandler(true),
        relayProtocolOptions,
      ),
      this.libp2p.handle(
        documentKeyUpdateV2,
        keyUpdateHandler,
        relayProtocolOptions,
      ),
      this.libp2p.handle(
        beekemWelcomeV1,
        beekemWelcomeV1Handler,
        relayProtocolOptions,
      ),
      this.libp2p.handle(
        beekemWelcomeV2,
        beekemWelcomeV2Handler,
        relayProtocolOptions,
      ),
      ...(this._allowInsecureLegacyBeeKEMPathUpdateV1
        ? [
            this.libp2p.handle(
              beekemPathUpdateV1,
              beekemPathUpdateV1Handler,
              relayProtocolOptions,
            ),
          ]
        : []),
      this.libp2p.handle(
        beekemPathUpdateV2,
        beekemPathUpdateV2Handler,
        relayProtocolOptions,
      ),
      this.libp2p.handle(
        tipAdvertiseV1,
        tipAdvertiseHandler(false),
        relayProtocolOptions,
      ),
      this.libp2p.handle(
        securityAdvertiseV1,
        tipAdvertiseHandler(true),
        relayProtocolOptions,
      ),
      this.libp2p.handle(
        invitationJoinV1,
        invitationJoinHandler,
        relayProtocolOptions,
      ),
    ]).then(() => undefined);
    this._sharedHandlersRegistration = registration;

    try {
      await registration;
    } catch (error) {
      if (this._sharedHandlersRegistration === registration) {
        this._sharedHandlersRegistration = undefined;
      }
      throw error;
    }
  }

  /**
   * Connects to a peerborne swarm.
   *
   * An address of any peer of the desired swarm will work. Providing multiple addresses will cause
   * each to be connected to in sequence.
   *
   * @param addresses Peers that should be connected to identified by their address.
   */
  public async connect(addresses: string[]) {
    // Connect to bootstrapping node(s).
    const connectionPromises: Promise<unknown>[] = [];
    for (const address of addresses) {
      // Multiaddr strings start with '/'; bare peer IDs need conversion.
      // multiaddr() validates the address format and fails fast on invalid input.
      // Cast required: @multiformats/multiaddr types are structurally incompatible
      // with the version bundled in @libp2p/interface due to sub-dependency version
      // mismatches in the dependency tree.
      const dialTarget = address.startsWith('/')
        ? (multiaddr(address) as any)
        : peerIdFromString(address);
      connectionPromises.push(this.heliaNode.libp2p.dial(dialTarget));
    }
    await Promise.all(connectionPromises);
  }

  /**
   * Create and register a signed, expiring invitation for an open document.
   * The returned offer is public and may be placed in a link fragment or QR
   * code; it contains no document key or private identity material.
   *
   * @internal Prefer `PeerborneDocument.createInvitation()`.
   */
  public async createInvitationForDocument(
    document: PeerborneDocument<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >,
    options: CreateInvitationOptions,
  ): Promise<InvitationOfferV1> {
    if (this._documentRegistry.get(document.documentPath) !== document) {
      throw new Error('Invitations can only be created for an open document');
    }
    if (!this.enableSigning) {
      throw new Error(
        'Initial-release invitations require application-level signing',
      );
    }
    assertInitialInvitationHistoryVisibility(document.historyVisibility);
    await document.assertCanCreateInitialInvitation();
    this._pruneExpiredInvitationState();
    if (this._invitationRegistry.size >= MAX_ACTIVE_INVITATION_OFFERS) {
      throw new Error(
        `Cannot create more than ${MAX_ACTIVE_INVITATION_OFFERS} active invitations`,
      );
    }
    if (!document.getKemPublicKeyRaw()) {
      throw new Error(
        'Invitation creation requires a founder KEM key pair installed via setKemKeyPair',
      );
    }
    if (!Array.isArray(options.rendezvous) || options.rendezvous.length === 0) {
      throw new Error('Invitation creation requires at least one rendezvous address');
    }
    const expiresInMs = options.expiresInMs ?? DEFAULT_INVITATION_TTL_MS;
    assertInvitationOfferLifetime(expiresInMs);
    if (options.role !== 'reader' && options.role !== 'editor') {
      throw new Error('Invitation role must be "reader" or "editor"');
    }

    const signatureProvider = this._invitationSignatureProvider();
    const serializePublicKey = signatureProvider.serializePublicKey;
    const now = Date.now();
    const unsigned: UnsignedInvitationOfferV1 = {
      version: 1,
      invitationId: crypto.getRandomValues(
        new Uint8Array(INVITATION_ID_LENGTH),
      ),
      documentId: document.documentPath,
      issuer: await serializePublicKey(this._userPublicKey),
      role: options.role,
      issuedAtMs: now,
      expiresAtMs: now + expiresInMs,
      rendezvous: Array.from(options.rendezvous),
    };
    const offer = await signInvitationOffer(
      unsigned,
      this._userKey,
      this._userPublicKey,
      signatureProvider,
    );
    const encodedOffer = encodeInvitationOffer(offer);
    const registeredOffer = decodeInvitationOffer(encodedOffer);
    const offerKey = bytesToHex(await digestInvitationOffer(registeredOffer));
    this._pruneExpiredInvitationState();
    if (this._documentRegistry.get(document.documentPath) !== document) {
      throw new Error('Invitation document closed before offer registration');
    }
    if (this._invitationRegistry.size >= MAX_ACTIVE_INVITATION_OFFERS) {
      throw new Error(
        `Cannot create more than ${MAX_ACTIVE_INVITATION_OFFERS} active invitations`,
      );
    }
    this._invitationRegistry.set(offerKey, {
      offer: registeredOffer,
      document,
      replayGuard: new InMemoryInvitationReplayGuard(),
      acceptanceCoordinator:
        new InMemoryInvitationAcceptanceCoordinator(),
    });
    return decodeInvitationOffer(encodedOffer);
  }

  /**
   * Join an existing document from a signed public invitation. This path never
   * falls back to document creation: any verification, transport, bootstrap,
   * or ACL failure rejects and leaves the returned document unavailable.
   * Each of at most eight signed rendezvous attempts and the final founder
   * catch-up stream has a 30-second deadline with stream teardown. The initial
   * release does not expose caller-driven cancellation, so attempts are tried
   * sequentially until one succeeds or all reject. Application-level signing
   * must be enabled on both founder and recipient.
   */
  public async acceptInvitation(
    encodedOrDecodedOffer: Uint8Array | InvitationOfferV1,
    kemKeyPair: CryptoKeyPair,
  ): Promise<
    PeerborneDocument<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >
  > {
    if (this._initializationInFlight) {
      throw new Error(
        'Cannot accept an invitation while initialization is active',
      );
    }
    if (!this.enableSigning) {
      throw new Error(
        'Initial-release invitations require application-level signing',
      );
    }
    const frozenKemKeyPair = snapshotKemKeyPair(kemKeyPair);
    const offer = decodeInvitationOffer(
      encodedOrDecodedOffer instanceof Uint8Array
        ? encodedOrDecodedOffer
        : encodeInvitationOffer(encodedOrDecodedOffer),
    );
    const documentId = offer.documentId;
    assertInvitationOfferUsable(offer);
    if (
      this._documentRegistry.has(documentId) ||
      this._pendingInvitationDocuments.has(documentId)
    ) {
      throw new Error(
        `Cannot accept an invitation for active document "${documentId}"`,
      );
    }

    // Reserve synchronously before the first await. This makes request
    // creation single-flight for a document and prevents a competing open()
    // from taking the path between preflight and bootstrap activation.
    const document = this.doc(documentId);
    this._pendingInvitationDocuments.set(documentId, document);
    try {
      return await this._acceptInvitationOffer(
        offer,
        frozenKemKeyPair,
        document,
      );
    } finally {
      if (
        this._pendingInvitationDocuments.get(documentId) === document
      ) {
        this._pendingInvitationDocuments.delete(documentId);
      }
    }
  }

  private async _acceptInvitationOffer(
    offer: InvitationOfferV1,
    kemKeyPair: CryptoKeyPair,
    document: PeerborneDocument<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >,
  ): Promise<
    PeerborneDocument<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >
  > {
    const deserializePublicKey = requireDeserializePublicKey(
      this._authProvider,
      'Public invitations',
    );
    const signatureProvider = this._invitationSignatureProvider();
    const issuerPublicKey = await deserializePublicKey(offer.issuer);
    if (
      !(await verifyInvitationOffer(
        offer,
        issuerPublicKey,
        signatureProvider,
      ))
    ) {
      throw new Error('Invitation offer signature is invalid');
    }
    if (offer.rendezvous.length === 0) {
      throw new Error('Invitation offer has no rendezvous address');
    }

    // Validate and snapshot the recipient KEM binding before any network I/O.
    await document.setKemKeyPair(kemKeyPair);
    const recipientKemPublicKey = document.getKemPublicKeyRaw();
    if (!recipientKemPublicKey) {
      throw new Error('Invitation recipient KEM public key is unavailable');
    }
    const serializePublicKey = signatureProvider.serializePublicKey;
    const offerDigest = await digestInvitationOffer(offer);
    const offerKey = bytesToHex(offerDigest);
    const recipient = await serializePublicKey(this._userPublicKey);
    if (recipient === offer.issuer) {
      throw new Error('Invitation recipient must use a distinct identity');
    }
    this._pruneExpiredInvitationState();
    const cachedRequest = this._outboundInvitationRequests.get(offerKey);
    let request: InvitationJoinRequestV1;
    if (cachedRequest) {
      if (
        cachedRequest.request.documentId !== offer.documentId ||
        cachedRequest.request.role !== offer.role ||
        cachedRequest.request.recipient !== recipient ||
        bytesToHex(cachedRequest.request.recipientKemPublicKey) !==
          bytesToHex(recipientKemPublicKey)
      ) {
        throw new Error(
          'Invitation retry must use the same recipient identity and KEM key pair',
        );
      }
      request = cachedRequest.request;
    } else {
      if (
        this._outboundInvitationRequests.size >=
        MAX_ACTIVE_INVITATION_OFFERS
      ) {
        throw new Error(
          `Cannot track more than ${MAX_ACTIVE_INVITATION_OFFERS} invitation retries`,
        );
      }
      const unsignedRequest: UnsignedInvitationJoinRequestV1 = {
        version: 1,
        offerDigest,
        requestId: crypto.getRandomValues(
          new Uint8Array(INVITATION_ID_LENGTH),
        ),
        documentId: offer.documentId,
        role: offer.role,
        recipient,
        recipientKemPublicKey,
      };
      request = await signInvitationJoinRequest(
        unsignedRequest,
        this._userKey,
        this._userPublicKey,
        signatureProvider,
      );
      this._pruneExpiredInvitationState();
      if (
        this._outboundInvitationRequests.size >=
        MAX_ACTIVE_INVITATION_OFFERS
      ) {
        throw new Error(
          `Cannot track more than ${MAX_ACTIVE_INVITATION_OFFERS} invitation retries`,
        );
      }
      this._outboundInvitationRequests.set(offerKey, {
        request,
        expiresAtMs: offer.expiresAtMs,
      });
    }
    const encodedRequest = encodeInvitationProtocolFrame(
      encodeInvitationJoinRequest(request),
      MAX_INVITATION_JOIN_REQUEST_BYTES,
    );

    const { address: acceptedRendezvous, value: accepted } =
      await firstSuccessfulInvitationRendezvous(
        offer.rendezvous,
        (address) =>
          withInvitationProtocolStream(
            (signal) =>
              this.libp2p.dialProtocol(
                multiaddr(address) as any,
                [invitationJoinV1],
                {
                  runOnLimitedConnection: true,
                  signal,
                },
              ),
            async (rawStream) => {
              const stream = wrapStream(rawStream);
              await pipe([encodedRequest], stream.sink);
              const acceptance = await readInvitationProtocolMessage(
                stream.source,
                decodeInvitationAcceptance,
                MAX_INVITATION_MESSAGE_BYTES,
              );
              assertInvitationAcceptanceUsable(acceptance);
              await assertInvitationAcceptanceMatches(
                acceptance,
                offer,
                request,
              );
              if (
                !(await verifyInvitationAcceptance(
                  acceptance,
                  issuerPublicKey,
                  signatureProvider,
                ))
              ) {
                throw new Error(
                  'invitation acceptance signature is invalid',
                );
              }
              await this._recipientInvitationReplayGuard.observeAcceptance(
                offer,
                request,
                acceptance,
              );
              return acceptance;
            },
          ),
      );
    await document.acceptInvitationBootstrap(
      {
        welcomeEpochId: accepted.welcomeEpochId,
        sealedWelcome: accepted.sealedWelcome,
        encryptedBootstrap: accepted.encryptedBootstrap,
      },
      issuerPublicKey,
      offer.role,
      acceptedRendezvous,
    );
    return document;
  }

  /**
   * Opens a peerborne document instance.
   *
   * @param documentPath Path identifying the document to open.
   * @returns The requested peerborne document.
   */
  doc(
    documentPath: string,
  ): PeerborneDocument<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  > {
    // Return new document reference.
    return new PeerborneDocument(
      this,
      documentPath,
      this._userKey,
      this._userPublicKey,
      this._crdtProvider,
      this._authProvider,
      this._aclProvider,
      this._keychainProvider,
      this._changesSerializer,
      this._syncMessageSerializer,
      this._loadMessageSerializer,
    );
  }

  /**
   * Adds a handler that is run every time that a peer connects.
   *
   * @param handlerId An identifier used to unsubscribe the provided handler later.
   * @param handler A function that is run every time a peer connects.
   */
  subscribeToPeerConnect(handlerId: string, handler: PeerbornePeersHandler) {
    this._peerConnectHandlers.set(handlerId, handler);
  }

  /**
   * Removes a peer-connect handler.
   *
   * @param handlerId The identifier of the handler to remove.
   */
  unsubscribeFromPeerConnect(handlerId: string) {
    this._peerConnectHandlers.delete(handlerId);
  }

  /**
   * Adds a handler that is run every time that a peer disconnects.
   *
   * @param handlerId An identifier used to unsubscribe the provided handler later.
   * @param handler A function that is run every time a peer disconnects.
   */
  subscribeToPeerDisconnect(handlerId: string, handler: PeerbornePeersHandler) {
    this._peerDisconnectHandlers.set(handlerId, handler);
  }

  /**
   * Removes a peer-disconnect handler.
   *
   * @param handlerId The identifier of the handler to remove.
   */
  unsubscribeFromPeerDisconnect(handlerId: string) {
    this._peerDisconnectHandlers.delete(handlerId);
  }
}
