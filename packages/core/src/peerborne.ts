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
import { AuthProvider } from './auth-provider.js';
import { CRDTProvider } from './crdt-provider.js';
import {
  PeerborneConfig,
  defaultConfig,
  defaultBootstrapConfig,
} from './peerborne-config.js';
import { PeerborneDocument } from './peerborne-document.js';
import { NetworkStats } from './network-stats.js';
import { SyncMessageSerializer } from './sync-message-serializer.js';
import { ChangesSerializer } from './changes-serializer.js';
import { ACLProvider } from './acl-provider.js';
import { KeychainProvider } from './keychain-provider.js';
import { LoadMessageSerializer } from './load-request-serializer.js';
import { validateLoadQuorumConfig } from './load-quorum.js';
import {
  beekemPathUpdateV1,
  beekemWelcomeV1,
  documentLoadV3,
  documentKeyUpdateV2,
  snapshotLoadV3,
  tipAdvertiseV1,
} from './wire-protocols.js';
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

/** Maximum allowed document path length in key-update V2 wire format. */
export const MAX_DOCUMENT_PATH_LENGTH = 4096;

/** Maximum allowed request size for shared protocol handlers (10 MB). */
const MAX_REQUEST_SIZE = 10 * 1024 * 1024;

/** Minimal stream shape used by shared protocol handlers. */
interface ProtocolStream {
  source: AsyncIterable<Uint8ArrayList | Uint8Array>;
  sink: (data: Iterable<Uint8Array>) => Promise<void>;
  close: () => Promise<void>;
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
    private readonly _syncMessageSerializer: SyncMessageSerializer<ChangesType, PublicKey>,
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

  // configs for the swarm, thus passing its config to all documents opened in a swarm
  protected _config: PeerborneConfig | null = null;
  private _heliaNode: PeerborneHeliaNode | undefined;
  private _peerId: PeerId | undefined;
  private _peerIds: string[] = [];
  private _peerConnectHandlers: Map<string, PeerbornePeersHandler> = new Map<
    string,
    PeerbornePeersHandler
  >();
  private _peerDisconnectHandlers: Map<string, PeerbornePeersHandler> =
    new Map<string, PeerbornePeersHandler>();
  private _networkStats?: NetworkStats;

  private _sharedHandlersRegistration: Promise<void> | undefined;
  private _openedLegacyStores: OpenableStore[] = [];

  // Registry of open documents keyed by document path. Shared protocol
  // handlers use this to route incoming stream requests to the correct
  // PeerborneDocument instance.
  private _documentRegistry = new Map<
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
  public get heliaNode(): HeliaWithLibp2p<
    ServiceMap & { pubsub: GossipSub }
  > {
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
   * Gets the current peerborne configuration.
   */
  public get config(): PeerborneConfig | null {
    return this._config;
  }

  /**
   * Sets up the peerborne node and starts its underlying Helia/libp2p node.
   *
   * @param config General settings for peerborne.
   */
  public async initialize(config?: PeerborneConfig) {
    if (this._documentRegistry.size > 0) {
      throw new Error(
        'Cannot reinitialize while documents are open. ' +
        'Close all documents before calling initialize() again.',
      );
    }

    // Tear down the previous Helia/libp2p instance if reinitializing,
    // preventing leaked background resources (connections, timers, etc.).
    if (this._heliaNode) {
      try { await this._heliaNode.stop(); } catch { /* best-effort */ }
      await closeLegacyHeliaStores(this._openedLegacyStores);
      this._openedLegacyStores = [];
      this._heliaNode = undefined;
      this._peerId = undefined;
      this._peerIds = [];
    }

    if (!config) {
      config = defaultConfig(defaultBootstrapConfig([]));
    }

    // Validate the load-quorum tuning knobs at startup so an operator
    // misconfiguration (e.g. `loadQuorumK: 1.5`, `loadQuorumQ: NaN`)
    // surfaces immediately as a structured `LoadQuorumFailedError(
    // invalid-config)` rather than silently degrading every subsequent
    // `load()` to a single-peer probe. See PR #284 r9 Copilot review for
    // the input-validation hardening rationale (issues #2/#3): fractional
    // K let `peers.slice(0, 1.5)` slip through to a 1-peer probe, and
    // NaN Q propagated through `effectiveQ` so `bestPeers.length < NaN`
    // evaluated as false and the gate passed with a single responder.
    //
    // Skip validation when the feature is explicitly disabled -- a
    // shared config object that carries leftover quorum knobs alongside
    // `loadQuorumEnabled: false` should still initialize cleanly via
    // the legacy load path. `runLoadQuorum` mirrors this early-exit
    // ordering: `enabled === false` is checked before validation, so
    // the two boundaries stay consistent.
    if (config.loadQuorumEnabled !== false) {
      validateLoadQuorumConfig(config);
    }

    this._config = config;

    this._sharedHandlersRegistration = undefined;

    this._networkStats = config.enableNetworkStats ? new NetworkStats() : undefined;

    // Setup Helia node.
    const { heliaNode, openedLegacyStores } =
      await createAndStartHeliaNode(config.helia);
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
    document: PeerborneDocument<DocType, ChangesType, ChangeFnType, PrivateKey, PublicKey, DocumentKey>,
  ): void {
    if (this._documentRegistry.has(documentPath)) {
      throw new Error(
        `A document is already registered for "${documentPath}". ` +
        'Multiple instances per path are not supported. Close the existing document first.',
      );
    }
    this._documentRegistry.set(documentPath, document);
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
    document: PeerborneDocument<DocType, ChangesType, ChangeFnType, PrivateKey, PublicKey, DocumentKey>,
  ): void {
    if (this._documentRegistry.get(documentPath) === document) {
      this._documentRegistry.delete(documentPath);
    }
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
    const docLoadHandler = (rawStream: Stream) => {
      const stream: ProtocolStream = wrapStream(rawStream);
      return pipe(
        stream.source,
        async (source: AsyncIterable<Uint8ArrayList | Uint8Array>) => {
          let request;
          try {
            request = await readFirstDeserializable(
              source,
              (data) => this._loadMessageSerializer.deserializeLoadRequest(data),
              MAX_REQUEST_SIZE,
            );
          } catch (err) {
            const reason = err instanceof RangeError ? 'request too large' : 'failed to read request';
            console.warn(`Shared doc-load handler: ${reason}, dropping`);
            await stream.sink([] as Iterable<Uint8Array>);
            return [];
          }
          const doc = this._documentRegistry.get(request.documentId);
          if (!doc) {
            console.warn(
              `Shared doc-load handler: no document registered for "${request.documentId}"`,
            );
            await stream.sink([] as Iterable<Uint8Array>);
            return [];
          }
          await doc.handleLoadRequestData(request, stream);
          return [];
        },
      ).then(() => undefined).catch((err: unknown) => {
        console.error('Error in shared doc-load handler:', err);
      });
    };

    // Handler implementation for snapshot-load requests.
    // See note on `docLoadHandler` above re: the v3 StreamHandler signature.
    const snapshotLoadHandler = (rawStream: Stream) => {
      const stream: ProtocolStream = wrapStream(rawStream);
      return pipe(
        stream.source,
        async (source: AsyncIterable<Uint8ArrayList | Uint8Array>) => {
          let request;
          try {
            request = await readFirstDeserializable(
              source,
              (data) => this._loadMessageSerializer.deserializeLoadRequest(data),
              MAX_REQUEST_SIZE,
            );
          } catch (err) {
            const reason = err instanceof RangeError ? 'request too large' : 'failed to read request';
            console.warn(`Shared snapshot-load handler: ${reason}, dropping`);
            await stream.sink([] as Iterable<Uint8Array>);
            return [];
          }
          const doc = this._documentRegistry.get(request.documentId);
          if (!doc) {
            console.warn(
              `Shared snapshot-load handler: no document registered for "${request.documentId}"`,
            );
            await stream.sink([] as Iterable<Uint8Array>);
            return [];
          }
          await doc.handleSnapshotLoadRequestData(request, stream);
          return [];
        },
      ).then(() => undefined).catch((err: unknown) => {
        console.error('Error in shared snapshot-load handler:', err);
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
        stream.source,
        async (source: AsyncIterable<Uint8ArrayList | Uint8Array>) => {
          try {
            const header = await readPathPrefixedProtocolHeader(
              source,
              this._documentRegistry,
              'key-update',
              MAX_REQUEST_SIZE,
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
      ).then(() => undefined).catch((err: unknown) => {
        console.error('Error in shared key-update handler:', err);
      });
    };

    // Handler for BeeKEM Welcome v1. Wire format mirrors key-update v2:
    // 4-byte big-endian path length, then UTF-8 path, then the serialized
    // welcome sync-message body. After routing by path, the per-document
    // handler verifies the writer signature, merges the keychain delta,
    // and records the invitation epoch.
    // See note on `docLoadHandler` above re: the v3 StreamHandler signature.
    //
    // Header parse shared with the key-update handler above via
    // `readPathPrefixedProtocolHeader`.
    const beekemWelcomeHandler = (rawStream: Stream) => {
      const stream: ProtocolStream = wrapStream(rawStream);
      return pipe(
        stream.source,
        async (source: AsyncIterable<Uint8ArrayList | Uint8Array>) => {
          try {
            const header = await readPathPrefixedProtocolHeader(
              source,
              this._documentRegistry,
              'beekem-welcome',
              MAX_REQUEST_SIZE,
              MAX_DOCUMENT_PATH_LENGTH,
            );
            if (header.kind !== 'ok') {
              return [];
            }
            await header.doc.handleBeeKEMWelcomeRequestData(header.payload);
            return [];
          } finally {
            // Welcome is fire-and-forget (no response over stream.sink),
            // but the inbound stream still needs to be closed to release
            // resources.
            await stream.close();
          }
        },
      ).then(() => undefined).catch((err: unknown) => {
        console.error('Error in shared beekem-welcome handler:', err);
      });
    };

    // Handler for BeeKEM PathUpdate v1 (reader-revocation rotations).
    // Wire format mirrors key-update v2 / BeeKEM Welcome v1: 4-byte
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
    const beekemPathUpdateHandler = (rawStream: Stream) => {
      const stream: ProtocolStream = wrapStream(rawStream);
      return pipe(
        stream.source,
        async (source: AsyncIterable<Uint8ArrayList | Uint8Array>) => {
          try {
            const header = await readPathPrefixedProtocolHeader(
              source,
              this._documentRegistry,
              'beekem-pathupdate',
              MAX_REQUEST_SIZE,
              MAX_DOCUMENT_PATH_LENGTH,
            );
            if (header.kind !== 'ok') {
              return [];
            }
            await header.doc.handleBeeKEMPathUpdateRequestData(header.payload);
            return [];
          } finally {
            // PathUpdate is fire-and-forget (no response over
            // stream.sink), but the inbound stream still needs to be
            // closed to release resources.
            await stream.close();
          }
        },
      ).then(() => undefined).catch((err: unknown) => {
        console.error('Error in shared beekem-pathupdate handler:', err);
      });
    };

    // Handler implementation for tip-advertise requests (initial-load
    // quorum probe; see `wire-protocols.ts::tipAdvertiseV1`). Wire format
    // mirrors documentLoadV3: a single serialized CRDTLoadRequest in,
    // a single (small) encrypted/serialized CRDTSyncMessage out (whose
    // only populated payload field is `tipsHash`), or an empty response
    // on decline.
    // See note on `docLoadHandler` above re: the v3 StreamHandler signature.
    const tipAdvertiseHandler = (rawStream: Stream) => {
      const stream: ProtocolStream = wrapStream(rawStream);
      return pipe(
        stream.source,
        async (source: AsyncIterable<Uint8ArrayList | Uint8Array>) => {
          try {
            let request;
            try {
              request = await readFirstDeserializable(
                source,
                (data) => this._loadMessageSerializer.deserializeLoadRequest(data),
                MAX_REQUEST_SIZE,
              );
            } catch (err) {
              const reason = err instanceof RangeError ? 'request too large' : 'failed to read request';
              console.warn(`Shared tip-advertise handler: ${reason}, dropping`);
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
              // (the honest hash X wins the tally). Worst case is the same
              // Q-Byzantine threshold the rest of the quorum gate already
              // tolerates. See `decideLoadQuorum` for the tally semantics
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
              await stream.sink([
                new Uint8Array([0xff]),
              ] as Iterable<Uint8Array>);
              return [];
            }
            await doc.handleTipAdvertiseRequestData(request, stream);
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
      ).then(() => undefined).catch((err: unknown) => {
        console.error('Error in shared tip-advertise handler:', err);
      });
    };

    // Register shared protocol handlers. Each protocol ID uses a single
    // handler for all documents; the document path is extracted from the
    // stream payload for routing.
    const relayProtocolOptions = { runOnLimitedConnection: true };
    const registration = Promise.all([
      this.libp2p.handle(documentLoadV3, docLoadHandler, relayProtocolOptions),
      this.libp2p.handle(snapshotLoadV3, snapshotLoadHandler, relayProtocolOptions),
      this.libp2p.handle(documentKeyUpdateV2, keyUpdateHandler, relayProtocolOptions),
      this.libp2p.handle(beekemWelcomeV1, beekemWelcomeHandler, relayProtocolOptions),
      this.libp2p.handle(beekemPathUpdateV1, beekemPathUpdateHandler, relayProtocolOptions),
      this.libp2p.handle(tipAdvertiseV1, tipAdvertiseHandler, relayProtocolOptions),
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
        ? multiaddr(address) as any
        : peerIdFromString(address);
      connectionPromises.push(
        this.heliaNode.libp2p.dial(dialTarget),
      );
    }
    await Promise.all(connectionPromises);
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
  subscribeToPeerDisconnect(
    handlerId: string,
    handler: PeerbornePeersHandler,
  ) {
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
