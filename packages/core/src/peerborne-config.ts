import type { HeliaInit } from 'helia';
import type { BitswapOptions } from '@helia/bitswap';
import type { CreateLibp2pOptions } from '@helia/libp2p';
import type { ServiceMap } from '@libp2p/interface';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { bootstrap, BootstrapInit } from '@libp2p/bootstrap';
import { pubsubPeerDiscovery } from '@libp2p/pubsub-peer-discovery';
import { circuitRelayTransport } from '@libp2p/circuit-relay-v2';
import { webRTC, webRTCDirect } from '@libp2p/webrtc';
import { webTransport } from '@libp2p/webtransport';
import { webSockets } from '@libp2p/websockets';
// Note: `@libp2p/websockets` v3 removed the `/filters` subpath and the
// `filter` option from `WebSocketsInit`. WebSocket dial filtering is now
// internal to the transport.
import { identify } from '@libp2p/identify';
import { dcutr } from '@libp2p/dcutr';
import { autoNAT } from '@libp2p/autonat';
import { gossipsub } from '@libp2p/gossipsub';
import { kadDHT } from '@libp2p/kad-dht';
import { ping } from '@libp2p/ping';
import { ipnsSelector } from 'ipns/selector';
import { ipnsValidator } from 'ipns/validator';
import { IDBDatastore } from 'datastore-idb';
import { IDBBlockstore } from 'blockstore-idb';
import { CompactionConfig } from './compaction-config.js';
import { DEFAULT_DOCUMENT_TOPIC_PREFIX } from './document-topic.js';
import { hasBootstrapPeers } from './bootstrap-config.js';
import type { LoadSecurityCommitments } from './load-security-state.js';

/**
 * Project-local ICE-server interface used in place of the DOM lib's
 * `RTCIceServer` so consumers don't need `lib: ["DOM"]` in their tsconfig
 * (especially Node-only consumers of `peerborne-node.ts`). The shape
 * mirrors the subset of WebIDL `RTCIceServer` peerborne actually reads
 * and forwards into libp2p's webRTC transport configuration.
 *
 * Structurally compatible with `RTCIceServer` in browser environments, so
 * values typed as `IceServer` can be cast to `RTCIceServer[]` at the
 * libp2p call site without runtime conversion.
 */
export interface IceServer {
  /** A single STUN/TURN URL or a list of URLs for this server entry. */
  urls: string | string[];
  /** Username for TURN authentication. Optional. */
  username?: string;
  /** Credential (typically a shared secret / password) for TURN
   *  authentication. Optional. */
  credential?: string;
}

/**
 * Default list of free public STUN servers used to populate the WebRTC
 * `iceServers` configuration when none is provided by the consumer.
 *
 * STUN lets peers discover their public IP/port mapping so they can attempt
 * direct browser-to-browser WebRTC connections without depending on a
 * Circuit Relay for data forwarding (issue #236, layered NAT-traversal phase 3).
 *
 * The list is intentionally kept small (3-4 servers across multiple operators)
 * so we get redundancy without flooding ICE gathering with redundant probes.
 *
 * **Privacy note:** Using these defaults discloses each peer's public
 * IP/port mapping (and approximate location/ISP) to the listed third-party
 * STUN operators. Privacy-sensitive deployments should pass `[]` to disable
 * STUN entirely, or supply their own self-hosted STUN/TURN endpoints via
 * the `webrtcIceServers` parameter.
 *
 * Sources:
 * - Google: `stun.l.google.com:19302` -- the de-facto reference public STUN
 *   server, widely used in WebRTC examples and production apps.
 * - Cloudflare: `stun.cloudflare.com:3478` -- operated by Cloudflare's
 *   public WebRTC infra; geographically diverse from Google's anycast.
 * - Twilio (Mozilla-style fallback): `global.stun.twilio.com:3478` --
 *   commonly recommended free public STUN endpoint.
 */
export const DEFAULT_WEBRTC_ICE_SERVERS: ReadonlyArray<Readonly<IceServer>> =
  Object.freeze([
    Object.freeze({ urls: 'stun:stun.l.google.com:19302' }),
    Object.freeze({ urls: 'stun:stun1.l.google.com:19302' }),
    Object.freeze({ urls: 'stun:stun.cloudflare.com:3478' }),
    Object.freeze({ urls: 'stun:global.stun.twilio.com:3478' }),
  ]);

/**
 * Returns a deep-enough copy of an {@link IceServer} so callers can hand the
 * result to libp2p (which expects a mutable `RTCIceServer`) without sharing
 * any inner references with the source object.
 *
 * In particular:
 * - the top-level object is a fresh `{ ...server }` so mutating fields like
 *   `username`/`credential` on the copy cannot affect the source;
 * - if `urls` is an array, it is copied to a fresh array so `push()`/`splice()`
 *   on the copy cannot affect the source's URL list (a single `string` value
 *   is immutable, so it is forwarded as-is).
 *
 * `credential` is a `string` in the project-local {@link IceServer} shape
 * (and strings are immutable), so no nested copy is needed there.
 *
 * Exported so {@link defaultNodeConfig} (and any future config helpers) can
 * share the same defensive-copy behavior.
 */
export const cloneIceServer = (server: Readonly<IceServer>): IceServer => {
  const clone: IceServer = { ...server };
  if (Array.isArray(server.urls)) {
    clone.urls = [...server.urls];
  }
  return clone;
};

/**
 * Freezes an {@link IceServer} and any nested mutable structures it owns so
 * the returned value is safe to expose to consumers as deeply-immutable.
 *
 * `Object.freeze` is shallow, so without also freezing the nested `urls`
 * array (when present) a caller could still mutate it through the exposed
 * reference. This helper closes that gap. `urls` as a plain `string` and
 * the `string` `credential`/`username` fields are already immutable and
 * need no extra handling.
 *
 * Mutates the input in place (then returns it) -- callers should pair it
 * with {@link cloneIceServer} when they need to freeze a copy without
 * affecting the source.
 *
 * Exported so {@link defaultNodeConfig} (and any future config helpers) can
 * share the same deep-freeze behavior.
 */
export const freezeIceServer = (server: IceServer): Readonly<IceServer> => {
  if (Array.isArray(server.urls)) {
    Object.freeze(server.urls);
  }
  return Object.freeze(server);
};

/**
 * Internal helper: resolve the source ICE-server list (override or frozen
 * defaults) and produce a deeply-frozen, defensively-cloned `exposed` view
 * suitable for assigning to `config.webrtcIceServers`.
 *
 * Returning both halves lets the caller hand out fresh per-transport copies
 * of `sourceIceServers` (via `cloneIceServer`) without re-deriving the
 * source, while sharing the deep-freeze/clone setup between the browser
 * (`defaultConfig`) and Node (`defaultNodeConfig`) defaults so they cannot
 * drift over time.
 *
 * Not exported from the package barrel: this is an implementation detail of
 * the default config builders.
 */
export function resolveIceServers(override?: ReadonlyArray<Readonly<IceServer>>): {
  sourceIceServers: ReadonlyArray<Readonly<IceServer>>;
  exposedIceServers: ReadonlyArray<Readonly<IceServer>>;
} {
  const sourceIceServers = override ?? DEFAULT_WEBRTC_ICE_SERVERS;
  const exposedIceServers: ReadonlyArray<Readonly<IceServer>> = Object.freeze(
    sourceIceServers.map((server) => freezeIceServer(cloneIceServer(server))),
  );
  return { sourceIceServers, exposedIceServers };
}

/**
 * Default peerborne config to use if none is provided.
 *
 * Note: This is a browser-compatible default. It does not include mDNS
 *       (which requires the Node-only `dgram` module). Without bootstrap
 *       nodes this node will be in a swarm of one; use
 *       `peerborne.connect()` or pass bootstrap addresses to join peers.
 *
 * @param bootstrapConfig Bootstrap peer list to seed peer discovery.
 * @param webrtcIceServers Optional override for the WebRTC ICE server list.
 *   When undefined, {@link DEFAULT_WEBRTC_ICE_SERVERS} is used so peers can
 *   discover their public address mappings via STUN without relying on relay
 *   infrastructure for data plane forwarding.
 */
export const defaultConfig = (
  bootstrapConfig: BootstrapInit,
  webrtcIceServers?: ReadonlyArray<Readonly<IceServer>>,
) => {
  // Resolve the source list and a deeply-frozen exposed view in one place so
  // the browser and Node defaults stay in sync. Each transport below still
  // gets its own fresh `cloneIceServer`-deep-cloned copy of `sourceIceServers`
  // so mutations never leak between transport state and `config.webrtcIceServers`.
  const { sourceIceServers, exposedIceServers } = resolveIceServers(webrtcIceServers);
  return ({
    // Helia configuration (ref: https://gist.github.com/bellbind/23ad8d6e3a1509335253ff074fcd3cb6)
    helia: {
      blockstore: new IDBBlockstore('/collabswarm-blocks'),
      datastore: new IDBDatastore('/collabswarm-data'),
      libp2p: {
        // https://github.com/ipfs/helia/blob/main/packages/libp2p/src/utils/libp2p-defaults.browser.ts
        addresses: {
          listen: ['/p2p-circuit', '/webrtc', '/wss', '/ws'],
        },
        transports: [
          circuitRelayTransport({
            reservationConcurrency: 1,
          }),
          webSockets(),
          // Pass STUN servers so RTCPeerConnection can gather server-reflexive
          // candidates and attempt direct connections without relay forwarding.
          // Each transport gets its own fresh mutable copy (with each server
          // object also deep-enough-cloned via `cloneIceServer`) to avoid
          // aliasing with the array exposed on `config.webrtcIceServers` below.
          // Cast to `RTCIceServer[]` only at the libp2p call site so the
          // public peerborne API stays free of DOM lib types.
          webRTC({ rtcConfiguration: { iceServers: sourceIceServers.map(cloneIceServer) as RTCIceServer[] } }),
          webRTCDirect({ rtcConfiguration: { iceServers: sourceIceServers.map(cloneIceServer) as RTCIceServer[] } }),
          webTransport(),
        ],
        connectionEncrypters: [noise()],
        streamMuxers: [yamux()],
        // @libp2p/bootstrap rejects an empty list during construction. A
        // brand-new/offline swarm is valid, so omit that discovery service
        // until at least one bootstrap address is configured.
        peerDiscovery: [
          ...(hasBootstrapPeers(bootstrapConfig) ? [bootstrap(bootstrapConfig)] : []),
          pubsubPeerDiscovery(),
        ],
        services: {
          identify: identify(),
          dcutr: dcutr(),
          autoNAT: autoNAT(),
          // Required capability for the Kademlia DHT service in libp2p v3.
          ping: ping(),
          pubsub: gossipsub({
            allowPublishToZeroTopicPeers: true,
            emitSelf: false,
            canRelayMessage: true,
            globalSignaturePolicy: 'StrictSign',
          }),
          dht: kadDHT({
            clientMode: true,
            validators: { ipns: ipnsValidator },
            selectors: { ipns: ipnsSelector },
          }),
        },
        // https://github.com/libp2p/js-libp2p/blob/master/doc/CONFIGURATION.md#configuring-connection-gater
        connectionGater: { denyDialMultiaddr: async () => false },
      },
    },

    pubsubDocumentPrefix: DEFAULT_DOCUMENT_TOPIC_PREFIX,
    pubsubDocumentPublishPath: '/documents',
    webrtcIceServers: exposedIceServers,
  // Cast required: libp2p sub-dependency types have version mismatches that prevent structural compatibility
  } as unknown as PeerborneConfig);
};

/**
 * PeerborneConfig is a settings object for peerborne.
 */
export interface PeerborneConfig {
  /**
   * Configuration for Helia/libp2p.
   *
   * Helia 7 accepts libp2p creation options here, not an already-created
   * libp2p node.
   */
  helia?: HeliaInit & {
    libp2p?: CreateLibp2pOptions<ServiceMap>;
    bitswap?: BitswapOptions;
  };

  /**
   * Prefix to apply to document pubsub topics.
   *
   * Defaults to {@link DEFAULT_DOCUMENT_TOPIC_PREFIX} to namespace document
   * traffic on the pubsub mesh and avoid collisions with other topic types.
   *
   * Set to an empty string (`''`) to disable prefixing; topic strings
   * will be the bare document path.
   *
   * @default DEFAULT_DOCUMENT_TOPIC_PREFIX
   */
  pubsubDocumentPrefix: string;

  /**
   * Prefix to apply to Libp2p PubSub topics for documents.
   */
  pubsubDocumentPublishPath: string;

  /**
   * Enable GossipSub topic validators for authorization enforcement.
   * When enabled, messages from unauthorized peers are rejected at the
   * transport layer (P4 penalty in peer scoring).
   *
   * Topic validators are registered during `open()` and properly removed
   * during `close()` to prevent stale validator references.
   * A requested `true` is normalized to `false` when `enableSigning` is false,
   * because an unsigned document has no writer signature for them to enforce.
   * The value is captured by `Peerborne.initialize()`; mutate the policy by
   * reinitializing rather than changing the caller-owned config object.
   *
   * Default: false (for backward compatibility).
   */
  enableTopicValidators?: boolean;

  /**
   * Enable Peerborne application-level signing and verification for ordinary
   * CRDT sync, document/snapshot load, and document-key update messages.
   * When false, signatures and signature checks are bypassed on those message
   * paths. Topic validators are not registered at all when signing is disabled
   * to avoid unnecessary per-message overhead.
   *
   * This flag does not disable writer authentication for BeeKEM Welcome or
   * PathUpdate messages: those group-security transitions always require a
   * valid writer signature. The invitation APIs also reject while ordinary
   * application-level signing is disabled.
   * Note: libp2p/GossipSub transport-level signing (e.g., `globalSignaturePolicy`)
   * is NOT affected by this flag.
   *
   * **WARNING: Disabling signing removes authentication and authorization
   * checks from the ordinary sync, load, snapshot, and document-key update
   * paths. Any peer that can decrypt that traffic (e.g., possesses a previous
   * document key) can forge those messages. Peers with `enableSigning: false`
   * will NOT interoperate on those paths with peers that have signing enabled
   * (they will reject empty/missing signatures). Only use in trusted
   * development/testing environments. BeeKEM writer authentication remains
   * mandatory.**
   *
   * The value is captured by `Peerborne.initialize()`. Mutating the caller's
   * config object afterward does not change the active authentication policy;
   * reinitialize with a new config to change it.
   *
   * Default: true (signatures are computed and verified).
   */
  enableSigning?: boolean;

  /**
   * Allow receiving the legacy BeeKEM PathUpdate v1 protocol.
   *
   * **INSECURE MIGRATION OPTION:** v1 updates carry no generation number or
   * parent-tree commitment. A valid previously signed update can therefore be
   * replayed against generation-less legacy state and roll the ratchet and
   * document key back. Peerborne does not register the v1 protocol handler and
   * rejects direct v1 application unless this option is exactly `true`.
   *
   * Enable this only for a bounded migration of a legacy document, then move
   * every member to generation-bearing BeeKEM v2 state and reinitialize with
   * the option disabled. Current membership operations send only v2 updates.
   * The value is captured by `Peerborne.initialize()` so mutating the caller's
   * config object cannot enable the legacy path at runtime.
   *
   * @default false
   */
  allowInsecureLegacyBeeKEMPathUpdateV1?: boolean;

  /**
   * Configuration for history compaction.
   * When provided with `enabled: true`, the document will periodically
   * create snapshot nodes to compact the Merkle-DAG change history.
   */
  compaction?: Partial<CompactionConfig>;

  /**
   * Enable network statistics tracking.
   * When true, a `NetworkStats` counter container is created and accessible
   * via `peerborne.networkStats`. Callers must invoke `record*()` methods
   * explicitly; automatic event wiring will be added in a follow-up.
   *
   * Default: false.
   */
  enableNetworkStats?: boolean;

  /**
   * Optional override for the WebRTC ICE server list used by the `webRTC()`
   * and `webRTCDirect()` transports. When undefined, the built-in
   * {@link DEFAULT_WEBRTC_ICE_SERVERS} list (Google + Cloudflare + Twilio
   * public STUN endpoints) is used so peers can discover their public
   * address mappings without depending on Circuit Relay for the data plane.
   *
   * **Privacy note:** Using the public STUN defaults discloses each peer's
   * public IP/port mapping to the third-party STUN operators. For
   * privacy-sensitive deployments, pass `[]` to disable STUN entirely (e.g.
   * for fully-internal LAN deployments where mDNS is sufficient), or supply
   * self-hosted STUN/TURN servers.
   *
   * Note: this field is informational once the libp2p config has already
   * been built by {@link defaultConfig}; to actually change the ICE
   * configuration, pass the override into `defaultConfig(bootstrap, ice)`
   * (or `getDefaultConfig(ice)`) so it is wired into the transports at
   * construction time.
   *
   * @default DEFAULT_WEBRTC_ICE_SERVERS
   */
  webrtcIceServers?: ReadonlyArray<Readonly<IceServer>>;

  /**
   * Enable the initial-load quorum gate.
   *
   * When `true` (the default), `PeerborneDocument.load()` queries up to
   * {@link loadQuorumK} distinct peers in parallel through the negotiated
   * initial-load advertisement protocol before selecting a full response.
   * The legacy negotiation compares a digest of the advertised tip frontier.
   * A strict security-aware negotiation uses signer-authenticated votes over
   * a digest that also binds the document identity, durable group-security
   * commitments, and complete response manifest. The load proceeds only when
   * {@link loadQuorumQ} accepted votes agree on the same negotiated digest.
   * If quorum is not met, `load()` rejects with `LoadQuorumFailedError`.
   *
   * This gate reduces reliance on a single source, but it is not by itself a
   * Byzantine-consensus guarantee. Its protection depends on the configured
   * Q-of-K threshold, peer independence, and the authentication guarantees of
   * the negotiated protocol. In particular, an explicit Q of 1 provides no
   * independent corroboration.
   *
   * Setting this to `false` uses single-source selection: the loader may
   * proceed with the first response that passes the checks required by the
   * negotiated protocol and the rest of the configuration. This is useful for
   * development and intentionally accepts the weaker single-peer trust model.
   *
   * The complete quorum policy (enabled, K, explicit Q, timeout, and
   * single-peer permission) is captured by `Peerborne.initialize()`.
   * Post-initialization mutation of the caller's config object cannot lower
   * the active threshold or enable a single-peer decision; reinitialize to
   * change the policy.
   *
   * @default true
   */
  loadQuorumEnabled?: boolean;

  /**
   * Maximum number of peers to probe in parallel for the initial-load
   * advertisement step. The effective K is
   * `min(loadQuorumK, knownPeers.length)`, so no more distinct peers are
   * selected than are currently known.
   *
   * When three peers are known, the default of 3 paired with the default Q
   * requires two matching votes while limiting open latency and bandwidth.
   * That numerical majority does not establish Byzantine fault tolerance
   * without corresponding peer identity, selection, and authentication
   * assumptions.
   *
   * @default 3
   */
  loadQuorumK?: number;

  /**
   * Minimum number of accepted votes that must agree on the same negotiated
   * advertisement digest. Together, {@link loadQuorumK} and this value define
   * the configured Q-of-K policy. Once at least one peer is known, an explicit
   * Q is a hard trust floor: if fewer than Q peers can be probed, loading fails
   * closed instead of reducing Q to the currently reachable cohort. With no
   * known peers (`effectiveK = 0`), the loader retains its new-document/no-peer
   * skip path because there is no remote state to accept.
   *
   * When Q is omitted, it is the strict numerical majority
   * `Math.floor(effectiveK / 2) + 1`, derived from the effective K after
   * limiting the configured K to the known-peer count.
   *
   * Worked examples (`effectiveK -> default Q`):
   *   - effectiveK=1 -> Q=1 (single-peer pass-through; requires
   *     `loadQuorumAllowSinglePeer: true`)
   *   - effectiveK=2 -> Q=2 (both peers must agree)
   *   - effectiveK=3 -> Q=2
   *   - effectiveK=4 -> Q=3
   *   - effectiveK=5 -> Q=3
   *   - effectiveK=7 -> Q=4
   *
   * An explicit valid Q is used as configured, even when it is not a majority
   * of K. It is also preserved when a partition lowers the effective K, which
   * makes the load fail closed if Q can no longer be reached. Choosing Q=1 or
   * another non-majority threshold provides only that amount of agreement and
   * must not be interpreted as Byzantine-majority protection.
   *
   * @default Math.floor(effectiveK / 2) + 1
   */
  loadQuorumQ?: number;

  /**
   * Per-peer timeout (milliseconds) for each initial-load quorum
   * advertisement probe and for the remote-read phase of each selected
   * full-document or snapshot response. Probe timeouts are non-votes; a
   * full-response timeout aborts that stream and advances to the next peer.
   * The full-response deadline remains active when quorum is disabled.
   *
   * Default chosen to be larger than typical RTT + protocol-negotiation
   * latency on a wide-area mesh, but small enough that a partitioned peer
   * does not stall document open by more than ~5 seconds.
   *
   * @default 5000
   */
  loadQuorumTimeoutMs?: number;

  /**
   * Allow the initial-load quorum gate to pass with a single responding
   * peer when the effective K is 1.
   *
   * Effective K can resolve to 1 because only one peer is known, or because
   * `loadQuorumK` is configured as 1 even when multiple peers are known. When
   * this flag is `true`, the loader may accept the sole probed peer's
   * negotiated advertisement and proceed with the full load. An explicit
   * Q greater than 1 remains a hard floor and is not overridden by this flag.
   *
   * **Trust caveat:** with K=1 there is no second opinion, so this flag
   * selects single-peer trust semantics regardless of which advertisement
   * protocol is negotiated. A warning is logged when this path is taken.
   *
   * When `false` (the default), any effective-K=1 load fails with
   * `LoadQuorumFailedError`. Callers that intentionally use one probe should
   * either disable the quorum gate or enable this flag and accept the warning.
   *
   * @default false
   */
  loadQuorumAllowSinglePeer?: boolean;

  /**
   * Require the first accepted load response and quorum advertisement to be
   * signed by an application-pinned writer when the local writers ACL is
   * empty. This removes the legacy bootstrap fallback that treated knowledge
   * of the document encryption key as sufficient authentication.
   *
   * The unauthenticated legacy `0xff` unknown-document sentinel is also
   * ignored in this mode. Consequently, creating a fresh document name while
   * already connected to peers currently fails closed: the protocol has no
   * authenticated nonexistence proof, and {@link validateDocumentPath} does
   * not override a failed network load. This avoids treating an
   * unauthenticated absence claim as truth.
   * The same ambiguity exists with no connected peers: an empty first load may
   * be a genuine founder or an eclipse/partition. Peerborne therefore requires
   * the captured {@link validateDocumentPath} callback to return exact `true`
   * before founding an empty strict document on that no-peer path. An
   * already-loaded local replica can still reopen offline.
   *
   * Requires {@link resolveTrustedDocumentWriters} and signing to be enabled.
   * @default false
   */
  requireAuthenticatedInitialLoad?: boolean;

  /**
   * Resolve writer identities trusted out-of-band for two empty-local-ACL
   * bootstrap boundaries: a document's first load and an inbound BeeKEM
   * Welcome. These keys are never learned from the untrusted message they
   * authenticate. For a Welcome received before the local writer ACL has
   * converged, the returned identities are therefore authorized to bootstrap
   * the recipient's group-security state and document key, not merely to
   * attest an initial load. Once a local writer ACL exists, that ACL takes
   * precedence and this resolver is not used for the Welcome authorization.
   * Return an empty list to reject either empty-ACL bootstrap.
   * Key values must remain immutable for the duration of an authorization
   * attempt; Peerborne snapshots the list and canonical authority IDs but
   * cannot generically clone an application-defined `PublicKey` object.
   * The resolver function identity is captured by `Peerborne.initialize()`.
   */
  resolveTrustedDocumentWriters?: (
    documentPath: string,
  ) => readonly unknown[] | Promise<readonly unknown[]>;

  /**
   * Select the V4 initial-load protocol family, whose signed quorum value
   * binds the served CRDT frontier and canonical complete response manifest
   * (node graph, snapshot, and keychain delta) to control-log and group-state
   * commitments. Strict documents never fall back to the legacy V3/tip-v1
   * family.
   *
   * Requires the quorum gate, authenticated initial load, and
   * {@link resolveLoadSecurityCommitments}. V4 votes are deduplicated by the
   * verified writer authority returned by `AuthProvider.serializePublicKey`,
   * not merely by libp2p PeerId. The serializer therefore must be
   * deterministic and collision-resistant, and the pinned writer set must
   * represent independently controlled authorities for Q to provide a real
   * second opinion. Every load uses a fresh request challenge that is echoed
   * inside the writer-signed advertisement and selected full response, so a
   * previously recorded quorum transcript is not valid in a later round.
   * @default false
   */
  requireSecurityStateQuorum?: boolean;

  /**
   * Return an atomic view of the document's current control and group
   * commitments. Responders attach this tuple to V4 loads and security-aware
   * advertisements. Loaders bind it to the served frontier before applying
   * state. Supplying this callback alone does not select V4 for outgoing
   * loads; set {@link requireSecurityStateQuorum} for strict selection. A V4
   * load captures one defensive copy before its first peer probe. Rejection,
   * `undefined`, or malformed output aborts that load without downgrade.
   * The resolver function identity is captured by `Peerborne.initialize()`.
   */
  resolveLoadSecurityCommitments?: (
    documentPath: string,
  ) => LoadSecurityCommitments | Promise<LoadSecurityCommitments>;

  /**
   * Optional callback to validate document paths before creation.
   *
   * Called when `open()` determines the document is new (i.e., `load()` returned
   * false -- no peers could provide the document). Note that `load()` can also
   * return false during network partitions when peers are unavailable.
   *
   * Validation runs before pubsub subscription and protocol handler registration,
   * so rejected paths never temporarily join the topic.
   *
   * - If the callback returns `false`, `open()` throws
   *   `new Error('Document path "<path>" is not allowed for the current user')`.
   * - If the callback throws, `open()` rethrows the error as-is (if it is
   *   already an `Error`) or wraps it via `new Error(String(err))`.
   *
   * May return a boolean or a Promise<boolean> for async validation.
   * Return `true` to allow creation, `false` to reject it.
   * When absent, all document paths are allowed.
   * The callback identity is captured by `Peerborne.initialize()` so later
   * mutation of the caller-owned config cannot bypass creation policy.
   * Authenticated initial-load mode requires this callback to explicitly
   * authorize creation whenever no existing local state was loaded.
   *
   * @param documentPath The path of the document being created.
   * @param userPublicKey The public key of the current user.
   */
  validateDocumentPath?: (documentPath: string, userPublicKey: unknown) => boolean | Promise<boolean>;
}

/**
 * Default bootstrap configuration to use if none is provided.
 *
 * @param clientAddresses The list of bootstrap addresses to use.
 * @returns A BootstrapInit object with the provided addresses.
 */
export const defaultBootstrapConfig = (clientAddresses: string[]) =>
  ({
    list: clientAddresses,
  } as BootstrapInit);

/**
 * Returns a fresh default config with no bootstrap peers.
 *
 * Use this as a starting point for browser applications. Connect to peers
 * after initialization via `peerborne.connect([relayMultiaddr])`.
 *
 * For configs with bootstrap peers baked in, use
 * `defaultConfig(defaultBootstrapConfig(['/ip4/.../ws/p2p/...']))` instead.
 *
 * Each call creates new IDB-backed blockstore/datastore instances so callers
 * can safely mutate the returned config without leaking state across
 * consumers. For shared/reused configs, store the result in a variable.
 *
 * **Note:** Lazily instantiated -- safe to import in Node.js test environments
 * that lack IndexedDB as long as the function is not called.
 *
 * @param webrtcIceServers Optional override for the WebRTC ICE server list.
 *   When undefined, {@link DEFAULT_WEBRTC_ICE_SERVERS} is used.
 */
export function getDefaultConfig(
  webrtcIceServers?: ReadonlyArray<Readonly<IceServer>>,
): PeerborneConfig {
  return defaultConfig(defaultBootstrapConfig([]), webrtcIceServers);
}
