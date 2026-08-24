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
   *
   * Default: false (for backward compatibility).
   */
  enableTopicValidators?: boolean;

  /**
   * Enable Peerborne application-level signing and verification.
   * When false, application-level signing is bypassed: sync message signatures,
   * load request signatures, snapshot signatures, topic validator signature
   * checks, and key update verification. Topic validators are not registered
   * at all when signing is disabled to avoid unnecessary per-message overhead.
   * Note: libp2p/GossipSub transport-level signing (e.g., `globalSignaturePolicy`)
   * is NOT affected by this flag.
   *
   * **WARNING: Disabling signing removes all authentication and authorization
   * checks. Any peer that can decrypt traffic (e.g., possesses a previous
   * document key) can forge sync, key-update, and load messages. Peers with
   * `enableSigning: false` will NOT interoperate with peers that have signing
   * enabled (they will reject empty/missing signatures). Only use in trusted
   * development/testing environments.**
   *
   * Default: true (signatures are computed and verified).
   */
  enableSigning?: boolean;

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
   * {@link loadQuorumK} peers in parallel via the `tipAdvertiseV1` protocol
   * for a lightweight tip-set hash before accepting any one peer's full
   * document state. The full load proceeds only if at least
   * {@link loadQuorumQ} peers returned the same hash. If quorum is not
   * met, `load()` rejects with a `LoadQuorumFailedError` and the open
   * sequence fails -- the application can catch the error and decide how
   * to recover.
   *
   * Closes the gap tracked under issue #189 §5.4 item 2 (also bulleted in
   * #186). Defends against a single malicious or partitioned peer
   * unilaterally serving a stale or maliciously-crafted initial state.
   *
   * Setting this to `false` reverts to the legacy single-peer load: any
   * one peer's response is accepted on the strength of its outer
   * writer-signature alone. This is appropriate for solo-peer dev,
   * single-node tests, and small-mesh dev scenarios where no second peer
   * is reachable, but **weakens the trust assumptions** of an open mesh
   * (the loader has no defence-in-depth against an actively malicious
   * peer that holds a valid writer key but advertises a forged tip set).
   *
   * @default true
   */
  loadQuorumEnabled?: boolean;

  /**
   * Maximum number of peers to probe in parallel for the initial-load
   * quorum tip-advertise step. The effective K is
   * `min(loadQuorumK, knownPeers.length)` so the loader never blocks on a
   * peer that does not exist.
   *
   * The default of 3 is a deliberately small number: it gives the gate
   * defence against a single dishonest peer (Q=2 majority of 3) without
   * fanning out enough requests to noticeably impact open latency or
   * bandwidth.
   *
   * @default 3
   */
  loadQuorumK?: number;

  /**
   * Minimum number of peers that must agree on the same tip-set hash to
   * pass the initial-load quorum gate. Clamped at runtime to
   * `[1, effectiveK]` so `Q > K` never makes quorum unreachable.
   *
   * Default formula: `Math.floor(effectiveK / 2) + 1` (strict majority).
   * IMPORTANT: the default Q is derived from the EFFECTIVE K (i.e.
   * `min(loadQuorumK, knownPeersCount)`), NOT from the configured
   * `loadQuorumK`. This matters when fewer than `loadQuorumK` peers are
   * reachable: with `loadQuorumK=7` but only 3 peers in the mesh,
   * `defaultQuorumQ(7) = 4` would require ALL 3 reachable peers to
   * agree -- losing the one-fault tolerance the formula is meant to
   * provide. Deriving from effective K instead gives `defaultQuorumQ(3) =
   * 2`, which tolerates one non-vote among the 3 reachable peers. See
   * `load-quorum-orchestrator.ts` and PR #284 r7 / r23 reviews.
   *
   * Worked examples (`effectiveK -> default Q`):
   *   - effectiveK=1 -> Q=1 (single-peer pass-through; requires
   *     `loadQuorumAllowSinglePeer: true`)
   *   - effectiveK=2 -> Q=2 (both peers must agree)
   *   - effectiveK=3 -> Q=2 (a single dishonest peer cannot win the vote)
   *   - effectiveK=4 -> Q=3
   *   - effectiveK=5 -> Q=3
   *   - effectiveK=7 -> Q=4
   * This is the standard "strictly more than half" Byzantine-fault-
   * tolerant threshold and matches the design note in #189 §5.4.2.
   * Using `floor + 1` rather than `ceil + 1` tolerates one fault at
   * effectiveK=3 (Q=2, not Q=3) as the PR description requires.
   *
   * When the operator explicitly sets `loadQuorumQ`, this default is a
   * no-op and the explicit value flows through `effectiveQ`'s `[1, k]`
   * clamp instead.
   *
   * @default Math.floor(effectiveK / 2) + 1, clamped to [1, effectiveK]
   */
  loadQuorumQ?: number;

  /**
   * Per-peer timeout (milliseconds) for the initial-load quorum
   * tip-advertise probes. A peer that does not respond within this window
   * is recorded as a non-vote (NOT a disagreement); see
   * `load-quorum.ts::decideLoadQuorum` for the distinction.
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
   * peer when no other peers are reachable.
   *
   * When `true` and the effective K resolves to 1 (only one known peer),
   * the loader accepts that peer's tip-advertise response and proceeds
   * with the full load. Useful for small private swarms or development
   * scenarios where running multiple peers is impractical.
   *
   * **Trust caveat:** with K=1 there is no second opinion, so this flag
   * weakens the gate's protection back to legacy single-peer trust
   * semantics in exactly the case it was designed to defend. A warning
   * is logged when the single-peer path is taken so operators can spot
   * the regression in their environment.
   *
   * When `false` (the default), a single-peer mesh forces a
   * `LoadQuorumFailedError`. Callers that genuinely run solo (e.g.
   * brand-new documents, founding member) should either set
   * `loadQuorumEnabled: false` or set this flag and accept the warning.
   *
   * @default false
   */
  loadQuorumAllowSinglePeer?: boolean;

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
