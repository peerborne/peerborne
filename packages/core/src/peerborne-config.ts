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
import {
  DEFAULT_DOCUMENT_TOPIC_PREFIX,
  defaultDocumentPubsubConfig,
} from './document-topic.js';
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

    ...defaultDocumentPubsubConfig(),
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
   * traffic on the pubsub mesh and keep default-configured older peers on a
   * separate topic. Topic names are routing labels, not authenticated version
   * negotiation; wire decoding and admission checks remain mandatory.
   *
   * Set to an empty string (`''`) to disable prefixing; topic strings
   * will be the bare document path. Custom and empty prefixes are protocol
   * compatibility boundaries: every peer sharing one must be upgraded
   * together.
   *
   * @default DEFAULT_DOCUMENT_TOPIC_PREFIX
   */
  pubsubDocumentPrefix: string;

  /**
   * GossipSub topic retained for legacy document-publish V1 messages.
   *
   * The current document-publish V1 payload is not an authenticated remote
   * pinning request. `PeerborneNode` does not subscribe to this topic or
   * perform any document, subscription, or pinning effect from it.
