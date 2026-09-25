/**
 * @module peerborne-node
 *
 * **Node-only module.** Do not import in browser environments.
 *
 * This module depends on Node.js built-ins (`fs`, `dgram` via `@libp2p/mdns`)
 * that are unavailable in browsers. It is intentionally excluded from the
 * barrel export in `index.ts` to keep the main entry point browser-compatible.
 *
 * Import from the dedicated `/node` subpath export when running in Node.js:
 *   import { PeerborneNode, defaultNodeConfig } from '@peerborne/core/node';
 */
import * as fs from 'fs';
import {
  PeerborneConfig,
  IceServer,
  cloneIceServer,
  defaultBootstrapConfig,
  defaultConfig,
  resolveIceServers,
} from './peerborne-config.js';
import { Peerborne } from './peerborne.js';
import { CRDTProvider } from './crdt-provider.js';
import { SyncMessageSerializer } from './sync-message-serializer.js';
import { ChangesSerializer } from './changes-serializer.js';
import { AuthProvider } from './auth-provider.js';
import { ACLProvider } from './acl-provider.js';
import { KeychainProvider } from './keychain-provider.js';
import { LoadMessageSerializer } from './load-request-serializer.js';
import { gossipsub } from '@libp2p/gossipsub';
import { autoNAT } from '@libp2p/autonat';
import { circuitRelayTransport } from '@libp2p/circuit-relay-v2';
import { identify } from '@libp2p/identify';
import { dcutr } from '@libp2p/dcutr';
import { kadDHT } from '@libp2p/kad-dht';
import { ping } from '@libp2p/ping';
// mDNS is Node-only: it depends on the `dgram` built-in for UDP multicast,
// which is unavailable in browsers. The browser-compatible default config in
// peerborne-config.ts intentionally omits it.
import { mdns } from '@libp2p/mdns';
import { pubsubPeerDiscovery } from '@libp2p/pubsub-peer-discovery';
import { webRTC, webRTCDirect } from '@libp2p/webrtc';
import { webSockets } from '@libp2p/websockets';
// Note: `@libp2p/websockets` v3 removed the `/filters` subpath and the
// `filter` option from `WebSocketsInit`. WebSocket dial filtering is now
// internal to the transport.
import { webTransport } from '@libp2p/webtransport';
import { ipnsSelector } from 'ipns/selector';
import { ipnsValidator } from 'ipns/validator';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { bootstrap, BootstrapInit } from '@libp2p/bootstrap';
import { hasBootstrapPeers } from './bootstrap-config.js';
import { createNodeHeliaStores } from './node-stores.js';
import {
  copyDocumentPubsubConfig,
  DEFAULT_PEER_DISCOVERY_TOPIC,
  defaultDocumentPubsubConfig,
} from './document-topic.js';

/**
 * Default config for Node.js environments.
 *
 * **Note on mDNS (LAN broadcast):** This default includes mDNS peer discovery,
 * which advertises and discovers peers on the local LAN via UDP multicast.
 * This allows same-network nodes to find each other without relay servers or
 * bootstrap peers. Because this actively broadcasts the node's presence on the
 * local network, privacy-sensitive deployments should disable it by building a
 * custom config (copy this one and omit `mdns()` from `peerDiscovery`) rather
 * than using `defaultNodeConfig` directly.
 *
 * The default blockstore and datastore are process-local and ephemeral. Node
 * applications that require persistence should replace `config.helia`'s
 * stores before starting Peerborne.
 *
 * @param bootstrapConfig Bootstrap peer list to seed peer discovery.
 * @param webrtcIceServers Optional override for the WebRTC ICE server list.
 *   When undefined, the package-level `DEFAULT_WEBRTC_ICE_SERVERS` list is
 *   used (see `./peerborne-config`) so peers can discover their public
 *   address mappings via STUN without relying on relay infrastructure for
 *   data plane forwarding (issue #236 phase 3).
 */
export const defaultNodeConfig = (
  bootstrapConfig: BootstrapInit,
  webrtcIceServers?: ReadonlyArray<Readonly<IceServer>>,
) => {
  // Resolve the source list and a deeply-frozen exposed view in one place so
  // the browser and Node defaults stay in sync. Each transport below still
  // gets its own fresh `cloneIceServer`-deep-cloned copy of `sourceIceServers`
  // so mutations never leak between transport state and `config.webrtcIceServers`.
  const { sourceIceServers, exposedIceServers } = resolveIceServers(webrtcIceServers);
  return ({
    helia: {
      ...createNodeHeliaStores(),
      libp2p: {
        // See: https://github.com/ipfs/helia/blob/main/packages/libp2p/src/utils/libp2p-defaults.browser.ts
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
        peerDiscovery: [
          ...(hasBootstrapPeers(bootstrapConfig) ? [bootstrap(bootstrapConfig)] : []),
          pubsubPeerDiscovery({
            topics: [DEFAULT_PEER_DISCOVERY_TOPIC],
          }),
          mdns(),
        ],
        services: {
          identify: identify(),
          dcutr: dcutr(),
          autoNAT: autoNAT(),
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

export class PeerborneNode<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
> {
  private _swarm: Peerborne<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  >;
  public get swarm(): Peerborne<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  > {
    return this._swarm;
  }

  constructor(
    private readonly nodeKey: PrivateKey,
    private readonly nodePublicKey: PublicKey,
    public readonly provider: CRDTProvider<DocType, ChangesType, ChangeFnType>,
    public readonly changesSerializer: ChangesSerializer<ChangesType>,
    public readonly syncMessageSerializer: SyncMessageSerializer<ChangesType, PublicKey>,
    public readonly loadMessageSerializer: LoadMessageSerializer,
    public readonly authProvider: AuthProvider<
      PrivateKey,
      PublicKey,
      DocumentKey
    >,
    private readonly aclProvider: ACLProvider<ChangesType, PublicKey>,
    private readonly keychainProvider: KeychainProvider<
      ChangesType,
      DocumentKey
    >,
    public readonly config: PeerborneConfig,
  ) {
    this._swarm = new Peerborne(
      this.nodeKey,
      this.nodePublicKey,
      this.provider,
      this.changesSerializer,
      this.syncMessageSerializer,
      this.loadMessageSerializer,
      this.authProvider,
      this.aclProvider,
      this.keychainProvider,
    );
  }

  // Start
  public async start(bootstrapAddresses?: string[]) {
    await this.swarm.initialize(this.config);
    // Thread the Node-side ICE override (resolved and exposed on
    // `this.config.webrtcIceServers` by `defaultNodeConfig`) into the
    // browser-side client config so a deployment that customizes STUN/TURN
    // (or disables it via `[]`) ends up with the same list on both sides.
    //
    // Edge case: if a hand-rolled config skips `defaultNodeConfig` and
    // leaves `webrtcIceServers` unset, `browserSafeIceServers` is left
    // undefined and `defaultConfig` falls back to its own
    // `DEFAULT_WEBRTC_ICE_SERVERS`. Configs built via `defaultNodeConfig`
    // never hit that path.
    //
    // Strip `username`/`credential` before passing the list across: TURN
    // credentials are server-side secrets and the resulting `clientConfig`
    // is written to a file that can be bundled into browser builds. Browsers
    // that need authenticated TURN should obtain ephemeral credentials at
    // runtime instead of receiving long-lived secrets via this file.
    //
    // Warn loudly when stripping a non-empty credential: a TURN entry without
    // its credential will not authenticate, so the browser silently degrades
    // to STUN-only / host candidates and may fail to connect through
    // symmetric NATs. Operators should either provide STUN-only entries or
    // wire up an ephemeral-TURN-credential flow in their app code.
    const strippedTurnEntries = new Set<string>();
    const browserSafeIceServers = this.config.webrtcIceServers?.map(
      ({ username, credential, ...rest }) => {
        if (username !== undefined || credential !== undefined) {
          const urlsLabel = Array.isArray(rest.urls)
            ? rest.urls.join(',')
            : rest.urls;
          strippedTurnEntries.add(urlsLabel);
        }
        return rest;
      },
    );
    if (strippedTurnEntries.size > 0) {
      console.warn(
        `[peerborne] Stripped TURN credentials from clientConfig for: ${Array.from(
          strippedTurnEntries,
        ).join('; ')}. Browsers will not authenticate against these TURN servers; ` +
          'supply ephemeral credentials at runtime instead of long-lived ' +
          'secrets in clientConfig.',
      );
    }
    const clientConfig = {
      ...defaultConfig(
        defaultBootstrapConfig(bootstrapAddresses ?? []),
        browserSafeIceServers,
      ),
      ...copyDocumentPubsubConfig(this.config),
    };
    const clientConfigFile =
      process.env.REACT_APP_CLIENT_CONFIG_FILE || 'client-config.env';
    fs.writeFile(
      clientConfigFile,
      `REACT_APP_CLIENT_CONFIG='${JSON.stringify(clientConfig)}'`,
      (err: NodeJS.ErrnoException | null) => {
        if (err) {
          console.error(`Failed to write ${clientConfigFile}:`, err);
        } else {
          console.log(`Wrote ${clientConfigFile}:`, clientConfig);
        }
      },
    );
  }
}
