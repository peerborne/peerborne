# Peerborne Coordination Server Guide

This document describes the server infrastructure required to run Peerborne in production. Peerborne is a peer-to-peer system, but browsers cannot directly connect to each other without coordination servers to bootstrap the network.

## Table of Contents

1. [Server Types Overview](#1-server-types-overview)
2. [Minimal Single-Server Setup](#2-minimal-single-server-setup)
3. [Production Multi-Server Deployment](#3-production-multi-server-deployment)
4. [Public Alternatives](#4-public-alternatives)
5. [Fly.io Deployment](#5-flyio-deployment)
6. [Docker Deployment Configs](#6-docker-deployment-configs)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. Server Types Overview

Peerborne uses [libp2p](https://libp2p.io/) for networking. The following server types facilitate peer-to-peer connectivity, especially for browser-based peers.

### 1.1 Bootstrap / Signaling Node

| | |
|---|---|
| **Purpose** | Initial peer discovery. When a Peerborne client starts, it dials the bootstrap node to join the network and discover other peers. |
| **When needed** | Always. At least one bootstrap node must be reachable for a new peer to join the swarm. |
| **Required?** | **Yes** (minimum 1) |
| **Protocol** | WebSocket (`/ip4/<IP>/tcp/<PORT>/ws`) or WebSocket Secure (`/ip4/<IP>/tcp/<PORT>/wss`) |
| **Ports** | TCP 9001 (WebSocket), TCP 9002 (TCP for node-to-node) |

In Peerborne, the bootstrap node and relay node are combined into a single process (`relay-server/`). The relay server listens on WebSocket (port 9001) and TCP (port 9002), runs the libp2p identify protocol, and participates in GossipSub peer discovery via the `swarmdb._peer-discovery._p2p._pubsub` topic.

**How it works:**
1. Browser client is configured with the relay's multiaddress (e.g., `/ip4/1.2.3.4/tcp/9001/ws/p2p/<PEER_ID>`)
2. Client dials the relay via WebSocket
3. libp2p `identify` protocol exchanges peer information
4. `pubsub-peer-discovery` advertises the new peer to all connected peers
5. GossipSub mesh forms, enabling document synchronization

### 1.2 Circuit Relay Node

| | |
|---|---|
| **Purpose** | NAT traversal for browsers that cannot establish direct WebRTC connections. The relay forwards data between two peers that cannot reach each other directly. |
| **When needed** | Whenever browser peers are behind restrictive NATs (symmetric NAT, corporate firewalls). This is the common case on the open internet. |
| **Required?** | **Recommended** (effectively required for reliable browser-to-browser) |
| **Protocol** | Circuit Relay V2 (`@libp2p/circuit-relay-v2`) |
| **Ports** | Same as bootstrap node (combined process) |

In Peerborne's architecture, the relay server runs `circuitRelayServer()` which implements libp2p Circuit Relay V2. Browser clients configure `circuitRelayTransport()` to connect through the relay.

**Data flow through relay:**
```text
Browser A ──WebSocket──> Relay Server ──WebSocket──> Browser B
                  (Circuit Relay V2)
```

After the relayed connection is established, libp2p may upgrade to a direct WebRTC connection if both peers' NATs allow it (ICE hole-punching). If direct connection succeeds, the relay is no longer in the data path.

### 1.3 STUN Server

| | |
|---|---|
| **Purpose** | WebRTC ICE candidate gathering. STUN (Session Traversal Utilities for NAT) allows browsers to discover their public IP address and port mapping, which is needed to establish direct WebRTC connections. |
| **When needed** | Whenever WebRTC is used (browser-to-browser). |
| **Required?** | **Yes** for WebRTC, but public STUN servers can be used |
| **Protocol** | STUN (RFC 5389) |
| **Ports** | UDP 3478 (standard STUN port) |

Peerborne's browser clients use `@libp2p/webrtc` which relies on the browser's built-in WebRTC stack. The browser's RTCPeerConnection uses STUN servers configured at the system/browser level, or defaults to public servers. You do not typically need to run your own STUN server.

### 1.4 TURN Server

| | |
|---|---|
| **Purpose** | Relays media/data when STUN-based hole-punching fails (symmetric NAT on both sides). TURN (Traversal Using Relays around NAT) is a fallback relay at the WebRTC layer. |
| **When needed** | When peers are behind symmetric NATs where STUN cannot establish a direct path. |
| **Required?** | **Optional** (Circuit Relay V2 serves a similar purpose at the libp2p layer) |
| **Ports** | UDP/TCP 3478 |

In practice, Peerborne's Circuit Relay V2 provides relay functionality at the libp2p protocol layer, making a separate TURN server less critical. However, adding TURN support improves connection success rates in networks with aggressive firewalls.

If you need TURN, consider [coturn](https://github.com/coturn/coturn) (open source) or hosted services like Twilio or Xirsys.

### 1.5 Pinning Service

| | |
|---|---|
| **Purpose** | Persistent storage for IPFS/Helia content. When all peers go offline, pinned content remains available. Without pinning, document data exists only while at least one peer with that data is online. |
| **When needed** | When data persistence is required beyond peer availability. |
| **Required?** | **Optional** but strongly recommended for production |
| **Protocol** | IPFS Bitswap (built into Helia) |

Peerborne's Node-only `PeerborneNode` includes the listener side of a pinning flow, but the normal document commit path does not publish the announcements that activate it. Peerborne does not currently ship a runnable end-to-end pinning daemon or durability guarantee.

Self-hosted pinning therefore requires application-specific publication, persistence, and recovery integration. See the [pinning cookbook](../site/src/content/docs/cookbook/pinning.md) before designing one. For managed IPFS services, see [Public Alternatives](#4-public-alternatives).

### 1.6 DHT Bootstrap Node

| | |
|---|---|
| **Purpose** | Kademlia DHT for large-scale peer discovery. The DHT enables peers to find each other without relying solely on pubsub-based discovery. |
| **When needed** | At scale (hundreds+ of peers) where pubsub discovery alone is insufficient. |
| **Required?** | **No** (Peerborne clients run DHT in `clientMode: true` by default) |

Peerborne clients configure `kadDHT({ clientMode: true })` which means they query the DHT but do not serve DHT requests. For large deployments, running dedicated DHT server nodes improves peer discovery reliability.

### Summary Table

| Server | Required? | Default Port(s) | Self-Hosted? | Public Available? |
|--------|-----------|-----------------|-------------|-------------------|
| Bootstrap/Relay | Yes | 9001 (WS), 9002 (TCP) | Yes (`relay-server/`) | No |
| STUN | Yes (WebRTC) | 3478 (UDP) | Optional | Yes (Google, etc.) |
| TURN | Optional | 3478 (UDP/TCP) | coturn | Yes (Twilio, Xirsys) |
| Pinning | Recommended | N/A (Bitswap) | Incomplete hooks only | Yes (Pinata, web3.storage) |
| DHT Bootstrap | At scale | Same as relay | Yes | No |

---

## 2. Minimal Single-Server Setup

This section describes running everything needed for Peerborne on a single machine.

### 2.1 What You Need

At minimum, you need **one relay/bootstrap server** and access to **public STUN servers**. This topology is suitable for development and limited initial trials; it has not been capacity-tested and carries no concurrent-peer guarantee.

### 2.2 Architecture

```text
                    ┌─────────────────────┐
                    │   Your Server       │
                    │                     │
                    │  ┌───────────────┐  │
                    │  │ Relay Server  │  │
                    │  │ (Bootstrap +  │  │
                    │  │  Circuit Relay│  │
                    │  │  + GossipSub) │  │
                    │  └──────┬────────┘  │
                    │         │           │
                    │    Port 9001 (WS)   │
                    │    Port 9002 (TCP)  │
                    └─────────┼───────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
         ┌────┴────┐    ┌────┴────┐    ┌────┴────┐
         │Browser A│    │Browser B│    │Browser C│
         └─────────┘    └─────────┘    └─────────┘

         (All browsers use public STUN for WebRTC)
```

### 2.3 Quick Start with Docker

```bash
# From the repository root
docker compose -f guides/docker/docker-compose.single.yaml up -d
```

Or build and run the relay server directly:

```bash
cd relay-server
yarn install
yarn build
node dist/index.js
```

The relay server will:
1. Listen on port 9001 (WebSocket) and 9002 (TCP)
2. Load or create an app-managed libp2p identity at `RELAY_IDENTITY_KEY_PATH`
3. Write connection info to `relay-info.json`
4. Subscribe to peer discovery and document sync topics

### 2.4 Connecting Clients

After the relay starts, configure your Peerborne client with the relay's multiaddress:

```typescript
import { defaultNodeConfig } from '@peerborne/core/node';

// The relay's multiaddress is printed on startup and written to relay-info.json
const relayMultiaddr = '/ip4/<YOUR_SERVER_IP>/tcp/9001/ws/p2p/<RELAY_PEER_ID>';

const config = defaultNodeConfig({
  list: [relayMultiaddr],
});
```

For browser apps, you can also serve the relay info as a config file:

```json
{
  "relayMultiaddr": "/ip4/1.2.3.4/tcp/9001/ws/p2p/12D3KooW..."
}
```

### 2.5 Port Requirements

| Port | Protocol | Purpose | Required? |
|------|----------|---------|-----------|
| 9001 | TCP (WebSocket) | Browser-to-relay communication | Yes |
| 9002 | TCP | Node-to-node communication | Only if node peers connect |

### 2.6 DNS and TLS

**For development:** Plain WebSocket (`ws://`) works on localhost or private networks.

**For production:** When the client is served over HTTPS, browsers' mixed-content policy blocks plain `ws://`, so the relay multiaddr must use `wss://`. (Plain `ws://` is fine from `localhost` or HTTP origins, but production deployments are almost always HTTPS.) You need:

1. A domain name pointing to your server
2. A TLS certificate (Let's Encrypt is free and automated)
3. A reverse proxy (nginx, Caddy, or Traefik) that terminates TLS and proxies to port 9001

Example nginx configuration:

```nginx
server {
    listen 443 ssl;
    server_name relay.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/relay.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:9001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

With TLS, clients connect using:
```text
/dns4/relay.yourdomain.com/tcp/443/wss/p2p/<RELAY_PEER_ID>
```

### 2.7 Environment Variables

The relay server reads the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `WS_PORT` | WebSocket listen port | `9001` |
| `TCP_PORT` | TCP listen port | `9002` |
| `WS_LISTEN` | Full WebSocket listen multiaddr | `/ip4/0.0.0.0/tcp/${WS_PORT}/ws` |
| `TCP_LISTEN` | Full TCP listen multiaddr | `/ip4/0.0.0.0/tcp/${TCP_PORT}` |
| `DOCUMENT_PUBLISH_PATH` | Pubsub topic for document publish notifications | `/documents` |
| `EXTRA_TOPICS` | Additional pubsub topics to subscribe to (comma-separated) | *(none)* |
| `TOPIC_ALLOWLIST` | Comma-separated prefixes for auto-subscribe filtering. Set exactly `*` for explicit open mode. | `/document/,/documents` |
| `MAX_AUTO_TOPICS` | Hard cap on auto-subscribed topics to prevent unbounded memory growth | `1000` |
| `MAX_AUTO_TOPICS_PER_PEER` | Hard cap on dynamic topics tracked for one remote peer | `32` |
| `GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER` | Ingestion-layer topic-name byte budget for one remote peer | `65536` |
| `MAX_CONNECTIONS` | Global ceiling for established libp2p transport connections | `256` |
| `RELAY_IDENTITY_KEY_PATH` | Persistent app-managed libp2p private-key file | `./relay-identity.key` |
| `READINESS_PORT` | Internal HTTP `/livez` and `/readyz` port | `9000` |
| `RELAY_MAX_RESERVATIONS` | Active Circuit Relay v2 reservation cap | `128` |
| `RELAY_RESERVATION_TTL_MS` | Reservation lifetime before renewal | `600000` |
| `RELAY_MAX_CIRCUIT_DURATION_MS` | Per-circuit duration limit | `1800000` |
| `RELAY_MAX_CIRCUIT_BYTES` | Per-circuit byte limit | `16777216` |

`TOPIC_ALLOWLIST` applies only to GossipSub topics that the relay node
auto-subscribes to. It cannot inspect or restrict opaque, Noise-encrypted
Circuit Relay streams and is not an authorization control. HOP/STOP stream
limits are per connection; `MAX_CONNECTIONS` is the separate global transport
connection ceiling. The pinned dependency may retain a disconnected reservation
until its 10-minute TTL expires. The 128-reservation cap bounds capacity while
those stale entries remain. `MAX_AUTO_TOPICS` bounds total dynamic subscriptions;
`MAX_AUTO_TOPICS_PER_PEER` prevents one peer from consuming that global allowance.
`GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER` also bounds remote topic metadata before
the relay's application-level registry receives subscription events.

The relay-info.json output path is determined automatically: `/shared/relay-info.json` if the `/shared` directory exists (Docker volume), otherwise `./relay-info.json` in the working directory.

---

## 3. Production Multi-Server Deployment

> **See also:** [`docs/deployment.md`](../docs/deployment.md) is the
> authoritative operations reference for running the relay/bootstrap server
> (Docker, TLS, multi-relay, Kubernetes, monitoring, troubleshooting).
> The sections below give a higher-level topology overview; where the two
> documents disagree on relay operations, `docs/deployment.md` wins.

### 3.1 Architecture

For production with 100+ peers, deploy multiple relay nodes. Note that each
relay has its own libp2p peer ID, so a single load-balanced hostname that
routes clients to arbitrary backends will break dialing of
`/.../p2p/<peerId>` addresses. The supported pattern is one public DNS name
per relay (clients are configured with all of them); see
[`docs/deployment.md`](../docs/deployment.md) for details.

```text
                          ┌──────────────┐
                          │   DNS / LB   │
                          │ relay.app.com│
                          └──────┬───────┘
                                 │
                 ┌───────────────┼───────────────┐
                 │               │               │
          ┌──────┴──────┐ ┌─────┴──────┐ ┌──────┴──────┐
          │  Relay #1   │ │  Relay #2  │ │  Relay #3   │
          │ (Region A)  │ │ (Region B) │ │ (Region C)  │
          │ Port 9001   │ │ Port 9001  │ │ Port 9001   │
          │ Port 9002   │ │ Port 9002  │ │ Port 9002   │
          └──────┬──────┘ └─────┬──────┘ └──────┬──────┘
                 │              │               │
                 └──────────────┼───────────────┘
                                │ (TCP mesh between relays)
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
         ┌────┴────┐      ┌────┴────┐      ┌────┴────┐
         │Browser  │      │Browser  │      │Pinning  │
         │ Peers   │      │ Peers   │      │ Node    │
         └─────────┘      └─────────┘      └─────────┘
```

### 3.2 Recommended Topology by Scale

#### Small (10-50 peers)
- 1 relay/bootstrap server
- Public STUN servers
- Optional: 1 pinning node

#### Medium (50-500 peers)
- 2-3 relay/bootstrap servers in different regions
- Each relay connects to the others via TCP (port 9002)
- Multiple bootstrap addresses in client config
- 1 pinning node
- Consider adding a TURN server (coturn)

#### Large (500-1000+ peers)
- 3-5 relay/bootstrap servers, geographically distributed
- Relay nodes form a full mesh via TCP
- DNS-based load balancing or anycast
- Multiple pinning nodes
- Dedicated DHT bootstrap nodes (set `clientMode: false`)
- TURN server cluster
- Monitoring and alerting

### 3.3 Multi-Relay Client Configuration

When multiple relay nodes are available, configure clients with all bootstrap addresses:

```typescript
const config = defaultNodeConfig({
  list: [
    '/dns4/relay1.yourdomain.com/tcp/443/wss/p2p/<PEER_ID_1>',
    '/dns4/relay2.yourdomain.com/tcp/443/wss/p2p/<PEER_ID_2>',
    '/dns4/relay3.yourdomain.com/tcp/443/wss/p2p/<PEER_ID_3>',
  ],
});
```

The client will attempt to connect to all bootstrap nodes. Once connected to any one, pubsub peer discovery will find the rest of the network.

### 3.4 Relay Node Inter-Connection

Relay nodes should connect to each other so GossipSub messages propagate across the entire network. Configure each relay to bootstrap from the others:

```typescript
// In relay-server/src/index.ts, add bootstrap for peer relays
peerDiscovery: [
  bootstrap({
    list: [
      '/ip4/<RELAY_2_IP>/tcp/9002/p2p/<RELAY_2_PEER_ID>',
      '/ip4/<RELAY_3_IP>/tcp/9002/p2p/<RELAY_3_PEER_ID>',
    ],
  }),
  pubsubPeerDiscovery({
    topics: [PUBSUB_PEER_DISCOVERY_TOPIC],
  }),
],
```

### 3.5 Load Balancing

**WebSocket connections are long-lived.** Standard HTTP round-robin load balancing does not apply well. Guidelines:

- A **TLS-terminating reverse proxy** (nginx, Caddy, Traefik) in front of a single relay is fine and required for `wss://` in production (see Section 2.6). The proxy terminates TLS and forwards WebSocket frames transparently via `Upgrade` headers — this is technically Layer 7 but preserves the connection end-to-end.
- Do **not** use a **connection-splitting proxy** that terminates one WebSocket and opens a new upstream WebSocket, as this breaks libp2p's connection state and multiplexed streams.
- For **multiple relay nodes**, give clients all relay addresses (one
  multiaddr per relay, each with its own peer ID) and let libp2p handle
  connection management. A single shared hostname that load-balances across
  backends with different peer IDs is **not** supported. Source-IP hashing
  does not pin a peer ID. Use one hostname/SNI route per durable relay identity;
  DNS round-robin on a single hostname has the same problem.

### 3.6 Monitoring and Health Checks

The standard relay Dockerfile waits for the internal readiness endpoint:

```dockerfile
HEALTHCHECK --interval=3s --timeout=3s --retries=20 --start-period=5s \
  CMD node -e "fetch('http://127.0.0.1:9000/readyz').then((response) => \
    process.exit(response.ok ? 0 : 1)).catch(() => process.exit(1))"
```

**Metrics to monitor:**
- Number of connected peers (`libp2p.getPeers().length`)
- Number of active relay reservations
- GossipSub mesh size per topic
- Memory usage (grows with number of connections)
- Bandwidth usage (grows with message volume)

### 3.7 Resource Requirements

The following are planning examples, not measured Peerborne capacity tiers.
Benchmark your traffic pattern before choosing a production size.

| Scale | CPU | RAM | Bandwidth | Storage |
|-------|-----|-----|-----------|---------|
| Small (10-50 peers) | 1 vCPU | 512 MB | 10 Mbps | 1 GB |
| Medium (50-500 peers) | 2 vCPU | 1-2 GB | 100 Mbps | 10 GB |
| Large (500+ peers) | 4+ vCPU | 4+ GB | 1 Gbps | 50+ GB |

Storage is only significant for pinning nodes. Relay-only nodes have minimal storage needs.

### 3.8 Backup and Recovery

**Relay payload forwarding is stateless, but relay identity is not.** Preserve
the file named by `RELAY_IDENTITY_KEY_PATH` to retain the public peer ID. The
standard Docker image stores it under `/shared`, alongside `relay-info.json`.
Losing it changes the peer ID; exposing it compromises the relay identity.

**Pinning nodes are stateful.** Back up:
- The IDB blockstore/datastore (or underlying storage)
- The node's private key for consistent identity

---

## 4. Public Alternatives

### 4.1 STUN Servers

Public STUN servers provide NAT type detection and public address discovery at no cost. They handle only the signaling phase, not actual data traffic.

| Provider | Address | Notes |
|----------|---------|-------|
| Google | `stun:stun.l.google.com:19302` | Most widely used |
| Google (backup) | `stun:stun1.l.google.com:19302` | Secondary |
| Twilio | `stun:global.stun.twilio.com:3478` | |
| Mozilla | `stun:stun.services.mozilla.com:3478` | |

These are used by the browser's WebRTC stack automatically. libp2p's `@libp2p/webrtc` uses the browser's defaults.

### 4.2 TURN Servers

TURN servers relay actual data traffic, so they are not available for free at scale. Options:

| Provider | Type | Pricing |
|----------|------|---------|
| [coturn](https://github.com/coturn/coturn) | Self-hosted (open source) | Free (your infrastructure) |
| [Twilio Network Traversal](https://www.twilio.com/stun-turn) | Hosted | Pay per GB |
| [Xirsys](https://xirsys.com/) | Hosted | Free tier + paid plans |
| [Metered](https://www.metered.ca/stun-turn) | Hosted | Free tier (500 MB/month) |

### 4.3 IPFS Pinning Services

For persistent data storage without running your own pinning node:

| Provider | Free Tier | Notes |
|----------|-----------|-------|
| [Pinata](https://www.pinata.cloud/) | 500 MB | Popular, REST API |
| [web3.storage](https://web3.storage/) | 5 GB | Built on Filecoin |
| [Infura IPFS](https://infura.io/) | 5 GB | Ethereum-focused |
| [Filebase](https://filebase.com/) | 5 GB | S3-compatible API |

**Note:** These services pin standard IPFS content. Peerborne's CRDT data stored as IPFS blocks can be pinned by any IPFS-compatible pinning service, but the service cannot interpret CRDT semantics or reconstruct the document's keys, graph state, or metadata. Peerborne does not yet provide the complete publication and recovery path needed to use `PeerborneNode` as a durability service.

### 4.4 Cost Considerations

| Component | Self-Hosted Cost | Hosted/Managed Cost |
|-----------|-----------------|---------------------|
| Bootstrap/Relay | $5-20/month (small VPS) | ~$2/month (Fly.io `shared-cpu-1x`) |
| STUN | Free (use public) | Free |
| TURN | $10-50/month (VPS + bandwidth) | $0.40-1.00 per GB relayed |
| Pinning | $5-20/month (storage VPS) | Free tier usually sufficient for dev |

**Key takeaway:** The checked-in Fly shape is a low-cost initial-release
starting point, not a production capacity claim. Compute, volume storage, and
bandwidth are billed separately; verify current pricing before deployment. See
[Section 5](#5-flyio-deployment) for the deployment steps.

---

## 5. Fly.io Deployment

[Fly.io](https://fly.io/) is a managed container platform and a convenient
deployment target for the relay server. The checked-in `shared-cpu-1x`/256 MB
shape has not been capacity-tested; measure connection, memory, and bandwidth
behavior before increasing traffic.

Fly.io pricing and allowances change over time. Check the current
[Fly.io pricing documentation](https://fly.io/docs/about/pricing/) before
committing to a deployment.

### 5.1 Prerequisites

1. **Install `flyctl`** — the Fly.io CLI:
   ```bash
   # macOS
   brew install flyctl

   # Linux / WSL
   curl -L https://fly.io/install.sh | sh

   # Windows (PowerShell)
   iwr https://fly.io/install.ps1 -useb | iex
   ```
   See [fly.io/docs/flyctl/install/](https://fly.io/docs/flyctl/install/) for all options.

2. **Create a Fly.io account** at [fly.io](https://fly.io/) and add a payment method.
   Billing only starts when you deploy a machine.

3. **Authenticate:**
   ```bash
   fly auth login
   ```

### 5.2 Deploy

The relay server ships with a `fly.toml` in `relay-server/`. All Fly commands
must be run from inside the `relay-server/` directory (where `fly.toml` lives).

```bash
cd relay-server
```

#### First-time setup

```bash
# Import fly.toml without deploying yet.
# When prompted, enter a unique app name (e.g. "myapp-relay") and
# confirm the primary region. Do NOT let fly launch override fly.toml.
fly launch --no-deploy

# Create the volume required by fly.toml in its primary region.
fly volumes create peerborne_relay_data --region iad --size 1

# Deploy the image built from relay-server/Dockerfile
fly deploy
```

`fly deploy` builds the Docker image on Fly's remote builder and deploys it.
No local Docker installation is required.

#### Subsequent deploys

```bash
fly deploy
```

### 5.3 Find the Relay's Multiaddr

After deploying, retrieve the public hostname and peer ID:

```bash
# Show the app hostname and IP
fly info

# Stream live logs to find the peer ID printed at startup
fly logs
```

The startup log includes a line like:

```text
PeerId: 12D3KooWAbc123...
Multiaddrs: [ '/ip4/0.0.0.0/tcp/9001/ws/p2p/12D3KooWAbc123...' ]
```

The public multiaddr your clients should use is constructed from the Fly hostname:

```text
/dns4/<APP_NAME>.fly.dev/tcp/443/wss/p2p/<PEER_ID>
```

> **TLS and WSS:** The checked-in raw TCP service maps external port 443 to
> internal port 9001 with Fly's `tls` handler:
> ```toml
> [[services.ports]]
>   port = 443
>   handlers = ["tls"]
> ```
> Fly terminates TLS and forwards the WebSocket upgrade to the relay. Do not
> publish the internal 9001 address to an HTTPS browser. Clients connect with:
> ```text
> /dns4/<APP_NAME>.fly.dev/tcp/443/wss/p2p/<PEER_ID>
> ```

Fly monitors the private HTTP `/readyz` check for deployment health, while the
public WSS service uses a TCP routing check. A successful `/readyz` is local
startup evidence and does not itself gate Fly routing or prove a remote Circuit
Relay reservation.

### 5.4 Client Configuration

Once you have the multiaddr, configure your Peerborne client.

In a **browser** application, combine `defaultConfig` and
`defaultBootstrapConfig` (both exported from `@peerborne/core`):

```typescript
import {
  defaultConfig,
  defaultBootstrapConfig,
} from '@peerborne/core';

const config = defaultConfig(
  defaultBootstrapConfig([
    '/dns4/myapp-relay.fly.dev/tcp/443/wss/p2p/12D3KooWAbc123...',
  ]),
);
```

In a **Node** process, import the Node-only helper from the `/node` subpath:

```typescript
import { defaultNodeConfig } from '@peerborne/core/node';

const config = defaultNodeConfig({
  list: [
    '/dns4/myapp-relay.fly.dev/tcp/443/wss/p2p/12D3KooWAbc123...',
  ],
});
```

Replace `myapp-relay` with your app name and `12D3KooWAbc123...` with the peer ID
from `fly logs`.

### 5.5 Environment Variables

Override relay defaults by adding entries to `[env]` in `fly.toml`:

```toml
[env]
  TOPIC_ALLOWLIST  = "/document/,/documents"
  MAX_AUTO_TOPICS  = "500"
  MAX_AUTO_TOPICS_PER_PEER = "32"
  GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER = "65536"
  MAX_CONNECTIONS  = "256"
  EXTRA_TOPICS     = "/documents"
```

For secrets (e.g. future auth tokens), use `fly secrets set` instead:

```bash
fly secrets set MY_SECRET=value
```

### 5.6 Scaling and Cost Management

The volume-backed `fly.toml` is a one-Machine deployment. Inspect or restore
that Machine with:

```bash
# Ensure one Machine is present
fly scale count 1

# Check current machine status
fly status
```

**Stopping the VM entirely** to stop compute charges:

```bash
fly scale count 0   # stops all machines; attached volume storage is still billed
fly scale count 1   # restart when needed
```

The checked-in Fly configuration mounts `/data`, so scaling to zero and back
preserves the peer ID. Losing or replacing that volume creates a new identity.
Do not scale one volume-backed identity to concurrent machines; provision a
distinct volume, hostname, and advertised peer ID for each relay instead.

### 5.7 Caveats

| Topic | Details |
|-------|---------|
| **Cost** | ~$2/month for `shared-cpu-1x 256mb`. Bandwidth is billed above regional thresholds (see [pricing page](https://fly.io/docs/about/pricing/)). |
| **Scale-to-zero** | Fly.io can suspend machines on inactivity if configured, but this is opt-in (`auto_stop_machines = true` in `fly.toml`). The provided `fly.toml` does not enable it, so the relay runs continuously. Stopped compute and attached volume storage have separate billing. |
| **Single-instance** | Capacity and failover remain unvalidated. For another relay, create a separate app/volume/hostname so clients can pin its distinct peer ID; do not load-balance one hostname across identities. |
| **Peer ID stability** | `/data/relay-identity.key` on the Fly volume preserves the peer ID. Back up the volume if retaining pinned client multiaddrs matters. |
| **Browser-only network surface** | The checked-in Fly app publishes WSS on 443 only. It does not publish raw TCP 9002 because this launch configuration does not provision a dedicated IPv4 address for that service. |

---

## 6. Docker Deployment Configs

Ready-to-use Docker configurations are provided in `guides/docker/`.

### 6.1 Files

| File | Purpose |
|------|---------|
| `docker-compose.single.yaml` | All-in-one single server deployment |
| `docker-compose.production.yaml` | Production multi-relay deployment |
| `Dockerfile.relay` | Circuit relay / bootstrap node |
| `Dockerfile.bootstrap` | DHT bootstrap node (for large deployments) |

### 6.2 Single-Server Deployment

```bash
# Start the relay server
docker compose -f guides/docker/docker-compose.single.yaml up -d

# View relay connection info
docker compose -f guides/docker/docker-compose.single.yaml exec relay cat /shared/relay-info.json

# View logs
docker compose -f guides/docker/docker-compose.single.yaml logs -f relay

# Stop
docker compose -f guides/docker/docker-compose.single.yaml down
```

### 6.3 Production Deployment

```bash
# Start all services
docker compose -f guides/docker/docker-compose.production.yaml up -d

# Monitor health
docker compose -f guides/docker/docker-compose.production.yaml ps
```

> **Scaling:** The production compose file defines individually named relay services
> (`relay-1`, `relay-2`) rather than a single scalable `relay` service, because each
> relay node needs unique port mappings and may run on separate hosts. To add more
> relay nodes, duplicate a `relay-N` service block in the compose file with
> appropriate port offsets.

See individual Dockerfile documentation in `guides/docker/` for build instructions.

---

## 7. Troubleshooting

### 7.1 Common Connectivity Issues

#### "Cannot connect to relay"

**Symptoms:** Browser shows "error-no-relay" or connection timeout.

**Causes and solutions:**
1. **Relay not running:** Check `docker compose ps` and `docker compose logs relay`
2. **Wrong multiaddress:** Verify the peer ID and IP in the client config match the relay's output
3. **Port blocked:** Ensure port 9001 is open in firewall/security group
4. **TLS required:** When serving the client over HTTPS, browsers' mixed-content policy blocks plain `ws://`, so the relay multiaddr must use `wss://`. (Plain `ws://` is fine from `localhost` or HTTP origins.) Set up a reverse proxy with TLS (see Section 2.6).
5. **CORS issues:** Not applicable to WebSocket connections, but if serving config.json, ensure CORS headers are set

#### "Peers connect but messages don't sync"

**Symptoms:** Peers appear connected but GossipSub messages are not received.

**Causes and solutions:**
1. **Relay not forwarding:** Ensure the relay has `floodPublish: true` and `canRelayMessage: true` in GossipSub config
2. **Topic mismatch:** Verify both peers subscribe to the same topic (e.g., `/document/<id>`)
3. **Mesh not formed:** GossipSub mesh takes 5-10 seconds to form. Wait or send warmup messages
4. **libp2p version mismatch:** Use `@libp2p/gossipsub` v17.x with libp2p v3.x. Verify that both packages resolve to compatible `@libp2p/interface` v3.x versions.

#### "WebRTC connection fails"

**Symptoms:** Peers connect via relay but never upgrade to direct WebRTC.

**Causes and solutions:**
1. **Symmetric NAT on both sides:** Direct WebRTC is impossible. The relay connection is the final path. Consider adding a TURN server
2. **STUN failure:** Check browser console for ICE candidate errors. Try a different STUN server
3. **Firewall blocking UDP:** WebRTC uses UDP. Corporate firewalls may block it. Circuit relay (TCP-based) is the fallback

### 7.2 Debugging Peer Discovery

Enable verbose logging to trace peer discovery:

```bash
# On the relay server
DEBUG=libp2p:* node dist/index.js

# In the browser app
localStorage.setItem('debug', 'libp2p:*')
```

**What to check:**
1. `libp2p:identify` — Verify the identify protocol completes between peers
2. `libp2p:gossipsub` — Check that peers join the mesh and exchange messages
3. `libp2p:circuit-relay-v2` — Verify relay reservations are established

### 7.3 Verifying the Relay is Working

1. **Check relay startup output:**
   ```text
   PeerId: 12D3KooW...
   Multiaddrs: [ '/ip4/0.0.0.0/tcp/9001/ws/p2p/12D3KooW...' ]
   Subscribed to topics: swarmdb._peer-discovery._p2p._pubsub /documents
   ```

2. **Check relay-info.json:**
   ```bash
   cat relay-info.json
   # Should contain: { "peerId": "...", "multiaddrs": [...], "wsMultiaddr": "..." }
   ```

3. **Test WebSocket connectivity:**
   ```bash
   # From another machine, test that the WebSocket port is open
   nc -zv <RELAY_IP> 9001
   ```

4. **Use the integration test app:**
   ```bash
   docker compose -f docker-compose.integration.yaml up -d
   # Open http://localhost:3001 and http://localhost:3002 in two browsers
   # Both should show "connected-to-relay" status and discover each other
   ```

### 7.4 Firewall and NAT Configuration

**Minimum ports to open on the relay server:**

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 9001 | TCP | Inbound | WebSocket connections from browsers |
| 9002 | TCP | Inbound | TCP connections from other nodes |

**For browsers behind corporate firewalls:**
- Ensure outbound TCP to port 9001 (or 443 if using TLS) is allowed
- Ensure outbound UDP to STUN server port (19302 for Google) is allowed
- If UDP is blocked entirely, WebRTC will not work. Circuit Relay (TCP-based) will be the only transport

**Cloud provider security groups:**
- AWS: Add inbound rules for TCP 9001 and 9002
- GCP: Add firewall rules for tcp:9001 and tcp:9002
- Azure: Add NSG rules for TCP 9001 and 9002
- DigitalOcean: Configure cloud firewall for TCP 9001 and 9002

### 7.5 Performance Tuning

**Relay server:**
- Increase `ulimit -n` (file descriptor limit) for many concurrent connections: `ulimit -n 65535`
- Set `NODE_OPTIONS=--max-old-space-size=4096` for large deployments
- Monitor event loop lag; high lag indicates the relay is overloaded

**GossipSub tuning (relay-server/src/index.ts):**
```typescript
gossipsub({
  allowPublishToZeroTopicPeers: true,
  canRelayMessage: true,
  floodPublish: true,        // Ensures messages reach all peers (important for relay)
  // For large deployments, consider:
  // D: 6,                   // Target mesh degree (default 6)
  // Dlo: 4,                 // Low watermark (default 4)
  // Dhi: 12,                // High watermark (default 12)
  // heartbeatInterval: 700, // Heartbeat interval in ms (default 1000)
})
```

**Client-side tuning:**
```typescript
circuitRelayTransport({
  reservationConcurrency: 1,  // Number of concurrent relay reservations
  // Increase for better redundancy:
  // reservationConcurrency: 3,
})
```
