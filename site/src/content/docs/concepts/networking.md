---
title: Networking
description: Peer discovery, transport protocols, NAT traversal, and the relay trust model in Peerborne.
---

## Overview

Peerborne uses **libp2p** for all peer-to-peer networking. libp2p is a modular networking stack that handles transport, stream multiplexing, connection encryption, peer discovery, NAT traversal, and pubsub messaging — all in one framework.

## Transport protocols

Peerborne supports these transport protocols. The actual set used depends on the runtime (browser vs. Node.js) and network topology:

| Transport | Runtime | Purpose |
|---|---|---|
| **WebSocket** | Browser, Node.js | Reliable bidirectional stream. Used for relay and bootstrap connections. |
| **WebRTC** | Browser | Browser-to-browser direct connections (STUN improves NAT traversal; TURN or Circuit Relay may be needed for restrictive NATs). |
| **WebRTC Direct** | Node.js | Node-to-Node direct connections. |
| **WebTransport** | Browser (Chrome 97+) | Modern, low-latency QUIC-based transport. |
| **TCP** | Node.js | Traditional stream transport for Node.js peers. |

### Transport selection

```ts
import { defaultConfig, defaultBootstrapConfig } from '@peerborne/core';

const bootstrapPeers = [
  '/dns4/relay.example.com/tcp/443/wss/p2p/12D3KooW...',
];
const config = defaultConfig(defaultBootstrapConfig(bootstrapPeers));

// Pass config to Peerborne.initialize()
await swarm.initialize(config);
```

In practice, browser peers typically use WebSocket to reach a relay, and may upgrade to WebRTC or WebTransport for direct peer connections when NAT traversal succeeds.

## PubSub: GossipSub

Document updates are announced and delivered via **GossipSub** — a pubsub protocol built on libp2p. Each document has a corresponding pubsub topic derived from its document ID:

```ts
// Document /todo-list → topic: /document/todo-list
// Changes published to this topic reach all subscribed peers.
```

GossipSub is **best-effort**:

- Messages are relayed through the mesh, not stored
- Peers that join late may miss announcements
- There is no message persistence, acknowledgment, or guaranteed delivery
- Initial load and catch-up use point-to-point bitswap / HTTP fetch, not GossipSub

## Peer discovery

Peerborne peers find each other through several mechanisms:

### Bootstrap nodes

A static list of well-known peers that new nodes connect to first:

```ts
bootstrap: [
  '/dns4/bootstrap.peerborne.dev/tcp/443/wss/p2p/12D3KooW...',
  '/ip4/192.168.1.100/tcp/4002/p2p/12D3KooW...',
]
```

Bootstrap nodes introduce the new peer to the network. They do not store or relay document data.

### Kademlia DHT

Once connected, nodes participate in a distributed hash table (Kademlia) for peer and content routing. The DHT maps peer IDs to multiaddrs and CIDs to providers.

### AutoNAT

AutoNAT determines whether a peer is reachable from the public internet. If a peer is behind NAT, it cannot accept incoming connections and must use a relay.

## NAT traversal

Browsers and most home/office networks are behind NAT, which prevents direct incoming connections. Peerborne uses several mechanisms to work around this:

### Circuit Relay v2

A relay node bridges traffic between two peers behind NAT:

```
Peer A (browser, NAT) ──WebSocket── Relay ──WebSocket── Peer B (browser, NAT)
                    encrypted traffic only          encrypted traffic only
```

The relay forwards encrypted packets. It sees metadata (peer IDs, timing, data volume) but cannot decrypt document content.

### DCUtR (Direct Connection Upgrade through Relay)

After an initial relayed connection, peers attempt to establish a direct WebRTC connection using DCUtR. The relay facilitates the hole-punching handshake; if successful, peers communicate directly, reducing relay load and latency.

### STUN / TURN

- **STUN** servers help peers discover their public IP and port for WebRTC hole-punching.
- **TURN** servers relay media when direct WebRTC connections are impossible (e.g., symmetric NAT). TURN is more expensive than Circuit Relay but handles a broader range of NAT types.

## Relay trust model

Relays are the most important infrastructure component in a Peerborne deployment, and their trust properties matter:

**What relays can see:**
- Peer IDs and multiaddrs of connecting peers
- Connection timing and duration
- Data volume and message frequency
- PubSub topic IDs (derived from document IDs)

**What relays cannot see:**
- Document content (encrypted with AES-GCM)
- Signing keys or document keys
- ACL entries or identity information (embedded in encrypted blocks)

**What relays can do:**
- Drop, delay, or reorder messages
- Terminate transport connections and forward relayed traffic
- Censor specific peers or topics
- Log metadata about who communicates with whom

**What relays cannot do:**
- Decrypt document content without the document key
- Forge application-level signatures without the signing private key
- Authenticate as another peer at the libp2p level (Noise provides end-to-end peer authentication)
- Modify encrypted blocks (detected via CID integrity check)

### Identity pinning risk

A relay that restarts with a new peer ID breaks connections from clients that pinned to the old identity. Mitigation options include using a persistent relay key so the peer ID stays stable across restarts, or using authenticated discovery to learn a trusted new peer ID after the relay restarts. DNS (`/dns4/...`) changes address resolution but `/p2p/<peerID>` still pins the relay identity.

## Operational limits

- **Relay restart changes peer ID.** The current relay implementation generates a new libp2p identity on each restart. Clients must rediscover the new peer ID.
- **No relay meshing.** Each relay operates independently. There is no relay-to-relay routing.
- **Topic allowlists are not authentication.** The relay's `TOPIC_ALLOWLIST` controls which topics it will forward, but does not authenticate publishers.
- **No HTTP health endpoint.** The relay exposes no health-check endpoint for load balancers or monitoring.
- **No durable storage on relay.** The relay does not store messages. If a subscriber is offline, it misses messages.

## CI-backed evidence

Verified in CI:

- WebSocket transport through Circuit Relay in Docker-backed NAT tests
- Cross-NAT encrypted document retrieval (real Peerborne nodes behind NAT)
- Basic peer discovery (bootstrap connection) in integration tests
- GossipSub message delivery in NAT topology

Not verified:

- WebRTC direct connection upgrade (DCUtR)
- WebTransport transport
- Relay failover (kill one relay, verify peers reconnect through another)
- Live post-load convergence under network partition
- AutoNAT detection and relay fallback
- DHT content/provider routing at scale

## Next steps

- [Running a relay](../../cookbook/running-a-relay/) — set up a development relay
- [Security model](../security/) — how the trust model interacts with encryption and ACL
- [Limitations](../limitations/) — complete list of networking gaps
