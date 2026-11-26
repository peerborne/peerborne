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

`defaultConfig` is browser only: it stores blocks and data in IndexedDB, so
`initialize()` rejects with `indexedDB is not defined` under Node.js. Node
processes use `defaultNodeConfig` from `@peerborne/core/node`. Neither default
includes the TCP transport. The Node default's listen addresses bind no local
socket, so a Node process accepts connections only through a Circuit Relay
reservation. To let another node dial it directly, add a listen address that a
configured transport can bind:

```ts
import { defaultBootstrapConfig } from '@peerborne/core';
import { defaultNodeConfig } from '@peerborne/core/node';

const config = defaultNodeConfig(defaultBootstrapConfig([]));
const libp2p = config.helia!.libp2p!;
libp2p.addresses = {
  ...libp2p.addresses,
  listen: [...(libp2p.addresses?.listen ?? []), '/ip4/127.0.0.1/tcp/4010/ws'],
};
```

### Dial policy

Peers learn each other's addresses from identify and the discovery topic, and
Peerborne dials them during loads and catch-up. Both defaults therefore refuse
addresses outside the public internet, so a remote peer cannot make a node
connect to services on its host or network:

- `defaultNodeConfig` installs `denyLocalNetworkDial`. It refuses loopback,
  private, shared (CGNAT), link-local (including the `169.254.169.254` cloud
  metadata service), unique-local and other special-purpose IP addresses, Unix
  sockets, and DNS names that cannot be public, such as `localhost`,
  `*.local`, `*.internal` and single-label names. A public DNS name that
  resolves to a private address is not detected.
- `defaultConfig` keeps libp2p's browser connection gater, which refuses
  private and loopback addresses and insecure `/ws` WebSockets.
- The background upgrade of a relayed connection dials only public addresses.

A node that dials the loopback listener above, a LAN peer, a Docker network
or a relay on `127.0.0.1` or plain `/ws` opts in with the third argument of
either builder:

```ts
const config = defaultNodeConfig(defaultBootstrapConfig([]), undefined, {
  allowLocalNetworkDials: true,
});
```

The option admits every address and sets
`PeerborneConfig.allowLocalNetworkDials`, which also lets relayed connections
upgrade over local addresses. A custom libp2p config chooses its own
`connectionGater`; `denyLocalNetworkDial` and `isLocalNetworkAddress` are
exported for it.

## PubSub: GossipSub

Document updates are announced and delivered via **GossipSub** — a pubsub protocol built on libp2p. Each document has a corresponding pubsub topic derived from its document ID:

```ts
// Document /todo-list → topic: /peerborne/document/v3/todo-list
// Changes published to this topic reach all subscribed peers.
```

Relays admit the current document namespace by default. A custom
`pubsubDocumentPrefix` requires a matching slash-terminated namespace in every
relay's `TOPIC_ALLOWLIST`. With an empty prefix, allow each concrete document
topic or explicitly select unrestricted `*` mode. All peers must use the same
runtime and topic prefix.

Topic names are public routing labels, not authentication, authorization, or
wire validation. Application URLs such as `/document/:id`
are unrelated and do not change.

GossipSub is **best-effort**:

- Messages are relayed through the mesh, not stored
- Peers that join late may miss announcements
- There is no message persistence, acknowledgment, or guaranteed delivery
- Initial load and catch-up use point-to-point bitswap / HTTP fetch, not GossipSub

### Receive capacity

Each open document processes at most 16 frames and 16 MiB of ciphertext at a
time, and all documents together at most 64 frames and 64 MiB. A frame that
arrives while the document's budget is full is skipped, but the latest skipped
frame of each GossipSub sender is retained, holding one of the shared credits.
One at a time, a retained frame is checked to decrypt under the document's
current key; a frame that passes is kept and processed once a credit frees. A
writer's later frames carry its earlier changes inline, so this recovers the
end of a typing burst. A sender's frame is only replaced by a newer one from
the same sender, and a frame that fails the check, including one under a
retired epoch key, is never kept. At most eight senders and 16 MiB are kept
per document; sync requests are dropped first, then the oldest frame. A frame
skipped while the shared credits are exhausted is not retained.

### Frame size

`@libp2p/gossipsub` sends and accepts RPCs of at most 4 MiB, and the outbound
limit is not configurable. A longer RPC is never sent: `publish()` resolves
with no recipients and no error. Peerborne caps one serialized sync message at
3.5 MiB (`MAX_GOSSIP_SYNC_MESSAGE_BYTES`), leaving room for encryption, the
GossipSub envelope and piggybacked control messages.

Every frame carries the retained change tree inline, so the cap is split in
half:

- **One change** may need at most 1.75 MiB on its own
  (`MAX_CHANGE_FRAME_BYTES`). A larger one is refused before a block is
  stored: `change()` or `endChange()` rejects with `GossipFrameLimitError`
  and nothing reaches history. The edit is already in the local document,
  because Yjs edits in place and Automerge marks the previous document
  outdated, so the instance is retired as for an oversized block; reopen it
  from accepted state and split the edit.
- **The retained tree** is compacted once the change frame that carried it
  passes 1.75 MiB: the writer snapshots and keeps only its newest changes, up
  to 512 KiB of payload, and a depth-bound compaction keeps no more than that
  either. A writer that adopts a published change frame prunes the same tree
  the same way. A `requestSync()` reply does not trigger this, since it can
  carry a snapshot the author never published. Retained trees then match, but
  load digests can still differ, because each writer signs its own snapshot.
  A reader keeps the larger tree, as with depth-bound compaction. A peer that
  missed the pruned changes recovers them through
  [automatic catch-up](#automatic-catch-up).
- **A membership change** is never refused for retained size: if its frame
  would not fit, the tree is compacted first and the change published again.

A `requestSync()` reply that does not fit GossipSub, usually because of its
snapshot, is not sent and does not use up the request or the response rate
limit. The responder logs a warning, and the requester loads the document
instead; see [large catch-up](#large-catch-up).

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

![Two NAT-isolated Chromium peers loading encrypted document history through Circuit Relay after the test gives peer B peer A's relayed circuit address; an optional direct path is shown as unverified.](../../../assets/diagrams/browser-relay-path.svg "The cross-NAT path is verified through Circuit Relay; a direct path remains unverified.")

**Evidence boundary:** The solid relay path represents the narrow CI-backed result: one user identity runs in two NAT-isolated Chromium processes, the document key is restored to the second device out of band, and that device loads existing encrypted document history through Circuit Relay. The test reads peer A's `/p2p-circuit/` address and has peer B dial it explicitly; it does not establish a separate bootstrap-discovery proof edge. The topology has app servers and a relay but no application database service. It does not demonstrate live post-load synchronization, invitation delivery, direct WebRTC/DCUtR, relay failover, or production deployment behavior.

The relay forwards encrypted packets. It sees metadata (peer IDs, timing, data volume) but cannot decrypt document content.

Relayed connections are limited connections in libp2p. Peerborne runs Bitswap on them by default (`helia.bitswap.runOnLimitedConnections: true`), so a peer reachable only through a relay can still fetch change blocks within the relay's circuit data and duration limits. Setting it to `false` stops block fetches over relays, which can stall loads and invitations.

Streams that accept limited connections, Bitswap included, open on the existing relayed connection to the peer. On its own, libp2p reuses only unlimited connections and dials a new circuit for each such stream. libp2p limits inbound connections per host, five per second by default, and counts every relayed connection against the relay's host, so a burst of block requests would be refused and the load would stall. The stream opens on the relayed connection at once. When the peer also has a direct or WebRTC address that this node has a transport for, one libp2p dial per relayed connection runs in the background to upgrade it, and later streams use the unlimited connection if that dial succeeds. Streams that need an unlimited connection always get the libp2p dial, and DCUtR upgrades are unaffected.

Different peers that arrive through one relay share that per-host budget. `defaultConfig` and `defaultNodeConfig` therefore set `connectionManager.inboundConnectionThreshold` to `DEFAULT_INBOUND_CONNECTION_THRESHOLD` (128 per second). libp2p still bounds open connections with `maxConnections`, and refuses a new inbound connection while 10 upgrades are pending (`maxIncomingPendingConnections`), so more than ten peers arriving at the same moment still see refusals. A custom libp2p config should set the same option; with the libp2p default, the sixth peer to join or reconnect through a relay within a second is refused.

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
- Document content (encrypted with the document key; AES-GCM by default)
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

A relay that loses its identity file restarts with a new peer ID and breaks clients pinned to the old identity. The standard relay image persists an app-managed key on its `/shared` volume; hosted deployments must likewise mount durable storage at `RELAY_IDENTITY_KEY_PATH`. DNS (`/dns4/...`) changes address resolution but `/p2p/<peerID>` still pins the relay identity. Never share one private identity between concurrently running relays.

## Diagnose connection failures

Use the SDK's structured progress callback to distinguish dialing, transport
opening, secure-channel setup, retries, and final failure:

```ts
await peerborne.connect([relayMultiaddr], {
  signal: AbortSignal.timeout(30_000),
  maxAttempts: 3,
  retryDelayMs: 1000,
  onProgress: (event) => console.info('Peerborne connection', event),
});
```

Events contain only stage, address index/count, attempt limits, elapsed time,
cancellation state, and a fixed error-type label. Native progress details,
addresses, raw errors, invitation URLs, and document data are not included.
The rejected error remains available to the caller for controlled debugging;
use the progress event when recording diagnostics. Observer exceptions and
rejections are isolated from the operation.

The default is one attempt. At most three attempts are allowed, and only
transport failures, closed connections, or timeouts qualify for retry.
Authentication failures and caller cancellation stop the attempt sequence.
An established transport does not establish a relay reservation or verify an
invitation. Applications should report those later phases separately.
The optional `NetworkStats` container still requires explicit `record*()` calls.

## Automatic catch-up

GossipSub can drop frames, a writer can edit while disconnected, and a writer
that has pruned its retained tree cannot resend older changes inline. Every
open default (non-coordinated) document therefore asks members for missed
updates without an application call. It sends the signed sync request that
`document.requestSync()` sends:

- shortly after `open()`, `create()`, invitation acceptance or a restored
  checkpoint;
- when a peer subscribed to the document's topic connects or reconnects;
- when the CRDT holds remote changes that wait for missing dependencies
  (Automerge's queued changes, Yjs pending structs or deletions);
- when a frame names a change that cannot be fetched;
- when a verified member's request names, as its own head, a change this
  replica does not hold;
- otherwise every 30 to 60 s, drawn uniformly around 45 s.

A request names the requester's head, up to 32 recent tips, its known
snapshots and its libp2p PeerId. It is signed by a current reader or writer
and encrypted with the document key. A request is ignored, and rejected by
topic validators, unless that PeerId is the GossipSub publisher of its frame,
so a member cannot speak for other peers. Members learn the requester's
PeerId, which GossipSub's signed `from` field already shows them. A writer answers only
when the requester lacks its head or its snapshot, with an ordinary signed
update, so every reply passes the normal signature, ACL and admission checks.
Replies go to the whole topic, so one request repairs every replica that is
behind in the same way.

### Bounds

- Signals that arrive within 0.5 to 1.5 s are coalesced into one request. A
  document sends at most one request per 5 s (`minRequestIntervalMs`), and
  while a detected gap stays open that spacing doubles up to the periodic
  interval.
- Advertised heads are counted per member signing key, however many PeerIds
  the member uses. One member triggers at most one request per kind of signal
  per 30 s (`peerCooldownMs`), and a document verifies at most four
  advertisements at once, refilled at one per 2 s.
- Topic names are public, so a peer subscribing to the topic counts on its
  own only if it recently sent a verified request or writer frame. All other
  peers share one cooldown per document.
- An advertisement expires after three periodic intervals, a member's newer
  advertisement replaces its older one, and a verified request naming a head
  the replica holds retracts it. An expired or unresolved advertisement
  closes as `abandoned`, not `repaired`, and the member's advertisements are
  then ignored for 5 minutes, doubling to 2 hours.
- A periodic request is postponed once when another member asks with the same
  head, since writers' replies reach every subscriber.
- All documents of one Peerborne instance share a request bucket of 16,
  refilled at four per second. Periodic requests leave four tokens for
  requests a gap or a new peer triggered, and the periodic interval stretches
  with the number of open documents so that they plan at most half of the
  rate (beyond about 90 documents at the default interval). At most one
  catch-up load runs at a time, and at most one per peer every 10 s.
- Responders keep the existing limits: one reply per document every 2 s, a
  60 s freshness window and a 128-entry replay ledger, however many members
  ask.
- Change blocks a frame cites without carrying are fetched within that
  frame's bounded fetches; the ones left unfetched, failed or waiting out a
  retry delay are reported to catch-up as missing changes. A cross-linked
  change whose inline copy sits below a change the replica already holds,
  such as a snapshot boundary, is taken from the frame instead of being
  fetched.

### Large catch-up

A reply carries the responder's retained tree and, when the requester lacks
it, the snapshot. If that does not fit a GossipSub frame, no reply arrives
and a detected gap stays open; a writer's own request still names its head.
Once the gap outlives the first request by 15 s (`loadAfterMs`), the document
runs the authenticated V4 `load()` if the evidence is strong enough: local
evidence (pending CRDT state or an unfetched change), for at most three loads
per gap, or a head that at least two members advertise. One member, honest
or not, can make replicas ask over gossip but not load. The load prefers the
newest connected writer that named the head. Every load rule applies. It needs
`resolveLoadSecurityCommitments`, and with the quorum enabled the agreeing
peers decide what is served, so a single peer that is ahead of the others is
not loaded from unless `loadQuorumAllowSinglePeer` or a disabled quorum allows
it. Readers are never load targets, because they cannot sign load responses.
A load that leaves an advertised head unknown penalizes its advertisers, and
an unfetched change it does not reveal is not escalated again for an hour.
Each load that leaves anything unresolved doubles the delay before the next,
from 60 s (`loadIntervalMs`) up to 64 minutes; only a repair resets it.
Closing the document aborts a load in progress.

### Configuration and status

```ts
await peerborne.initialize({ ...config, antiEntropy: { enabled: false } });

document.antiEntropyStatus; // enabled, running, phase, gap, requests, loads, ...
document.subscribeToAntiEntropy('status', (event, status) => {
  if (event.type === 'repaired') console.info('caught up', event.afterMs);
});
```

Events are `gap`, `request`, `load`, `repaired` and `abandoned`. Catch-up runs only for
signed documents on a node with a libp2p identity; coordinated documents
request their [controller checkpoint on the document topic](https://github.com/Peerborne/peerborne/blob/main/docs/coordinated-document-security.md#automatic-catch-up-on-the-document-topic).
`requestSync()` still sends a request at once, within its 2 s rate limit, and
restarts the periodic delay.

## Resume a saved document

An application restoring an authenticated checkpoint reconnects its transport
and opens the restored document; catch-up then requests missed updates.
Fresh nonces, timestamp bounds, recent-request deduplication and response
throttling bound replay and amplification, and known roots avoid repeatedly
sending an already received update. Catch-up requires an online member that
holds the missing state and the current key; it does not restore a lost
identity or recover an unknown group-key epoch.

## Operational limits

- **Relay identity requires durable storage.** Restart preserves the peer ID only while the configured identity file survives. Losing it requires clients to learn a new peer ID.
- **No relay meshing.** Each relay operates independently. There is no relay-to-relay routing.
- **Topic allowlists are not Circuit Relay policy.** `TOPIC_ALLOWLIST` controls only which GossipSub topics the relay node auto-subscribes to. It does not inspect or restrict opaque, Noise-encrypted Circuit Relay streams, authenticate publishers, or authorize documents.
- **Readiness is local evidence.** `/readyz` confirms local startup and seed subscriptions, not a remote reservation or end-to-end convergence.
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
