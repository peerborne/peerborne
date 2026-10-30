---
title: Comparisons
description: How Peerborne compares to other local-first, CRDT, and realtime collaboration tools.
---

Peerborne occupies a specific niche: **encrypted, peer-to-peer CRDT document collaboration with open-source libraries**. This page compares it to related projects to help you understand when Peerborne is the right choice.

## Baseline architectures

Peerborne wraps Yjs or Automerge; those engines are also useful independently.
The table compares baseline setups, not every plugin, custom encryption layer,
or hosted product. It is not a speed or memory benchmark.

| Choice | Peerborne | Yjs + providers | Automerge + Repo | WebSockets + Postgres |
| --- | --- | --- | --- | --- |
| Transport | libp2p; WebRTC / configured Circuit Relay | Choose WebRTC, WebSocket, or another provider | Choose Repo network adapters | App server broadcasts updates |
| Document E2EE | Built in; group lifecycle is alpha | Provider/application choice; y-webrtc supports a shared room password | Separate from baseline Repo configuration | Add application encryption; TLS alone ends at the server |
| State storage | Encrypted Helia blocks; browser IndexedDB | Add a persistence provider, such as y-indexeddb | Storage adapter, including IndexedDB or filesystem | Authoritative server tables; optional application cache |
| Client memory | Loaded CRDT + graph/caches; no total cap | Loaded document + CRDT metadata | Loaded documents + history/metadata | Application chooses a working set |
| Offline reconciliation | CRDT adapters; live partition/rejoin unverified | Merge when updates arrive | Merge when updates arrive | Application queue and conflict policy |

Upstream sources: [Yjs providers](https://docs.yjs.dev/ecosystem/connection-provider),
[Yjs persistence](https://docs.yjs.dev/getting-started/allowing-offline-editing),
[y-webrtc security](https://github.com/yjs/y-webrtc#readme),
[Automerge Repo](https://automerge.org/docs/reference/repositories/), and
[Postgres client/server architecture](https://www.postgresql.org/docs/current/tutorial-arch.html).
Memory entries describe where state lives; no universal safe document size is
implied. The WebSockets/Postgres column describes a conventional application
architecture, not a single packaged product. See Peerborne's
[feature audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md)
for its evidence boundaries. Forward secrecy and MLS are not implemented.

## Peerborne vs Yjs (standalone)

[Yjs](https://docs.yjs.dev) is a high-performance CRDT library for shared editing. It provides shared types (`Y.Map`, `Y.Array`, `Y.Text`), network-agnostic sync, and an ecosystem of network and persistence providers. Encryption, authentication, access control, and provider selection remain application choices.

| | Peerborne | Yjs (standalone) |
|---|---|---|
| **CRDT** | Adapts Yjs or Automerge | Built-in CRDT runtime |
| **Encryption** | AES-GCM by default, BeeKEM key sharing | Application responsibility |
| **Authentication** | ECDSA P-384 signing (optional; can be disabled with `enableSigning: false`); UCAN helpers exist but are not integrated into the document change path | Application responsibility |
| **Access control** | Reader/writer ACL with cryptographic enforcement | Application responsibility |
| **Storage** | Helia/IPFS (IndexedDB in browser) | Application responsibility (y-indexeddb plugin) |
| **Networking** | libp2p (WebSocket, WebRTC, WebTransport, GossipSub) | y-websocket, y-webrtc providers |
| **Peer discovery** | Bootstrap, Kademlia DHT, AutoNAT | Application responsibility |

Peerborne is a good choice when you need encryption, signing, and access control out of the box. Use Yjs standalone when you already have your own auth, transport, and encryption layers.

## Peerborne vs Automerge (standalone)

[Automerge](https://automerge.org) is a CRDT library with a JSON-like document model and transport-agnostic sync protocol. Automerge Repo adds storage and networking through configurable adapters; encryption and access control remain application concerns.

| | Peerborne | Automerge (standalone) |
|---|---|---|
| **Data model** | Adapts Automerge or Yjs | JSON-like CRDT documents |
| **Sync transport** | libp2p + GossipSub | Automerge-repo (WebSocket, HTTP) |
| **Encryption at rest** | AES-GCM per document by default | Application responsibility |
| **Key exchange** | BeeKEM for dynamic groups | Application responsibility |
| **Rich text** | Via Yjs adapter | Via Automerge Text type |

Peerborne wraps Automerge documents with encryption and access control. If you only need the CRDT merge semantics, use Automerge directly.

## Peerborne vs Liveblocks

[Liveblocks](https://liveblocks.io) is a managed realtime collaboration platform. It provides presence, comments, notifications, and CRDT-based storage as a hosted service.

| | Peerborne | Liveblocks |
|---|---|---|
| **Architecture** | Peer-to-peer with relay infrastructure | Client-server (Liveblocks backend) |
| **Deployment** | Self-hosted (you run relays) | Managed service (Liveblocks cloud) |
| **Data sovereignty** | Full control (encrypted on your infrastructure) | Data stored on Liveblocks servers |
| **Encryption model** | Document payloads are end-to-end encrypted; connection and traffic metadata remain visible | Encrypted in transit (server sees data) |
| **Offline behavior** | IndexedDB-backed Helia/IPFS storage; partition/rejoin recovery is not yet verified end to end | Yjs + IndexedDB support is available after initial load |
| **Pricing** | Open source (MIT) | Free tier + paid plans |
| **Project status** | Initial release; not production-ready | Established managed service |
| **AI collaboration features** | Not included | AI comments, AI copilots |

Use Liveblocks for production collaborative UIs with presence, comments, and rich-text when you are comfortable with a managed service. Use Peerborne when you need end-to-end encryption and data sovereignty, or when you want to own your infrastructure.

## Peerborne vs RxDB

[RxDB](https://rxdb.info) is a local-first NoSQL database for JavaScript. It stores JSON documents locally, provides reactive queries (RxJS observables), and syncs with backend servers via replication plugins.

| | Peerborne | RxDB |
|---|---|---|
| **Data model** | CRDT documents (Yjs/Automerge) | JSON documents with schemas |
| **Query language** | IndexManager (full-text + blind indexes) | Mango/MongoDB query syntax |
| **Sync model** | Peer-to-peer (libp2p) | Client-server replication |
| **Backend** | Relay nodes (stateless) | RxServer, CouchDB, GraphQL, Firebase, Supabase, etc. |
| **Encryption** | End-to-end (AES-GCM per document by default) | Field-level encryption plugin |
| **Convergence** | CRDT (Yjs/Automerge) | CRDT plugin + conflict handlers |
| **Framework support** | React, Redux | React, Angular, Vue, Svelte, Node.js, Expo |
| **Project status** | Initial release; not production-ready | Established project |

RxDB is an established local-first database with broad backend support. Peerborne is focused on encrypted peer-to-peer CRDT collaboration without a central database. They solve different problems.

## Peerborne vs Jazz

[Jazz](https://jazz.tools) is a local-first relational database with row-level permissions and real-time sync. Jazz v2 is a public alpha with hosted and self-hosted database-server options.

| | Peerborne | Jazz |
|---|---|---|
| **Data model** | CRDT documents | Relational tables with schemas |
| **Sync model** | Peer-to-peer (libp2p) | Client-server (Jazz Cloud or self-hosted) |
| **Permissions** | Cryptographic ACL (reader/writer keys) | Server-enforced row-level policies |
| **Encryption** | Document payloads are end-to-end encrypted | Server is trusted for access control; the v2 design scopes E2E encryption to selected sensitive fields |
| **Server** | Relay nodes (pass-through) | Jazz sync server (stateful) |
| **Framework support** | React, Redux | React, Vue, Svelte, Solid, Expo |
| **Project status** | Initial release; not production-ready | Public alpha (Jazz v2) |

Jazz v2 provides a relational model and managed or self-hosted sync infrastructure. Peerborne focuses on encrypted CRDT documents and user-operated peer-to-peer networking. Both are early-stage projects that require careful evaluation.

## Peerborne vs Electric Sync

[Electric Sync](https://electric-sql.com) is a read-path sync engine that streams selected Postgres data to local clients over HTTP.

| | Peerborne | Electric Sync |
|---|---|---|
| **Sync direction** | Bidirectional (peers read and write) | Primarily read-path sync (writes go through your API) |
| **Source of truth** | CRDT merge (no central authority) | Postgres (server is authoritative) |
| **Data model** | CRDT documents | Postgres tables with Shapes |
| **Schema** | Schema-less (CRDT types) | Postgres DDL |
| **Encryption** | End-to-end | Server-side (you control Postgres access) |
| **Offline** | IndexedDB-backed Helia/IPFS storage; partition/rejoin recovery is not yet verified end to end | Depends on the client stack, such as PGlite or TanStack DB |
| **Deployment** | Self-hosted peer, relay, and bootstrap infrastructure | Electric Cloud or self-hosted sync service |

Electric Sync fits applications that already use Postgres and need a read-path sync engine. Peerborne is designed for peer-to-peer document collaboration without a central database.

## When to choose Peerborne

Peerborne stands out when you need:

1. **End-to-end encrypted peer-to-peer documents** — relay and bootstrap infrastructure does not see document plaintext, though connection and traffic metadata remain visible
2. **No central database server** — your application has no backend database at all
3. **Full control over infrastructure** — you run the relay nodes, you hold the keys
4. **Composable libraries** — use only the packages you need, not a monolithic platform
5. **Open-source transparency** — every layer is inspectable and modifiable

If any of the projects above matches your requirements more closely, use it — most are more mature and have larger communities. Peerborne is exploring a specific design point: encrypted CRDT documents that sync between peers without a trusted central database, while self-hosted relay infrastructure may remain in the data path.
