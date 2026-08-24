---
title: Architecture
description: How Peerborne is structured — packages, data flow, networking, and the sync model.
---

Peerborne composes several open-source subsystems into a coherent local-first stack. This page describes how the pieces fit together.

## Package dependency graph

```
@peerborne/core (core)
├── libp2p (peer-to-peer networking)
├── Helia (content-addressed storage)
├── @chainsafe/js-ipns (naming)
├── BeeKEM (key encapsulation for dynamic groups)
├── UCAN (authorization capabilities)
└── @peerborne/yjs / @peerborne/automerge (CRDT adapters)

@peerborne/react → @peerborne/core
@peerborne/redux → @peerborne/core
@peerborne/index → @peerborne/core
```

## Data flow: writing a change

```
Application
  │
  ▼
document.change((state) => { state.getArray('items').push(['buy milk']) })
  │
  ▼
CRDT Provider (Yjs / Automerge)
  │  applies mutation to local CRDT replica
  │  serializes the update
  ▼
PeerborneDocument
  │  wraps update in a signed CRDTChangeBlock
  │  encrypts block with document AES-GCM key
  │  addresses block by CID (SHA-256 hash of ciphertext)
  ▼
Helia Blockstore (local IndexedDB)
  │  stores encrypted block
  ▼
libp2p PubSub (GossipSub)
  │  publishes CID to document topic peers
  ▼
Remote Peers
  │  receive CID announcement
  │  fetch encrypted block via libp2p bitswap / HTTP
  │  verify signature, decrypt, apply to local replica
  ▼
CRDT converges
```

## Data flow: loading an existing document

```
Application
  │
  ▼
document.open()
  │
  ▼
PeerborneNode
  │  resolves document ID to CID via IPNS or bootstrap
  │  if local: loads frontier from Helia blockstore
  │  if remote: queries Q-of-K peers for frontier agreement
  ▼
Load Quorum Orchestrator
  │  requests tips from configured bootstrap peers
  │  selects candidate with highest epoch
  │  waits for Q-of-K agreement before proceeding
  ▼
Shadow Graph Walk
  │  walks CRDTChangeNode chain from frontier backward
  │  fetches missing blocks (bitswap / HTTP)
  │  verifies signatures, decrypts, applies to CRDT
  ▼
Document is ready
  │  Mutations are now accepted via document.change()
  │  Reception of remote updates continues via GossipSub
```

## The sync model

Peerborne uses a **shadow sync graph** rather than a conventional Merkle-DAG:

- Each `document.change()` call creates one `CRDTChangeBlock` — an encrypted, signed, CID-addressed node containing a serialized CRDT update.
- Each block references its parent(s) by CID, forming a DAG.
- New blocks are announced to peers via GossipSub (by CID, never by content).
- Peers fetch missing blocks on demand (bitswap or HTTP fetch).
- The CRDT layer resolves concurrent edits without a consensus leader.

This model is **eventually consistent**: local edits apply immediately, remote edits merge when they arrive. There is no global ordering, no server-assigned sequence number, and no single source of truth.

## Peer-to-peer networking stack

```
┌─────────────────────────────────────┐
│            Application              │
├─────────────────────────────────────┤
│  PeerborneNode                    │
│  (document lifecycle, ACL, crypto)  │
├─────────────────────────────────────┤
│  libp2p                             │
│  ├── Transport layer                │
│  │   ├── WebSocket (relay, bootstrap)│
│  │   ├── WebRTC (browser-to-browser)│
│  │   └── WebTransport (modern)      │
│  ├── Stream Muxing (yamux/mplex)    │
│  ├── Connection Encryption (noise) │
│  ├── Discovery                      │
│  │   ├── Bootstrap list             │
│  │   ├── Kademlia DHT              │
│  │   └── AutoNAT                    │
│  ├── NAT Traversal                  │
│  │   ├── Circuit Relay v2           │
│  │   ├── DCUtR (hole-punching)      │
│  │   └── STUN/TURN                 │
│  └── PubSub                         │
│      └── GossipSub (document topics)│
├─────────────────────────────────────┤
│  Helia / IPFS                       │
│  ├── Blockstore (IndexedDB/local)   │
│  ├── Bitswap (block exchange)       │
│  └── IPNS (naming)                  │
└─────────────────────────────────────┘
```

## Encryption and identity

```
Application provides:
  ├── ECDSA P-384 signing key pair (writer identity)
  └── ECDH P-256 KEM key pair (key encapsulation)

PeerborneNode manages:
  ├── Document AES-GCM keys (one per document, shared via BeeKEM)
  ├── Signing key → libp2p PeerId mapping (separate keys)
  └── ACL entries (reader/writer lists bound to signing public keys)

Per change:
  ├── Writer signs the CRDT update with their P-384 key
  ├── Payload is encrypted with the document's AES-GCM key
  ├── Signature is verified by receivers before decryption
  └── Encryption is transparent to the CRDT layer
```

Key material never leaves the device in plaintext. Document keys are shared between authorized peers using BeeKEM — a key encapsulation mechanism that wraps the document key for each group member.

## Where infrastructure is needed

Peerborne documents can sync over peer-to-peer links, but most deployments need supporting infrastructure:

| Component | Required? | Purpose |
|---|---|---|
| **Relay node** | For browser peers | Bridges NAT; peers behind restrictive firewalls connect through it |
| **Bootstrap node** | For initial discovery | Provides a well-known entry point for the libp2p network |
| **STUN/TURN server** | For WebRTC direct connections | Helps peers establish direct browser-to-browser links |
| **Remote pinning** | Optional (integration incomplete) | Would persist encrypted blocks when all local peers go offline; the listener API exists but the current commit path does not invoke a publisher |
| **Identity service** | Application responsibility | Peerborne does not provide user authentication or key management |

The relay server source is in `relay-server/`. The Docker Compose files in the repository root provide ready-to-run multi-node topologies for testing.

## Current limitations

See the [limitations page](../limitations/) for a complete list. Key architectural limitations to be aware of:

- **No durable outbox**: local blocks are stored in IndexedDB, but an unreachable peer may not receive the update; there is no delivery retry queue
- **No automatic reconnect**: the application must detect disconnection and re-establish transport
- **No pass/fail performance budgets**: benchmarks exist but have no thresholds
- **Pinning is incomplete**: the listener exists but the publisher does not
- **Browser restart recovery is unverified**: IndexedDB persistence works in tests but full close/reopen cycles are not proven in CI

## Next steps

- [Local-first design](../local-first/) — what "local-first" means in Peerborne
- [CRDT model](../crdts/) — how Yjs and Automerge integrate
- [Networking](../networking/) — transports, discovery, and NAT traversal
- [Security model](../security/) — threat model, encryption, and ACL
- [Storage](../storage/) — persistence, pinning, and recovery