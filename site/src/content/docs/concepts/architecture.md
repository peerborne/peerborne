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

![A local CRDT mutation creates an encrypted CID-addressed stored payload and a separate signed-when-enabled, encrypted GossipSub sync envelope; receivers decrypt and authorize the envelope, apply inline history, and fetch only missing or deferred CID blocks for CID validation and decryption.](../../../assets/diagrams/change-pipeline.svg)

The local replica changes before either outbound artifact is complete. First,
Peerborne serializes the change payload, encrypts it with the document key, and
stores that ciphertext in Helia under its CID. It then builds a separate
`CRDTSyncMessage` containing the new CID, inline change history, and any deferred
CID references. The complete sync message is signed when signing is enabled,
serialized, encrypted, and published through GossipSub; the publication is not
a CID-only announcement.

A receiving peer decrypts the GossipSub envelope before deserializing it and,
when signing is enabled, checking the outer signature against known authorized
writers. It applies inline history directly and fetches only missing or deferred
CID references. Helia validates fetched ciphertext against the requested CID;
Peerborne then decrypts and deserializes the stored change payload. Those stored
blocks do not carry their own writer signature or ACL decision. A storage or
publication error can reject `change()` after the mutation is already visible
locally. There is no automatic rollback, durable outbox, or remote delivery
receipt.

**Evidence boundary:** the component pipeline and its failure semantics are
implemented and covered by focused tests. Live post-load browser mutation and
convergence through this complete path are not yet demonstrated in CI.

## Data flow: loading an existing document

![A quorum-enabled remote document load obtains Q-of-K frontier agreement, decrypts the selected response before any conditional known-writer signature check, binds its served frontier, and fetches the CIDs enumerated by its served changes tree before mutation; a quorum-bound first load drops an unverifiable snapshot and requires an available changes tree, while the quorum-disabled legacy path skips those gates.](../../../assets/diagrams/initial-load.svg)

The configured initial-load gate probes up to an effective K distinct connected
peers and requires Q matching frontier advertisements before accepting a remote
history. Peerborne decrypts the selected response first. On a subsequent load,
when signing is enabled and a prior writer set is already known, it then verifies
the response's outer signature before mutating document state. If quorum ran,
Peerborne also derives the served frontier and binds it to the agreed hash and
required tips.

For a quorum-bound load, inline changes are stripped from the response and every
CID enumerated by its served changes tree is prefetched before state mutation.
Helia validates the fetched ciphertext against each CID during that prefetch.
After the gate passes, `sync()` decrypts, deserializes, and applies the cached
payloads. A later per-block failure can therefore follow partial local mutation;
there is no rollback. CID integrity authenticates those ciphertext bytes, not
the responder-supplied node kind or interior tree topology, a writer identity,
or a complete-history claim. The fetched blocks have no per-block signature or
ACL decision.

On a first load there is no prior writer set with which to authenticate the
outer response. A quorum-bound first load therefore drops an unverifiable
snapshot and replays an available changes tree; a snapshot-only response is
refused. When quorum is disabled, the legacy response path skips advertisement
probes, frontier binding, inline stripping, and the prefetch-before-mutation
gate. The decision logic and orchestration have focused tests; conflicting real
peers serving adversarial DAG payloads are not yet exercised end to end.

## The sync model

Peerborne uses a **shadow sync graph** rather than putting its graph links inside
each stored block:

- Each `document.change()` call stores an encrypted serialized change payload in Helia; the CID addresses the resulting ciphertext.
- A separate `CRDTSyncMessage` names the new CID and carries an inline shadow change tree whose child keys reference earlier CIDs; older cross-links may be deferred to CID-only references.
- The complete sync message is signed when signing is enabled, then serialized, encrypted, and published through GossipSub.
- Receivers apply inline history and fetch only missing or deferred CID blocks on demand through the configured block-fetch path.
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
  ├── Document encryption keys (AES-GCM by default)
  ├── Signing key → libp2p PeerId mapping (separate keys)
  └── ACL entries (reader/writer lists bound to signing public keys)

Per document change:
  ├── Stored artifact
  │   ├── Serialized change is encrypted with the document key and stored by CID
  │   └── The stored block has no separate writer signature or ACL check
  ├── GossipSub artifact
  │   ├── CRDTSyncMessage is signed with P-384 when signing is enabled
  │   └── The complete message is serialized and encrypted with the document key
  └── Receiver
      ├── Decrypts the envelope before conditional known-writer authorization
      └── CID-validates, decrypts, and deserializes only fetched change blocks
```

Peerborne does not transmit private signing or KEM keys. Public identity keys
are exchanged as protocol inputs. When reader KEM enrollment is configured, a
writer sends a writer-signed Welcome whose recipient-bound ECIES-sealed payload
contains a visibility-filtered keychain delta and BeeKEM bootstrap data. Later
BeeKEM PathUpdates let surviving readers derive a new root, from which
Peerborne derives the next document epoch key. Applications still own identity
enrollment, private-key storage, backup, and recovery.

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
- **No durable reconnect-and-replay guarantee**: libp2p may redial and explicit loads or later sync history may catch a peer up, but connection restoration and replay of every missed update are not guaranteed
- **No pass/fail performance budgets**: benchmarks exist but have no thresholds
- **Pinning is incomplete**: the listener exists but the publisher does not
- **Browser restart recovery is unverified**: IndexedDB persistence works in tests but full close/reopen cycles are not proven in CI

## Next steps

- [Local-first design](../local-first/) — what "local-first" means in Peerborne
- [CRDT model](../crdts/) — how Yjs and Automerge integrate
- [Networking](../networking/) — transports, discovery, and NAT traversal
- [Security model](../security/) — threat model, encryption, and ACL
- [Storage](../storage/) — persistence, pinning, and recovery
