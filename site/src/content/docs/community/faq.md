---
title: FAQ
description: Frequently asked questions about Peerborne.
---

## Is Peerborne production-ready?

**Not yet.** Peerborne is under active development. It is suitable for experiments, prototypes, and learning about local-first systems. Several critical paths are not yet verified end-to-end, including browser restart recovery, partition/rejoin convergence, and automatic reconnect. See the [feature audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md) for a complete capability map.

## Can I use Peerborne with npm/pnpm/yarn install?

Not yet. The `@peerborne/*` packages are **unpublished**. You must clone the repository and build from source. See the [quick start guide](../../getting-started/quick-start/).

## Why should I use Peerborne instead of Yjs or Automerge directly?

Peerborne is not a replacement for Yjs or Automerge — it **adapts** them. Use Peerborne when you also need encryption, signing, access control, peer-to-peer discovery, content-addressed storage, and multi-transport networking. If you already have those layers, use Yjs or Automerge directly and integrate your own infrastructure.

## What happens if I lose my signing key?

Your signing key is your identity in the Peerborne network. If you lose it, you cannot issue new changes or prove you authored past ones. Peerborne does not provide key recovery, rotation, or backup — key management is the application's responsibility. Treat signing keys with the same care as any private key material.

## What happens if all peers go offline?

Documents are only available while at least one peer with a replica is online — or while encrypted blocks are pinned to remote storage. Peerborne's pinning integration is **incomplete**: a listener exists but the core publishing path does not. Without pinning, the last online peer is the last surviving copy.

## Can I use Peerborne in a mobile app?

Peerborne targets browser and Node.js environments. It has not been tested on React Native, Expo, or other mobile runtimes. The libp2p and WebCrypto dependencies may not be available in all mobile JavaScript environments.

## Do I need to run a relay server?

**For browser peers behind NAT: yes.** Browsers cannot listen for incoming connections. A Circuit Relay bridges NAT by forwarding encrypted traffic between peers. For Node.js peers on the same network, direct connections may work without a relay. See [running a relay](../../cookbook/running-a-relay/).

## How does Peerborne handle conflicts?

Peerborne delegates conflict resolution to the underlying CRDT library (Yjs or Automerge). Both libraries provide deterministic merge semantics — concurrent edits are resolved automatically, without application-level conflict handlers. For example, Yjs merges concurrent `Y.Map` key updates using deterministic per-key conflict resolution (not wall-clock ordering), and merges concurrent `Y.Array` insertions by preserving both at their intended positions.

## How does Peerborne compare to CRDT-based databases?

Most CRDT databases (like RxDB's CRDT plugin) add CRDT merge semantics to a document store. Peerborne adds encryption, signing, access control, and peer-to-peer networking to existing CRDT libraries. The key difference: Peerborne's documents are encrypted and signed before they leave the device, and there is no server that sees plaintext.

## Does Peerborne support real-time collaborative editing?

Partial. CRDT updates propagate via GossipSub, which has sub-second latency in typical deployments. However, presence (cursors, selections) is not implemented, and there is no operational transform layer for sub-100ms typing synchronization. For "Google Docs-like" real-time editing with presence, consider Liveblocks or PartyKit with Yjs. Peerborne is designed for document-level collaboration, not character-level real-time editing.

## Can multiple people edit the same document at the same time?

Yes. Each peer's changes are signed, encrypted, and published independently. The CRDT layer merges concurrent edits when they arrive. There is no lock, no leader election, and no "last write wins" — the merge is deterministic and conflict-free.

## How do I share a document with another person?

Document sharing requires key exchange. The document owner must:
1. Generate a BeeKEM key encapsulation for the recipient
2. Add the recipient as a reader (and optionally writer) to the document ACL
3. Transmit the KEM-wrapped document key and signing public key to the recipient

This process is not automated — the application must implement the key exchange channel. See the [password manager cookbook](../../cookbook/password-manager/) for an example.

## Can a relay read my documents?

**No.** Relays see encrypted ciphertext only. They can see metadata (peer IDs, document topic IDs, timing, data volume) but cannot decrypt document content without the document key. However, a relay **can** drop, delay, or censor traffic — Peerborne does not protect against denial of service by relay operators.

## Can I revoke someone's access to a document?

**Partially.** Revoking a writer prevents them from publishing new changes that other peers will accept. Revoking a reader requires BeeKEM key separation — existing keys must be invalidated and new keys distributed to remaining members. BeeKEM's rekey state is currently **memory-only** (does not survive restart), and the PathUpdate revocation mechanism is best-effort. See the [security page](../../concepts/security/#revocation) for details.

## What browsers are supported?

Peerborne requires WebCrypto (for ECDSA, ECDH, AES-GCM) and IndexedDB. These are available in all modern browsers: Chrome 37+, Firefox 34+, Safari 11+, Edge 79+. WebTransport support requires Chrome 97+ or Edge 97+.

## How large can documents be?

CRDT documents grow with every change. Yjs documents of a few megabytes are typical; tens of megabytes may cause performance issues in browsers. The document size depends on the CRDT data model and change frequency, not on Peerborne itself. Consider splitting large datasets across multiple documents and using the index layer for search.

## Is there a hosted version of Peerborne?

No. Peerborne is a set of libraries, not a service. There is no cloud offering, no managed relay service, and no hosted storage. You run your own infrastructure.

## What license is Peerborne?

MIT. All six packages are licensed under MIT. You can use, modify, and distribute them freely.