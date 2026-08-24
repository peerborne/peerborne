# `@peerborne/core`

Encrypted, peer-to-peer collaboration for TypeScript. Peerborne provides the core document, storage, networking, encryption, access-control, and key-management primitives that the Peerborne project composes into a local-first CRDT toolkit.

## What you get

- **Encrypted documents** — every change is signed (ECDSA P-384) and encrypted (AES-GCM) before leaving the device
- **Peer-to-peer sync** — libp2p networking with WebSocket, WebRTC, WebTransport, and GossipSub
- **Content-addressed storage** — CID-addressed blocks in a browser IndexedDB-backed Helia blockstore
- **Cryptographic access control** — reader/writer ACLs enforced by key possession and signature verification
- **No application server** — relays carry ciphertext; they never see document plaintext

## Choose this package

Use this package for Peerborne document and runtime APIs. Most applications pair it with one of the shipped CRDT adapters:

- [`@peerborne/yjs`](https://github.com/Peerborne/peerborne/tree/main/packages/yjs) for Yjs documents
- [`@peerborne/automerge`](https://github.com/Peerborne/peerborne/tree/main/packages/automerge) for Automerge documents

Applications can instead supply compatible provider, serializer, ACL, and keychain implementations. Add the React or Redux package only when those bindings are useful.

## Entry points

- `@peerborne/core` — shared document, provider, configuration, cryptography, ACL, and keychain APIs
- `@peerborne/core/node` — the Node-only `PeerborneNode` runtime and default node configuration
- `@peerborne/core/browser-primitives` — targeted browser-safe primitives without the full libp2p and Helia stack

## Start here

- [Quick start from source](https://peerborne.io/getting-started/quick-start/)
- [API reference](https://peerborne.io/reference/)
- [Security model](https://peerborne.io/concepts/security/)
- [Current limitations](https://peerborne.io/concepts/limitations/)
- [Architecture overview](https://peerborne.io/concepts/architecture/)
- [Documentation index for coding agents](https://peerborne.io/llms.txt)
