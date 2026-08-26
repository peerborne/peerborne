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

The application-supplied signing key authenticates document messages. If you
lose it, you cannot sign new ordinary document messages when signing is enabled
or produce the always-writer-signed BeeKEM Welcome and PathUpdate messages.
Existing stored change payloads do not contain a persistent per-block author signature.
Peerborne does not provide signing-key recovery, rotation, or backup; key
management is the application's responsibility.

## What happens if all peers go offline?

No peer can serve a local copy while every holder is offline. IndexedDB bytes
may survive offline, but complete close/restart reconstruction is not verified.
Peerborne's pinning integration is **incomplete**: a listener API exists, but
the normal core commit path does not publish to it. Data is lost if every local
copy is cleared or otherwise becomes unrecoverable.

## Can I use Peerborne in a mobile app?

Peerborne targets browser and Node.js environments. It has not been tested on React Native, Expo, or other mobile runtimes. The libp2p and WebCrypto dependencies may not be available in all mobile JavaScript environments.

## Do I need to run a relay server?

**For browser peers behind NAT: yes.** Browsers cannot listen for incoming connections. A Circuit Relay bridges NAT by forwarding encrypted traffic between peers. For Node.js peers on the same network, direct connections may work without a relay. See [running a relay](../../cookbook/running-a-relay/).

## How does Peerborne handle conflicts?

Peerborne delegates conflict resolution to the underlying CRDT library (Yjs or Automerge). Both libraries provide deterministic merge semantics — concurrent edits are resolved automatically, without application-level conflict handlers. For example, Yjs merges concurrent `Y.Map` key updates using deterministic per-key conflict resolution (not wall-clock ordering), and merges concurrent `Y.Array` insertions by preserving both at their intended positions.

## How does Peerborne compare to CRDT-based databases?

Most CRDT databases add merge semantics to a document store. Peerborne adds
encrypted stored payloads, signed-by-default encrypted sync messages, access
control, and peer-to-peer networking to existing CRDT libraries. Network
infrastructure that is not given the document key handles ciphertext rather
than document plaintext.

## Does Peerborne support real-time collaborative editing?

Partial. The GossipSub update path is implemented, but relay-backed live
post-load propagation and its latency are not yet verified end to end. Presence
(cursors and selections) is not implemented. Treat Peerborne as an experimental
document-replication toolkit, not an evidenced low-latency collaborative editing
service.

## Can multiple people edit the same document at the same time?

At the CRDT-adapter level, yes: delivered concurrent updates merge without a
lock or leader. Each peer creates encrypted stored change payloads and can
independently publish an encrypted sync message, signed when document signing is
enabled. Relay-backed live post-load multi-peer convergence is not yet verified
end to end, so applications should not treat that complete runtime path as a
proven capability.

## How do I share a document with another person?

Document sharing requires application-owned identity enrollment and public-key
exchange; Peerborne has no document-owner role. The recipient installs its KEM
key pair with `setKemKeyPair()` and shares its signing and KEM public keys with
an authorized writer. That writer calls `addReader(reader, readerKemPublicKey)`
and may separately grant writer access.

Peerborne then updates the reader ACL, creates a writer-signed Welcome, seals
its visibility-filtered keychain and BeeKEM bootstrap payload to the recipient,
and sends it best effort to connected peers. The application still owns peer
reachability, public-key enrollment, onboarding UX, retry/acknowledgment, and
recovery. See the [password manager cookbook](../../cookbook/password-manager/)
for an example.

## Can a relay read my documents?

**No.** Relays see encrypted ciphertext only. They can see metadata (peer IDs, document topic IDs, timing, data volume) but cannot decrypt document content without the document key. However, a relay **can** drop, delay, or censor traffic — Peerborne does not protect against denial of service by relay operators.

## Can I revoke someone's access to a document?

**Partially.** With document signing enabled, a replica rejects later ordinary
sync envelopes signed only by a removed writer after that replica applies the
writer-removal ACL update. There is no simultaneous cutover: stale replicas may
still evaluate against an older writer set, and signing-disabled replicas skip
that gate. Reader removal separately attempts BeeKEM key separation for future
epochs. BeeKEM's rekey state is currently **memory-only** (does not survive
restart), and PathUpdate delivery is best effort. See the
[security page](../../concepts/security/#revocation) for details.

## What browsers are supported?

Peerborne requires WebCrypto (for ECDSA, ECDH, AES-GCM) and IndexedDB. These are available in all modern browsers: Chrome 37+, Firefox 34+, Safari 11+, Edge 79+. WebTransport support requires Chrome 97+ or Edge 97+.

## How large can documents be?

CRDT documents grow with every change. Yjs documents of a few megabytes are typical; tens of megabytes may cause performance issues in browsers. The document size depends on the CRDT data model and change frequency, not on Peerborne itself. Consider splitting large datasets across multiple documents and using the index layer for search.

## Is there a hosted version of Peerborne?

No. Peerborne is a set of libraries, not a service. There is no cloud offering, no managed relay service, and no hosted storage. You run your own infrastructure.

## What license is Peerborne?

MIT. All six packages are licensed under MIT. You can use, modify, and distribute them freely.
