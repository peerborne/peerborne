---
title: FAQ
description: Frequently asked questions about Peerborne.
---

## Is Peerborne production-ready?

**Not yet.** Peerborne is under active development. It is suitable for experiments, prototypes, and learning about local-first systems. Several critical paths are not yet verified end-to-end, including restart recovery outside the two examples that test their own encrypted checkpoints, general partition/rejoin convergence, and automatic reconnect. [Peerborne Note](../../cookbook/peerborne-note/) is an initial-release demo, not evidence of production readiness. See the [feature audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md) for a complete capability map.

## Can I use Peerborne with npm/pnpm/yarn install?

Not from the npm registry. The `@peerborne/*` packages are **unpublished**. Build them from a repository checkout, pack them with `yarn release:prepare <directory>`, and install the tarballs in your project with `npm install <directory>/*.tgz`. See [Use the packages in another project](../../getting-started/react-workspace/#use-the-packages-in-another-project) and the [quick start guide](../../getting-started/quick-start/).

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

No peer can serve a local copy while every holder is offline. IndexedDB keeps
encrypted blocks, but a closed document reopens only from an
[encrypted checkpoint](../../concepts/storage/#local-checkpoints) the
application saved.
Peerborne's pinning integration is **not implemented**: `PeerborneNode` does not
implement an authenticated pinning protocol, and the normal core
commit path has no authenticated publisher. Data is lost if every local copy is
cleared or otherwise becomes unrecoverable.

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

Partial. A cross-NAT CI job verifies live updates in both directions between
two Chromium processes with separate identities through a Circuit Relay, after
an invitation, and Peerborne Note's owned-relay tests have two editors typing
concurrently. Both use Automerge, the only adapter that supports invitations.
Latency, larger groups and relay failover are not verified, and presence
(cursors and selections) is not implemented. Treat Peerborne as an
experimental document-replication toolkit, not an evidenced low-latency
collaborative editing service.

## Can multiple people edit the same document at the same time?

At the CRDT-adapter level, yes: delivered concurrent updates merge without a
lock or leader. Each peer creates encrypted stored change payloads and can
independently publish an encrypted sync message, signed when document signing is
enabled. Between identities this needs an Automerge document, because only
Automerge supports invitations, and the initial release has one collaborator
per document. Relay-backed live convergence of two such peers is verified in
CI; larger groups and partitions are not.

## How do I share a document with another person?

The core API automates one narrow online flow for Automerge documents: the
founder creates a signed `reader` or `editor` offer, and one distinct recipient
accepts it with a P-256 KEM key pair. The signed handshake grants the exact ACL
role and transfers bootstrap keychain material only inside a
recipient-encrypted Welcome. Peerborne has no separate document-owner role.

A Yjs or Loro document cannot be shared. Invitations require the Automerge
provider profile, and no other path admits another identity, so a Yjs or Loro
document has only its founder. The editor bridge and the password-manager
example are Yjs and stay single-identity.

[Peerborne Note](../../cookbook/peerborne-note/) supplies one bounded link and
explicit-acceptance interface and persists a local browser signing identity.
Applications still own link delivery, human identity verification, backup,
recovery, and the rest of the product experience. The initial release is
founder-plus-one and online-only; offers and replay state do not survive an
inviter restart. See [Invite a collaborator](../../cookbook/invitations/) for
the API and its trust boundary.

## Can a relay read my documents?

**No.** Relays see encrypted ciphertext only. They can see metadata (peer IDs, document topic IDs, timing, data volume) but cannot decrypt document content without the document key. However, a relay **can** drop, delay, or censor traffic — Peerborne does not protect against denial of service by relay operators.

## Can I revoke someone's access to a document?

**Partially.** With document signing enabled, a replica rejects later ordinary
sync envelopes signed only by a removed writer after that replica applies the
writer-removal ACL update. There is no simultaneous cutover: stale replicas may
still evaluate against an older writer set, and signing-disabled replicas skip
that gate. Reader removal separately attempts BeeKEM key separation for future
epochs. BeeKEM's rekey state is held in memory and survives a restart only
through a [checkpoint](../../concepts/storage/#local-checkpoints) the
application saves and restores, and PathUpdate delivery is best effort. See the
[security page](../../concepts/security/#revocation) for details.

## What browsers are supported?

Peerborne requires WebCrypto (for ECDSA, ECDH, AES-GCM) and IndexedDB. These are available in all modern browsers: Chrome 37+, Firefox 34+, Safari 11+, Edge 79+. WebTransport support requires Chrome 97+ or Edge 97+.

## How large can documents be?

CRDT documents grow with every change. Yjs documents of a few megabytes are typical; tens of megabytes may cause performance issues in browsers. The document size depends on the CRDT data model and change frequency, not on Peerborne itself. Consider splitting large datasets across multiple documents and using the index layer for search.

## Is there a hosted version of Peerborne?

There is no managed Peerborne service. [Peerborne Note](https://try.peerborne.io/)
is a hosted initial-release demo backed by one project-operated relay, not a
cloud offering or durable hosted store. It has no availability or data-recovery
guarantee. Applications using the libraries still operate their own relay and
storage infrastructure.

## What license is Peerborne?

MIT. All eleven packages are licensed under MIT. You can use, modify, and distribute them freely.
