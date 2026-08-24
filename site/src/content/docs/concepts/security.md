---
title: Security
description: Identity model, encryption, access control, quorum loading, and revocation in Peerborne.
---

## Overview

Peerborne encrypts documents end-to-end and signs every change. No server — relay, bootstrap, or pinning service — ever sees document plaintext or signing keys. Access control is enforced cryptographically: a peer without the document key cannot decrypt content, and a peer without a valid writer key cannot publish changes that other peers will accept.

## Identity and trust roots

Peerborne uses two separate key systems:

| Key | Algorithm | Purpose | Managed by |
|---|---|---|---|
| **Signing key** | ECDSA P-384 | Signs document changes; proves authorship | Application |
| **KEM key** | ECDH P-256 | Key encapsulation for document key sharing (BeeKEM) | Application |
| **Document key** | AES-GCM (256-bit) | Encrypts/decrypts document content | Peerborne (per-document) |
| **Libp2p peer ID** | Ed25519 | Identifies the node on the libp2p network | libp2p (auto-generated) |

The signing key and KEM key are **application-supplied**. Peerborne does not generate, store, recover, or back up user keys — key management is entirely the application's responsibility.

The libp2p peer ID is separate from the signing identity. This means:
- Changing the libp2p key (e.g., relay restart) does not affect document authorship
- The same signing identity can be used across multiple libp2p nodes

## Implemented authorization

### Reader/writer ACL

Each document has an access control list with two roles:

```ts
// Grant read access (the second argument is the reader's raw
// SEC1-uncompressed P-256 ECDH public key bytes, optional)
await document.addReader(peerSigningPublicKey, readerKemPublicKeyBytes);

// Grant write access
await document.addWriter(peerSigningPublicKey);
```

Before calling `addReader`, a founder node must set its KEM key pair:

```ts
await document.setKemKeyPair(kemKeyPair);
```

- **Readers** receive the document key (via BeeKEM encapsulation) and can decrypt blocks.
- **Writers** can publish new changes. Their signature is verified against the writer list before a change is applied.
- **Signing is currently optional** — a change without a valid writer signature may be accepted depending on configuration.

### Current-writer authorization only

The current writer list on the document is the only authorization check. There is no:
- Time-bound access (a writer added today can always write)
- Role-based access beyond reader/writer
- Delegation or sub-key authorization (UCAN capabilities exist but are not integrated)
- Rate limiting or abuse prevention

### UCAN capabilities

UCAN (User Controlled Authorization Networks) helpers exist in `@peerborne/core` as a standalone module. They are **not integrated** into the document change path. The UCAN module can:

- Issue capability tokens delegating specific permissions
- Verify capability chains
- Encode delegation proofs

But the document change path does not check UCAN tokens. UCAN integration is a future capability.

## Encryption and history visibility

Every document is encrypted with a unique 256-bit AES-GCM key. Blocks are encrypted before storage and decrypted only on authorized peers.

```ts
// Document content is always encrypted at rest and in transit
const block = {
  parent: previousTipCID,
  epoch: currentEpoch,
  signature: await sign(signingKey, blockPayload),
  payload: await encrypt(documentKey, serializedCRDTUpdate),
};
```

### Signing configuration

Document signing is controlled by `PeerborneConfig.enableSigning` (default: `true`):

| Setting | Effect |
|---|---|
| **`enableSigning: true`** (default) | Changes are signed with ECDSA P-384 and encrypted with AES-GCM. Receivers verify signatures. |
| **`enableSigning: false`** | Changes are still encrypted with AES-GCM but not signed. ACL enforcement is disabled — any peer that can connect may publish changes. |

Documents are always encrypted at rest and in transit. There is no configuration toggle to disable encryption.

## Initial-load quorum

Before trusting a document's state, Peerborne can require **Q-of-K** bootstrap peers to agree on the current tip hashes. This prevents loading a fork or a truncated history. Quorum is configured via `PeerborneConfig`:

```ts
// Set loadQuorumK and loadQuorumQ when initializing:
await swarm.initialize(defaultConfig({
  ...defaultBootstrapConfig([]),
  loadQuorumK: 3,  // probe up to 3 peers
  loadQuorumQ: 2,  // require agreement from at least 2
}));

// Documents are then opened normally; quorum runs automatically:
const document = swarm.doc('/shared-note');
await document.open();
```

The quorum check:
- Probes up to `loadQuorumK` peers for their current frontier hashes
- Proceeds only when at least `loadQuorumQ` peers agree on the same frontier
- Rejects the load if agreement cannot be reached
- Is **not Sybil-resistant** — a peer controlling multiple identities can subvert it

## Revocation

### Writer revocation

When a writer is removed from the ACL:
- Other peers reject future changes signed by the revoked key
- Existing blocks from the revoked writer remain in the document — revocation is forward-looking only
- There is no mechanism to retroactively remove a revoked writer's past contributions

```ts
await document.removeWriter(revokedPeerSigningPublicKey);
```

### Reader revocation

Reader revocation is more complex. Since readers hold the document key, simply removing them from the ACL does not prevent them from decrypting blocks they've already received.

What exists:
- **BeeKEM key separation** can generate new document keys that exclude a former member
- **PathUpdate** is a best-effort mechanism to notify peers about ACL changes
- Both mechanisms are **incomplete**: BeeKEM rekey state is memory-only (lost on restart), and PathUpdate has no delivery guarantee

```ts
// Be aware: BeeKEM state is memory-only
await document.removeReader(revokedPeerSigningPublicKey);
```
`removeReader` generates and distributes BeeKEM PathUpdates internally as part of the operation. PathUpdate distribution is best-effort — there is no guarantee that ACL change notifications reach all peers.

### Limitations of revocation

- **No absolute guarantee.** A revoked reader with a copy of the encrypted blocks and the old document key can still decrypt them offline.
- **BeeKEM state is lost on restart.** If the node restarts, it loses track of which keys have been invalidated.
- **PathUpdate is not guaranteed.** There is no acknowledgment or retry mechanism.
- **Key reuse risk.** If the application reuses KEM key pairs across documents, revoking access to one document may not fully revoke it from another.

## Metadata and hostile infrastructure

Relays and other infrastructure nodes can observe:
- Peer IDs and connection patterns
- Document topic IDs (derived from document IDs)
- Message timing, frequency, and size
- Network topology

This metadata may reveal:
- Which peers are collaborating on which documents
- When collaboration is happening (message frequency)
- The rough size of documents (encrypted block sizes)
- The network location of peers (IP addresses, relay selection)

Peerborne does not protect against traffic analysis or metadata leakage.

## CI-backed evidence

Verified in CI:

- ECDSA P-384 signing and verification of document changes
- AES-GCM encryption and decryption of document blocks
- Reader/writer ACL enforcement (writer check before accepting changes)
- BeeKEM key encapsulation and decapsulation
- UCAN capability issuance and verification (standalone module)
- Encrypted document retrieval through Circuit Relay

Not verified:

- Reader revocation with key rotation and live peer notification
- K-of-Q quorum loading with K > 1
- PathUpdate delivery across NAT boundaries
- Resistance to Sybil attacks on quorum
- Key recovery or backup flows

## Next steps

- [Architecture](../architecture/) — how encryption fits into the data flow
- [Password manager cookbook](../../cookbook/password-manager/) — key sharing and ACL management example
- [Limitations](../limitations/) — complete security limitations