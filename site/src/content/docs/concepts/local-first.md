---
title: Local-first design
description: What "local-first" means in Peerborne, what is implemented today, and where the boundaries are.
---

## Design intent

A local-first application stores its primary data on the user's device — not on a remote server. Changes apply to the local replica immediately, with zero network latency. The network is used to sync state between peers, not to enforce a global write order.

Peerborne adopts these local-first principles:

- **Local replica near the user.** The application reads and writes a local CRDT document. There is no server round-trip for reads or writes.
- **Work offline.** Once a document is loaded, the local replica can be edited without network access. Changes are applied immediately to the CRDT and stored locally in IndexedDB.
- **No server-ordained write ordering.** Two peers can edit the same document concurrently. The CRDT layer merges their changes when they eventually exchange updates.
- **Eventually consistent.** When peers reconnect, they may discover and fetch blocks that were created during the offline period. Delivery is not guaranteed — see limitations below.

## What is implemented today

### Offline editing (loaded replicas only)

A Peerborne document that has already been loaded can be edited offline. The `document.change()` call applies the mutation to the local Yjs or Automerge replica immediately and returns a promise that covers signing, encryption, storage to the local Helia blockstore, and publication to connected peers.

```ts
await todos.change((state) => {
  state.getArray<string>('items').push(['buy milk']);
});
```

If no peers are connected, the encrypted block is still stored locally in IndexedDB. When peers reconnect, they will discover and fetch the new blocks.

### What `change()` covers

The `document.change()` promise resolves when:

1. The CRDT provider has applied the mutation to the local replica
2. The update has been serialized into a `CRDTChangeBlock`
3. The block has been signed with the writer's ECDSA P-384 key
4. The signed block has been encrypted with the document's AES-GCM key
5. The encrypted block has been stored in the local Helia blockstore
6. The CID has been published to connected peers via GossipSub

If storage or publication fails (e.g., IndexedDB quota exceeded, network error), the CRDT mutation **may already be applied**. The CRDT state reflects the mutation even if the remote sync path failed. There is no automatic rollback.

## What is not yet implemented

### No durable outbox

If a peer is unreachable when `change()` publishes to GossipSub, the update may not reach them. Peerborne does not persist a queue of outgoing changes to retry later. There is no delivery acknowledgment or guaranteed-at-least-once semantics.

### No delivery acknowledgment

When a change is published, there is no confirmation that remote peers received, verified, or applied it. The application must implement its own acknowledgment protocol if it needs delivery guarantees.

### No automatic reconnection

If the libp2p connection drops, Peerborne does not automatically reconnect. The application must detect disconnection and reinitialize the transport. See the [networking page](../networking/) for transport details.

### No close/restart recovery verified in CI

Documents store encrypted blocks in browser IndexedDB via Helia's blockstore. Local persistence works in single-session tests, but complete browser close → reopen → verify document state has not been proven in CI. See the [roadmap](../../community/roadmap/) for current status.

### Automerge/Yjs mutation persistence on rejection

If part of the `change()` pipeline fails (e.g., storage quota exceeded), the CRDT mutation may already be applied to the local replica. The mutation persists locally even though the remote sync failed. There is no automatic undo or rollback of the CRDT state.

## The infrastructure boundary

"Local-first" does not mean "infrastructure-free." Browser peers cannot listen for incoming connections and cannot participate in a DHT without a bootstrap node. Most Peerborne deployments need:

- **Relay nodes** to bridge NAT for browser peers
- **Bootstrap nodes** as well-known entry points for the libp2p network
- **STUN/TURN servers** for WebRTC hole-punching (optional, for direct peer connections)

These infrastructure components carry **encrypted traffic only** — they never see document plaintext. But they are necessary for peers to discover and reach each other.

See [running a relay](../../cookbook/running-a-relay/) for the development relay setup.

## What local-first Peerborne is a good fit for

Peerborne's local-first model works well for:

- **Small collaborative documents** (todos, notes, wikis, password vaults) where the document fits in a single CRDT replica
- **Applications that own identity and recovery** — Peerborne does not provide authentication or key recovery
- **Deployments where you control the relay infrastructure** — there is no cloud service to delegate to
- **Experiments and prototypes** learning about local-first architecture

It is not a good fit for:

- Large datasets (hundreds of megabytes per document)
- Applications that need SQL or relational queries
- Production systems requiring guaranteed delivery and durability
- Applications expecting a managed backend service

## CI-backed evidence

These behaviors are verified by CI:

- Document creation, local mutation, and retrieval in a single browser session
- Encrypted block storage and retrieval through a Circuit Relay
- Automerge and Yjs provider initialization and basic operation
- Crypto operations (signing, encryption, key generation)

These behaviors are **not** verified:

- Browser restart and document recovery
- Multi-session persistence across browser closes
- Offline editing with later reconnection
- Automatic reconnection after transport failure

## Next steps

- [Architecture](../architecture/) — data flow and system structure
- [CRDT model](../crdts/) — how Yjs and Automerge integrate
- [Limitations](../limitations/) — complete list of current gaps