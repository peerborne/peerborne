---
title: Why Peerborne
description: What makes Peerborne different from other local-first and CRDT solutions, and when to use it.
---

A centralized database is simpler and should be the default for most applications. Peerborne is for collaboration where requiring every participant to trust one plaintext data custodian is itself the problem.

Peerborne is an **encrypted, peer-to-peer CRDT document toolkit** for TypeScript. Documents live on user devices and synchronize between peers. It is not a database, a backend-as-a-service, or a drop-in realtime layer.

## What makes Peerborne different

### When centralization is the downside

Peerborne removes the plaintext application database from the document path. Documents are encrypted, signed, and content-addressed before peers exchange them through relay infrastructure. Relays do not receive document plaintext, but they still observe connection and traffic metadata and can drop, delay, or censor traffic. Peerborne changes the trust boundary; it does not eliminate infrastructure.

### Encryption is the default, not an add-on

By default (`enableSigning: true`), every document change is signed with the writer's identity and encrypted with AES-GCM before it leaves the device. Relays, bootstrap nodes, and remote storage see only opaque ciphertext. Encryption is always on, whether signing is enabled or not. Key material stays on devices — Peerborne never transmits unencrypted document content.

### Composable, not monolithic

Peerborne is not a single package. It is six libraries you compose:

| Package | Role |
|---|---|
| `@peerborne/core` | Core: encryption, signing, ACL, storage, networking |
| `@peerborne/yjs` | Yjs CRDT adapter |
| `@peerborne/automerge` | Automerge CRDT adapter |
| `@peerborne/react` | React hooks and bindings |
| `@peerborne/redux` | Redux state management bindings |
| `@peerborne/index` | Client-side search indexing |

Use only what you need. Compose the adapters, bindings, and indexing layers that fit your application.

### CRDT adapters, not a CRDT library

Peerborne does not implement its own CRDT. It adapts existing, well-tested CRDT libraries — Yjs and Automerge — wrapping them with encryption, signing, access control, and peer-to-peer transport. You get the battle-tested merge semantics of Yjs or Automerge combined with Peerborne's security and networking model.

### Open source from end to end

All six packages are source workspaces in a single repository. You build from source, run the examples locally, and inspect every layer. There is no closed-source coordination service or proprietary sync server.

## When to use Peerborne

Peerborne is a good fit for applications that need:

- **Collaboration across independently operated peers** that cannot appoint one trusted plaintext custodian
- **Encrypted document exchange** through infrastructure that should carry ciphertext only
- **Local writes and CRDT merge semantics** instead of synchronous transactions through one database
- **Application-controlled identity, keys, relays, and storage**
- **Experiments with intermittent or user-operated networks**, with the current restart and partition/rejoin limitations understood

Peerborne is **not** a good fit when:

- A trusted, highly available central database is acceptable—it will usually be simpler and more mature
- You want a managed backend service (Peerborne has no cloud offering)
- You need transactional constraints, globally exclusive claims, or authoritative server-side workflows
- You need sub-100ms multiplayer presence (CRDT conflict resolution is eventual, not real-time)
- You are building a simple single-user offline app (use IndexedDB directly)
- You need SQL queries or relational data (Peerborne exposes CRDT documents, not relational queries)

## Current status

Peerborne is alpha software. It is suitable for experiments, prototypes, and learning about local-first systems, not production deployment.

Current evidence includes:

- Real encrypted document retrieval across a Circuit Relay and NAT boundary
- Single-browser smoke tests for all three example applications
- Separate Docker-backed transport tests for discovery, GossipSub delivery, and NAT behavior

That evidence does not yet prove durable restart recovery, invitation delivery, automatic reconnect, or system-level partition/rejoin convergence.

See the [feature audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md) for a detailed capability-to-evidence map, and the [limitations](../limitations/) page for a complete list of current gaps.

## Next steps

- [Quick start](../../getting-started/quick-start/) — build from source and run the examples
- [Concepts](../local-first/) — understand the architecture and design choices
- [Cookbook](../../cookbook/collaborative-wiki/) — code patterns for common tasks
- [Roadmap](../../community/roadmap/) — what is being worked on next
