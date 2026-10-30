---
title: Offline persistence and size limits
description: Set document budgets, inspect browser quota, and plan recovery tests for local encrypted state.
---

**Scope: evaluation guidance for alpha software.** IndexedDB-backed block
storage exists; complete browser restart recovery, durable offline delivery,
and live partition/rejoin convergence are not established acceptance gates.

## Choose budgets from a real workload

There is no published maximum safe document size, total memory cap, or linear
scaling guarantee. Encoded bytes, materialized CRDT state, history/tombstones,
the shadow graph, and caches consume different resources.

Use representative documents and record:

| Measurement | Why it matters |
| --- | --- |
| Encoded document size after repeated edits/deletes | History and CRDT metadata can outgrow visible content |
| Open/reopen latency | Replaying history can dominate a small current state |
| Mutation latency and browser long tasks | Local-first does not imply off-main-thread work |
| Memory with your expected number of open documents | Bounded caches do not cap the whole CRDT or application |
| Origin storage usage and available quota | Browser eviction and quota apply outside Peerborne's control |

Split documents by collaboration/permission boundary when those measurements
exceed your application's budget. The [Yjs schema guide](../../cookbook/yjs-schema-design/)
covers shared-type and history-growth trade-offs.

## Inspect origin storage

In a secure browser context, use the Storage API for an **estimate**, not a
reservation or a Peerborne-specific byte count:

```ts
const { usage = 0, quota = 0 } = await navigator.storage.estimate();
const storageSummary = {
  usedMiB: Math.round(usage / 1024 ** 2),
  quotaMiB: Math.round(quota / 1024 ** 2),
};
```

Use those aggregate values in local diagnostics without printing document
contents or keys. Usage includes other data in the origin. An application can
request persistent storage using `navigator.storage.persist()` where supported;
the browser decides whether to grant it. It does not create a backup. See
[MDN's Storage API documentation](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API).

## Test recovery before relying on it

1. Create a disposable document with a known value. Record aggregate size and
   latency measurements.
2. Exercise the application's intended signing-identity and document-key
   persistence paths. A new key after reload is a different identity.
3. Close every tab and browser process, reopen, restore the same application
   identity/key material, and verify the document. Repeat without network
   access and with missing blocks.
4. Test quota exhaustion, interrupted writes, and browser data eviction in a
   disposable profile. Verify that the UI reports failures and that a separate
   recovery path works.
5. Test two clients editing through a disconnection, reconnecting, and agreeing
   on the final state. Treat this as a required application acceptance test;
   the landing simulation is not that test.

These steps are requirements to validate, not guarantees that the current
packages pass them. A successful local write or retained IndexedDB database
does not prove crash recovery, restored group state, or remote delivery.

## Treat compaction as a recovery decision

Snapshots, compaction, and block garbage collection have focused tests.
Compaction is opt-in, and pruning can remove historical data that another
replica still needs. Test recovery and lagging peers with disposable data
before choosing a retention policy. Do not clear IndexedDB as a routine size
management strategy for retained documents.

Encrypted blocks also need an independent retention/recovery plan. The relay
does not durably store documents and [pinning integration](../../cookbook/pinning/)
is incomplete. See [Storage](../../concepts/storage/) for the distinct block,
key-history, signing-identity, and membership-state recovery requirements.
