---
title: Offline persistence and size limits
description: Set document budgets, inspect browser quota, save encrypted checkpoints, and plan recovery tests for local encrypted state.
---

**Scope: evaluation guidance for alpha software.** IndexedDB-backed block
storage exists, but blocks alone do not reopen a document: restart recovery
needs an encrypted checkpoint that the application saves and restores. Durable
offline delivery and live partition/rejoin convergence are not established
acceptance gates.

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

## Save a checkpoint after every change

IndexedDB keeps a document's encrypted blocks, but not the document keys,
membership or CRDT state an instance needs to open. After `close()`, a new
`peerborne.doc(path).open()` loads from a connected peer that holds the
document; offline, or with no such peer, it rejects with
`No document state is available`. An application that relies on IndexedDB
alone cannot reopen its documents after a reload.

1. Keep a non-extractable 256-bit AES-GCM storage key with the application's
   signing identity, for example as a `CryptoKey` in IndexedDB.
2. After each committed change, and always after a change reported to
   `subscribeDeliveryFailures()`, save
   `await document.exportEncryptedCheckpoint(storageKey)`. Replace the saved
   checkpoint only after an export succeeds.
3. On the next start, restore it on a fresh instance before opening:

   ```ts
   const document = peerborne.doc(path);
   const saved = await loadCheckpoint(path);
   if (saved) await document.restoreEncryptedCheckpoint(saved, storageKey);
   await document.open();
   ```

4. To reject a replayed older checkpoint, also keep
   `await documentCheckpointCommitment(bytes)` of each saved checkpoint
   outside the checkpoint store, and pass the latest one to
   `restoreEncryptedCheckpoint()` as the third argument.

A checkpoint holds the document's plaintext state and its document keys. Keep
it encrypted at rest and never send it to another party. If the application
encrypts checkpoints with its own format instead, as the examples'
[`browser-checkpoint-store.ts`](https://github.com/Peerborne/peerborne/blob/main/examples/shared/browser-checkpoint-store.ts)
does, it must encrypt the result of `exportPlaintextCheckpoint()` before
storing it. See [Local checkpoints](../../concepts/storage/#local-checkpoints).

## Test recovery before relying on it

1. Create a disposable document with a known value. Record aggregate size and
   latency measurements.
2. Exercise the application's intended signing-identity, storage-key and
   checkpoint persistence paths. A new signing key after reload is a different
   identity, and a new storage key cannot open the saved checkpoints.
3. Close every tab and browser process, reopen, restore the same application
   identity and storage key, restore the latest checkpoint before `open()`,
   and verify the document. Repeat without network access and with missing
   blocks.
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
