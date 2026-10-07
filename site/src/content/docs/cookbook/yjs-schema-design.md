---
title: Designing Yjs schemas
description: Choose Yjs shared types and current-schema validation for Peerborne documents.
---

**Status: Illustrative schema patterns, not a complete application.** Yjs adapter behavior has focused tests, but these patterns do not prove multi-peer application convergence, persistence, or schema safety. See [CRDTs](../../concepts/crdts/) and [Limitations](../../concepts/limitations/).

## Choose merge behavior explicitly

| Data | Shared type | Merge behavior |
| --- | --- | --- |
| Independent record fields | `Y.Map` | Same-key writes resolve by Yjs conflict rules; different keys survive |
| Ordered items | `Y.Array` | Concurrent inserts are retained in deterministic order |
| Collaborative prose | `Y.Text` | Character/operation-level merge |
| Editor trees | `Y.XmlFragment` / `Y.XmlElement` | Shared tree operations |
| Set-like membership | `Y.Map<boolean>` | Application interprets present/true keys as members |
| Counter | `Y.Map<number>` keyed by stable replica ID | Each replica owns one component; sum on read |

Do not treat plain objects stored inside shared types as recursively collaborative. Use nested shared types when fields require independent mutation.

## Mutate through Peerborne

All mutations and initialization must run inside and await `swarmDoc.change`. A bare `Y.Doc` mutation is not automatically authorized, encrypted, stored, or published by Peerborne.

```ts
await swarmDoc.change((doc: Y.Doc) => {
  const tasks = doc.getArray<Y.Map<unknown>>('tasks');
  const task = new Y.Map<unknown>();
  task.set('id', crypto.randomUUID());
  task.set('title', 'Review schema');
  task.set('status', 'todo');
  tasks.push([task]);
});
```

Use `doc.transact` inside that callback when several Yjs operations should emit one Yjs transaction:

```ts
await swarmDoc.change((doc: Y.Doc) => {
  doc.transact(() => {
    doc.getMap('meta').set('updatedAt', Date.now());
    doc.getText('body').insert(0, 'Imported text');
  });
});
```

A Yjs transaction does not make network publication transactional, does not span Peerborne documents, and does not roll back an in-place Yjs mutation if later asynchronous storage/publication fails.

## IDs, lists, and counters

Reference list entries by stable IDs, never array indexes. Reordering by delete/reinsert can duplicate an item under concurrency; for frequently sorted collections, consider a map keyed by ID plus an application-defined sortable key.

For a distributed counter, persist one random `replicaId` per application replica/device. Do not use a transient libp2p peer ID or a newly generated value per increment:

```ts
await swarmDoc.change((doc: Y.Doc) => {
  const counts = doc.getMap<number>('votesByReplica');
  counts.set(replicaId, (counts.get(replicaId) ?? 0) + 1);
});
```

This avoids same-key increment races between distinct replicas, but concurrent sessions incorrectly sharing one replica ID can still overwrite one another.

## Validate the current schema

Each application supports one current schema. Initialize it only after founding a new document with `create()`:

```ts
await swarmDoc.create();
await swarmDoc.change((doc: Y.Doc) => {
  doc.getMap<unknown>('meta').set('schemaVersion', 1);
  doc.getArray<Y.Map<unknown>>('tasks');
});
```

Validate loaded state and remote updates against that exact schema before interpreting fields, and reject an unsupported `schemaVersion` instead of upgrading it in place. A schema tag alone does not validate nested values. During alpha, change producers, readers, validators, and tests together, and use fresh local state for incompatible changes. Do not add fallback decoders, dual field names, or automatic upgrades.

## Heuristics, not limits

- Split documents at access-control, lazy-loading, ownership, and recovery boundaries.
- Document size targets such as 1 MB and nesting guidance such as two or three levels are application heuristics, not Peerborne or Yjs limits.
- Deep structures, large histories, and high update rates require measurement with realistic peers and storage.
- One Peerborne document has one ACL/key domain; separately shared data belongs in separate documents.

Yjs garbage collection can remove some deleted structs when safe in the local state, but GC changes history/update assumptions and does not mean every document or encoded history only shrinks. Retained updates, snapshots, peers with older state vectors, repeated writes, and Peerborne's own change/block history all affect storage. Do not promise that tombstones are always permanent or that GC provides application-level deletion. See [Storage](../../concepts/storage/).
