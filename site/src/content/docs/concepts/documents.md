---
title: Documents
description: Open a document, change typed state, subscribe to updates, and choose the right document boundary.
---

A Peerborne document is a local CRDT replica plus its encrypted change history,
keys, and reader/writer permissions. Use the Automerge adapter for JSON-like
object mutations or the Yjs adapter for shared maps, arrays, and text.

## The document lifecycle

To create a new local document with an initialized node and the Automerge adapter:

```ts
const document = peerborne.doc('/workspace');
await document.create();
document.subscribe('workspace-ui', (state) => render(state));
await document.change((draft) => {
  draft.title = 'Ready to ship';
});
// When the view is finished:
document.unsubscribe('workspace-ui');
await document.close();
```

`peerborne` and `render` above belong to your application. For complete setup,
use the [React workspace tutorial](../../getting-started/react-workspace/).
Use `open()` for an existing document with its required trust and key material.
The direct change API returns a promise: handle rejection before telling the
user a save succeeded. A successful local operation is not a durable
acknowledgment from every other replica.

## Paths are names, not credentials

`/workspace` identifies the document. A second client using that path still
needs the appropriate document keys, a trusted identity/ACL, and a route to
peers. Sharing a path or signing identity alone does not deliver encryption
keys. See [Identities](../identities/).

## What concurrent edits mean

The CRDT adapter decides how updates merge. Independent list inserts can both
survive; competing assignments to one scalar have the adapter's conflict
semantics. Convergence means replicas agree after valid updates arrive. It
does not mean every overwritten value remains visible or that your business
rules are automatically preserved.

The landing animation is scripted. The tutorial's in-page exercise runs Yjs
merge and Web Crypto, but neither is evidence of live Peerborne partition/rejoin
behavior. See [CRDTs](../crdts/) for the adapter and evidence boundaries.

## Choose a bounded unit of collaboration

A loaded document materializes CRDT state and associated metadata in memory.
Avoid making one document your application's entire dataset. Group state that
needs the same permissions and editing lifecycle; use several documents when
those boundaries differ. There is no universal safe size or automatic total
memory cap. Follow the [persistence runbook](../../runbooks/offline-persistence/)
and measure realistic edits, deletes, reopen time, and memory use.

Continue with [Identities](../identities/), [Epoch Transitions](../epoch-transitions/),
or the [runtime architecture](../architecture/).
