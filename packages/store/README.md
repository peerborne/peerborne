# `@peerborne/store`

Framework-independent document subscriptions and lifecycle management. This
alpha source workspace is not published to npm. Its runtime has no dependencies
and imports no browser APIs, React, networking, or cryptography.

```js
import { createDocumentStore } from '@peerborne/store';

// peerborne is an initialized node; share this store for this node/path.
const document = peerborne.doc('/workspace');
await document.create();
const store = createDocumentStore(document, { manageLifecycle: false });
const unsubscribe = store.subscribe(() => {
  const { status, data } = store.getSnapshot();
  output.textContent =
    status === 'ready'
      ? String(data.getMap('data').get('title') ?? 'Untitled')
      : status;
});
const release = store.connect();

await store.change((doc) => doc.getMap('data').set('title', 'Hello'));

// When this consumer is removed:
unsubscribe();
release();
await store.stop();
await document.close();
```

`subscribe` only registers a notification listener. `connect` retains ownership,
opens the document, and returns an idempotent release function. The final release
queues a close; a same-turn reconnect keeps the document open, and the
`closeDelay` option, in milliseconds, keeps it open for a later remount. The
final release never closes a document while `snapshot.deliveryFailure` is set,
because that change exists only in the open handle. That includes an edit made
with no connected peer, which the default GossipSub configuration reports as a
`NoDeliveryPeersError`. The store closes the document once a later local frame
reaches a peer and delivers the change. Explicit `start()` and `stop()` return
promises for imperative applications: `start()` keeps the document open until
`stop()`, and `stop()` closes it even with consumers or a delivery failure.
Operations are serialized so a close waits for pending writes. `change` never
opens the document: it rejects with `Document store is closed` unless the store
is open. Mutation rejections reach the caller and `snapshot.error`.

Snapshots have `status`, `data`, `readers`, `writers`, `revision`, `error`, and
`deliveryFailure`. Their object identity changes for in-place CRDT updates.
Snapshot wrappers and membership arrays are frozen; the CRDT in `data` is still
mutable and every application edit must go through `store.change`. A stopped
snapshot drops its data reference. The underlying document and its owner may
still retain data. When a change rejects because its handle was retired, as a
Yjs or Loro document is after a change it cannot roll back, the status becomes
`retired`, `data` is dropped because the CRDT may still hold the discarded
edit, and `error` is the rejection. `stop()` and then `start()` open a fresh
handle in a store that owns the lifecycle.

Construction, subscription, and `getServerSnapshot()` perform no I/O. Do not
call `connect` or `start` while rendering on the server. If another owner has
already opened the handle and will close it, pass that handle with
`{ manageLifecycle: false }`. Otherwise one store must own each node/path:
Peerborne does not support multiple independent document handles for the same
path. A store that owns the lifecycle takes a function that creates the handle:

```js
const store = createDocumentStore(() => peerborne.doc('/workspace'));
```

It calls the function for every open, including a reconnect after the final
release closed the document or a retry after a failed open. A closed Peerborne
handle is not reopened: a configured `beekemForkStore` keeps its guard closed,
and a closed coordinated document stays closed. A fresh handle loads the
document from a connected peer, so a remount after the close needs a peer that
holds it, or a factory that restores the document's latest checkpoint before
the store opens the handle:

```js
const store = createDocumentStore(async () => {
  const document = peerborne.doc('/workspace');
  const saved = await loadCheckpoint('/workspace');
  if (saved) await document.restoreCheckpoint(saved);
  return document;
});
```

`loadCheckpoint` is application code. Export a checkpoint with
`document.exportCheckpoint()` after each change: a restored older checkpoint
leaves out the changes made after it.

- [Framework-free web guide](https://peerborne.io/getting-started/vanilla/)
- [Runnable examples](https://github.com/peerborne/peerborne/blob/main/examples/integrations/README.md)
- [Integration evidence and limits](https://peerborne.io/reference/integration-status/)

Peerborne remains alpha software, not production-ready. Package license: MIT.
