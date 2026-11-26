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
    status === 'ready' && data
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
final release keeps a document open while `snapshot.deliveryFailure` is set,
because that change may exist only in the open handle, for up to
`undeliveredCloseDelay` milliseconds (30 minutes by default, `Infinity` for no
limit). After that the store closes the handle, and the change is lost unless a
checkpoint holds it. A frame that reaches no peer known to serve a member, with
no peers at all or only a relay subscribed to the topic, is reported as a
`NoDeliveryPeersError`. The failure clears, and a released store then closes the
document, once there is evidence that a member holds the change or was sent it:
a later frame sent to a peer that recently proved it serves a member with a
signed sync request, a member's sync request that names the change, or a
writer's frame that builds on it. That is evidence of delivery, not an
acknowledgment that a member stored the change. A frame that reaches members
only through a relay mesh stays reported until a member's next sync request,
which a member with automatic catch-up sends 1 to 2 s after a frame adds a
change. A custom handle reports its
delivery state through `subscribeDeliveryState` and `unsubscribeDeliveryState`,
which every handle implements; one that never fails to deliver accepts the
handler and never calls it. Explicit `start()` and `stop()`
return promises for imperative applications: `start()` keeps the document open until
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
  if (saved) await document.restoreEncryptedCheckpoint(saved, storageKey);
  return document;
});
```

`loadCheckpoint` and `storageKey`, a non-extractable 256-bit AES-GCM
`CryptoKey`, are application code. Save
`await document.exportEncryptedCheckpoint(storageKey)` after each change: a
restored older checkpoint leaves out the changes made after it. A checkpoint
holds the document's state and its document keys, so keep it encrypted at
rest and never send it to another party. `exportPlaintextCheckpoint()` returns
it unencrypted; see
[Local checkpoints](https://peerborne.io/concepts/storage/#local-checkpoints).

- [Framework-free web guide](https://peerborne.io/getting-started/vanilla/)
- [Runnable examples](https://github.com/peerborne/peerborne/blob/main/examples/integrations/README.md)
- [Integration evidence and limits](https://peerborne.io/reference/integration-status/)

Peerborne remains alpha software, not production-ready. Package license: MIT.
