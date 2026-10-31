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
queues a close; a same-turn reconnect keeps the document open. Explicit
`start()` and `stop()` return promises for imperative applications. Operations
are serialized so a close waits for pending writes. Mutation rejections reach
the caller and `snapshot.error`.

Snapshots have `status`, `data`, `readers`, `writers`, `revision`, and `error`.
Their object identity changes for in-place CRDT updates. Snapshot wrappers and
membership arrays are frozen; the CRDT in `data` is still mutable and every
application edit must go through `store.change`. A stopped snapshot drops its
data reference. The underlying document and its owner may still retain data.

Construction, subscription, and `getServerSnapshot()` perform no I/O. Do not
call `connect` or `start` while rendering on the server. If another owner has
already opened the handle and will close it, use `{ manageLifecycle: false }`.
Otherwise one store must own each node/path: Peerborne does not support multiple
independent document handles for the same path.

- [Framework-free web guide](https://peerborne.io/getting-started/vanilla/)
- [Runnable examples](../../examples/integrations/README.md)
- [Integration evidence and limits](https://peerborne.io/reference/integration-status/)

Peerborne remains alpha software, not production-ready. Package license: MIT.
