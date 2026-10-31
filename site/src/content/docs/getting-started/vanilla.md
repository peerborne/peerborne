---
title: Framework-free web projects
description: Use Peerborne with plain JavaScript, DOM APIs, and optional build tooling.
---

Peerborne does not require a frontend framework. `@peerborne/store` provides
document subscriptions and lifecycle management without importing React, Vue,
Svelte, networking, or browser globals. Vite is development/build tooling and is
optional at the integration API boundary.

## Run the plain DOM example

Use Node.js 22.19.0 and Yarn 4.5.0 from a source checkout. All packages remain
unpublished alpha workspaces:

```sh
corepack enable
yarn install --immutable
yarn build
yarn workspace @peerborne/integration-examples start
```

Open the printed URL. The default view uses DOM APIs. Click **Start local
document**, enter a title, and save. The output reflects the real local Peerborne
document after its change pipeline runs. The other links exercise optional
framework and editor integrations.

## Subscribe from JavaScript

Once your application has initialized a node, share one store per node/document
path. The example's complete initialization lives in
[`browser-session.ts`](https://github.com/Peerborne/peerborne/blob/main/examples/shared/browser-session.ts).

```js
import { createDocumentStore } from '@peerborne/store';

const document = peerborne.doc('/workspace');
await document.create();
const store = createDocumentStore(document, { manageLifecycle: false });
const unsubscribe = store.subscribe(render);
const release = store.connect();

function render() {
  const snapshot = store.getSnapshot();
  output.textContent =
    snapshot.status === 'ready'
      ? String(snapshot.data.getMap('data').get('title') ?? 'Untitled')
      : snapshot.status;
}

render();
await store.change((doc) => doc.getMap('data').set('title', 'Hello'));

// When this consumer is removed:
unsubscribe();
release();
await store.stop();
await document.close();
```

`subscribe` does not open anything. `connect` opens and retains the shared
document until the last consumer releases it. Imperative applications can
instead `await store.start()` and `await store.stop()`. Every mutation returns a
promise; catch it to report authorization, storage, or publication failures.
Use `snapshot.error` for subscription-driven error UI.

Snapshots change identity when mutable CRDT state changes. The wrapper and
membership arrays are readonly, but `snapshot.data` is the actual CRDT: route
all writes through `store.change`. Peerborne does not support independent
document handles for the same node/path; share the store between consumers.

## Existing sites and native modules

Mount a DOM binding in any existing element and remove its listeners when that
element is removed. Custom elements can acquire ownership in
`connectedCallback` and release it in `disconnectedCallback`. Neither requires a
framework-specific adapter. A compiled single-file store entry can also be
served as native ESM because it has no runtime dependencies.

The full Peerborne runtime still needs its dependencies resolved for browsers,
as the Vite example does. No published CDN URL or standalone prebundled runtime
is provided. Build tooling is separate from framework choice.

The example generates a fresh signing identity on reload and has no bootstrap
peers. Durable identity/key storage and new-member onboarding are application
work; a document path does not grant access. See
[Identities](../../concepts/identities/) and
[integration evidence](../../reference/integration-status/).
