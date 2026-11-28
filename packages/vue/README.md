# `@peerborne/vue`

Vue 3 composables over `@peerborne/store`. Alpha source workspace; unpublished.

```ts
import { usePeerborneStore } from '@peerborne/vue';

// Inside setup(), using a shared, application-owned document store:
const snapshot = usePeerborneStore(store);
const rename = (title: string) =>
  store.change((doc) => doc.getMap('data').set('title', title));
```

The returned shallow readonly ref contains the complete document snapshot. It
does not proxy CRDT internals. Ownership starts in `onMounted`, and listeners
and ownership are released when the component scope is disposed. Server
rendering uses the idle snapshot without opening documents. Call
`store.change` from an event handler once `snapshot.value.status` is `ready`:
a change never opens the document, so one made in `setup()` rejects with
`Document store is closed`.

To follow a store prop, pass a getter or ref such as
`usePeerborneStore(() => props.store)`. When it changes, the composable
releases the previous store and connects the new one.

Use the same composable in Nuxt client components, creating the node in the
browser. This repository tests Vue server rendering and a Vue browser example;
a complete Nuxt application is not an acceptance target yet.

See the [framework guide](https://peerborne.io/cookbook/framework-integrations/)
and [runnable example](https://github.com/peerborne/peerborne/blob/main/examples/integrations/src/vue.ts). MIT licensed;
not production-ready.
