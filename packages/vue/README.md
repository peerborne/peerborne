# `@peerborne/vue`

Vue 3 composables over `@peerborne/store`. Alpha source workspace; unpublished.

```ts
import { usePeerborneStore } from '@peerborne/vue';

// Inside setup(), using a shared, application-owned document store:
const snapshot = usePeerborneStore(store);
await store.change((doc) => doc.getMap('data').set('title', 'Hello'));
```

The returned shallow readonly ref contains the complete document snapshot. It
does not proxy CRDT internals. Ownership starts in `onMounted`, and listeners
and ownership are released when the component scope is disposed. Server
rendering uses the idle snapshot without opening documents.

Use the same composable in Nuxt client components, creating the node in the
browser. This repository tests Vue server rendering and a Vue browser example;
a complete Nuxt application is not an acceptance target yet.

See the [framework guide](https://peerborne.io/cookbook/framework-integrations/)
and [runnable example](../../examples/integrations/src/vue.ts). MIT licensed;
not production-ready.
