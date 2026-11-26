# `@peerborne/svelte`

Svelte readable bindings over `@peerborne/store`. Alpha source workspace;
unpublished. The binding uses only `readable` from `svelte/store` and supports
Svelte 4 and 5. The example below uses Svelte 5 runes.

```svelte
<script>
  import { peerborneReadable } from '@peerborne/svelte';
  let { store } = $props();
  const snapshot = $derived(peerborneReadable(store));
</script>

<p>{$snapshot.status}</p>
```

The readable retains the shared document while browser subscribers exist and
releases it after the final unsubscribe. Reading the store during server
rendering returns the idle snapshot without starting a node or document. Make
mutations through the original `store.change` and await its promise.

For SvelteKit, create browser sessions in `onMount` and release them on teardown.
This repository tests readable behavior on the server and a compiled Svelte
browser example; a complete SvelteKit application is not an acceptance target
yet.

See the [framework guide](https://peerborne.io/cookbook/framework-integrations/)
and [runnable component](https://github.com/peerborne/peerborne/blob/main/examples/integrations/src/App.svelte). MIT
licensed; not production-ready.
