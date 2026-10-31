<script lang="ts">
  import { peerborneReadable } from '@peerborne/svelte';
  import type { BrowserSession } from '../../shared/browser-session';

  let { session }: { session: BrowserSession } = $props();
  const snapshot = $derived(peerborneReadable(session.store));
  let title = $state('');
  let failed = $state(false);
  async function save() {
    const nextTitle = title;
    try {
      await session.store.change((doc) => { doc.getMap('data').set('title', nextTitle); });
      failed = false;
    } catch { failed = true; }
  }
</script>

<section>
  <p role="status" aria-label="Document status">{$snapshot.status}</p>
  <output data-testid="document-title">{String($snapshot.data?.getMap('data').get('title') ?? 'Untitled')}</output>
  <label>Title <input bind:value={title} /></label>
  <button disabled={$snapshot.status !== 'ready'} onclick={save}>Save title</button>
  {#if failed || $snapshot.error !== undefined}<p role="alert">The document operation failed.</p>{/if}
</section>
