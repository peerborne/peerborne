import { createApp, h, ref } from 'vue';
import { usePeerborneStore } from '@peerborne/vue';
import type { BrowserSession } from '../../shared/browser-session';

export function mountVue(root: HTMLElement, session: BrowserSession) {
  const app = createApp({
    setup() {
      const snapshot = usePeerborneStore(session.store);
      const title = ref('');
      const failed = ref(false);
      const save = async () => {
        const nextTitle = title.value;
        try {
          await session.store.change((doc) => {
            doc.getMap('data').set('title', nextTitle);
          });
          failed.value = false;
        } catch {
          failed.value = true;
        }
      };
      return () =>
        h('section', [
          h(
            'p',
            { role: 'status', 'aria-label': 'Document status' },
            snapshot.value.status,
          ),
          h(
            'output',
            { 'data-testid': 'document-title' },
            String(
              snapshot.value.data?.getMap('data').get('title') ?? 'Untitled',
            ),
          ),
          h('label', [
            'Title ',
            h('input', {
              value: title.value,
              onInput: (event: Event) => {
                title.value = (event.target as HTMLInputElement).value;
              },
            }),
          ]),
          h(
            'button',
            { disabled: snapshot.value.status !== 'ready', onClick: save },
            'Save title',
          ),
          failed.value || snapshot.value.error !== undefined
            ? h('p', { role: 'alert' }, 'The document operation failed.')
            : null,
        ]);
    },
  });
  app.mount(root);
  return () => app.unmount();
}
