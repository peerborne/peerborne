import { createCollection } from '@tanstack/db';
import { peerborneCollectionOptions } from '@peerborne/tanstack-db';
import type { BrowserSession } from '../../shared/browser-session';

export async function mountCollection(
  root: HTMLElement,
  session: BrowserSession,
) {
  type Row = { id: string; title: string };
  const collection = createCollection(
    peerborneCollectionOptions({
      id: 'workspace',
      store: session.store,
      getKey: (row: Row) => row.id,
      select: (doc): Row[] => [
        {
          id: 'workspace',
          title: String(doc.getMap('data').get('title') ?? 'Untitled'),
        },
      ],
      mutate: (mutations) => (doc) => {
        for (const mutation of mutations) {
          if (
            mutation.type !== 'delete' &&
            mutation.changes.title !== undefined
          ) {
            doc.getMap('data').set('title', mutation.changes.title);
          }
        }
      },
    }),
  );
  await collection.preload();
  root.innerHTML =
    '<section><p role="status" aria-label="Document status">ready</p><output data-testid="document-title"></output><label>Title <input /></label><button>Save title</button><p role="alert" hidden></p></section>';
  const output = root.querySelector<HTMLOutputElement>('output')!;
  const render = () => {
    output.textContent = collection.get('workspace')?.title ?? 'Untitled';
  };
  const subscription = collection.subscribeChanges(render);
  const button = root.querySelector<HTMLButtonElement>('button')!;
  const input = root.querySelector<HTMLInputElement>('input')!;
  const alert = root.querySelector<HTMLElement>('[role="alert"]')!;
  const save = async () => {
    try {
      const transaction = collection.update('workspace', (row) => {
        row.title = input.value;
      });
      await transaction.when('settled');
      alert.hidden = true;
    } catch {
      alert.hidden = false;
      alert.textContent = 'The document operation failed.';
    }
  };
  const click = () => {
    void save();
  };
  button.addEventListener('click', click);
  render();
  return async () => {
    button.removeEventListener('click', click);
    subscription.unsubscribe();
    await collection.cleanup();
  };
}
