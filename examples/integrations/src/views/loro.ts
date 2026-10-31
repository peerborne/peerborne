import { LoroProvider } from '@peerborne/loro';
import { createSession } from '../../../shared/browser-session';
import { mountTitleForm } from '../dom';

export async function mount(root: HTMLElement) {
  const session = await createSession(new LoroProvider(), '/examples/loro');
  try {
    const unmount = mountTitleForm(
      root,
      session.store,
      (doc) => String(doc.getMap('data').get('title') ?? 'Untitled'),
      (title) => (doc) => {
        doc.getMap('data').set('title', title);
      },
    );
    return async () => {
      unmount();
      await session.dispose();
    };
  } catch (error) {
    await session.dispose();
    throw error;
  }
}
