import { zustandProjection } from '../zustand-recipe';
import { usingSession } from '../session-view';
import { mountTitleForm } from '../dom';

export const mount = (root: HTMLElement) =>
  usingSession(root, 'zustand', (target, session) => {
    const projection = zustandProjection(session.store);
    const store = {
      ...session.store,
      getSnapshot: () => projection.state.getState().snapshot,
      subscribe: (listener: () => void) => projection.state.subscribe(listener),
      connect: projection.connect,
    };
    return mountTitleForm(
      target,
      store,
      (doc) => String(doc.getMap('data').get('title') ?? 'Untitled'),
      (title) => (doc) => {
        doc.getMap('data').set('title', title);
      },
    );
  });
