import { jotaiProjection } from '../jotai-recipe';
import { usingSession } from '../session-view';
import { mountTitleForm } from '../dom';

export const mount = (root: HTMLElement) =>
  usingSession(root, 'jotai', (target, session) => {
    const projection = jotaiProjection(session.store);
    const store = {
      ...session.store,
      getSnapshot: () => projection.state.get(projection.snapshot),
      subscribe: (listener: () => void) =>
        projection.state.sub(projection.snapshot, listener),
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
