import { usingSession } from '../session-view';
import { mountTitleForm } from '../dom';

export const mount = (root: HTMLElement) =>
  usingSession(root, 'vanilla', (target, session) =>
    mountTitleForm(
      target,
      session.store,
      (doc) => String(doc.getMap('data').get('title') ?? 'Untitled'),
      (title) => (doc) => {
        doc.getMap('data').set('title', title);
      },
    ),
  );
