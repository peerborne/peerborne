import { createRoot } from 'react-dom/client';
import { StrictMode } from 'react';
import { DocumentWorkspace } from '../../../shared/Workspace';
import { usingSession } from '../session-view';

export const mount = (root: HTMLElement) =>
  usingSession(root, 'react', (target, session) => {
    target.replaceChildren();
    const app = createRoot(target);
    app.render(
      <StrictMode>
        <DocumentWorkspace session={session} />
      </StrictMode>,
    );
    return () => app.unmount();
  });
