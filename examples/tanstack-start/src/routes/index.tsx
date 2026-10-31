import { createFileRoute } from '@tanstack/react-router';
import { BrowserWorkspace } from '../../../shared/Workspace';

export const Route = createFileRoute('/')({
  component: () => (
    <main>
      <h1>Peerborne with TanStack Start</h1>
      <BrowserWorkspace />
    </main>
  ),
});
