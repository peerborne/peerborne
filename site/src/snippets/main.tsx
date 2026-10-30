import { createRoot } from 'react-dom/client';
import { createWorkspaceNode, DocumentSessions } from './peerborne';
import { Workspace } from './Workspace';

const root = createRoot(document.getElementById('root')!);

try {
  const peerborne = await createWorkspaceNode();
  root.render(
    <DocumentSessions>
      <Workspace peerborne={peerborne} />
    </DocumentSessions>,
  );
} catch {
  root.render(<p>Could not initialize the local workspace. Reload to retry.</p>);
}
