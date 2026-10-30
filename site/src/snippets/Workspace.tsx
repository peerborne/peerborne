import { usePeerborneDocumentState } from '@peerborne/react';
import type { WorkspaceNode } from './peerborne';

export function Workspace({ peerborne }: { peerborne: WorkspaceNode }) {
  const [doc, change, , error] = usePeerborneDocumentState(peerborne, '/workspace', 'all', 'create');
  if (!doc) return <p>{error ? 'Could not create workspace' : 'Opening…'}</p>;
  return <button onClick={() => change((draft) => {
    draft.title = 'Ready to ship';
  })}>{doc.title ?? 'Name this workspace'}</button>;
}
