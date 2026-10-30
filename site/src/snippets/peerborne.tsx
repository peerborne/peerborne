import { useState, type ContextType, type ReactNode } from 'react';
import { PeerborneContext } from '@peerborne/react';
import {
  Peerborne,
  SubtleCrypto,
  defaultConfig,
  defaultBootstrapConfig,
} from '@peerborne/core';
import {
  AutomergeProvider,
  AutomergeJSONSerializer,
  AutomergeACLProvider,
  AutomergeKeychainProvider,
} from '@peerborne/automerge';

type WorkspaceData = { title?: string };
type SessionContext = ContextType<typeof PeerborneContext>;

export async function createWorkspaceNode() {
  const keys = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  );
  const serializer = new AutomergeJSONSerializer();
  const peerborne = new Peerborne(
    keys.privateKey,
    keys.publicKey,
    new AutomergeProvider<WorkspaceData>(),
    serializer,
    serializer,
    serializer,
    new SubtleCrypto(),
    new AutomergeACLProvider(),
    new AutomergeKeychainProvider(),
  );
  await peerborne.initialize(defaultConfig(defaultBootstrapConfig([])));
  return peerborne;
}

export type WorkspaceNode = Awaited<ReturnType<typeof createWorkspaceNode>>;

export function DocumentSessions({ children }: { children: ReactNode }) {
  const [docCache, setDocCache] = useState<SessionContext['docCache']>({});
  const [docDataCache, setDocDataCache] = useState<SessionContext['docDataCache']>({});
  const [docReadersCache, setDocReadersCache] = useState<
    SessionContext['docReadersCache']
  >({});
  const [docWritersCache, setDocWritersCache] = useState<
    SessionContext['docWritersCache']
  >({});

  return (
    <PeerborneContext.Provider
      value={{
        docCache,
        setDocCache,
        docDataCache,
        setDocDataCache,
        docReadersCache,
        setDocReadersCache,
        docWritersCache,
        setDocWritersCache,
      }}
    >
      {children}
    </PeerborneContext.Provider>
  );
}
