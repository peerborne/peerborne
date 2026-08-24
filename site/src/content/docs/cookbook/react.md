---
title: React integration
description: Use the current React hooks for a basic, single-identity Yjs document from repository workspaces.
---

**Status: Runnable from source for basic single-identity hooks; sharing is incomplete.**

The packages are unpublished. Build and consume the repository workspaces as shown in the [quick start](../../getting-started/quick-start/). The current password-manager source typechecks, builds, and passes a Chromium startup smoke test:

```sh
yarn build
yarn workspace @peerborne/password-manager build
yarn test:e2e:password-manager
```

This evidence covers startup, not sharing or cross-browser convergence.

## Provide the current context shape

`usePeerborneDocumentState` requires four caches and four setters backed by React state:

```tsx
function SwarmDocumentProvider({ children }: { children: React.ReactNode }) {
  const [docCache, setDocCache] = React.useState<Record<string, any>>({});
  const [docDataCache, setDocDataCache] = React.useState<Record<string, any>>({});
  const [docReadersCache, setDocReadersCache] = React.useState<Record<string, any[]>>({});
  const [docWritersCache, setDocWritersCache] = React.useState<Record<string, any[]>>({});

  return (
    <PeerborneContext.Provider value={{
      docCache,
      docDataCache,
      docReadersCache,
      docWritersCache,
      setDocCache,
      setDocDataCache,
      setDocReadersCache,
      setDocWritersCache,
    }}>
      {children}
    </PeerborneContext.Provider>
  );
}
```

The default context setters are no-ops; omitting this provider prevents cache updates from driving renders.

## Initialize one identity

Create provider instances outside render, then pass stable ECDSA P-384 signing keys to the current hook signature:

```tsx
const crdt = new YjsProvider();
const serializer = new YjsJSONSerializer();
const auth = new SubtleCrypto();
const acl = new YjsACLProvider();
const keychain = new YjsKeychainProvider();

const swarm = usePeerborne(
  privateKey,
  publicKey,
  crdt,
  serializer,
  serializer,
  serializer,
  auth,
  acl,
  keychain,
  defaultConfig(defaultBootstrapConfig(
    import.meta.env.VITE_RELAY_MULTIADDR
      ? [import.meta.env.VITE_RELAY_MULTIADDR]
      : [],
  )),
);
```

The application must persist and restore the signing keys. New keys mean a new ACL identity. `usePeerborne` re-runs when key object identity changes, but it has no effect cleanup that stops the previous swarm; do not rotate or reconstruct keys during normal rendering.

## Open and change one document

```tsx
import type { Peerborne } from '@peerborne/core';
import type * as Y from 'yjs';

type YjsSwarm = Peerborne<
  Y.Doc,
  Uint8Array,
  (doc: Y.Doc) => void,
  CryptoKey,
  CryptoKey,
  CryptoKey
>;

function Note({ swarm }: { swarm: YjsSwarm }) {
  const [doc, changeDoc, acl] = usePeerborneDocumentState(
    swarm,
    '/notes/hello',
  );

  if (!doc) return <p>Opening…</p>;

  return (
    <button onClick={() => {
      changeDoc((current: Y.Doc) => {
        current.getText('content').insert(0, 'Hello ');
      });
    }}>
      {doc.getText('content').toString()} ({acl.writers?.length ?? 0} writers)
    </button>
  );
}
```

The tuple is `[document | undefined, changeDoc, aclControls]`; `originFilter` is optionally `'all'`, `'remote'`, or `'local'`.

`changeDoc` returns `void`. It fire-and-forgets `documentRef.change()` and does not return or catch its promise, so authorization, storage, encryption, or publication rejection is dropped by the wrapper. It is also a no-op before the document ref reaches the cache. Use the direct document API when the UI must await and report failures.

## Lifecycle boundaries

Each document-hook instance unsubscribes on cleanup, and the last subscriber closes and evicts that document. The open-task map deduplicates an in-flight open, including a rapid StrictMode remount. That is the only StrictMode guarantee: it is not a guarantee for swarm initialization, networking, mutations, or every side effect.

The ACL controls expose `addReader(user)` and cannot pass the recipient's raw P-256 ECDH KEM key or install a KEM key pair. They therefore cannot perform complete distinct-identity onboarding. Use the direct API and the sequence in [Encrypted shared secrets store](../password-manager/). See [Security](../../concepts/security/) for persistence and revocation limits.
