'use client';

import { useEffect, useSyncExternalStore } from 'react';
import type { DocumentSnapshot, DocumentStore } from '@peerborne/store';

/** Subscribe to a shared store without a context provider or render-time I/O. */
export function usePeerborneStore<Doc, Change, PublicKey>(
  store: DocumentStore<Doc, Change, PublicKey>,
): DocumentSnapshot<Doc, PublicKey> {
  const snapshot = useSyncExternalStore(
    store.subscribe,
    store.getSnapshot,
    store.getServerSnapshot,
  );
  useEffect(() => store.connect(), [store]);
  return snapshot;
}
