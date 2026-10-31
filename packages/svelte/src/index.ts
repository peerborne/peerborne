import { readable, type Readable } from 'svelte/store';
import type { DocumentSnapshot, DocumentStore } from '@peerborne/store';

/** A Svelte readable which opens only while browser subscribers are present. */
export function peerborneReadable<Doc, Change, PublicKey>(
  store: DocumentStore<Doc, Change, PublicKey>,
): Readable<DocumentSnapshot<Doc, PublicKey>> {
  return readable(store.getServerSnapshot(), (set) => {
    if (typeof window === 'undefined') return;
    const unsubscribe = store.subscribe(() => set(store.getSnapshot()));
    set(store.getSnapshot());
    const release = store.connect();
    return () => {
      unsubscribe();
      release();
    };
  });
}
