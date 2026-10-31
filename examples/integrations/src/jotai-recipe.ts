import { atom, createStore as createJotaiStore } from 'jotai/vanilla';
import type { DocumentStore } from '@peerborne/store';

export function jotaiProjection<Doc, Change, PublicKey>(
  source: DocumentStore<Doc, Change, PublicKey>,
) {
  const snapshot = atom(source.getServerSnapshot());
  const state = createJotaiStore();
  return {
    state,
    snapshot,
    connect() {
      const update = () => {
        state.set(snapshot, source.getSnapshot());
      };
      const unsubscribe = source.subscribe(update);
      update();
      const release = source.connect();
      return () => {
        unsubscribe();
        release();
      };
    },
  };
}
