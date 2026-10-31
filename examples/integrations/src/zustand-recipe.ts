import { createStore as createZustandStore } from 'zustand/vanilla';
import type { DocumentStore } from '@peerborne/store';

export function zustandProjection<Doc, Change, PublicKey>(
  source: DocumentStore<Doc, Change, PublicKey>,
) {
  const state = createZustandStore(() => ({
    snapshot: source.getServerSnapshot(),
  }));
  return {
    state,
    connect() {
      const update = () => {
        state.setState({ snapshot: source.getSnapshot() });
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
