import {
  onMounted,
  onScopeDispose,
  shallowReadonly,
  shallowRef,
  type ShallowRef,
} from 'vue';
import type { DocumentSnapshot, DocumentStore } from '@peerborne/store';

/** Bind a shared store in setup(); document access begins after mounting. */
export function usePeerborneStore<Doc, Change, PublicKey>(
  store: DocumentStore<Doc, Change, PublicKey>,
): Readonly<ShallowRef<DocumentSnapshot<Doc, PublicKey>>> {
  const snapshot = shallowRef(store.getServerSnapshot());
  let unsubscribe: (() => void) | undefined;
  let release: (() => void) | undefined;
  onMounted(() => {
    unsubscribe = store.subscribe(() => {
      snapshot.value = store.getSnapshot();
    });
    snapshot.value = store.getSnapshot();
    release = store.connect();
  });
  onScopeDispose(() => {
    unsubscribe?.();
    release?.();
  });
  return shallowReadonly(snapshot);
}
