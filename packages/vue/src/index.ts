import {
  onMounted,
  onScopeDispose,
  shallowReadonly,
  shallowRef,
  toValue,
  watch,
  type MaybeRefOrGetter,
  type ShallowRef,
} from 'vue';
import type { DocumentSnapshot, DocumentStore } from '@peerborne/store';

/**
 * Bind a shared store in setup(); document access begins after mounting.
 * Pass a ref or getter, such as `() => props.store`, to follow a changing store.
 */
export function usePeerborneStore<Doc, Change, PublicKey>(
  store: MaybeRefOrGetter<DocumentStore<Doc, Change, PublicKey>>,
): Readonly<ShallowRef<DocumentSnapshot<Doc, PublicKey>>> {
  const snapshot = shallowRef(toValue(store).getServerSnapshot());
  let mounted = false;
  let unbind: (() => void) | undefined;
  const bind = (current: DocumentStore<Doc, Change, PublicKey>) => {
    unbind?.();
    const unsubscribe = current.subscribe(() => {
      snapshot.value = current.getSnapshot();
    });
    snapshot.value = current.getSnapshot();
    const release = current.connect();
    unbind = () => {
      unsubscribe();
      release();
    };
  };
  watch(
    () => toValue(store),
    (current) => {
      if (mounted) bind(current);
      else snapshot.value = current.getServerSnapshot();
    },
  );
  onMounted(() => {
    mounted = true;
    bind(toValue(store));
  });
  onScopeDispose(() => {
    unbind?.();
    unbind = undefined;
  });
  return shallowReadonly(snapshot);
}
