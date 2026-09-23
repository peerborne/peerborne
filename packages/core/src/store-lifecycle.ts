/** A configured browser store whose lifecycle uses open/close. */
export interface OpenableStore {
  open(): Promise<void>;
  close?: () => Promise<void>;
}

function isOpenableStore(value: unknown): value is OpenableStore {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { open?: unknown }).open === 'function'
  );
}

/**
 * Open custom Helia stores before Helia/libp2p first access them.
 *
 * Current `datastore-idb` and `blockstore-idb` expose `open()` / `close()`.
 * Helia auto-starts stores implementing `start()` / `stop()` and checks its
 * datastore version before those hooks, so IndexedDB stores must be opened
 * before the node starts.
 */
export async function openHeliaStores(
  ...stores: unknown[]
): Promise<OpenableStore[]> {
  const opened: OpenableStore[] = [];
  try {
    for (const store of new Set(stores)) {
      if (!isOpenableStore(store)) continue;
      await store.open();
      opened.push(store);
    }
    return opened;
  } catch (error) {
    await closeHeliaStores(opened);
    throw error;
  }
}

/** Close stores in reverse-open order, attempting every close operation. */
export async function closeHeliaStores(
  stores: OpenableStore[],
): Promise<void> {
  for (const store of [...stores].reverse()) {
    try {
      await store.close?.();
    } catch {
      continue;
    }
  }
}
