import type { CollectionConfig, PendingMutation } from '@tanstack/db';
import type { DocumentStore } from '@peerborne/store';

export interface PeerborneRowMutation<
  Row extends object,
  Key extends string | number,
> {
  readonly type: 'insert' | 'update' | 'delete';
  readonly key: Key;
  readonly value: Row;
  readonly changes: Partial<Row>;
}

export interface PeerborneCollectionOptions<
  Row extends object,
  Key extends string | number,
  Doc,
  Change,
  PublicKey,
> {
  id: string;
  store: DocumentStore<Doc, Change, PublicKey>;
  getKey: (row: Row) => Key;
  /** Return plain, structured-cloneable rows with unique, stable keys. */
  select: (document: Doc) => readonly Row[];
  /** Translate field changes into CRDT operations; do not replace whole documents. */
  mutate: (mutations: readonly PeerborneRowMutation<Row, Key>[]) => Change;
}

/**
 * Experimental eager collection projection, pinned to the declared TanStack DB
 * peer version. Each document notification replaces the complete row snapshot.
 * This does not implement query-driven network synchronization or persistence.
 * Construct during SSR, but start/preload the collection only in its owner runtime.
 */
export function peerborneCollectionOptions<
  Row extends object,
  Key extends string | number,
  Doc,
  Change,
  PublicKey,
>(
  options: PeerborneCollectionOptions<Row, Key, Doc, Change, PublicKey>,
): CollectionConfig<Row, Key> {
  const persist = async ({
    transaction,
    collection,
  }: {
    transaction: { mutations: readonly PendingMutation<Row>[] };
    collection: unknown;
  }) => {
    const mutations = transaction.mutations.filter(
      (mutation) => mutation.collection === collection,
    );
    await options.store.change(
      options.mutate(
        mutations.map((mutation) => ({
          type: mutation.type,
          key: mutation.key as Key,
          value: structuredClone(mutation.modified),
          changes: structuredClone(mutation.changes),
        })),
      ),
      'Collection change',
    );
  };

  return {
    id: options.id,
    getKey: options.getKey,
    startSync: false,
    onInsert: persist,
    onUpdate: persist,
    onDelete: persist,
    sync: {
      rowUpdateMode: 'full',
      sync: ({ begin, write, commit, markReady, fail }) => {
        let active = true;
        let unsubscribe = () => {};
        let release = () => {};
        const stopWithError = (error: unknown) => {
          if (!active) return;
          active = false;
          unsubscribe();
          release();
          fail(error);
        };
        const refresh = () => {
          if (!active) return;
          const snapshot = options.store.getSnapshot();
          if (snapshot.status === 'error') {
            stopWithError(snapshot.error);
            return;
          }
          if (snapshot.status !== 'ready' || snapshot.data === undefined)
            return;
          try {
            const rows = options
              .select(snapshot.data)
              .map((row) => structuredClone(row));
            const keys = new Set<Key>();
            for (const row of rows) {
              const key = options.getKey(row);
              if (keys.has(key))
                throw new Error(
                  'Duplicate key in Peerborne collection projection',
                );
              keys.add(key);
            }
            begin({ snapshot: true });
            for (const value of rows) write({ type: 'insert', value });
            const applied = commit();
            if (applied !== true) void applied.catch(stopWithError);
            markReady();
          } catch (error) {
            stopWithError(error);
          }
        };
        unsubscribe = options.store.subscribe(refresh);
        release = options.store.connect();
        refresh();
        return () => {
          active = false;
          unsubscribe();
          release();
        };
      },
    },
  };
}
