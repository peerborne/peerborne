export type DocumentStatus = 'idle' | 'opening' | 'ready' | 'error' | 'closed';

/** The document surface needed by UI integrations. No networking code is imported. */
export interface DocumentHandle<Doc, Change, PublicKey = unknown> {
  readonly document: Doc;
  open(): Promise<unknown>;
  close(): Promise<unknown>;
  getReaders(): Promise<PublicKey[]>;
  getWriters(): Promise<PublicKey[]>;
  change(change: Change, message?: string): Promise<unknown>;
  subscribe(
    id: string,
    handler: (
      document: Doc,
      readers: PublicKey[],
      writers: PublicKey[],
      hashes: string[],
    ) => void,
    originFilter?: 'all' | 'local' | 'remote',
  ): void;
  unsubscribe(id: string): void;
}

/** A new snapshot is published even when the underlying CRDT mutates in place. */
export interface DocumentSnapshot<Doc, PublicKey = unknown> {
  readonly status: DocumentStatus;
  readonly data: Doc | undefined;
  readonly readers: readonly PublicKey[];
  readonly writers: readonly PublicKey[];
  readonly revision: number;
  readonly error: unknown;
}

export interface DocumentStore<Doc, Change, PublicKey = unknown> {
  getSnapshot(): DocumentSnapshot<Doc, PublicKey>;
  getServerSnapshot(): DocumentSnapshot<Doc, PublicKey>;
  /** Register a listener without opening a document or starting a node. */
  subscribe(listener: () => void): () => void;
  start(): Promise<void>;
  stop(): Promise<void>;
  /** Retain the shared document until the returned, idempotent release runs. */
  connect(): () => void;
  change(change: Change, message?: string): Promise<void>;
}

export interface DocumentStoreOptions {
  /** Set false when the caller opens and closes an already shared handle. */
  manageLifecycle?: boolean;
}

let nextSubscription = 0;

/**
 * Create one store per node/document path and share it between consumers.
 * Construction and subscription are safe during server rendering. Call start()
 * or connect() in the browser to open the document. Changes retain their promise.
 */
export function createDocumentStore<Doc, Change, PublicKey>(
  document: DocumentHandle<Doc, Change, PublicKey>,
  options: DocumentStoreOptions = {},
): DocumentStore<Doc, Change, PublicKey> {
  const id = `peerborne-store-${nextSubscription++}`;
  const manageLifecycle = options.manageLifecycle !== false;
  const initial: DocumentSnapshot<Doc, PublicKey> = Object.freeze({
    status: 'idle',
    data: undefined,
    readers: Object.freeze([]),
    writers: Object.freeze([]),
    revision: 0,
    error: undefined,
  });
  let snapshot = initial;
  let opened = false;
  let connected = 0;
  let tail = Promise.resolve();
  const listeners = new Set<() => void>();

  function publish(next: Omit<DocumentSnapshot<Doc, PublicKey>, 'revision'>) {
    snapshot = Object.freeze({
      ...next,
      readers: Object.freeze([...next.readers]),
      writers: Object.freeze([...next.writers]),
      revision: snapshot.revision + 1,
    });
    for (const listener of [...listeners]) listener();
  }

  function enqueue(action: () => Promise<void>): Promise<void> {
    const task = tail.then(action);
    tail = task.catch(() => {});
    return task;
  }

  function start(): Promise<void> {
    return enqueue(async () => {
      if (opened) return;
      publish({ ...initial, status: 'opening' });
      let latest: { readers: PublicKey[]; writers: PublicKey[] } | undefined;
      try {
        document.subscribe(id, (data, readers, writers) => {
          latest = { readers, writers };
          if (opened) {
            publish({
              status: 'ready',
              data,
              readers,
              writers,
              error: undefined,
            });
          }
        });
        if (manageLifecycle) await document.open();
        const [readers, writers] = await Promise.all([
          document.getReaders(),
          document.getWriters(),
        ]);
        opened = true;
        publish({
          status: 'ready',
          data: document.document,
          readers: latest?.readers ?? readers,
          writers: latest?.writers ?? writers,
          error: undefined,
        });
      } catch (cause) {
        opened = false;
        const errors = [cause];
        try {
          document.unsubscribe(id);
        } catch (cleanupError) {
          errors.push(cleanupError);
        }
        if (manageLifecycle) {
          try {
            await document.close();
          } catch (cleanupError) {
            errors.push(cleanupError);
          }
        }
        const error =
          errors.length === 1
            ? cause
            : new AggregateError(errors, 'Document open and cleanup failed');
        publish({ ...initial, status: 'error', error });
        throw error;
      }
    });
  }

  function stop(): Promise<void> {
    return enqueue(async () => {
      const shouldClose = opened && manageLifecycle;
      opened = false;
      const errors: unknown[] = [];
      try {
        document.unsubscribe(id);
      } catch (error) {
        errors.push(error);
      }
      if (shouldClose) {
        try {
          await document.close();
        } catch (error) {
          errors.push(error);
        }
      }
      if (errors.length > 0) {
        const error =
          errors.length === 1
            ? errors[0]
            : new AggregateError(errors, 'Document cleanup failed');
        publish({ ...initial, status: 'error', error });
        throw error;
      }
      publish({ ...initial, status: 'closed' });
    });
  }

  return {
    getSnapshot: () => snapshot,
    getServerSnapshot: () => initial,
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    start,
    stop,
    connect() {
      connected++;
      if (connected === 1) void start().catch(() => {});
      let released = false;
      return () => {
        if (released) return;
        released = true;
        connected--;
        queueMicrotask(() => {
          if (connected === 0) void stop().catch(() => {});
        });
      };
    },
    change(change, message) {
      const opening = start();
      return enqueue(async () => {
        await opening;
        if (!opened) throw new Error('Document store is closed');
        try {
          await document.change(change, message);
          if (snapshot.error !== undefined) {
            publish({ ...snapshot, error: undefined });
          }
        } catch (error) {
          publish({ ...snapshot, error });
          throw error;
        }
      });
    },
  };
}
