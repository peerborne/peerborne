export type DocumentStatus = 'idle' | 'opening' | 'ready' | 'error' | 'closed';

/** A local change that was committed but whose frame could not be published. */
export interface DocumentDeliveryFailure {
  readonly documentPath: string;
  readonly changeId: string;
  readonly error: unknown;
}

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
  subscribeDeliveryFailures?(
    id: string,
    handler: (failure: DocumentDeliveryFailure) => void,
  ): void;
  unsubscribeDeliveryFailures?(id: string): void;
}

/** A new snapshot is published even when the underlying CRDT mutates in place. */
export interface DocumentSnapshot<Doc, PublicKey = unknown> {
  readonly status: DocumentStatus;
  readonly data: Doc | undefined;
  readonly readers: readonly PublicKey[];
  readonly writers: readonly PublicKey[];
  readonly revision: number;
  readonly error: unknown;
  /**
   * The latest change made on this device that is committed locally but was
   * not delivered, because its frame could not be published. A later change
   * through this store whose frame is published clears it, since that frame
   * carries the earlier change.
   */
  readonly deliveryFailure: DocumentDeliveryFailure | undefined;
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
 *
 * A managed store calls `createHandle`, such as `() => peerborne.doc(path)`,
 * for every open and closes that handle when it stops. It never reopens a
 * closed handle: a durable BeeKEM fork guard or coordinated document refuses.
 */
export function createDocumentStore<Doc, Change, PublicKey>(
  createHandle: () => DocumentHandle<Doc, Change, PublicKey>,
  options?: DocumentStoreOptions & { manageLifecycle?: true },
): DocumentStore<Doc, Change, PublicKey>;
/** An unmanaged store subscribes to a handle that the caller opens and closes. */
export function createDocumentStore<Doc, Change, PublicKey>(
  document: DocumentHandle<Doc, Change, PublicKey>,
  options: DocumentStoreOptions & { manageLifecycle: false },
): DocumentStore<Doc, Change, PublicKey>;
export function createDocumentStore<Doc, Change, PublicKey>(
  source:
    | DocumentHandle<Doc, Change, PublicKey>
    | (() => DocumentHandle<Doc, Change, PublicKey>),
  options: DocumentStoreOptions = {},
): DocumentStore<Doc, Change, PublicKey> {
  const id = `peerborne-store-${nextSubscription++}`;
  const manageLifecycle = options.manageLifecycle !== false;
  if (manageLifecycle !== (typeof source === 'function')) {
    throw new TypeError(
      manageLifecycle
        ? 'A managed document store needs a function that creates a handle'
        : 'An unmanaged document store needs the handle its caller opens',
    );
  }
  const createHandle = typeof source === 'function' ? source : () => source;
  let document: DocumentHandle<Doc, Change, PublicKey> | undefined =
    manageLifecycle ? undefined : createHandle();
  const initial: DocumentSnapshot<Doc, PublicKey> = Object.freeze({
    status: 'idle',
    data: undefined,
    readers: Object.freeze([]),
    writers: Object.freeze([]),
    revision: 0,
    error: undefined,
    deliveryFailure: undefined,
  });
  let snapshot = initial;
  let opened = false;
  let connected = 0;
  let deliveryFailures = 0;
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

  async function finishCleanup(
    shouldClose: boolean,
    errors: unknown[],
    message: string,
  ): Promise<void> {
    const current = document;
    if (manageLifecycle) document = undefined;
    if (current) {
      try {
        current.unsubscribe(id);
        current.unsubscribeDeliveryFailures?.(id);
      } catch (error) {
        errors.push(error);
      }
      if (shouldClose) {
        try {
          await current.close();
        } catch (error) {
          errors.push(error);
        }
      }
    }
    if (errors.length > 0) {
      const error =
        errors.length === 1 ? errors[0] : new AggregateError(errors, message);
      publish({ ...initial, status: 'error', error });
      throw error;
    }
    publish({ ...initial, status: 'closed' });
  }

  function start(): Promise<void> {
    return enqueue(async () => {
      if (opened) return;
      publish({ ...initial, status: 'opening' });
      let latest: { readers: PublicKey[]; writers: PublicKey[] } | undefined;
      try {
        const current = (document ??= createHandle());
        current.subscribe(id, (data, readers, writers) => {
          latest = { readers, writers };
          if (opened && document === current) {
            publish({
              status: 'ready',
              data,
              readers,
              writers,
              error: undefined,
              deliveryFailure: snapshot.deliveryFailure,
            });
          }
        });
        current.subscribeDeliveryFailures?.(id, (failure) => {
          deliveryFailures++;
          if (opened && document === current)
            publish({ ...snapshot, deliveryFailure: failure });
        });
        if (manageLifecycle) await current.open();
        const [readers, writers] = await Promise.all([
          current.getReaders(),
          current.getWriters(),
        ]);
        opened = true;
        publish({
          status: 'ready',
          data: current.document,
          readers: latest?.readers ?? readers,
          writers: latest?.writers ?? writers,
          error: undefined,
          deliveryFailure: undefined,
        });
      } catch (cause) {
        opened = false;
        return finishCleanup(
          manageLifecycle,
          [cause],
          'Document open and cleanup failed',
        );
      }
    });
  }

  function stop(): Promise<void> {
    return enqueue(async () => {
      const shouldClose = opened && manageLifecycle;
      opened = false;
      return finishCleanup(shouldClose, [], 'Document cleanup failed');
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
        const current = document;
        if (!opened || !current) throw new Error('Document store is closed');
        const reported = deliveryFailures;
        try {
          await current.change(change, message);
          const delivered = deliveryFailures === reported;
          if (
            snapshot.error !== undefined ||
            (delivered && snapshot.deliveryFailure !== undefined)
          ) {
            publish({
              ...snapshot,
              error: undefined,
              deliveryFailure: delivered ? undefined : snapshot.deliveryFailure,
            });
          }
        } catch (error) {
          publish({ ...snapshot, error });
          throw error;
        }
      });
    },
  };
}
