export type DocumentStatus =
  'idle' | 'opening' | 'ready' | 'retired' | 'error' | 'closed';

/** A local change that was committed but whose frame could not be published. */
export interface DocumentDeliveryFailure {
  readonly documentPath: string;
  readonly changeId: string;
  readonly error: unknown;
}

/** The document surface needed by UI integrations. No networking code is imported. */
export interface DocumentHandle<Doc, Change, PublicKey = unknown> {
  readonly document: Doc;
  /** True once the handle refuses further work and must be replaced. */
  readonly retired?: boolean;
  /** The latest undelivered local change, until a later frame reaches a peer. */
  readonly deliveryFailure?: DocumentDeliveryFailure;
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
  /**
   * `retired` means the handle refused a change because it was retired, so
   * `data` is dropped and `error` is that rejection. A managed store opens a
   * fresh handle after `stop()` and `start()`.
   */
  readonly status: DocumentStatus;
  readonly data: Doc | undefined;
  readonly readers: readonly PublicKey[];
  readonly writers: readonly PublicKey[];
  readonly revision: number;
  readonly error: unknown;
  /**
   * The latest change made on this device that is committed locally but was
   * not delivered, because its frame could not be published or reached no
   * peer. A later local change whose frame reaches a peer clears it, through
   * this store or not, since that frame carries the earlier change.
   */
  readonly deliveryFailure: DocumentDeliveryFailure | undefined;
}

export interface DocumentStore<Doc, Change, PublicKey = unknown> {
  getSnapshot(): DocumentSnapshot<Doc, PublicKey>;
  getServerSnapshot(): DocumentSnapshot<Doc, PublicKey>;
  /** Register a listener without opening a document or starting a node. */
  subscribe(listener: () => void): () => void;
  /** Open the document and keep it open until `stop()`, whatever consumers release. */
  start(): Promise<void>;
  /** Close the document now, even when consumers or a delivery failure remain. */
  stop(): Promise<void>;
  /** Retain the shared document until the returned, idempotent release runs. */
  connect(): () => void;
  /**
   * Apply a change to the open document. Rejects with `Document store is
   * closed` when it is not open: a change never opens the document.
   */
  change(change: Change, message?: string): Promise<void>;
}

export interface DocumentStoreOptions {
  /** Set false when the caller opens and closes an already shared handle. */
  manageLifecycle?: boolean;
  /**
   * Milliseconds to keep the document open after the final release, so a
   * remount within that time reuses it. By default the close is queued after
   * the current turn, so only a same-turn reconnect, such as a StrictMode
   * remount, keeps it open.
   */
  closeDelay?: number;
}

/** Creates a handle, or resolves to one after restoring its state. */
export type DocumentHandleFactory<Doc, Change, PublicKey> = () =>
  | DocumentHandle<Doc, Change, PublicKey>
  | PromiseLike<DocumentHandle<Doc, Change, PublicKey>>;

let nextSubscription = 0;

/**
 * Create one store per node/document path and share it between consumers.
 * Construction and subscription are safe during server rendering. Call start()
 * or connect() in the browser to open the document. Changes retain their promise.
 *
 * A managed store calls `createHandle`, such as `() => peerborne.doc(path)`,
 * for every open and closes that handle when it stops. It never reopens a
 * closed handle: a durable BeeKEM fork guard or coordinated document refuses.
 * The final release does not close the document while a delivery failure is
 * outstanding, because the undelivered change exists only in that handle.
 * A fresh handle loads the document from a peer, so a remount after a close
 * needs a connected peer that holds it, or a factory that restores the
 * document's latest checkpoint before returning the handle.
 */
export function createDocumentStore<Doc, Change, PublicKey>(
  createHandle: DocumentHandleFactory<Doc, Change, PublicKey>,
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
    | DocumentHandleFactory<Doc, Change, PublicKey>,
  options: DocumentStoreOptions = {},
): DocumentStore<Doc, Change, PublicKey> {
  const id = `peerborne-store-${nextSubscription++}`;
  const localId = `${id}-local`;
  const manageLifecycle = options.manageLifecycle !== false;
  const closeDelay = options.closeDelay ?? 0;
  if (manageLifecycle !== (typeof source === 'function')) {
    throw new TypeError(
      manageLifecycle
        ? 'A managed document store needs a function that creates a handle'
        : 'An unmanaged document store needs the handle its caller opens',
    );
  }
  if (!(closeDelay >= 0 && closeDelay <= 2_147_483_647)) {
    throw new RangeError(
      'closeDelay must be from 0 to 2147483647 milliseconds',
    );
  }
  const createHandle = typeof source === 'function' ? source : () => source;
  let document = typeof source === 'function' ? undefined : source;
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
  let retired = false;
  let started = false;
  let connected = 0;
  let pendingClose: { timer?: ReturnType<typeof setTimeout> } | undefined;
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

  function retire(error: unknown) {
    retired = true;
    publish({ ...initial, status: 'retired', error });
    scheduleClose();
  }

  function enqueue(action: () => Promise<void>): Promise<void> {
    const task = tail.then(action);
    tail = task.catch(() => {});
    return task;
  }

  function unused(): boolean {
    return connected === 0 && !started;
  }

  function cancelClose() {
    if (pendingClose?.timer !== undefined) clearTimeout(pendingClose.timer);
    pendingClose = undefined;
  }

  function scheduleClose() {
    if (!unused() || pendingClose) return;
    const scheduled: { timer?: ReturnType<typeof setTimeout> } = {};
    pendingClose = scheduled;
    const close = () => {
      if (pendingClose !== scheduled) return;
      pendingClose = undefined;
      void enqueue(async () => {
        if (!unused()) return;
        if (!retired && snapshot.deliveryFailure !== undefined) return;
        await deactivate();
      }).catch(() => {});
    };
    if (closeDelay > 0) scheduled.timer = setTimeout(close, closeDelay);
    else queueMicrotask(close);
  }

  async function finishCleanup(
    shouldClose: boolean,
    errors: unknown[],
    message: string,
  ): Promise<void> {
    const current = document;
    if (manageLifecycle) document = undefined;
    retired = false;
    if (current) {
      try {
        current.unsubscribe(id);
        current.unsubscribe(localId);
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

  function activate(): Promise<void> {
    const opening = () => {
      if (snapshot.status !== 'opening')
        publish({ ...initial, status: 'opening' });
    };
    if (!opened) opening();
    return enqueue(async () => {
      if (opened) return;
      opening();
      let latest: { readers: PublicKey[]; writers: PublicKey[] } | undefined;
      try {
        if (!document) {
          const created = createHandle();
          document = 'then' in created ? await created : created;
        }
        const current = document;
        if (current.retired === true) {
          opened = true;
          retire(new Error('Document handle was retired'));
          return;
        }
        const live = () => opened && !retired && document === current;
        const ready = (
          data: Doc,
          readers: PublicKey[],
          writers: PublicKey[],
          deliveryFailure: DocumentDeliveryFailure | undefined,
        ) =>
          publish({
            status: 'ready',
            data,
            readers,
            writers,
            error: undefined,
            deliveryFailure,
          });
        current.subscribe(
          id,
          (data, readers, writers) => {
            latest = { readers, writers };
            if (live()) ready(data, readers, writers, snapshot.deliveryFailure);
          },
          'remote',
        );
        current.subscribe(
          localId,
          (data, readers, writers, hashes) => {
            latest = { readers, writers };
            if (!live()) return;
            const failure = snapshot.deliveryFailure;
            const delivered =
              failure !== undefined && !hashes.includes(failure.changeId);
            ready(data, readers, writers, delivered ? undefined : failure);
            if (delivered) scheduleClose();
          },
          'local',
        );
        current.subscribeDeliveryFailures?.(id, (failure) => {
          if (live()) publish({ ...snapshot, deliveryFailure: failure });
        });
        if (manageLifecycle) await current.open();
        const [readers, writers] = await Promise.all([
          current.getReaders(),
          current.getWriters(),
        ]);
        opened = true;
        ready(
          current.document,
          latest?.readers ?? readers,
          latest?.writers ?? writers,
          current.deliveryFailure,
        );
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

  function deactivate(): Promise<void> {
    const shouldClose = opened && manageLifecycle;
    opened = false;
    return finishCleanup(shouldClose, [], 'Document cleanup failed');
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
    start() {
      started = true;
      cancelClose();
      return activate();
    },
    stop() {
      started = false;
      cancelClose();
      return enqueue(deactivate);
    },
    connect() {
      connected++;
      cancelClose();
      if (connected === 1) void activate().catch(() => {});
      let released = false;
      return () => {
        if (released) return;
        released = true;
        connected--;
        scheduleClose();
      };
    },
    change(change, message) {
      return enqueue(async () => {
        const current = document;
        if (!opened || !current) throw new Error('Document store is closed');
        try {
          await current.change(change, message);
          if (snapshot.error !== undefined)
            publish({ ...snapshot, error: undefined });
        } catch (error) {
          if (current.retired === true) retire(error);
          else publish({ ...snapshot, error });
          throw error;
        }
      });
    },
  };
}
