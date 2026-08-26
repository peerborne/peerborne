import { IndexManager } from './index-manager.js';

/**
 * Minimal document interface matching PeerborneDocument's subscribe API.
 * Avoids coupling to the full generic PeerborneDocument class.
 */
export interface SubscribableDocument<DocType> {
  readonly documentPath: string;
  readonly document: DocType;
  subscribe(
    id: string,
    handler: (current: DocType, ...args: unknown[]) => void,
    originFilter?: 'all' | 'remote' | 'local',
  ): void;
  unsubscribe(id: string): void;
}

const INDEX_HANDLER_PREFIX = '__peerborne_index_';

/**
 * Wires an IndexManager to PeerborneDocument instances via their subscribe() API.
 * Tracks multiple documents and automatically updates the index on every change.
 *
 * @typeParam DocType The CRDT document type (e.g., Y.Doc).
 */
export class PeerborneIndexIntegration<DocType> {
  private _manager: IndexManager<DocType>;
  private _trackedDocuments: Map<
    string,
    { document: SubscribableDocument<DocType> }
  > = new Map();

  constructor(manager: IndexManager<DocType>) {
    this._manager = manager;
  }

  /** The underlying IndexManager. */
  get manager(): IndexManager<DocType> {
    return this._manager;
  }

  /**
   * Begin tracking a document. Subscribes to all changes and indexes the current state.
   */
  trackDocument(doc: SubscribableDocument<DocType>): Promise<void> {
    if (this._trackedDocuments.has(doc.documentPath)) {
      return this._manager.flush(doc.documentPath);
    }

    const registration = { document: doc };
    this._trackedDocuments.set(doc.documentPath, registration);

    const handlerId = INDEX_HANDLER_PREFIX + doc.documentPath;

    doc.subscribe(
      handlerId,
      (current: DocType) => {
        if (this._trackedDocuments.get(doc.documentPath) !== registration) {
          return;
        }
        this._manager.updateIndex(doc.documentPath, current).catch(() => {
          console.warn(`PeerborneIndexIntegration: failed to update index for ${doc.documentPath}`);
        });
      },
      'all',
    );

    // Index current state immediately
    const ready = this._manager.updateIndex(doc.documentPath, doc.document);
    ready.catch(() => {
      console.warn(`PeerborneIndexIntegration: failed to index initial state of ${doc.documentPath}`);
    });
    return ready;
  }

  /**
   * Stop tracking a document. Unsubscribes from changes and removes from index.
   */
  untrackDocument(documentPath: string): Promise<void>;
  untrackDocument(doc: SubscribableDocument<DocType>): Promise<void>;
  untrackDocument(docOrPath: SubscribableDocument<DocType> | string): Promise<void> {
    const path = typeof docOrPath === 'string' ? docOrPath : docOrPath.documentPath;
    const tracked = this._trackedDocuments.get(path);
    if (!tracked) return Promise.resolve();
    const handlerId = INDEX_HANDLER_PREFIX + path;
    this._trackedDocuments.delete(path);
    tracked.document.unsubscribe(handlerId);
    const removed = this._manager.removeFromIndex(path);
    removed.catch(() => {
      console.warn(`PeerborneIndexIntegration: failed to remove ${path} from index`);
    });
    return removed;
  }

  /**
   * Get the set of currently tracked document paths.
   */
  getTrackedPaths(): string[] {
    return Array.from(this._trackedDocuments.keys());
  }

  /**
   * Stop tracking all documents and unsubscribe handlers.
   * Does not close the index manager's storage.
   */
  async dispose(): Promise<void> {
    const trackedDocuments = Array.from(this._trackedDocuments.values());
    this._trackedDocuments.clear();
    for (const { document } of trackedDocuments) {
      const handlerId = INDEX_HANDLER_PREFIX + document.documentPath;
      document.unsubscribe(handlerId);
    }
    await this._manager.flush();
  }
}
