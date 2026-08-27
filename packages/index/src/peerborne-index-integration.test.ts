import { afterEach, beforeEach, describe, expect, jest as jestFn, test } from '@jest/globals';
import { PeerborneIndexIntegration, SubscribableDocument } from './peerborne-index-integration.js';
import { IndexManager } from './index-manager.js';
import { MemoryIndexStorage } from './memory-index-storage.js';

interface MockDoc {
  title: string;
  author: string;
}

interface OperationGate {
  promise: Promise<void>;
  resolve(): void;
  reject(error: Error): void;
}

function createOperationGate(): OperationGate {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((resolvePromise, rejectPromise) => {
    resolve = () => resolvePromise();
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

class ControlledIndexStorage extends MemoryIndexStorage {
  readonly operations: string[] = [];
  private _putGates: Map<string, OperationGate> = new Map();

  blockPut(title: string): OperationGate {
    const gate = createOperationGate();
    this._putGates.set(title, gate);
    return gate;
  }

  override async put(
    indexName: string,
    documentPath: string,
    fields: Record<string, unknown>,
  ): Promise<void> {
    const title = String(fields.title);
    this.operations.push(`put:${title}`);
    await this._putGates.get(title)?.promise;
    await super.put(indexName, documentPath, fields);
  }

  override async delete(indexName: string, documentPath: string): Promise<void> {
    this.operations.push('delete');
    await super.delete(indexName, documentPath);
  }
}

async function waitFor(condition: () => Promise<boolean>, timeoutMs: number = 2000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await condition()) return;
    await new Promise(r => setTimeout(r, 10));
  }
  throw new Error('waitFor timed out');
}

class MockSubscribableDocument implements SubscribableDocument<MockDoc> {
  documentPath: string;
  document: MockDoc;
  private _handlers: Map<string, (current: MockDoc, ...args: unknown[]) => void> = new Map();

  constructor(path: string, doc: MockDoc) {
    this.documentPath = path;
    this.document = doc;
  }

  subscribe(
    id: string,
    handler: (current: MockDoc, ...args: unknown[]) => void,
    _originFilter?: 'all' | 'remote' | 'local',
  ): void {
    this._handlers.set(id, handler);
  }

  unsubscribe(id: string): void {
    this._handlers.delete(id);
  }

  /** Simulate a CRDT change event. */
  simulateChange(newDoc: MockDoc): void {
    this.document = newDoc;
    for (const handler of this._handlers.values()) {
      handler(newDoc);
    }
  }

  captureChangeHandler(): (current: MockDoc, ...args: unknown[]) => void {
    const handler = this._handlers.values().next().value;
    if (!handler) {
      throw new Error('No change handler is registered');
    }
    return handler;
  }

  get handlerCount(): number {
    return this._handlers.size;
  }
}

async function createTestIntegration(storage: MemoryIndexStorage): Promise<{
  manager: IndexManager<MockDoc>;
  integration: PeerborneIndexIntegration<MockDoc>;
}> {
  const manager = new IndexManager(
    storage,
    (doc: MockDoc) => doc as unknown as Record<string, unknown>,
  );
  await manager.defineIndex({
    name: 'docs',
    collectionPrefix: '/docs/',
    fields: [
      { path: 'title', type: 'string' },
      { path: 'author', type: 'string' },
    ],
  });
  return { manager, integration: new PeerborneIndexIntegration(manager) };
}

describe('PeerborneIndexIntegration', () => {
  let storage: MemoryIndexStorage;
  let manager: IndexManager<MockDoc>;
  let integration: PeerborneIndexIntegration<MockDoc>;

  beforeEach(async () => {
    storage = new MemoryIndexStorage();
    ({ manager, integration } = await createTestIntegration(storage));
  });

  afterEach(() => {
    jestFn.restoreAllMocks();
  });

  describe('trackDocument', () => {
    test('should index the document immediately', async () => {
      const doc = new MockSubscribableDocument('/docs/1', { title: 'Hello', author: 'Alice' });
      integration.trackDocument(doc);

      await waitFor(async () => {
        const result = await manager.query({
          indexName: 'docs',
          filters: [{ path: 'title', operator: 'eq', value: 'Hello' }],
        });
        return result.documents.length === 1;
      });
    });

    test('should subscribe to document changes', async () => {
      const doc = new MockSubscribableDocument('/docs/1', { title: 'v1', author: 'Alice' });
      integration.trackDocument(doc);
      expect(doc.handlerCount).toBe(1);
    });

    test('should update index on document change', async () => {
      const doc = new MockSubscribableDocument('/docs/1', { title: 'v1', author: 'Alice' });
      integration.trackDocument(doc);

      await waitFor(async () => {
        const result = await manager.query({
          indexName: 'docs',
          filters: [{ path: 'title', operator: 'eq', value: 'v1' }],
        });
        return result.documents.length === 1;
      });

      doc.simulateChange({ title: 'v2', author: 'Alice' });

      await waitFor(async () => {
        const result = await manager.query({
          indexName: 'docs',
          filters: [{ path: 'title', operator: 'eq', value: 'v2' }],
        });
        return result.documents.length === 1;
      });
    });

    test('should serialize updates so a stale write cannot finish last', async () => {
      const controlledStorage = new ControlledIndexStorage();
      const controlled = await createTestIntegration(controlledStorage);
      const initialWrite = controlledStorage.blockPut('v1');
      const newerWrite = controlledStorage.blockPut('v2');
      const doc = new MockSubscribableDocument('/docs/1', { title: 'v1', author: 'Alice' });

      controlled.integration.trackDocument(doc);
      await waitFor(async () => controlledStorage.operations.includes('put:v1'));

      doc.simulateChange({ title: 'v2', author: 'Alice' });
      newerWrite.resolve();
      await Promise.resolve();
      await Promise.resolve();

      expect(controlledStorage.operations).toEqual(['put:v1']);

      initialWrite.resolve();
      await waitFor(async () => {
        const result = await controlled.manager.query({ indexName: 'docs', filters: [] });
        return result.documents[0]?.snapshot.title === 'v2';
      });
      expect(controlledStorage.operations).toEqual(['put:v1', 'put:v2']);
    });

    test('should not block updates for a different document path', async () => {
      const controlledStorage = new ControlledIndexStorage();
      const controlled = await createTestIntegration(controlledStorage);
      const blockedWrite = controlledStorage.blockPut('blocked');
      const blockedDoc = new MockSubscribableDocument('/docs/1', {
        title: 'blocked',
        author: 'Alice',
      });
      const independentDoc = new MockSubscribableDocument('/docs/2', {
        title: 'independent',
        author: 'Bob',
      });

      controlled.integration.trackDocument(blockedDoc);
      await waitFor(async () => controlledStorage.operations.includes('put:blocked'));

      controlled.integration.trackDocument(independentDoc);
      await waitFor(async () => {
        const result = await controlled.manager.query({ indexName: 'docs', filters: [] });
        return result.documents.some(({ documentPath }) => documentPath === '/docs/2');
      });

      expect(controlledStorage.operations).toEqual(['put:blocked', 'put:independent']);
      blockedWrite.resolve();
      await waitFor(async () => {
        const result = await controlled.manager.query({ indexName: 'docs', filters: [] });
        return result.documents.some(({ documentPath }) => documentPath === '/docs/1');
      });
    });

    test('should not double-track the same document', () => {
      const doc = new MockSubscribableDocument('/docs/1', { title: 'v1', author: 'Alice' });
      integration.trackDocument(doc);
      integration.trackDocument(doc);
      expect(doc.handlerCount).toBe(1);
    });

    test('should wait for queued writes when tracking the same document again', async () => {
      const controlledStorage = new ControlledIndexStorage();
      const controlled = await createTestIntegration(controlledStorage);
      const initialWrite = controlledStorage.blockPut('v1');
      const newerWrite = controlledStorage.blockPut('v2');
      const doc = new MockSubscribableDocument('/docs/1', { title: 'v1', author: 'Alice' });

      const initialReady = controlled.integration.trackDocument(doc);
      await waitFor(async () => controlledStorage.operations.includes('put:v1'));
      doc.simulateChange({ title: 'v2', author: 'Alice' });

      let duplicateResolved = false;
      const duplicateReady = controlled.integration.trackDocument(doc).then(() => {
        duplicateResolved = true;
      });
      await Promise.resolve();
      expect(duplicateResolved).toBe(false);

      initialWrite.resolve();
      await waitFor(async () => controlledStorage.operations.includes('put:v2'));
      expect(duplicateResolved).toBe(false);

      newerWrite.resolve();
      await Promise.all([initialReady, duplicateReady]);
      expect(duplicateResolved).toBe(true);
      expect(doc.handlerCount).toBe(1);
    });

    test('should ignore a stale handler after the same document is retracked', async () => {
      const doc = new MockSubscribableDocument('/docs/1', { title: 'v1', author: 'Alice' });
      integration.trackDocument(doc);
      await waitFor(async () => {
        const result = await manager.query({ indexName: 'docs', filters: [] });
        return result.documents[0]?.snapshot.title === 'v1';
      });
      const staleHandler = doc.captureChangeHandler();

      integration.untrackDocument(doc);
      await waitFor(async () => {
        const result = await manager.query({ indexName: 'docs', filters: [] });
        return result.documents.length === 0;
      });

      doc.document = { title: 'v2', author: 'Alice' };
      integration.trackDocument(doc);
      await waitFor(async () => {
        const result = await manager.query({ indexName: 'docs', filters: [] });
        return result.documents[0]?.snapshot.title === 'v2';
      });

      staleHandler({ title: 'stale', author: 'Alice' });
      await new Promise(resolve => setTimeout(resolve, 0));

      const result = await manager.query({ indexName: 'docs', filters: [] });
      expect(result.documents[0]?.snapshot.title).toBe('v2');
      expect(doc.handlerCount).toBe(1);
    });
  });

  describe('untrackDocument', () => {
    test('should unsubscribe from document', () => {
      const doc = new MockSubscribableDocument('/docs/1', { title: 'Hello', author: 'Alice' });
      integration.trackDocument(doc);
      integration.untrackDocument(doc);
      expect(doc.handlerCount).toBe(0);
    });

    test('should remove document from index', async () => {
      const doc = new MockSubscribableDocument('/docs/1', { title: 'Hello', author: 'Alice' });
      integration.trackDocument(doc);

      await waitFor(async () => {
        const result = await manager.query({ indexName: 'docs', filters: [] });
        return result.documents.length === 1;
      });

      integration.untrackDocument(doc);

      await waitFor(async () => {
        const result = await manager.query({ indexName: 'docs', filters: [] });
        return result.documents.length === 0;
      });
    });

    test('should wait for an in-flight update before removing the document', async () => {
      const controlledStorage = new ControlledIndexStorage();
      const controlled = await createTestIntegration(controlledStorage);
      const initialWrite = controlledStorage.blockPut('v1');
      const doc = new MockSubscribableDocument('/docs/1', { title: 'v1', author: 'Alice' });

      controlled.integration.trackDocument(doc);
      await waitFor(async () => controlledStorage.operations.includes('put:v1'));

      controlled.integration.untrackDocument(doc);
      await Promise.resolve();
      await Promise.resolve();
      expect(controlledStorage.operations).toEqual(['put:v1']);

      initialWrite.resolve();
      await waitFor(async () => controlledStorage.operations.includes('delete'));
      await waitFor(async () => {
        const result = await controlled.manager.query({ indexName: 'docs', filters: [] });
        return result.documents.length === 0;
      });
      expect(controlledStorage.operations).toEqual(['put:v1', 'delete']);
    });

    test('should remove the document after an in-flight update fails', async () => {
      jestFn.spyOn(console, 'warn').mockImplementation(() => undefined);
      const controlledStorage = new ControlledIndexStorage();
      const controlled = await createTestIntegration(controlledStorage);
      const initialWrite = controlledStorage.blockPut('v1');
      const doc = new MockSubscribableDocument('/docs/1', { title: 'v1', author: 'Alice' });

      controlled.integration.trackDocument(doc);
      await waitFor(async () => controlledStorage.operations.includes('put:v1'));

      controlled.integration.untrackDocument(doc);
      await Promise.resolve();
      await Promise.resolve();
      expect(controlledStorage.operations).toEqual(['put:v1']);

      initialWrite.reject(new Error('write failed'));
      await waitFor(async () => controlledStorage.operations.includes('delete'));
      expect(controlledStorage.operations).toEqual(['put:v1', 'delete']);
    });
  });

  describe('getTrackedPaths', () => {
    test('should return tracked document paths', () => {
      integration.trackDocument(new MockSubscribableDocument('/docs/1', { title: 'A', author: 'X' }));
      integration.trackDocument(new MockSubscribableDocument('/docs/2', { title: 'B', author: 'Y' }));
      const paths = integration.getTrackedPaths();
      expect(paths.sort()).toEqual(['/docs/1', '/docs/2']);
    });
  });

  describe('dispose', () => {
    test('should unsubscribe all documents', async () => {
      const doc1 = new MockSubscribableDocument('/docs/1', { title: 'A', author: 'X' });
      const doc2 = new MockSubscribableDocument('/docs/2', { title: 'B', author: 'Y' });
      integration.trackDocument(doc1);
      integration.trackDocument(doc2);

      await integration.dispose();

      expect(doc1.handlerCount).toBe(0);
      expect(doc2.handlerCount).toBe(0);
      expect(integration.getTrackedPaths()).toHaveLength(0);
    });
  });
});
