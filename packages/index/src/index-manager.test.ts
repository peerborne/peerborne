import { describe, expect, test, beforeEach } from '@jest/globals';
import { IndexManager } from './index-manager.js';
import { MemoryIndexStorage } from './memory-index-storage.js';
import { IndexDefinition, IndexFieldDefinition } from './types.js';

async function waitFor(condition: () => Promise<boolean>, timeoutMs: number = 2000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await condition()) return;
    await new Promise(r => setTimeout(r, 10));
  }
  throw new Error('waitFor timed out');
}

interface WikiArticle {
  title: string;
  content: string;
  author: string;
  createdOn: string;
  tags: string[];
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

class ControlledLifecycleStorage extends MemoryIndexStorage {
  readonly operations: string[] = [];
  private _nextPutGate?: OperationGate;
  private _nextClearGate?: OperationGate;
  private _nextQueryGate?: OperationGate;

  blockNextPut(): OperationGate {
    const gate = createOperationGate();
    this._nextPutGate = gate;
    return gate;
  }

  blockNextClear(): OperationGate {
    const gate = createOperationGate();
    this._nextClearGate = gate;
    return gate;
  }

  blockNextQuery(): OperationGate {
    const gate = createOperationGate();
    this._nextQueryGate = gate;
    return gate;
  }

  override async put(
    indexName: string,
    documentPath: string,
    fields: Record<string, unknown>,
  ): Promise<void> {
    const gate = this._nextPutGate;
    this._nextPutGate = undefined;
    this.operations.push('put:start');
    await gate?.promise;
    await super.put(indexName, documentPath, fields);
    this.operations.push('put:finish');
  }

  override async clear(indexName: string): Promise<void> {
    const gate = this._nextClearGate;
    this._nextClearGate = undefined;
    this.operations.push('clear');
    await gate?.promise;
    await super.clear(indexName);
  }

  override async query(
    ...args: Parameters<MemoryIndexStorage['query']>
  ): ReturnType<MemoryIndexStorage['query']> {
    const gate = this._nextQueryGate;
    this._nextQueryGate = undefined;
    const result = await super.query(...args);
    if (gate) {
      this.operations.push('query:read');
      await gate.promise;
      this.operations.push('query:finish');
    }
    return result;
  }
}

class ControlledInitializeStorage extends MemoryIndexStorage {
  initializeStarted = false;
  private _nextInitializeGate?: OperationGate;

  blockNextInitialize(): OperationGate {
    const gate = createOperationGate();
    this._nextInitializeGate = gate;
    return gate;
  }

  override async initialize(
    indexName: string,
    fields: IndexFieldDefinition[],
  ): Promise<void> {
    const gate = this._nextInitializeGate;
    this._nextInitializeGate = undefined;
    this.initializeStarted = true;
    await gate?.promise;
    await super.initialize(indexName, fields);
  }
}

describe('IndexManager', () => {
  let storage: MemoryIndexStorage;
  let manager: IndexManager<WikiArticle>;
  const articleIndex: IndexDefinition = {
    name: 'articles-by-title',
    collectionPrefix: '/articles/',
    fields: [
      { path: 'title', type: 'string' },
      { path: 'author', type: 'string' },
      { path: 'createdOn', type: 'date' },
    ],
  };

  beforeEach(async () => {
    storage = new MemoryIndexStorage();
    manager = new IndexManager(storage, (doc: WikiArticle) => doc as unknown as Record<string, unknown>);
    await manager.defineIndex(articleIndex);
  });

  describe('defineIndex / removeIndex / getDefinitions', () => {
    test('should register an index definition', () => {
      const defs = manager.getDefinitions();
      expect(defs).toHaveLength(1);
      expect(defs[0].name).toBe('articles-by-title');
    });

    test('should support multiple indexes', async () => {
      await manager.defineIndex({
        name: 'articles-by-author',
        collectionPrefix: '/articles/',
        fields: [{ path: 'author', type: 'string' }],
      });
      expect(manager.getDefinitions()).toHaveLength(2);
    });

    test('should wait for an identical definition that is still initializing', async () => {
      const controlledStorage = new ControlledInitializeStorage();
      const controlledManager = new IndexManager(
        controlledStorage,
        (doc: WikiArticle) => doc as unknown as Record<string, unknown>,
      );
      const initialization = controlledStorage.blockNextInitialize();
      const firstDefinition = controlledManager.defineIndex(articleIndex);
      await waitFor(async () => controlledStorage.initializeStarted);

      let duplicateResolved = false;
      const duplicateDefinition = controlledManager.defineIndex({
        ...articleIndex,
        fields: [...articleIndex.fields],
      }).then(() => {
        duplicateResolved = true;
      });
      await Promise.resolve();
      await Promise.resolve();
      expect(duplicateResolved).toBe(false);

      initialization.resolve();
      await Promise.all([firstDefinition, duplicateDefinition]);
      expect(duplicateResolved).toBe(true);
    });

    test('should retract a definition when initialization fails', async () => {
      const controlledStorage = new ControlledInitializeStorage();
      const controlledManager = new IndexManager(
        controlledStorage,
        (doc: WikiArticle) => doc as unknown as Record<string, unknown>,
      );
      const initialization = controlledStorage.blockNextInitialize();
      const definition = controlledManager.defineIndex(articleIndex);
      await waitFor(async () => controlledStorage.initializeStarted);
      const failure = expect(definition).rejects.toThrow('initialize failed');

      initialization.reject(new Error('initialize failed'));
      await failure;

      expect(controlledManager.getDefinitions()).toHaveLength(0);
    });

    test('should allow an ordinary retry after initialization fails', async () => {
      const controlledStorage = new ControlledInitializeStorage();
      const controlledManager = new IndexManager(
        controlledStorage,
        (doc: WikiArticle) => doc as unknown as Record<string, unknown>,
      );
      const initialization = controlledStorage.blockNextInitialize();
      const definition = controlledManager.defineIndex(articleIndex);
      await waitFor(async () => controlledStorage.initializeStarted);
      const failure = expect(definition).rejects.toThrow('initialize failed');

      initialization.reject(new Error('initialize failed'));
      await failure;

      await controlledManager.defineIndex(articleIndex);
      expect(controlledManager.getDefinitions()).toEqual([articleIndex]);
    });

    test('should not retract a replacement when an old initialization fails', async () => {
      const controlledStorage = new ControlledInitializeStorage();
      const controlledManager = new IndexManager(
        controlledStorage,
        (doc: WikiArticle) => doc as unknown as Record<string, unknown>,
      );
      const initialization = controlledStorage.blockNextInitialize();
      const oldDefinition = controlledManager.defineIndex(articleIndex);
      await waitFor(async () => controlledStorage.initializeStarted);
      const oldFailure = expect(oldDefinition).rejects.toThrow('initialize failed');

      const replacement: IndexDefinition = {
        ...articleIndex,
        fields: [{ path: 'author', type: 'string' }],
      };
      const removal = controlledManager.removeIndex(articleIndex.name);
      const replacementDefinition = controlledManager.defineIndex(replacement);
      initialization.reject(new Error('initialize failed'));

      await oldFailure;
      await Promise.all([removal, replacementDefinition]);
      expect(controlledManager.getDefinitions()).toEqual([replacement]);
    });

    test('should remove an index', async () => {
      await manager.removeIndex('articles-by-title');
      expect(manager.getDefinitions()).toHaveLength(0);
    });

    test('should clear after an in-flight update and discard queued updates', async () => {
      const controlledStorage = new ControlledLifecycleStorage();
      const controlledManager = new IndexManager(
        controlledStorage,
        (doc: WikiArticle) => doc as unknown as Record<string, unknown>,
      );
      await controlledManager.defineIndex(articleIndex);
      const write = controlledStorage.blockNextPut();

      const update = controlledManager.updateIndex('/articles/1', {
        title: 'Pending',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });
      await waitFor(async () => controlledStorage.operations.includes('put:start'));

      const queuedUpdate = controlledManager.updateIndex('/articles/1', {
        title: 'Queued',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-02',
        tags: [],
      });

      const removal = controlledManager.removeIndex(articleIndex.name);
      await Promise.resolve();
      await Promise.resolve();
      expect(controlledStorage.operations).toEqual(['put:start']);

      write.resolve();
      await Promise.all([update, queuedUpdate, removal]);

      expect(controlledStorage.operations).toEqual(['put:start', 'put:finish', 'clear']);
      expect(await controlledStorage.get(articleIndex.name, '/articles/1')).toBeUndefined();
    });

    test('should not carry a pending update into a redefined index', async () => {
      const controlledStorage = new ControlledLifecycleStorage();
      const controlledManager = new IndexManager(
        controlledStorage,
        (doc: WikiArticle) => doc as unknown as Record<string, unknown>,
      );
      await controlledManager.defineIndex(articleIndex);
      const write = controlledStorage.blockNextPut();

      const update = controlledManager.updateIndex('/articles/1', {
        title: 'Old schema',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });
      await waitFor(async () => controlledStorage.operations.includes('put:start'));

      const queuedUpdate = controlledManager.updateIndex('/articles/1', {
        title: 'Queued old schema',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-02',
        tags: [],
      });

      const redefined: IndexDefinition = {
        name: articleIndex.name,
        collectionPrefix: articleIndex.collectionPrefix,
        fields: [{ path: 'author', type: 'string' }],
      };
      const removal = controlledManager.removeIndex(articleIndex.name);
      const redefinition = controlledManager.defineIndex(redefined);

      write.resolve();
      await Promise.all([update, queuedUpdate, removal, redefinition]);

      expect(controlledStorage.operations).toEqual(['put:start', 'put:finish', 'clear']);
      expect(await controlledStorage.get(articleIndex.name, '/articles/1')).toBeUndefined();
      expect(controlledManager.getDefinitions()).toEqual([redefined]);

      await controlledManager.updateIndex('/articles/1', {
        title: 'New schema',
        content: '',
        author: 'Bob',
        createdOn: '2024-01-01',
        tags: [],
      });
      expect(await controlledStorage.get(articleIndex.name, '/articles/1')).toEqual({
        author: 'Bob',
      });
    });

    test('should not expose old rows while a replacement index is pending', async () => {
      const controlledStorage = new ControlledLifecycleStorage();
      const controlledManager = new IndexManager(
        controlledStorage,
        (doc: WikiArticle) => doc as unknown as Record<string, unknown>,
      );
      await controlledManager.defineIndex(articleIndex);
      await controlledManager.updateIndex('/articles/1', {
        title: 'Old schema',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });
      controlledStorage.operations.length = 0;
      const clearing = controlledStorage.blockNextClear();

      const replacement: IndexDefinition = {
        ...articleIndex,
        fields: [{ path: 'author', type: 'string' }],
      };
      const removal = controlledManager.removeIndex(articleIndex.name);
      const redefinition = controlledManager.defineIndex(replacement);
      let queryResolved = false;
      const query = controlledManager.query({
        indexName: articleIndex.name,
        filters: [],
      }).then((result) => {
        queryResolved = true;
        return result;
      });

      await waitFor(async () => controlledStorage.operations.includes('clear'));
      await Promise.resolve();
      await Promise.resolve();
      expect(queryResolved).toBe(false);
      expect(await controlledStorage.get(articleIndex.name, '/articles/1')).toBeDefined();

      clearing.resolve();
      await Promise.all([removal, redefinition]);
      const result = await query;

      expect(result.documents).toHaveLength(0);
      expect(await controlledStorage.get(articleIndex.name, '/articles/1')).toBeUndefined();
    });

    test('should discard an in-flight query after removing its generation', async () => {
      const controlledStorage = new ControlledLifecycleStorage();
      const controlledManager = new IndexManager(
        controlledStorage,
        (doc: WikiArticle) => doc as unknown as Record<string, unknown>,
      );
      await controlledManager.defineIndex(articleIndex);
      await controlledManager.updateIndex('/articles/1', {
        title: 'Old generation',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });
      controlledStorage.operations.length = 0;
      const queryGate = controlledStorage.blockNextQuery();

      const query = controlledManager.query({
        indexName: articleIndex.name,
        filters: [],
      });
      await waitFor(async () => controlledStorage.operations.includes('query:read'));

      await controlledManager.removeIndex(articleIndex.name);
      queryGate.resolve();

      await expect(query).resolves.toEqual({ documents: [], totalCount: 0 });
    });

    test('should discard an in-flight query after redefining its generation', async () => {
      const controlledStorage = new ControlledLifecycleStorage();
      const controlledManager = new IndexManager(
        controlledStorage,
        (doc: WikiArticle) => doc as unknown as Record<string, unknown>,
      );
      await controlledManager.defineIndex(articleIndex);
      await controlledManager.updateIndex('/articles/1', {
        title: 'Old generation',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });
      controlledStorage.operations.length = 0;
      const queryGate = controlledStorage.blockNextQuery();
      const replacement: IndexDefinition = {
        ...articleIndex,
        fields: [{ path: 'author', type: 'string' }],
      };

      const query = controlledManager.query({
        indexName: articleIndex.name,
        filters: [],
      });
      await waitFor(async () => controlledStorage.operations.includes('query:read'));

      const removal = controlledManager.removeIndex(articleIndex.name);
      const redefinition = controlledManager.defineIndex(replacement);
      await Promise.all([removal, redefinition]);
      queryGate.resolve();

      await expect(query).resolves.toEqual({ documents: [], totalCount: 0 });
      expect(controlledManager.getDefinitions()).toEqual([replacement]);
    });

    test('should reject a replacement and hide orphan rows when clear fails', async () => {
      const controlledStorage = new ControlledLifecycleStorage();
      const controlledManager = new IndexManager(
        controlledStorage,
        (doc: WikiArticle) => doc as unknown as Record<string, unknown>,
      );
      await controlledManager.defineIndex(articleIndex);
      await controlledManager.updateIndex('/articles/1', {
        title: 'Old schema',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });
      controlledStorage.operations.length = 0;
      const clearing = controlledStorage.blockNextClear();

      const replacement: IndexDefinition = {
        ...articleIndex,
        fields: [{ path: 'author', type: 'string' }],
      };
      const removal = controlledManager.removeIndex(articleIndex.name);
      const redefinition = controlledManager.defineIndex(replacement);
      const replacementUpdate = controlledManager.updateIndex('/articles/1', {
        title: 'New schema',
        content: '',
        author: 'Bob',
        createdOn: '2024-01-02',
        tags: [],
      });
      const query = controlledManager.query({
        indexName: articleIndex.name,
        filters: [],
      });
      await waitFor(async () => controlledStorage.operations.includes('clear'));
      const removalFailure = expect(removal).rejects.toThrow('clear failed');
      const redefinitionFailure = expect(redefinition).rejects.toThrow('clear failed');
      const updateFailure = expect(replacementUpdate).rejects.toThrow('clear failed');

      clearing.reject(new Error('clear failed'));
      await Promise.all([removalFailure, redefinitionFailure, updateFailure]);

      expect(controlledManager.getDefinitions()).toHaveLength(0);
      expect((await query).documents).toHaveLength(0);
      expect(await controlledStorage.get(articleIndex.name, '/articles/1')).toBeDefined();

      await expect(controlledManager.defineIndex(replacement)).rejects.toThrow('clear failed');
      expect(controlledManager.getDefinitions()).toHaveLength(0);
      expect(await controlledStorage.get(articleIndex.name, '/articles/1')).toBeDefined();

      await controlledManager.removeIndex(articleIndex.name);
      expect(await controlledStorage.get(articleIndex.name, '/articles/1')).toBeUndefined();
      await controlledManager.defineIndex(replacement);
      expect(controlledManager.getDefinitions()).toEqual([replacement]);
    });

    test('should clear an index after an active update fails', async () => {
      const controlledStorage = new ControlledLifecycleStorage();
      const controlledManager = new IndexManager(
        controlledStorage,
        (doc: WikiArticle) => doc as unknown as Record<string, unknown>,
      );
      await controlledManager.defineIndex(articleIndex);
      const write = controlledStorage.blockNextPut();

      const update = controlledManager.updateIndex('/articles/1', {
        title: 'Pending',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });
      await waitFor(async () => controlledStorage.operations.includes('put:start'));
      const updateFailure = expect(update).rejects.toThrow('write failed');
      const removal = controlledManager.removeIndex(articleIndex.name);

      write.reject(new Error('write failed'));
      await updateFailure;
      await removal;

      expect(controlledStorage.operations).toEqual(['put:start', 'clear']);
      expect(await controlledStorage.get(articleIndex.name, '/articles/1')).toBeUndefined();
    });

    test('should not block removing an unrelated index on an active update', async () => {
      const controlledStorage = new ControlledLifecycleStorage();
      const controlledManager = new IndexManager(
        controlledStorage,
        (doc: WikiArticle) => doc as unknown as Record<string, unknown>,
      );
      await controlledManager.defineIndex(articleIndex);
      await controlledManager.defineIndex({
        name: 'users-by-name',
        collectionPrefix: '/users/',
        fields: [{ path: 'author', type: 'string' }],
      });
      const write = controlledStorage.blockNextPut();

      const update = controlledManager.updateIndex('/articles/1', {
        title: 'Pending',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });
      await waitFor(async () => controlledStorage.operations.includes('put:start'));

      const removal = controlledManager.removeIndex('users-by-name');
      await Promise.resolve();
      await Promise.resolve();
      expect(controlledStorage.operations).toEqual(['put:start', 'clear']);
      await removal;

      write.resolve();
      await update;
      expect(await controlledStorage.get(articleIndex.name, '/articles/1')).toBeDefined();
    });
  });

  describe('updateIndex', () => {
    test('should index a matching document', async () => {
      await manager.updateIndex('/articles/1', {
        title: 'Hello World',
        content: 'body',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: ['intro'],
      });

      const result = await manager.query({
        indexName: 'articles-by-title',
        filters: [{ path: 'title', operator: 'eq', value: 'Hello World' }],
      });
      expect(result.documents).toHaveLength(1);
      expect(result.documents[0].documentPath).toBe('/articles/1');
    });

    test('should skip documents not matching collectionPrefix', async () => {
      await manager.updateIndex('/users/1', {
        title: 'Profile',
        content: '',
        author: 'Bob',
        createdOn: '2024-01-01',
        tags: [],
      });

      const result = await manager.query({
        indexName: 'articles-by-title',
        filters: [],
      });
      expect(result.documents).toHaveLength(0);
    });

    test('should skip write if fields unchanged', async () => {
      const doc: WikiArticle = {
        title: 'Same',
        content: 'changing content',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      };
      await manager.updateIndex('/articles/1', doc);

      // Update with same indexed fields (content changes but is not indexed)
      doc.content = 'different content';
      await manager.updateIndex('/articles/1', doc);

      const result = await manager.query({
        indexName: 'articles-by-title',
        filters: [],
      });
      expect(result.documents).toHaveLength(1);
      expect(result.documents[0].snapshot.title).toBe('Same');
    });

    test('should update when indexed fields change', async () => {
      await manager.updateIndex('/articles/1', {
        title: 'v1',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });

      await manager.updateIndex('/articles/1', {
        title: 'v2',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });

      const result = await manager.query({
        indexName: 'articles-by-title',
        filters: [{ path: 'title', operator: 'eq', value: 'v2' }],
      });
      expect(result.documents).toHaveLength(1);
    });
  });

  describe('removeFromIndex', () => {
    test('should remove a document from all indexes', async () => {
      await manager.updateIndex('/articles/1', {
        title: 'Hello',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });

      await manager.removeFromIndex('/articles/1');

      const result = await manager.query({
        indexName: 'articles-by-title',
        filters: [],
      });
      expect(result.documents).toHaveLength(0);
    });
  });

  describe('query', () => {
    beforeEach(async () => {
      const articles: [string, WikiArticle][] = [
        ['/articles/1', { title: 'Alpha', content: '', author: 'Alice', createdOn: '2024-01-01', tags: [] }],
        ['/articles/2', { title: 'Beta', content: '', author: 'Bob', createdOn: '2024-02-01', tags: [] }],
        ['/articles/3', { title: 'Alpha Plus', content: '', author: 'Alice', createdOn: '2024-03-01', tags: [] }],
        ['/articles/4', { title: 'Gamma', content: '', author: 'Charlie', createdOn: '2024-04-01', tags: [] }],
      ];
      for (const [path, doc] of articles) {
        await manager.updateIndex(path, doc);
      }
    });

    test('exact match', async () => {
      const result = await manager.query({
        indexName: 'articles-by-title',
        filters: [{ path: 'title', operator: 'eq', value: 'Beta' }],
      });
      expect(result.documents).toHaveLength(1);
      expect(result.totalCount).toBe(1);
      expect(result.documents[0].documentPath).toBe('/articles/2');
    });

    test('prefix match', async () => {
      const result = await manager.query({
        indexName: 'articles-by-title',
        filters: [{ path: 'title', operator: 'prefix', value: 'Alpha' }],
      });
      expect(result.documents).toHaveLength(2);
    });

    test('sorted results', async () => {
      const result = await manager.query({
        indexName: 'articles-by-title',
        filters: [],
        sort: [{ path: 'createdOn', direction: 'desc' }],
      });
      expect(result.documents.map(d => d.documentPath)).toEqual([
        '/articles/4', '/articles/3', '/articles/2', '/articles/1',
      ]);
    });

    test('pagination with limit and offset', async () => {
      const result = await manager.query({
        indexName: 'articles-by-title',
        filters: [],
        sort: [{ path: 'title', direction: 'asc' }],
        limit: 2,
        offset: 1,
      });
      expect(result.documents).toHaveLength(2);
      expect(result.totalCount).toBe(4);
    });

    test('query by collectionPrefix instead of indexName', async () => {
      const result = await manager.query({
        collectionPrefix: '/articles/',
        filters: [{ path: 'author', operator: 'eq', value: 'Alice' }],
      });
      expect(result.documents).toHaveLength(2);
    });

    test('returns empty for nonexistent index', async () => {
      const result = await manager.query({
        indexName: 'nonexistent',
        filters: [],
      });
      expect(result.documents).toHaveLength(0);
    });
  });

  describe('subscribe', () => {
    test('should fire callback with initial results', async () => {
      await manager.updateIndex('/articles/1', {
        title: 'Hello',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });

      const results: number[] = [];
      const unsub = manager.subscribe(
        { indexName: 'articles-by-title', filters: [] },
        (result) => { results.push(result.totalCount); },
      );

      await waitFor(async () => results.length >= 1);
      expect(results[0]).toBe(1);

      unsub();
    });

    test('should fire callback on updates', async () => {
      const results: number[] = [];
      const unsub = manager.subscribe(
        { indexName: 'articles-by-title', filters: [] },
        (result) => { results.push(result.totalCount); },
      );

      await waitFor(async () => results.length >= 1);

      await manager.updateIndex('/articles/1', {
        title: 'New',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });

      await waitFor(async () => results.includes(1));

      // Should have initial (0) and updated (1) results
      expect(results).toContain(0);
      expect(results).toContain(1);

      unsub();
    });

    test('should not deliver a superseded query after a replacement result', async () => {
      const controlledStorage = new ControlledLifecycleStorage();
      const controlledManager = new IndexManager(
        controlledStorage,
        (doc: WikiArticle) => doc as unknown as Record<string, unknown>,
      );
      await controlledManager.defineIndex(articleIndex);
      await controlledManager.updateIndex('/articles/1', {
        title: 'Old generation',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });
      controlledStorage.operations.length = 0;
      const queryGate = controlledStorage.blockNextQuery();
      const deliveries: string[] = [];
      const unsub = controlledManager.subscribe(
        { indexName: articleIndex.name, filters: [] },
        (result) => {
          deliveries.push(String(result.documents[0]?.snapshot.author ?? 'empty'));
        },
      );
      await waitFor(async () => controlledStorage.operations.includes('query:read'));

      const replacement: IndexDefinition = {
        ...articleIndex,
        fields: [{ path: 'author', type: 'string' }],
      };
      const removal = controlledManager.removeIndex(articleIndex.name);
      const redefinition = controlledManager.defineIndex(replacement);
      await Promise.all([removal, redefinition]);
      await controlledManager.updateIndex('/articles/2', {
        title: 'New generation',
        content: '',
        author: 'Bob',
        createdOn: '2024-02-01',
        tags: [],
      });
      await waitFor(async () => deliveries.includes('Bob'));
      const deliveriesBeforeOldQuery = [...deliveries];

      queryGate.resolve();
      await waitFor(async () => controlledStorage.operations.includes('query:finish'));
      await new Promise(r => setTimeout(r, 0));

      expect(deliveries).toEqual(deliveriesBeforeOldQuery);
      expect(deliveries.at(-1)).toBe('Bob');
      unsub();
    });

    test('should publish logical removal before storage is cleared', async () => {
      const controlledStorage = new ControlledLifecycleStorage();
      const controlledManager = new IndexManager(
        controlledStorage,
        (doc: WikiArticle) => doc as unknown as Record<string, unknown>,
      );
      await controlledManager.defineIndex(articleIndex);
      await controlledManager.updateIndex('/articles/1', {
        title: 'Existing',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });
      const results: number[] = [];
      const unsub = controlledManager.subscribe(
        { indexName: articleIndex.name, filters: [] },
        (result) => { results.push(result.totalCount); },
      );
      await waitFor(async () => results.includes(1));
      results.length = 0;
      controlledStorage.operations.length = 0;
      const clearGate = controlledStorage.blockNextClear();
      let removalResolved = false;

      const removal = controlledManager.removeIndex(articleIndex.name).then(() => {
        removalResolved = true;
      });
      await waitFor(async () => (
        results.includes(0) && controlledStorage.operations.includes('clear')
      ));

      expect(removalResolved).toBe(false);
      expect(await controlledStorage.get(articleIndex.name, '/articles/1')).toBeDefined();

      clearGate.resolve();
      await removal;
      expect(await controlledStorage.get(articleIndex.name, '/articles/1')).toBeUndefined();
      unsub();
    });

    test('should publish logical removal when storage clearing fails', async () => {
      const controlledStorage = new ControlledLifecycleStorage();
      const controlledManager = new IndexManager(
        controlledStorage,
        (doc: WikiArticle) => doc as unknown as Record<string, unknown>,
      );
      await controlledManager.defineIndex(articleIndex);
      await controlledManager.updateIndex('/articles/1', {
        title: 'Existing',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });
      const results: number[] = [];
      const unsub = controlledManager.subscribe(
        { indexName: articleIndex.name, filters: [] },
        (result) => { results.push(result.totalCount); },
      );
      await waitFor(async () => results.includes(1));
      results.length = 0;
      controlledStorage.operations.length = 0;
      const clearGate = controlledStorage.blockNextClear();

      const removal = controlledManager.removeIndex(articleIndex.name);
      const removalFailure = expect(removal).rejects.toThrow('clear failed');
      await waitFor(async () => (
        results.includes(0) && controlledStorage.operations.includes('clear')
      ));

      expect(await controlledStorage.get(articleIndex.name, '/articles/1')).toBeDefined();

      clearGate.reject(new Error('clear failed'));
      await removalFailure;
      expect(results).toContain(0);
      expect(controlledManager.getDefinitions()).toHaveLength(0);
      expect(await controlledStorage.get(articleIndex.name, '/articles/1')).toBeDefined();
      unsub();
    });

    test('should stop firing after unsubscribe', async () => {
      const results: number[] = [];
      const unsub = manager.subscribe(
        { indexName: 'articles-by-title', filters: [] },
        (result) => { results.push(result.totalCount); },
      );

      await waitFor(async () => results.length >= 1);
      unsub();
      const countAfterUnsub = results.length;

      await manager.updateIndex('/articles/1', {
        title: 'New',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });
      // Wait a tick and verify no additional callbacks fired
      await waitFor(async () => true, 100);

      expect(results.length).toBe(countAfterUnsub);
    });
  });

  describe('rebuildIndex', () => {
    test('should rebuild from provided documents', async () => {
      await manager.updateIndex('/articles/1', {
        title: 'Stale',
        content: '',
        author: 'Alice',
        createdOn: '2024-01-01',
        tags: [],
      });

      const docs = new Map<string, WikiArticle>();
      docs.set('/articles/2', {
        title: 'Fresh',
        content: '',
        author: 'Bob',
        createdOn: '2024-02-01',
        tags: [],
      });
      docs.set('/articles/3', {
        title: 'New',
        content: '',
        author: 'Charlie',
        createdOn: '2024-03-01',
        tags: [],
      });

      await manager.rebuildIndex('articles-by-title', docs);

      const result = await manager.query({
        indexName: 'articles-by-title',
        filters: [],
      });
      // Should only have the rebuilt docs, not the stale one
      expect(result.totalCount).toBe(2);
      expect(result.documents.map(d => d.snapshot.title).sort()).toEqual(['Fresh', 'New']);
    });

    test('should skip documents not matching collectionPrefix', async () => {
      const docs = new Map<string, WikiArticle>();
      docs.set('/articles/1', { title: 'Match', content: '', author: 'A', createdOn: '2024-01-01', tags: [] });
      docs.set('/users/1', { title: 'NoMatch', content: '', author: 'B', createdOn: '2024-01-01', tags: [] });

      await manager.rebuildIndex('articles-by-title', docs);

      const result = await manager.query({ indexName: 'articles-by-title', filters: [] });
      expect(result.totalCount).toBe(1);
    });
  });
});
