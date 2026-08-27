import { afterEach, describe, expect, test } from '@jest/globals';
import 'fake-indexeddb/auto';
import { openDB } from 'idb';
import { IDBIndexStorage } from './idb-index-storage.js';
import { IndexManager } from './index-manager.js';
import { IndexDefinition } from './types.js';

const openStorages: IDBIndexStorage[] = [];

function schema(generation = 'one'): IndexDefinition {
  return {
    version: 2,
    name: 'articles',
    collectionPrefix: '/articles/',
    generation,
    storageMode: 'cleartext-local',
    fields: [
      { path: 'status', type: 'string', required: true },
      { path: 'created', type: 'number', required: true },
    ],
    indexes: [{ name: 'status_created', fields: ['status', 'created'] }],
  };
}

function manager(dbName: string, definition = schema()): {
  storage: IDBIndexStorage;
  manager: IndexManager<Record<string, unknown>>;
  ready: Promise<void>;
} {
  const storage = new IDBIndexStorage(dbName);
  openStorages.push(storage);
  const indexManager = new IndexManager<Record<string, unknown>>(storage, (value) => value);
  return { storage, manager: indexManager, ready: indexManager.defineIndex(definition) };
}

afterEach(async () => {
  await Promise.all(openStorages.splice(0).map((storage) => storage.close()));
});

describe('IndexedDB v2 physical indexes and migration', () => {
  test('uses a compound IDB cursor instead of visiting the full store', async () => {
    const dbName = `idb-v2-${Date.now()}-${Math.random()}`;
    const instance = manager(dbName);
    await instance.ready;
    for (let created = 0; created < 20; created++) {
      await instance.manager.updateIndex(`/articles/${created}`, {
        status: created < 15 ? 'draft' : 'published',
        created,
      });
    }
    const result = await instance.manager.query({
      version: 2,
      indexName: 'articles',
      where: {
        kind: 'and',
        expressions: [
          { kind: 'field', path: 'status', operator: 'eq', value: 'published' },
          { kind: 'field', path: 'created', operator: 'gte', value: 17 },
        ],
      },
      orderBy: [{ path: 'created', direction: 'asc' }],
    });
    expect(result.documents.map((entry) => entry.documentPath)).toEqual([
      '/articles/17', '/articles/18', '/articles/19',
    ]);
    expect(result.execution.rowsVisited).toBeLessThan(20);
    expect(result.execution.sort).toBe('index');
  });

  test('retains rows for the same schema and clears them on generation change', async () => {
    const dbName = `idb-generation-${Date.now()}-${Math.random()}`;
    const first = manager(dbName);
    await first.ready;
    await first.manager.updateIndex('/articles/one', { status: 'published', created: 1 });
    await first.storage.close();

    const same = manager(dbName);
    await same.ready;
    expect(await same.storage.get('articles', '/articles/one')).toBeDefined();
    await same.storage.close();

    const changed = manager(dbName, schema('two'));
    await changed.ready;
    expect(await changed.storage.get('articles', '/articles/one')).toBeUndefined();
  });

  test('backfills valid legacy rows when no schema identity exists', async () => {
    const dbName = `idb-backfill-${Date.now()}-${Math.random()}`;
    const legacy = new IDBIndexStorage(dbName);
    openStorages.push(legacy);
    await legacy.initialize('articles', schema().fields);
    await legacy.put('articles', '/articles/one', { status: 'published', created: 1 });
    await legacy.close();

    const upgraded = manager(dbName);
    await upgraded.ready;
    const result = await upgraded.manager.query({
      version: 2,
      indexName: 'articles',
      where: { kind: 'field', path: 'status', operator: 'eq', value: 'published' },
    });
    expect(result.documents.map((entry) => entry.documentPath)).toEqual(['/articles/one']);
  });

  test('removes wrong-prefix rows during legacy backfill', async () => {
    const dbName = `idb-prefix-backfill-${Date.now()}-${Math.random()}`;
    const legacy = new IDBIndexStorage(dbName);
    openStorages.push(legacy);
    await legacy.initialize('articles', schema().fields);
    await legacy.put('articles', '/other/wrong', { status: 'published', created: 1 });
    await legacy.put('articles', '/articles/right', { status: 'published', created: 2 });
    await legacy.close();

    const upgraded = manager(dbName);
    await upgraded.ready;
    const result = await upgraded.manager.query({
      version: 2,
      indexName: 'articles',
      where: { kind: 'field', path: 'status', operator: 'eq', value: 'published' },
    });
    expect(result.documents.map((entry) => entry.documentPath)).toEqual(['/articles/right']);
    await expect(upgraded.storage.get('articles', '/other/wrong')).resolves.toBeUndefined();
  });

  test('uses encoded physical keys for paths that are not valid raw IDB key paths', async () => {
    const dbName = `idb-unusual-paths-${Date.now()}-${Math.random()}`;
    const unusual: IndexDefinition = {
      version: 2,
      name: 'unusual',
      collectionPrefix: '/unusual/',
      storageMode: 'cleartext-local',
      fields: [
        { path: 'display-name', type: 'string', required: true },
        { path: 'items.0', type: 'string', required: true },
      ],
      indexes: [{ name: 'display_item', fields: ['display-name', 'items.0'] }],
    };
    const instance = manager(dbName, unusual);
    await instance.ready;
    await instance.manager.updateIndex('/unusual/one', {
      'display-name': 'Alice',
      items: ['first'],
    });
    const result = await instance.manager.query({
      version: 2,
      indexName: 'unusual',
      where: {
        kind: 'and',
        expressions: [
          { kind: 'field', path: 'display-name', operator: 'eq', value: 'Alice' },
          { kind: 'field', path: 'items.0', operator: 'eq', value: 'first' },
        ],
      },
    });
    expect(result.documents.map((entry) => entry.documentPath)).toEqual(['/unusual/one']);
  });

  test('drops a corrupt persisted row before rebuilding physical keys', async () => {
    const dbName = `idb-corrupt-${Date.now()}-${Math.random()}`;
    const first = manager(dbName);
    await first.ready;
    await first.storage.close();

    const raw = await openDB(dbName);
    await raw.put('articles', {
      documentPath: '/articles/corrupt',
      fields: { status: 'published', created: 'not-a-number' },
    });
    raw.close();

    const reopened = manager(dbName);
    await reopened.ready;
    expect(await reopened.storage.get('articles', '/articles/corrupt')).toBeUndefined();
  });

  test('uses deterministic code-unit ordering for indexed strings', async () => {
    const dbName = `idb-order-${Date.now()}-${Math.random()}`;
    const orderDefinition: IndexDefinition = {
      version: 2,
      name: 'titles',
      collectionPrefix: '/titles/',
      storageMode: 'cleartext-local',
      fields: [{ path: 'title', type: 'string', required: true }],
      indexes: [{ name: 'title', fields: ['title'] }],
    };
    const instance = manager(dbName, orderDefinition);
    await instance.ready;
    await Promise.all([
      instance.manager.updateIndex('/titles/lower', { title: 'apple' }),
      instance.manager.updateIndex('/titles/upper', { title: 'Banana' }),
    ]);
    const result = await instance.manager.query({
      version: 2,
      indexName: 'titles',
      orderBy: [{ path: 'title', direction: 'asc' }],
      allowScan: true,
    });
    expect(result.documents.map((entry) => entry.documentPath))
      .toEqual(['/titles/upper', '/titles/lower']);
    expect(result.execution.sort).toBe('index');
  });

  test('serializes concurrent schema upgrades for different indexes', async () => {
    const dbName = `idb-concurrent-schema-${Date.now()}-${Math.random()}`;
    const storage = new IDBIndexStorage(dbName);
    openStorages.push(storage);
    const indexManager = new IndexManager<Record<string, unknown>>(storage, (value) => value);
    await Promise.all([
      indexManager.defineIndex(schema()),
      indexManager.defineIndex({
        ...schema(),
        name: 'authors',
        collectionPrefix: '/authors/',
      }),
    ]);
    await Promise.all([
      indexManager.updateIndex('/articles/one', { status: 'published', created: 1 }),
      indexManager.updateIndex('/authors/one', { status: 'active', created: 2 }),
    ]);
    await expect(storage.get('articles', '/articles/one')).resolves.toBeDefined();
    await expect(storage.get('authors', '/authors/one')).resolves.toBeDefined();
  });

  test('waits for a concurrent schema upgrade before using an existing store', async () => {
    const dbName = `idb-schema-operation-${Date.now()}-${Math.random()}`;
    const storage = new IDBIndexStorage(dbName);
    openStorages.push(storage);
    const indexManager = new IndexManager<Record<string, unknown>>(storage, (value) => value);
    await indexManager.defineIndex(schema());
    const defineAuthors = indexManager.defineIndex({
      ...schema(),
      name: 'authors',
      collectionPrefix: '/authors/',
    });
    const updateArticle = indexManager.updateIndex('/articles/during-upgrade', {
      status: 'published',
      created: 3,
    });
    await Promise.all([defineAuthors, updateArticle]);
    await expect(storage.get('articles', '/articles/during-upgrade')).resolves.toBeDefined();
  });

  test('fails a schema upgrade promptly when an unmanaged connection blocks it', async () => {
    const dbName = `idb-blocked-schema-${Date.now()}-${Math.random()}`;
    const instance = manager(dbName);
    await instance.ready;
    const unmanaged = await openDB(dbName);
    const upgrade = instance.manager.defineIndex({
      ...schema(),
      name: 'authors',
      collectionPrefix: '/authors/',
    });
    await expect(upgrade).rejects.toThrow('schema upgrade blocked');
    unmanaged.close();
  });
});
