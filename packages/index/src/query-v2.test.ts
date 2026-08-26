import { describe, expect, test } from '@jest/globals';
import { IDBIndexStorage } from './idb-index-storage.js';
import {
  IndexManager,
  IndexSecurityPolicyError,
  InvalidIndexedDocumentError,
  QueryRequiresScanError,
} from './index-manager.js';
import { MemoryIndexStorage } from './memory-index-storage.js';
import { IndexDefinition, QueryAst } from './types.js';
import {
  hashIndexDefinition,
  InvalidIndexSchemaError,
  InvalidQueryError,
  validateIndexDefinition,
  validateQueryAst,
} from './query-ast.js';
import { parseQueryCursor } from './query-cursor.js';

interface Article {
  status: string;
  title: string;
  created: number;
  score?: number;
}

const definition: IndexDefinition = {
  version: 2,
  name: 'articles-v2',
  collectionPrefix: '/articles/',
  fields: [
    { path: 'status', type: 'string', required: true },
    { path: 'created', type: 'number', required: true },
    { path: 'title', type: 'string', required: true, maxStringLength: 100 },
    { path: 'score', type: 'number' },
  ],
  indexes: [
    { name: 'status_created', fields: ['status', 'created'] },
    { name: 'title', fields: ['title'] },
  ],
};

async function populatedManager(): Promise<IndexManager<Article>> {
  const manager = new IndexManager<Article>(new MemoryIndexStorage(), (article) => ({ ...article }));
  await manager.defineIndex(definition);
  await Promise.all([
    manager.updateIndex('/articles/a', { status: 'draft', title: 'Alpha', created: 1 }),
    manager.updateIndex('/articles/b', { status: 'published', title: 'Beta', created: 2 }),
    manager.updateIndex('/articles/c', { status: 'published', title: 'Charlie', created: 3 }),
    manager.updateIndex('/articles/d', { status: 'published', title: 'Delta', created: 4 }),
  ]);
  return manager;
}

describe('v2 local indexing and query contract', () => {
  test('plans and executes a compound equality/range query', async () => {
    const manager = await populatedManager();
    const result = await manager.query({
      version: 2,
      indexName: definition.name,
      where: {
        kind: 'and',
        expressions: [
          { kind: 'field', path: 'status', operator: 'eq', value: 'published' },
          { kind: 'field', path: 'created', operator: 'gte', value: 3 },
        ],
      },
      orderBy: [{ path: 'created', direction: 'asc' }],
      count: 'exact',
    });

    expect(result.documents.map((entry) => entry.documentPath)).toEqual([
      '/articles/c',
      '/articles/d',
    ]);
    expect(result.count).toEqual({ kind: 'verified', value: 2 });
    expect(result.execution.physicalIndexes).toEqual(['status_created']);
    expect(result.execution.scan).toBe('bounded');
    expect(result.execution.sort).toBe('index');
  });

  test('unions top-level OR lookups and verifies the complete predicate', async () => {
    const manager = await populatedManager();
    const result = await manager.query({
      version: 2,
      indexName: definition.name,
      where: {
        kind: 'or',
        expressions: [
          { kind: 'field', path: 'status', operator: 'eq', value: 'draft' },
          { kind: 'field', path: 'title', operator: 'prefix', value: 'Char' },
        ],
      },
      count: 'none',
    });
    expect(result.documents.map((entry) => entry.documentPath)).toEqual([
      '/articles/a',
      '/articles/c',
    ]);
    expect(result.execution.physicalIndexes.sort()).toEqual(['status_created', 'title']);
  });

  test('requires explicit opt-in for an unbounded scan', async () => {
    const manager = await populatedManager();
    const query: QueryAst = {
      version: 2,
      indexName: definition.name,
      where: { kind: 'field', path: 'title', operator: 'contains', value: 'a' },
    };
    await expect(manager.query(query)).rejects.toBeInstanceOf(QueryRequiresScanError);
    const result = await manager.query({ ...query, allowScan: true });
    expect(result.execution.scan).toBe('full');
  });

  test('provides query-bound stable cursors and projections', async () => {
    const manager = await populatedManager();
    const query: QueryAst = {
      version: 2,
      indexName: definition.name,
      where: { kind: 'field', path: 'status', operator: 'eq', value: 'published' },
      orderBy: [{ path: 'created', direction: 'asc' }],
      select: ['title'],
      first: 2,
      count: 'exact',
    };
    const first = await manager.query(query);
    expect(first.pageInfo.hasMore).toBe(true);
    expect(first.documents[0].snapshot).toEqual({ title: 'Beta' });
    const second = await manager.query({ ...query, after: first.pageInfo.cursor });
    expect(second.documents.map((entry) => entry.documentPath)).toEqual(['/articles/d']);
    await expect(manager.query({
      ...query,
      where: { kind: 'field', path: 'status', operator: 'eq', value: 'draft' },
      after: first.pageInfo.cursor,
    })).rejects.toThrow('cursor');
  });

  test('excludes malformed rows, removes stale values, and records no values', async () => {
    const manager = await populatedManager();
    await manager.updateIndex('/articles/a', {
      status: 'draft',
      title: 'x'.repeat(101),
      created: 1,
    });
    const result = await manager.query({
      version: 2,
      indexName: definition.name,
      where: { kind: 'field', path: 'status', operator: 'eq', value: 'draft' },
    });
    expect(result.documents).toEqual([]);
    const diagnostics = manager.getDiagnostics();
    expect(diagnostics.at(-1)).toMatchObject({
      documentPath: '/articles/a',
      fieldPath: 'title',
      reason: 'value-too-large',
    });
    expect(JSON.stringify(diagnostics)).not.toContain('xxxxxxxx');
  });

  test('reject policy preserves the previously indexed row', async () => {
    const manager = new IndexManager<Article>(new MemoryIndexStorage(), (article) => ({ ...article }));
    await manager.defineIndex({ ...definition, name: 'strict', invalidValuePolicy: 'reject' });
    await manager.updateIndex('/articles/a', { status: 'draft', title: 'Alpha', created: 1 });
    await expect(manager.updateIndex('/articles/a', {
      status: 'draft',
      title: 'x'.repeat(101),
      created: 1,
    })).rejects.toBeInstanceOf(InvalidIndexedDocumentError);
    const result = await manager.query({
      version: 2,
      indexName: 'strict',
      where: { kind: 'field', path: 'status', operator: 'eq', value: 'draft' },
    });
    expect(result.documents).toHaveLength(1);
  });

  test('requires explicit cleartext-local opt-in for persistent projections', async () => {
    const manager = new IndexManager<Article>(new IDBIndexStorage('security-policy'), (article) => ({ ...article }));
    await expect(manager.defineIndex(definition)).rejects.toBeInstanceOf(IndexSecurityPolicyError);

    const unclassifiedStorage = new MemoryIndexStorage();
    Object.defineProperty(unclassifiedStorage, 'persistent', { value: undefined });
    await expect(new IndexManager<Article>(
      unclassifiedStorage,
      (article) => ({ ...article }),
    ).defineIndex(definition)).rejects.toBeInstanceOf(IndexSecurityPolicyError);
  });

  test('keeps local persistence policy out of distributed schema compatibility', async () => {
    await expect(Promise.all([
      hashIndexDefinition({ ...definition, storageMode: 'memory' }),
      hashIndexDefinition({ ...definition, storageMode: 'cleartext-local' }),
    ])).resolves.toEqual([
      await hashIndexDefinition(definition),
      await hashIndexDefinition(definition),
    ]);
  });

  test('rejects hostile schema paths and bounded-query violations', async () => {
    const manager = new IndexManager<Article>(new MemoryIndexStorage(), (article) => ({ ...article }));
    await expect(manager.defineIndex({
      ...definition,
      name: 'hostile',
      fields: [{ path: '__proto__.polluted', type: 'string' }],
    })).rejects.toBeInstanceOf(InvalidIndexSchemaError);
    expect(() => validateQueryAst({
      version: 2,
      indexName: definition.name,
      first: 10_001,
    }, definition)).toThrow(InvalidQueryError);

    const inheritedWhere = Object.assign(Object.create({
      where: { kind: 'field', path: 'status', operator: 'eq', value: 'published' },
    }), {
      version: 2,
      indexName: definition.name,
    }) as QueryAst;
    expect(() => validateQueryAst(inheritedWhere, definition)).toThrow('plain version 2 object');

    const previousAllowScan = Object.getOwnPropertyDescriptor(Object.prototype, 'allowScan');
    Object.defineProperty(Object.prototype, 'allowScan', {
      configurable: true,
      value: true,
    });
    try {
      expect(() => validateQueryAst({
        version: 2,
        indexName: definition.name,
      }, definition)).toThrow('inherited query property: allowScan');
    } finally {
      if (previousAllowScan) {
        Object.defineProperty(Object.prototype, 'allowScan', previousAllowScan);
      } else {
        delete (Object.prototype as Record<string, unknown>).allowScan;
      }
    }

    const inheritedVersion = Object.assign(Object.create({ version: 2 }), {
      name: 'inherited-version',
      collectionPrefix: '/hostile/',
      fields: [{ path: 'title', type: 'string', required: true }],
    }) as IndexDefinition;
    await expect(manager.defineIndex(inheritedVersion)).rejects.toThrow('plain object');

    await expect(manager.defineIndex({
      ...definition,
      name: 'overlapping-paths',
      fields: [
        { path: 'author', type: 'string', required: true },
        { path: 'author.name', type: 'string', required: true },
      ],
      indexes: [{ name: 'author', fields: ['author'] }],
    })).rejects.toThrow('field paths must not overlap');
  });

  test('rejects sparse and inherited array elements before validation', () => {
    expect(() => validateIndexDefinition({
      ...definition,
      name: 'sparse-fields',
      fields: Array(1),
    })).toThrow('dense array');
    expect(() => validateIndexDefinition({
      ...definition,
      name: 'sparse-indexes',
      indexes: Array(1),
    })).toThrow('dense array');
    expect(() => validateIndexDefinition({
      ...definition,
      name: 'sparse-index-fields',
      indexes: [{ name: 'sparse', fields: Array(1) }],
    })).toThrow('dense array');

    expect(() => validateQueryAst({
      version: 2,
      indexName: definition.name,
      orderBy: Array(1),
    }, definition)).toThrow('dense array');
    expect(() => validateQueryAst({
      version: 2,
      indexName: definition.name,
      select: Array(1),
    }, definition)).toThrow('dense array');
    expect(() => validateQueryAst({
      version: 2,
      indexName: definition.name,
      where: { kind: 'and', expressions: Array(1) },
    }, definition)).toThrow('dense array');
    expect(() => validateQueryAst({
      version: 2,
      indexName: definition.name,
      where: { kind: 'field', path: 'status', operator: 'in', value: Array(1) },
    }, definition)).toThrow('dense array');

    const inheritedFields = Array<IndexDefinition['fields'][number]>(1);
    const inheritedArrayPrototype = Object.create(Array.prototype) as Record<string, unknown>;
    Object.defineProperty(inheritedArrayPrototype, '0', {
      configurable: true,
      value: { path: 'inherited', type: 'string', required: true },
    });
    Object.setPrototypeOf(inheritedFields, inheritedArrayPrototype);
    expect(() => validateIndexDefinition({
      ...definition,
      name: 'inherited-field-element',
      fields: inheritedFields,
    })).toThrow('dense array');
  });

  test('discards an in-flight legacy query against a removed v2 generation', async () => {
    let release!: () => void;
    let started!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const queryStarted = new Promise<void>((resolve) => { started = resolve; });
    class QueryGatedStorage extends MemoryIndexStorage {
      override async execute(
        request: Parameters<MemoryIndexStorage['execute']>[0],
      ): ReturnType<MemoryIndexStorage['execute']> {
        const result = await super.execute(request);
        started();
        await gate;
        return result;
      }
    }
    const manager = new IndexManager<Article>(new QueryGatedStorage(), (article) => ({ ...article }));
    await manager.defineIndex(definition);
    await manager.updateIndex('/articles/one', {
      status: 'published', title: 'Old', created: 1,
    });
    const queryResult = manager.query({ indexName: definition.name, filters: [] });
    await queryStarted;
    await manager.removeIndex(definition.name);
    release();
    await expect(queryResult).resolves.toEqual({ documents: [], totalCount: 0 });
  });

  test('retains the legacy API\'s unbounded limit semantics on v2 indexes', async () => {
    const manager = await populatedManager();
    const result = await manager.query({
      indexName: definition.name,
      filters: [],
      limit: 20_000,
    });
    expect(result.documents).toHaveLength(4);
    expect(result.totalCount).toBe(4);
  });

  test('treats ordering-only traversal as a scan and rejects optional physical keys', async () => {
    const manager = await populatedManager();
    await expect(manager.query({
      version: 2,
      indexName: definition.name,
      orderBy: [{ path: 'title', direction: 'asc' }],
      first: 1,
    })).rejects.toBeInstanceOf(QueryRequiresScanError);
    const result = await manager.query({
      version: 2,
      indexName: definition.name,
      orderBy: [{ path: 'title', direction: 'asc' }],
      first: 1,
      allowScan: true,
    });
    expect(result.execution.scan).toBe('full');

    await expect(new IndexManager<Record<string, unknown>>(
      new MemoryIndexStorage(),
      (value) => value,
    ).defineIndex({
      version: 2,
      name: 'unsafe-optional-key',
      collectionPrefix: '/optional/',
      fields: [{ path: 'optional', type: 'string' }],
      indexes: [{ name: 'optional', fields: ['optional'] }],
    })).rejects.toThrow('required');
  });

  test('indexed consistency waits for writes that were already queued', async () => {
    let release!: () => void;
    let started!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const putStarted = new Promise<void>((resolve) => { started = resolve; });
    class GatedStorage extends MemoryIndexStorage {
      override async put(
        indexName: string,
        documentPath: string,
        fields: Record<string, unknown>,
      ): Promise<void> {
        started();
        await gate;
        await super.put(indexName, documentPath, fields);
      }
    }
    const manager = new IndexManager<Article>(new GatedStorage(), (article) => ({ ...article }));
    await manager.defineIndex(definition);
    const update = manager.updateIndex('/articles/queued', {
      status: 'published', title: 'Queued', created: 5,
    });
    await putStarted;
    let queryResolved = false;
    const queryResult = manager.query({
      version: 2,
      indexName: definition.name,
      where: { kind: 'field', path: 'status', operator: 'eq', value: 'published' },
      consistency: 'indexed',
    }).then((result) => {
      queryResolved = true;
      return result;
    });
    await Promise.resolve();
    expect(queryResolved).toBe(false);
    release();
    await update;
    expect((await queryResult).documents.map((entry) => entry.documentPath))
      .toEqual(['/articles/queued']);
  });

  test('serializes rebuilds with concurrent updates so newer state wins', async () => {
    let blockNextPut = false;
    let release!: () => void;
    let started!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const putStarted = new Promise<void>((resolve) => { started = resolve; });
    class RebuildGatedStorage extends MemoryIndexStorage {
      override async put(
        indexName: string,
        documentPath: string,
        fields: Record<string, unknown>,
      ): Promise<void> {
        if (blockNextPut) {
          blockNextPut = false;
          started();
          await gate;
        }
        await super.put(indexName, documentPath, fields);
      }
    }
    const manager = new IndexManager<Article>(
      new RebuildGatedStorage(),
      (article) => ({ ...article }),
    );
    await manager.defineIndex(definition);
    await manager.updateIndex('/articles/a', {
      status: 'draft', title: 'Old', created: 1,
    });
    blockNextPut = true;
    const rebuild = manager.rebuildIndex(definition.name, new Map([
      ['/articles/a', { status: 'draft', title: 'Stale rebuild', created: 1 }],
    ]));
    await putStarted;
    const update = manager.updateIndex('/articles/a', {
      status: 'published', title: 'Newest', created: 2,
    });
    release();
    await Promise.all([rebuild, update]);
    const result = await manager.query({
      version: 2,
      indexName: definition.name,
      where: { kind: 'field', path: 'status', operator: 'eq', value: 'published' },
    });
    expect(result.documents).toEqual([{
      documentPath: '/articles/a',
      snapshot: { status: 'published', created: 2, title: 'Newest', score: undefined },
    }]);
  });

  test('sorts in memory when an unused compound suffix would break path tie ordering', async () => {
    const manager = new IndexManager<Record<string, unknown>>(
      new MemoryIndexStorage(),
      (value) => value,
    );
    await manager.defineIndex({
      version: 2,
      name: 'compound-ties',
      collectionPrefix: '/ties/',
      fields: [
        { path: 'status', type: 'string', required: true },
        { path: 'title', type: 'string', required: true },
        { path: 'rank', type: 'number', required: true },
      ],
      indexes: [{ name: 'status_title_rank', fields: ['status', 'title', 'rank'] }],
    });
    await Promise.all([
      manager.updateIndex('/ties/z', { status: 'live', title: 'Same', rank: 1 }),
      manager.updateIndex('/ties/a', { status: 'live', title: 'Same', rank: 2 }),
    ]);
    const result = await manager.query({
      version: 2,
      indexName: 'compound-ties',
      where: { kind: 'field', path: 'status', operator: 'eq', value: 'live' },
      orderBy: [{ path: 'title', direction: 'asc' }],
    });
    expect(result.documents.map((entry) => entry.documentPath)).toEqual(['/ties/a', '/ties/z']);
    expect(result.execution.sort).toBe('memory');
  });

  test('preserves unversioned schemas without permitting prototype pollution', async () => {
    const manager = new IndexManager<Record<string, unknown>>(
      new MemoryIndexStorage(),
      (value) => value,
    );
    await manager.defineIndex({
      name: 'legacy schema name',
      collectionPrefix: '/legacy/',
      fields: [{ path: '__proto__.polluted', type: 'string' }],
    });
    await manager.updateIndex('/legacy/one', JSON.parse('{"__proto__":{"polluted":"value"}}'));
    const result = await manager.query({
      indexName: 'legacy schema name',
      filters: [{ path: '__proto__.polluted', operator: 'eq', value: 'value' }],
    });
    expect(result.documents).toHaveLength(1);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  test('rejects cursors whose sort tuple has the wrong runtime type', () => {
    const cursor = btoa(JSON.stringify({
      version: 1,
      queryHash: 'query',
      schemaHash: 'schema',
      generation: 'generation',
      sort: ['not-a-number'],
      documentPath: '/articles/a',
    })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
    expect(() => parseQueryCursor(
      cursor,
      'query',
      'schema',
      'generation',
      1,
      ['number'],
    )).toThrow('wrong type');
  });
});
