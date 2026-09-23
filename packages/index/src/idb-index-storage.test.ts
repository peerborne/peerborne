import { hashIndexDefinition, physicalIndexesFor, validateQueryAst } from './query-ast.js';
import { planQuery } from './query-planner.js';
import type { IndexDefinition, QueryAst } from './types.js';
import { describe, expect, test, beforeEach, afterEach } from '@jest/globals';
import 'fake-indexeddb/auto';
import { openDB } from 'idb';
import { IDBIndexStorage } from './idb-index-storage.js';

describe('IDBIndexStorage', () => {
  let storage: IDBIndexStorage;
  const indexName = 'test-index';
  const definition: IndexDefinition = {
    version: 2, name: indexName, collectionPrefix: '/doc/',
    fields: [
      { path: 'title', type: 'string' },
      { path: 'count', type: 'number' },
      { path: 'active', type: 'boolean' },
    ],
  };
  async function query(input: QueryAst) {
    const query = validateQueryAst(input, definition);
    return (await storage.execute({ definition, query, plan: planQuery(definition, query) })).entries;
  }

  beforeEach(async () => {
    storage = new IDBIndexStorage(`test-db-${Date.now()}-${Math.random()}`);
    await storage.initialize(indexName, definition.fields, physicalIndexesFor(definition), {
      schemaHash: await hashIndexDefinition(definition),
      generation: 'one',
      collectionPrefix: '/doc/',
      invalidValuePolicy: 'skip-document',
    });
  });

  afterEach(async () => {
    await storage.close();
  });

  describe('put and get', () => {
    test('should store and retrieve a document', async () => {
      await storage.put(indexName, '/doc/1', { title: 'Hello', count: 10 });
      const result = await storage.get(indexName, '/doc/1');
      expect(result).toEqual({ title: 'Hello', count: 10 });
    });

    test('should return undefined for missing document', async () => {
      const result = await storage.get(indexName, '/doc/nonexistent');
      expect(result).toBeUndefined();
    });

    test('should return undefined for missing index', async () => {
      const result = await storage.get('no-such-index', '/doc/1');
      expect(result).toBeUndefined();
    });

    test('should overwrite existing document', async () => {
      await storage.put(indexName, '/doc/1', { title: 'v1', count: 1 });
      await storage.put(indexName, '/doc/1', { title: 'v2', count: 2 });
      const result = await storage.get(indexName, '/doc/1');
      expect(result).toEqual({ title: 'v2', count: 2 });
    });

    test('should return independent copies', async () => {
      const fields = { title: 'Hello', count: 10 };
      await storage.put(indexName, '/doc/1', fields);
      fields.title = 'Modified';
      const result = await storage.get(indexName, '/doc/1');
      expect(result!.title).toBe('Hello');
    });
  });

  describe('delete', () => {
    test('should remove a document', async () => {
      await storage.put(indexName, '/doc/1', { title: 'Hello' });
      await storage.delete(indexName, '/doc/1');
      const result = await storage.get(indexName, '/doc/1');
      expect(result).toBeUndefined();
    });

    test('should not throw for missing document', async () => {
      await expect(storage.delete(indexName, '/doc/nonexistent')).resolves.not.toThrow();
    });
  });

  describe('clear', () => {
    test('should remove all documents from index', async () => {
      await storage.put(indexName, '/doc/1', { title: 'A' });
      await storage.put(indexName, '/doc/2', { title: 'B' });
      await storage.clear(indexName);
      const results = await query({ version: 2, indexName });
      expect(results).toHaveLength(0);
    });
  });

  describe('query filters', () => {
    beforeEach(async () => {
      await storage.put(indexName, '/doc/1', { title: 'Alpha', count: 10, active: true });
      await storage.put(indexName, '/doc/2', { title: 'Beta', count: 20, active: false });
      await storage.put(indexName, '/doc/3', { title: 'Alpha Beta', count: 30, active: true });
      await storage.put(indexName, '/doc/4', { title: 'Gamma', count: 20, active: true });
    });

    test('eq: exact match', async () => {
      const results = await query({ version: 2, indexName, where: { kind: 'field', path: 'title', operator: 'eq', value: 'Alpha' } });
      expect(results).toHaveLength(1);
      expect(results[0].documentPath).toBe('/doc/1');
    });

    test('neq: not equal', async () => {
      const results = await query({ version: 2, indexName, where: { kind: 'field', path: 'count', operator: 'neq', value: 20 } });
      expect(results).toHaveLength(2);
      expect(results.map(r => r.documentPath).sort()).toEqual(['/doc/1', '/doc/3']);
    });

    test('gt: greater than', async () => {
      const results = await query({ version: 2, indexName, where: { kind: 'field', path: 'count', operator: 'gt', value: 10 } });
      expect(results).toHaveLength(3);
    });

    test('gte: greater than or equal', async () => {
      const results = await query({ version: 2, indexName, where: { kind: 'field', path: 'count', operator: 'gte', value: 20 } });
      expect(results).toHaveLength(3);
    });

    test('lt: less than', async () => {
      const results = await query({ version: 2, indexName, where: { kind: 'field', path: 'count', operator: 'lt', value: 20 } });
      expect(results).toHaveLength(1);
      expect(results[0].documentPath).toBe('/doc/1');
    });

    test('lte: less than or equal', async () => {
      const results = await query({ version: 2, indexName, where: { kind: 'field', path: 'count', operator: 'lte', value: 20 } });
      expect(results).toHaveLength(3);
    });

    test('range filters do not coerce null or undefined operands', async () => {
      await storage.put(indexName, '/doc/null', { title: 'Null', count: null });
      await storage.put(indexName, '/doc/missing', { title: 'Missing' });
      for (const operator of ['gt', 'gte', 'lt', 'lte'] as const) {
        await expect(query({ version: 2, indexName, where: { kind: 'field', path: 'count', operator, value: null } }))
          .rejects.toThrow('invalid number value');
        const numeric = await query({ version: 2, indexName, where: { kind: 'field', path: 'count', operator, value: 0 } });
        expect(numeric.map((entry) => entry.documentPath)).not.toContain('/doc/null');
        expect(numeric.map((entry) => entry.documentPath)).not.toContain('/doc/missing');
      }
    });

    test('lt/lte: excludes stored values of the wrong scalar type', async () => {
      await storage.put(indexName, '/doc/str-2', { title: 'StrNum', count: '2' as unknown as number, active: true });
      const lte = await query({ version: 2, indexName, where: { kind: 'field', path: 'count', operator: 'lte', value: 5 } });
      expect(lte.map((r) => r.documentPath)).not.toContain('/doc/str-2');
      const lt = await query({ version: 2, indexName, where: { kind: 'field', path: 'count', operator: 'lt', value: 5 } });
      expect(lt.map((r) => r.documentPath)).not.toContain('/doc/str-2');
    });

    test('prefix: string prefix match', async () => {
      const results = await query({ version: 2, indexName, where: { kind: 'field', path: 'title', operator: 'prefix', value: 'Alpha' } });
      expect(results).toHaveLength(2);
      expect(results.map(r => r.documentPath).sort()).toEqual(['/doc/1', '/doc/3']);
    });

    test('prefix: matches strings containing \\uffff after the prefix', async () => {
      // Regression test for the IDB-accelerated prefix path. A naive upper
      // bound of value + '￿' would miss strings whose tail contains
      // additional ￿ code units; the implementation computes a true
      // lexicographic successor as the half-open upper bound (and falls
      // back to a lowerBound-only range when no successor is representable),
      // and the JS-side filter validates `startsWith` on every candidate.
      // (The U+FFFF code units below are written as escapes rather than
      // literals because some tooling and editors don't render noncharacters
      // consistently.)
      const tricky = 'Alpha\uffff\uffff\uffff_tail';
      await storage.put(indexName, '/doc/uffff', { title: tricky, count: 99, active: true });
      const results = await query({ version: 2, indexName, where: { kind: 'field', path: 'title', operator: 'prefix', value: 'Alpha' } });
      const paths = results.map((r) => r.documentPath).sort();
      expect(paths).toContain('/doc/uffff');
    });

    test('in: value in array', async () => {
      const results = await query({ version: 2, indexName, where: { kind: 'field', path: 'count', operator: 'in', value: [10, 30] } });
      expect(results).toHaveLength(2);
      expect(results.map(r => r.documentPath).sort()).toEqual(['/doc/1', '/doc/3']);
    });

    test('contains: substring match', async () => {
      const results = await query({ version: 2, indexName, where: { kind: 'field', path: 'title', operator: 'contains', value: 'Beta' } });
      expect(results).toHaveLength(2);
      expect(results.map(r => r.documentPath).sort()).toEqual(['/doc/2', '/doc/3']);
    });

    test('multiple filters (AND)', async () => {
      const results = await query({
        version: 2,
        indexName,
        where: {
          kind: 'and',
          expressions: [
            { kind: 'field', path: 'count', operator: 'gte', value: 20 },
            { kind: 'field', path: 'active', operator: 'eq', value: true },
          ],
        },
      });
      expect(results).toHaveLength(2);
      expect(results.map(r => r.documentPath).sort()).toEqual(['/doc/3', '/doc/4']);
    });

    test('no filters returns all', async () => {
      const results = await query({ version: 2, indexName });
      expect(results).toHaveLength(4);
    });

    test('no matching results', async () => {
      const results = await query({ version: 2, indexName, where: { kind: 'field', path: 'title', operator: 'eq', value: 'Nonexistent' } });
      expect(results).toHaveLength(0);
    });
  });

  describe('query sorting', () => {
    beforeEach(async () => {
      await storage.put(indexName, '/doc/1', { title: 'Charlie', count: 30 });
      await storage.put(indexName, '/doc/2', { title: 'Alpha', count: 10 });
      await storage.put(indexName, '/doc/3', { title: 'Beta', count: 20 });
    });

    test('sort ascending by string', async () => {
      const results = await query({ version: 2, indexName, orderBy: [{ path: 'title', direction: 'asc' }] });
      expect(results.map(r => r.fields.title)).toEqual(['Alpha', 'Beta', 'Charlie']);
    });

    test('sort descending by number', async () => {
      const results = await query({ version: 2, indexName, orderBy: [{ path: 'count', direction: 'desc' }] });
      expect(results.map(r => r.fields.count)).toEqual([30, 20, 10]);
    });

    test('multi-field sort', async () => {
      await storage.put(indexName, '/doc/4', { title: 'Alpha', count: 5 });
      const results = await query({ version: 2, indexName, orderBy: [
        { path: 'title', direction: 'asc' },
        { path: 'count', direction: 'desc' },
      ] });
      expect(results.map(r => r.documentPath)).toEqual(['/doc/2', '/doc/4', '/doc/3', '/doc/1']);
    });
  });



  describe('close', () => {
    test('should clear state and make storage unusable', async () => {
      await storage.put(indexName, '/doc/1', { title: 'Hello' });
      await storage.close();
      // After close, getDB throws since db is null
      await expect(storage.get(indexName, '/doc/1')).rejects.toThrow();
    });
  });


  test('rejects initialization without a current schema identity', async () => {
    await storage.put(indexName, '/doc/current', { title: 'Current', count: 1 });
    await expect(Reflect.apply(storage.initialize, storage, [indexName, definition.fields]))
      .rejects.toThrow('requires physical indexes and a schema identity');
    await expect(storage.get(indexName, '/doc/current')).resolves.toEqual({ title: 'Current', count: 1 });
  });
});
