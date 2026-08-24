import { describe, expect, test, beforeEach } from '@jest/globals';
import { MemoryIndexStorage } from './memory-index-storage.js';
import { FieldFilter } from './types.js';

describe('MemoryIndexStorage', () => {
  let storage: MemoryIndexStorage;
  const indexName = 'test-index';

  beforeEach(async () => {
    storage = new MemoryIndexStorage();
    await storage.initialize(indexName, [
      { path: 'title', type: 'string' },
      { path: 'count', type: 'number' },
      { path: 'active', type: 'boolean' },
    ]);
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
      const results = await storage.query(indexName, []);
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
      const results = await storage.query(indexName, [{ path: 'title', operator: 'eq', value: 'Alpha' }]);
      expect(results).toHaveLength(1);
      expect(results[0].documentPath).toBe('/doc/1');
    });

    test('neq: not equal', async () => {
      const results = await storage.query(indexName, [{ path: 'count', operator: 'neq', value: 20 }]);
      expect(results).toHaveLength(2);
      expect(results.map(r => r.documentPath).sort()).toEqual(['/doc/1', '/doc/3']);
    });

    test('gt: greater than', async () => {
      const results = await storage.query(indexName, [{ path: 'count', operator: 'gt', value: 10 }]);
      expect(results).toHaveLength(3);
    });

    test('gte: greater than or equal', async () => {
      const results = await storage.query(indexName, [{ path: 'count', operator: 'gte', value: 20 }]);
      expect(results).toHaveLength(3);
    });

    test('lt: less than', async () => {
      const results = await storage.query(indexName, [{ path: 'count', operator: 'lt', value: 20 }]);
      expect(results).toHaveLength(1);
      expect(results[0].documentPath).toBe('/doc/1');
    });

    test('lte: less than or equal', async () => {
      const results = await storage.query(indexName, [{ path: 'count', operator: 'lte', value: 20 }]);
      expect(results).toHaveLength(3);
    });

    test('prefix: string prefix match', async () => {
      const results = await storage.query(indexName, [{ path: 'title', operator: 'prefix', value: 'Alpha' }]);
      expect(results).toHaveLength(2);
      expect(results.map(r => r.documentPath).sort()).toEqual(['/doc/1', '/doc/3']);
    });

    test('in: value in array', async () => {
      const results = await storage.query(indexName, [{ path: 'count', operator: 'in', value: [10, 30] }]);
      expect(results).toHaveLength(2);
      expect(results.map(r => r.documentPath).sort()).toEqual(['/doc/1', '/doc/3']);
    });

    test('contains: substring match', async () => {
      const results = await storage.query(indexName, [{ path: 'title', operator: 'contains', value: 'Beta' }]);
      expect(results).toHaveLength(2);
      expect(results.map(r => r.documentPath).sort()).toEqual(['/doc/2', '/doc/3']);
    });

    test('multiple filters (AND)', async () => {
      const results = await storage.query(indexName, [
        { path: 'count', operator: 'gte', value: 20 },
        { path: 'active', operator: 'eq', value: true },
      ]);
      expect(results).toHaveLength(2);
      expect(results.map(r => r.documentPath).sort()).toEqual(['/doc/3', '/doc/4']);
    });

    test('no filters returns all', async () => {
      const results = await storage.query(indexName, []);
      expect(results).toHaveLength(4);
    });

    test('no matching results', async () => {
      const results = await storage.query(indexName, [{ path: 'title', operator: 'eq', value: 'Nonexistent' }]);
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
      const results = await storage.query(indexName, [], [{ path: 'title', direction: 'asc' }]);
      expect(results.map(r => r.fields.title)).toEqual(['Alpha', 'Beta', 'Charlie']);
    });

    test('sort descending by number', async () => {
      const results = await storage.query(indexName, [], [{ path: 'count', direction: 'desc' }]);
      expect(results.map(r => r.fields.count)).toEqual([30, 20, 10]);
    });

    test('multi-field sort', async () => {
      await storage.put(indexName, '/doc/4', { title: 'Alpha', count: 5 });
      const results = await storage.query(indexName, [], [
        { path: 'title', direction: 'asc' },
        { path: 'count', direction: 'desc' },
      ]);
      expect(results.map(r => r.documentPath)).toEqual(['/doc/2', '/doc/4', '/doc/3', '/doc/1']);
    });
  });

  describe('query pagination', () => {
    beforeEach(async () => {
      for (let i = 1; i <= 10; i++) {
        await storage.put(indexName, `/doc/${i}`, { title: `Doc ${i}`, count: i });
      }
    });

    test('limit', async () => {
      const results = await storage.query(indexName, [], [{ path: 'count', direction: 'asc' }], 3);
      expect(results).toHaveLength(3);
      expect(results.map(r => r.fields.count)).toEqual([1, 2, 3]);
    });

    test('offset', async () => {
      const results = await storage.query(indexName, [], [{ path: 'count', direction: 'asc' }], undefined, 7);
      expect(results).toHaveLength(3);
      expect(results.map(r => r.fields.count)).toEqual([8, 9, 10]);
    });

    test('limit with offset', async () => {
      const results = await storage.query(indexName, [], [{ path: 'count', direction: 'asc' }], 3, 2);
      expect(results).toHaveLength(3);
      expect(results.map(r => r.fields.count)).toEqual([3, 4, 5]);
    });
  });

  describe('close', () => {
    test('should clear all stores', async () => {
      await storage.put(indexName, '/doc/1', { title: 'Hello' });
      await storage.close();
      const result = await storage.get(indexName, '/doc/1');
      expect(result).toBeUndefined();
    });
  });
});
