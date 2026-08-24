import { describe, expect, test, beforeEach, afterEach } from '@jest/globals';
import 'fake-indexeddb/auto';
import { openDB } from 'idb';
import { IDBIndexStorage } from './idb-index-storage.js';

describe('IDBIndexStorage', () => {
  let storage: IDBIndexStorage;
  const indexName = 'test-index';

  beforeEach(async () => {
    storage = new IDBIndexStorage(`test-db-${Date.now()}-${Math.random()}`);
    await storage.initialize(indexName, [
      { path: 'title', type: 'string' },
      { path: 'count', type: 'number' },
      { path: 'active', type: 'boolean' },
    ]);
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

    test('lt/lte: matches string-typed values that coerce numerically', async () => {
      // Regression test: the IDB-accelerated path used to apply
      // `IDBKeyRange.upperBound(numericValue)`, which silently dropped any
      // stored keys of non-numeric type (Date / string / binary / Array all
      // sort above numbers in IDB key order). JS comparison, however,
      // coerces operand types — `'2' <= 5` is true — so a stored string
      // numeric like `'2'` would match the JS-only path but be missed by
      // the cursor. We now route lt/lte through the full-scan fallback so
      // both backends agree.
      await storage.put(indexName, '/doc/str-2', { title: 'StrNum', count: '2' as unknown as number, active: true });
      const lte = await storage.query(indexName, [{ path: 'count', operator: 'lte', value: 5 }]);
      expect(lte.map((r) => r.documentPath)).toContain('/doc/str-2');
      const lt = await storage.query(indexName, [{ path: 'count', operator: 'lt', value: 5 }]);
      expect(lt.map((r) => r.documentPath)).toContain('/doc/str-2');
    });

    test('prefix: string prefix match', async () => {
      const results = await storage.query(indexName, [{ path: 'title', operator: 'prefix', value: 'Alpha' }]);
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
      const results = await storage.query(indexName, [
        { path: 'title', operator: 'prefix', value: 'Alpha' },
      ]);
      const paths = results.map((r) => r.documentPath).sort();
      expect(paths).toContain('/doc/uffff');
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
    test('should clear state and make storage unusable', async () => {
      await storage.put(indexName, '/doc/1', { title: 'Hello' });
      await storage.close();
      // After close, getDB throws since db is null
      await expect(storage.get(indexName, '/doc/1')).rejects.toThrow();
    });
  });

  describe('schema upgrades across initialize() calls', () => {
    test('adds missing IDB indexes when initialize() is called with new fields', async () => {
      // Start with a single field on a fresh DB.
      const dbName = `schema-upgrade-${Date.now()}-${Math.random()}`;
      const s1 = new IDBIndexStorage(dbName);
      await s1.initialize('store-a', [{ path: 'title', type: 'string' }]);
      await s1.put('store-a', '/d/1', { title: 'Hello', count: 7 });
      await s1.close();

      // Reopen the same DB requesting a second field that wasn't indexed
      // before. The IDB store must gain a `count` index so query() can use it
      // without throwing NotFoundError.
      const s2 = new IDBIndexStorage(dbName);
      await s2.initialize('store-a', [
        { path: 'title', type: 'string' },
        { path: 'count', type: 'number' },
      ]);

      // Querying on the newly-added indexed field should hit the IDB-accelerated
      // path (which calls store.index('count')) and succeed.
      const results = await s2.query('store-a', [
        { path: 'count', operator: 'eq', value: 7 },
      ]);
      expect(results).toHaveLength(1);
      expect(results[0].documentPath).toBe('/d/1');

      await s2.close();
    });

    test('does not bump version when no new indexes are needed', async () => {
      const dbName = `schema-noop-${Date.now()}-${Math.random()}`;
      const s1 = new IDBIndexStorage(dbName);
      await s1.initialize('store-b', [
        { path: 'title', type: 'string' },
        { path: 'count', type: 'number' },
      ]);
      await s1.put('store-b', '/d/1', { title: 'Hi', count: 1 });
      await s1.close();

      // Read the DB version after initial setup (via a raw open) so we can
      // assert the no-op reopen doesn't trigger an unnecessary version bump.
      const probe1 = await openDB(dbName);
      const versionBeforeReopen = probe1.version;
      probe1.close();

      const s2 = new IDBIndexStorage(dbName);
      await s2.initialize('store-b', [
        { path: 'title', type: 'string' },
        { path: 'count', type: 'number' },
      ]);
      const results = await s2.query('store-b', [
        { path: 'title', operator: 'eq', value: 'Hi' },
      ]);
      expect(results).toHaveLength(1);
      await s2.close();

      const probe2 = await openDB(dbName);
      const versionAfterReopen = probe2.version;
      probe2.close();
      expect(versionAfterReopen).toBe(versionBeforeReopen);
    });
  });
});
