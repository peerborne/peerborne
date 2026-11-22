import 'fake-indexeddb/auto';
import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { IndexManager } from './index-manager.js';
import { MemoryIndexStorage } from './memory-index-storage.js';
import { IDBIndexStorage } from './idb-index-storage.js';
import { boundedCartesianSize } from './query-budget.js';
import { FieldProjection } from './field-projection.js';
import type {
  IndexDefinition,
  QueryAst,
  QueryExpression,
  SortClause,
} from './types.js';

type Article = {
  status: string;
  title: string;
  rank: number;
  active: boolean;
  score?: number;
};
const article = fc.record({
  status: fc.constantFrom('draft', 'published', 'archived'),
  title: fc.string({ maxLength: 30 }),
  rank: fc.oneof(
    fc.integer({ min: -20, max: 20 }),
    fc.double({ min: -20, max: 20, noNaN: true }),
  ),
  active: fc.boolean(),
  score: fc.option(fc.integer({ min: -20, max: 20 }), { nil: undefined }),
});
const mutation = fc.record({
  id: fc.integer({ min: 0, max: 20 }),
  remove: fc.boolean(),
  article,
});
const leaf: fc.Arbitrary<QueryExpression> = fc.oneof(
  fc
    .constantFrom('draft', 'published', 'archived')
    .map((value) => ({
      kind: 'field' as const,
      path: 'status',
      operator: 'eq' as const,
      value,
    })),
  fc
    .tuple(
      fc.constantFrom('eq', 'gt', 'gte', 'lt', 'lte') as fc.Arbitrary<
        'eq' | 'gt' | 'gte' | 'lt' | 'lte'
      >,
      fc.integer({ min: -20, max: 20 }),
    )
    .map(([operator, value]) => ({
      kind: 'field' as const,
      path: 'rank',
      operator,
      value,
    })),
  fc
    .array(fc.integer({ min: -20, max: 20 }), { minLength: 1, maxLength: 5 })
    .map((value) => ({
      kind: 'field' as const,
      path: 'rank',
      operator: 'in' as const,
      value,
    })),
  fc
    .string({ maxLength: 3 })
    .map((value) => ({
      kind: 'field' as const,
      path: 'title',
      operator: 'prefix' as const,
      value,
    })),
  fc
    .boolean()
    .map((value) => ({
      kind: 'field' as const,
      path: 'active',
      operator: 'eq' as const,
      value,
    })),
);
const pair = fc
  .tuple(fc.constantFrom('and' as const, 'or' as const), leaf, leaf)
  .map(([kind, a, b]): QueryExpression => ({ kind, expressions: [a, b] }));
const expression = fc.oneof(
  leaf,
  pair,
  fc
    .tuple(fc.constantFrom('and' as const, 'or' as const), pair, leaf)
    .map(([kind, a, b]): QueryExpression => ({ kind, expressions: [a, b] })),
);
const sort = fc
  .array(fc.constantFrom('rank', 'title', 'score'), {
    minLength: 1,
    maxLength: 3,
  })
  .chain((paths) =>
    fc
      .tuple(fc.constantFrom('asc' as const, 'desc' as const))
      .map(([direction]): SortClause[] =>
        [...new Set(paths)].map((path) => ({ path, direction })),
      ),
  );

function matches(row: Article, where: QueryExpression): boolean {
  if (where.kind === 'and')
    return where.expressions.every((child) => matches(row, child));
  if (where.kind === 'or')
    return where.expressions.some((child) => matches(row, child));
  const value = row[where.path as keyof Article];
  const expected = where.value as string | number | boolean | number[];
  switch (where.operator) {
    case 'eq':
      return value === expected;
    case 'in':
      return (expected as number[]).includes(value as number);
    case 'prefix':
      return typeof value === 'string' && value.startsWith(expected as string);
    case 'gt':
      return typeof value === 'number' && value > (expected as number);
    case 'gte':
      return typeof value === 'number' && value >= (expected as number);
    case 'lt':
      return typeof value === 'number' && value < (expected as number);
    case 'lte':
      return typeof value === 'number' && value <= (expected as number);
    default:
      throw new Error('unhandled oracle operator');
  }
}
function compare(
  a: string | number | undefined,
  b: string | number | undefined,
): number {
  if (a === b) return 0;
  if (a === undefined) return -1;
  if (b === undefined) return 1;
  return a < b ? -1 : 1;
}
let database = 0;

describe('owned field projections', () => {
  test.each(['memory', 'indexeddb'] as const)(
    '%s stores and projects selected nested fields through updates and rebuilds',
    async (backend) => {
      await fc.assert(
        fc.asyncProperty(
          fc.constantFrom('profile', 'metrics', 'toString', 'valueOf'),
          fc.string({ maxLength: 30 }),
          fc.integer(),
          async (branch, name, count) => {
            const storage =
              backend === 'memory'
                ? new MemoryIndexStorage()
                : new IDBIndexStorage('projection-' + database++);
            const manager = new IndexManager<Record<string, unknown>>(
              storage,
              (document) => document,
            );
            const indexName = 'projected';
            const documentPath = '/records/first';
            const namePath = branch + '.name';
            const countPath = branch + '.count';
            const fields = Object.freeze({ name, count, private: 'unindexed' });
            try {
              await manager.defineIndex({
                version: 2,
                name: indexName,
                collectionPrefix: '/records/',
                storageMode: 'cleartext-local',
                fields: [
                  { path: namePath, type: 'string', required: true },
                  { path: countPath, type: 'number', required: true },
                ],
              });
              await manager.updateIndex(documentPath, { [branch]: fields });
              const query: QueryAst = {
                version: 2,
                indexName,
                allowScan: true,
                select: [countPath, namePath],
              };
              const [row] = (await manager.query(query)).documents;
              expect(row.snapshot).toStrictEqual({ [branch]: { count, name } });
              expect(row.snapshot[branch]).not.toBe(fields);
              await manager.rebuildIndex(indexName, new Map([
                [documentPath, { [branch]: { name, count: count + 1 } }],
              ]));
              const [rebuilt] = (await manager.query({
                ...query,
                select: [countPath],
              })).documents;
              expect(rebuilt.snapshot).toStrictEqual({
                [branch]: { count: count + 1 },
              });
            } finally {
              if (storage instanceof IDBIndexStorage) await storage.close();
            }
          },
        ),
        { seed: 9547, numRuns: 32 },
      );
    },
  );

  test('never traverses objects previously stored as leaf values', () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), (original, updated) => {
        const leaf = Object.freeze({ label: original });
        const projection = new FieldProjection();
        projection.set('details', leaf);
        projection.set('details.label', updated);
        expect(projection.fields).toStrictEqual({ details: { label: updated } });
        expect(leaf.label).toBe(original);
      }),
      { seed: 9548, numRuns: 100 },
    );
  });
});

describe('generated index updates, planning and cursor histories', () => {
  test.each(['memory', 'indexeddb'] as const)(
    '%s matches a full-scan oracle through updates and every cursor page',
    async (backend) => {
      await fc.assert(
        fc.asyncProperty(
          fc.array(mutation, { maxLength: 35 }),
          expression,
          sort,
          fc.integer({ min: 1, max: 7 }),
          async (program, where, orderBy, first) => {
            const databaseName = 'property-' + database++;
            const storage =
              backend === 'memory'
                ? new MemoryIndexStorage()
                : new IDBIndexStorage(databaseName);
            const name = 'generated';
            const definition: IndexDefinition = {
              version: 2,
              name,
              collectionPrefix: '/articles/',
              storageMode: 'cleartext-local',
              fields: [
                { path: 'status', type: 'string', required: true },
                { path: 'title', type: 'string', required: true },
                { path: 'rank', type: 'number', required: true },
                { path: 'active', type: 'boolean', required: true },
                { path: 'score', type: 'number' },
              ],
              indexes: [
                { name: 'status_rank', fields: ['status', 'rank'] },
                { name: 'title', fields: ['title'] },
                { name: 'active', fields: ['active'] },
              ],
            };
            const manager = new IndexManager<Article>(storage, (value) => ({
              ...value,
            }));
            const model = new Map<string, Article>();
            try {
              await manager.defineIndex(definition);
              for (const operation of program) {
                const path = '/articles/' + operation.id;
                if (operation.remove) {
                  await manager.removeFromIndex(path);
                  model.delete(path);
                } else {
                  model.set(path, { ...operation.article });
                  const input = { ...operation.article };
                  await manager.updateIndex(path, input);
                  input.title = 'changed after indexing';
                }
              }
              const expected = [...model]
                .filter(([, row]) => matches(row, where))
                .sort(([pathA, a], [pathB, b]) => {
                  for (const clause of orderBy) {
                    const compared = compare(
                      a[clause.path as 'rank' | 'title' | 'score'],
                      b[clause.path as 'rank' | 'title' | 'score'],
                    );
                    if (compared !== 0)
                      return clause.direction === 'desc' ? -compared : compared;
                  }
                  return compare(pathA, pathB);
                })
                .map(([path]) => path);
              const query: QueryAst = {
                version: 2,
                indexName: name,
                where,
                orderBy,
                first,
                count: 'exact',
                allowScan: true,
              };
              const seen: string[] = [];
              let after: string | undefined;
              const cursors = new Set<string>();
              for (let page = 0; ; page++) {
                expect(page).toBeLessThanOrEqual(model.size + 1);
                const result = await manager.query({
                  ...query,
                  ...(after === undefined ? {} : { after }),
                });
                seen.push(
                  ...result.documents.map((entry) => entry.documentPath),
                );
                expect(result.count).toEqual({
                  kind: 'verified',
                  value: expected.length,
                });
                if (!result.pageInfo.hasMore) break;
                after = result.pageInfo.cursor!;
                expect(cursors.has(after)).toBe(false);
                cursors.add(after);
              }
              expect(seen).toEqual(expected);
              expect(new Set(seen).size).toBe(seen.length);
              if (after)
                await expect(
                  manager.query({
                    ...query,
                    where: {
                      kind: 'field',
                      path: 'rank',
                      operator: 'eq',
                      value: 999,
                    },
                    after,
                  }),
                ).rejects.toThrow('cursor');
              if (storage instanceof IDBIndexStorage) await storage.close();
              const restored = new IndexManager<Article>(storage, (value) => ({
                ...value,
              }));
              await restored.defineIndex(definition);
              const reopened = await restored.query({ ...query, first: 1000 });
              expect(
                reopened.documents.map((entry) => entry.documentPath),
              ).toEqual(expected);
            } finally {
              if (storage instanceof IDBIndexStorage) {
                await storage.close();
                await new Promise<void>((resolve, reject) => {
                  const request = indexedDB.deleteDatabase(databaseName);
                  request.onsuccess = () => resolve();
                  request.onerror = () => reject(request.error);
                });
              }
            }
          },
        ),
        { seed: backend === 'memory' ? 9521 : 9522, numRuns: 100 },
      );
    },
  );

  test('query expansion arithmetic matches the JavaScript/BigInt boundary', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 65536 }),
        fc.integer({ min: 0, max: 65536 }),
        fc.maxSafeNat(),
        (left, right, limit) => {
          const product = BigInt(left) * BigInt(right);
          const expected = product > BigInt(limit) ? -1n : product;
          expect(BigInt(boundedCartesianSize(left, right, limit))).toBe(
            expected,
          );
        },
      ),
      { seed: 9523, numRuns: 1000 },
    );
  });
});
