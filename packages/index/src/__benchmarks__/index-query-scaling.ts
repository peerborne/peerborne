/**
 * Benchmark: Index Query Scaling
 *
 * Measures query latency vs index size:
 * - Insert 100, 1K, 10K, 100K entries
 * - Time exact match, range, and compound queries
 * - MemoryIndexStorage backend
 */
import { PaperBenchmarkRunner, BenchmarkSuiteResult } from './paper-benchmark-runner.js';
import { MemoryIndexStorage } from '../memory-index-storage.js';
import { IndexManager } from '../index-manager.js';
import { generateDocuments } from './mock-data.js';

const SCALES = [100, 1_000, 10_000, 100_000];

/**
 * Run the index query scaling benchmark suite.
 *
 * Populates a {@link MemoryIndexStorage}-backed index at various document counts
 * (100 to 100K) and measures latency for exact-match, range, prefix, compound,
 * and sorted queries, plus single-document update cost and a full-scan baseline.
 *
 * @param iterations - Number of timed iterations per benchmark (default 100).
 * @returns Promise<BenchmarkSuiteResult> with statistical summaries for each benchmark.
 */
export async function runIndexQueryScalingBenchmarks(
  iterations: number = 100,
): Promise<BenchmarkSuiteResult> {
  const runner = new PaperBenchmarkRunner('index-query-scaling');

  for (const count of SCALES) {
    console.log(`  Setting up ${count} documents...`);
    const storage = new MemoryIndexStorage();
    const manager = new IndexManager<Record<string, unknown>>(storage, (doc) => doc);
    await manager.defineIndex({
      name: 'articles',
      collectionPrefix: '/articles/',
      fields: [
        { path: 'title', type: 'string' },
        { path: 'author', type: 'string' },
        { path: 'category', type: 'string' },
        { path: 'createdOn', type: 'date' },
        { path: 'viewCount', type: 'number' },
      ],
    });

    const docs = generateDocuments('wiki', count);
    for (const [path, doc] of docs) {
      await manager.updateIndex(path, doc);
    }

    const iterCount = count >= 100_000 ? Math.max(10, Math.floor(iterations / 10)) : iterations;

    // Exact match query
    await runner.run(`exact-match-${count}`, async () => {
      await manager.query({
        indexName: 'articles',
        filters: [{ path: 'author', operator: 'eq', value: 'Alice' }],
      });
    }, iterCount);

    // Range query (numeric)
    await runner.run(`range-gte-${count}`, async () => {
      await manager.query({
        indexName: 'articles',
        filters: [{ path: 'viewCount', operator: 'gte', value: 500 }],
      });
    }, iterCount);

    // Range query (date)
    await runner.run(`range-date-${count}`, async () => {
      await manager.query({
        indexName: 'articles',
        filters: [{ path: 'createdOn', operator: 'gte', value: '2024-06-01' }],
      });
    }, iterCount);

    // Prefix query
    await runner.run(`prefix-query-${count}`, async () => {
      await manager.query({
        indexName: 'articles',
        filters: [{ path: 'title', operator: 'prefix', value: 'Article 1' }],
      });
    }, iterCount);

    // Compound query (two filters)
    await runner.run(`compound-query-${count}`, async () => {
      await manager.query({
        indexName: 'articles',
        filters: [
          { path: 'author', operator: 'eq', value: 'Alice' },
          { path: 'category', operator: 'eq', value: 'Technology' },
        ],
      });
    }, iterCount);

    // Sorted query with limit
    await runner.run(`sorted-limit-query-${count}`, async () => {
      await manager.query({
        indexName: 'articles',
        filters: [],
        sort: [{ path: 'createdOn', direction: 'desc' }],
        limit: 20,
      });
    }, iterCount);

    // Index update (single doc)
    let updateId = 0;
    await runner.run(`single-update-${count}`, async () => {
      await manager.updateIndex(`/articles/${updateId++ % count}`, {
        title: `Updated ${updateId}`,
        author: 'Updater',
        category: 'Updated',
        createdOn: new Date().toISOString(),
        viewCount: updateId,
        content: 'updated',
        tags: ['updated'],
      });
    }, iterCount);

    // Full scan baseline (no index, just filter in-memory array)
    const docsArray = Array.from(docs.entries());
    await runner.run(`full-scan-baseline-${count}`, () => {
      const matches = docsArray.filter(([, doc]) => doc.author === 'Alice');
      void matches.length;
    }, iterCount);
  }

  return runner.toSuiteResult();
}
