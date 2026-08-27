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
  maxDocuments: number = 100_000,
): Promise<BenchmarkSuiteResult> {
  const runner = new PaperBenchmarkRunner('index-query-scaling');

  const scales = SCALES.filter((count) => count <= maxDocuments);
  if (!scales.includes(maxDocuments)) scales.push(maxDocuments);
  for (const count of scales) {
    console.log(`  Setting up ${count} documents...`);
    const storage = new MemoryIndexStorage();
    const manager = new IndexManager<Record<string, unknown>>(storage, (doc) => doc);
    await manager.defineIndex({
      version: 2,
      name: 'articles',
      collectionPrefix: '/articles/',
      fields: [
        { path: 'title', type: 'string', required: true },
        { path: 'author', type: 'string', required: true },
        { path: 'category', type: 'string', required: true },
        { path: 'createdOn', type: 'date', required: true },
        { path: 'viewCount', type: 'number', required: true },
      ],
      indexes: [
        { name: 'by_author', fields: ['author'] },
        { name: 'by_view_count', fields: ['viewCount'] },
        { name: 'by_created_on', fields: ['createdOn'] },
        { name: 'by_title', fields: ['title'] },
        { name: 'by_author_category', fields: ['author', 'category'] },
      ],
    });

    const docs = generateDocuments('wiki', count);
    for (const [path, doc] of docs) {
      await manager.updateIndex(path, doc);
    }

    const iterCount = count >= 100_000 ? Math.max(1, Math.floor(iterations / 10)) : iterations;

    // Exact match query
    await runner.run(`exact-match-${count}`, async () => {
      await manager.query({
        version: 2,
        indexName: 'articles',
        where: { kind: 'field', path: 'author', operator: 'eq', value: 'Alice' },
      });
    }, iterCount);

    // Range query (numeric)
    await runner.run(`range-gte-${count}`, async () => {
      await manager.query({
        version: 2,
        indexName: 'articles',
        where: { kind: 'field', path: 'viewCount', operator: 'gte', value: 500 },
      });
    }, iterCount);

    // Range query (date)
    await runner.run(`range-date-${count}`, async () => {
      await manager.query({
        version: 2,
        indexName: 'articles',
        where: { kind: 'field', path: 'createdOn', operator: 'gte', value: '2024-06-01' },
      });
    }, iterCount);

    // Prefix query
    await runner.run(`prefix-query-${count}`, async () => {
      await manager.query({
        version: 2,
        indexName: 'articles',
        where: { kind: 'field', path: 'title', operator: 'prefix', value: 'Article 1' },
      });
    }, iterCount);

    // Compound query (two filters)
    await runner.run(`compound-query-${count}`, async () => {
      await manager.query({
        version: 2,
        indexName: 'articles',
        where: {
          kind: 'and',
          expressions: [
            { kind: 'field', path: 'author', operator: 'eq', value: 'Alice' },
            { kind: 'field', path: 'category', operator: 'eq', value: 'Technology' },
          ],
        },
      });
    }, iterCount);

    // Sorted query with limit
    await runner.run(`sorted-limit-query-${count}`, async () => {
      await manager.query({
        version: 2,
        indexName: 'articles',
        orderBy: [{ path: 'createdOn', direction: 'asc' }],
        first: 20,
        allowScan: true,
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
