import { describe, expect, test, beforeEach } from '@jest/globals';
import { IndexManager } from './index-manager.js';
import { MemoryIndexStorage } from './memory-index-storage.js';
import { QueryResult } from './types.js';

// We test the hooks' backing logic by directly exercising IndexManager's
// subscribe()/defineIndex()/removeIndex() — the same primitives the hooks
// wrap. This keeps the tests focused on observable behavior without the
// overhead of standing up a React renderer and jsdom.

/**
 * Subscribe to the manager and return a `waitForResults(count)` helper that
 * resolves once at least `count` callbacks have fired (or rejects on
 * timeout). This avoids the flakiness of fixed-duration `setTimeout` waits:
 * we proceed as soon as the callback is observed, and we still bail out
 * instead of hanging forever if it never fires.
 *
 * The returned `unsubscribe` both detaches from the manager and rejects any
 * outstanding `waitForResults` promises, clearing their timers — so callers
 * who unsubscribe early do not leave Jest open-handle warnings behind.
 */
function subscribeAndWait<T extends Record<string, unknown>>(
  manager: IndexManager<T>,
  options: Parameters<IndexManager<T>['subscribe']>[0],
  timeoutMs = 1000,
): {
  results: QueryResult<Record<string, unknown>>[];
  unsubscribe: () => void;
  waitForResults: (count: number, timeout?: number) => Promise<void>;
} {
  const results: QueryResult<Record<string, unknown>>[] = [];
  const waiters: Array<{
    target: number;
    resolve: () => void;
    reject: (e: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];

  const innerUnsubscribe = manager.subscribe(options, (r) => {
    results.push(r);
    // Wake up any waiters whose target count has been reached.
    for (let i = waiters.length - 1; i >= 0; i--) {
      if (results.length >= waiters[i].target) {
        clearTimeout(waiters[i].timer);
        waiters[i].resolve();
        waiters.splice(i, 1);
      }
    }
  });

  const waitForResults = (count: number, timeout = timeoutMs): Promise<void> => {
    if (results.length >= count) return Promise.resolve();
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = waiters.findIndex((w) => w.timer === timer);
        if (idx >= 0) waiters.splice(idx, 1);
        reject(new Error(`subscribeAndWait: expected ${count} results within ${timeout}ms, got ${results.length}`));
      }, timeout);
      waiters.push({ target: count, resolve, reject, timer });
    });
  };

  const unsubscribe = () => {
    innerUnsubscribe();
    while (waiters.length > 0) {
      const w = waiters.pop()!;
      clearTimeout(w.timer);
      w.reject(new Error('subscribeAndWait: unsubscribed before results arrived'));
    }
  };

  return { results, unsubscribe, waitForResults };
}

describe('React hooks (module surface)', () => {
  test('useIndexQuery should be exported as a function', async () => {
    const mod = await import('./react.js');
    expect(typeof mod.useIndexQuery).toBe('function');
  });

  test('useDefineIndexes should be exported as a function', async () => {
    const mod = await import('./react.js');
    expect(typeof mod.useDefineIndexes).toBe('function');
  });
});

describe('React hook backing logic (subscribe + defineIndex)', () => {
  let storage: MemoryIndexStorage;
  let manager: IndexManager<Record<string, unknown>>;

  beforeEach(async () => {
    storage = new MemoryIndexStorage();
    manager = new IndexManager(storage, (doc) => doc);
    await manager.defineIndex({
      name: 'items',
      collectionPrefix: '/items/',
      fields: [
        { path: 'name', type: 'string' },
        { path: 'priority', type: 'number' },
      ],
    });
  });

  test('subscribe delivers initial empty result (useIndexQuery lifecycle)', async () => {
    const { results, unsubscribe, waitForResults } = subscribeAndWait(manager, {
      indexName: 'items',
      filters: [],
    });

    await waitForResults(1);

    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].totalCount).toBe(0);
    expect(results[0].documents).toEqual([]);

    unsubscribe();
  });

  test('subscribe delivers updated results after index change', async () => {
    const { results, unsubscribe, waitForResults } = subscribeAndWait(manager, {
      indexName: 'items',
      filters: [],
    });

    // Wait for the initial empty result before mutating, so we can deterministically
    // assert that we see both the pre-update and post-update states.
    await waitForResults(1);

    await manager.updateIndex('/items/1', { name: 'Task A', priority: 1 });

    // Wait for the post-update notification to land.
    await waitForResults(2);

    // Should have received at least 2 results: initial (0) and after insert (1)
    expect(results.some((r) => r.totalCount === 0)).toBe(true);
    expect(results.some((r) => r.totalCount === 1)).toBe(true);

    unsubscribe();
  });

  test('subscribe with filters only delivers matching documents', async () => {
    await manager.updateIndex('/items/1', { name: 'Low', priority: 1 });
    await manager.updateIndex('/items/2', { name: 'High', priority: 10 });

    const { results, unsubscribe, waitForResults } = subscribeAndWait(manager, {
      indexName: 'items',
      filters: [{ path: 'priority', operator: 'gte', value: 5 }],
    });

    await waitForResults(1);

    expect(results.length).toBeGreaterThanOrEqual(1);
    const latest = results[results.length - 1];
    expect(latest.totalCount).toBe(1);
    expect(latest.documents[0].snapshot.name).toBe('High');

    unsubscribe();
  });

  test('unsubscribe prevents further callbacks (useIndexQuery teardown)', async () => {
    const { results, unsubscribe, waitForResults } = subscribeAndWait(manager, {
      indexName: 'items',
      filters: [],
    });

    await waitForResults(1);
    unsubscribe();
    const countAfter = results.length;

    await manager.updateIndex('/items/1', { name: 'X', priority: 1 });

    // After unsubscribe, no further callbacks should arrive. We still have
    // to bound the wait, but the assertion is that the count *did not grow*
    // by the time updateIndex (and its async notification) has resolved.
    // updateIndex awaits the storage write; the notification fires inside
    // a microtask after that. A single resolved-promise tick is enough.
    await Promise.resolve();
    await Promise.resolve();

    expect(results.length).toBe(countAfter);
  });

  test('defineIndex + removeIndex lifecycle (useDefineIndexes mount/unmount)', async () => {
    const newDef = {
      name: 'tags',
      collectionPrefix: '/tags/',
      fields: [{ path: 'label', type: 'string' as const }],
    };

    await manager.defineIndex(newDef);
    expect(manager.getDefinitions().map((d) => d.name)).toContain('tags');

    await manager.removeIndex('tags');
    expect(manager.getDefinitions().map((d) => d.name)).not.toContain('tags');
  });

  test('subscribe with sort and pagination', async () => {
    await manager.updateIndex('/items/a', { name: 'C', priority: 3 });
    await manager.updateIndex('/items/b', { name: 'A', priority: 1 });
    await manager.updateIndex('/items/c', { name: 'B', priority: 2 });

    const { results, unsubscribe, waitForResults } = subscribeAndWait(manager, {
      indexName: 'items',
      filters: [],
      sort: [{ path: 'priority', direction: 'asc' }],
      limit: 2,
      offset: 0,
    });

    await waitForResults(1);

    const latest = results[results.length - 1];
    expect(latest.totalCount).toBe(3);
    expect(latest.documents).toHaveLength(2);
    expect(latest.documents[0].snapshot.name).toBe('A');
    expect(latest.documents[1].snapshot.name).toBe('B');

    unsubscribe();
  });
});
