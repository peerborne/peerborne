import { describe, expect, test, beforeEach, afterEach } from '@jest/globals';
import {
  getPeerborneHookCaches,
  resetPeerborneHookCaches,
} from './hooks-cache.js';

beforeEach(() => {
  resetPeerborneHookCaches();
});

afterEach(() => {
  resetPeerborneHookCaches();
});

describe('per-Peerborne hook caches', () => {
  test('a new Peerborne instance starts with empty caches', () => {
    const { openTasks, openTaskResults, subscriberCounts } =
      getPeerborneHookCaches({});

    expect(openTasks.size).toBe(0);
    expect(openTaskResults.size).toBe(0);
    expect(subscriberCounts.size).toBe(0);
  });

  test('openTasks stores and retrieves promises by document path', async () => {
    const { openTasks } = getPeerborneHookCaches({});
    const mockResult = { docRef: { document: 'test' } as any, readers: ['r1'], writers: ['w1'] };
    const promise = Promise.resolve(mockResult);
    openTasks.set('/doc/a', promise);

    expect(openTasks.has('/doc/a')).toBe(true);
    expect(openTasks.has('/doc/b')).toBe(false);

    const retrieved = await openTasks.get('/doc/a');
    expect(retrieved).toBe(mockResult);
  });

  test('openTaskResults stores and retrieves results by document path', () => {
    const { openTaskResults } = getPeerborneHookCaches({});
    const result = { docRef: { document: 'hello' } as any, readers: ['r'], writers: ['w'] };
    openTaskResults.set('/my-doc', result);

    expect(openTaskResults.get('/my-doc')).toBe(result);
    expect(openTaskResults.size).toBe(1);
  });

  test('subscriberCounts increments and decrements correctly', () => {
    const { subscriberCounts } = getPeerborneHookCaches({});
    subscriberCounts.set('/doc', 1);
    expect(subscriberCounts.get('/doc')).toBe(1);

    subscriberCounts.set('/doc', (subscriberCounts.get('/doc') || 0) + 1);
    expect(subscriberCounts.get('/doc')).toBe(2);

    const count = (subscriberCounts.get('/doc') || 1) - 1;
    subscriberCounts.set('/doc', count);
    expect(subscriberCounts.get('/doc')).toBe(1);
  });

  test('multiple document paths are independent within one Peerborne instance', () => {
    const { openTaskResults, subscriberCounts } = getPeerborneHookCaches({});
    subscriberCounts.set('/doc/a', 3);
    subscriberCounts.set('/doc/b', 1);
    openTaskResults.set('/doc/a', { docRef: {} as any });
    openTaskResults.set('/doc/b', { docRef: {} as any });

    subscriberCounts.delete('/doc/b');
    openTaskResults.delete('/doc/b');

    expect(subscriberCounts.has('/doc/a')).toBe(true);
    expect(subscriberCounts.has('/doc/b')).toBe(false);
    expect(openTaskResults.has('/doc/a')).toBe(true);
    expect(openTaskResults.has('/doc/b')).toBe(false);
  });

  test('the same document path is independent across Peerborne instances', () => {
    const first = getPeerborneHookCaches({});
    const second = getPeerborneHookCaches({});
    const firstResult = { docRef: { document: 'first' } as any };
    const secondResult = { docRef: { document: 'second' } as any };

    first.openTaskResults.set('/shared', firstResult);
    first.subscriberCounts.set('/shared', 1);
    second.openTaskResults.set('/shared', secondResult);
    second.subscriberCounts.set('/shared', 2);

    expect(first.openTaskResults.get('/shared')).toBe(firstResult);
    expect(first.subscriberCounts.get('/shared')).toBe(1);
    expect(second.openTaskResults.get('/shared')).toBe(secondResult);
    expect(second.subscriberCounts.get('/shared')).toBe(2);
  });

  test('reset replaces all per-instance caches', () => {
    const peerborne = {};
    const caches = getPeerborneHookCaches(peerborne);
    caches.openTasks.set('/a', Promise.resolve({}));
    caches.openTaskResults.set('/a', { docRef: {} as any });
    caches.subscriberCounts.set('/a', 2);

    resetPeerborneHookCaches();

    const resetCaches = getPeerborneHookCaches(peerborne);
    expect(resetCaches.openTasks.size).toBe(0);
    expect(resetCaches.openTaskResults.size).toBe(0);
    expect(resetCaches.subscriberCounts.size).toBe(0);
  });
});
