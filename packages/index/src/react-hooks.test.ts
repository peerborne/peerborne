/**
 * @jest-environment jsdom
 */
import { afterEach, describe, expect, test } from '@jest/globals';
import { act, cleanup, renderHook } from '@testing-library/react';
import { IndexManager } from './index-manager.js';
import { useIndexQuery } from './react.js';
import { QueryAst, QueryAstResult } from './types.js';

type Listener = (result: QueryAstResult<Record<string, unknown>> | undefined) => void;

function fakeManager() {
  const subscriptions: Array<{ options: QueryAst; listener: Listener; active: boolean }> = [];
  const manager = {
    subscribe(options: QueryAst, listener: Listener) {
      const subscription = { options, listener, active: true };
      subscriptions.push(subscription);
      return () => {
        subscription.active = false;
      };
    },
  } as unknown as IndexManager<unknown>;
  return { manager, subscriptions };
}

function resultWithCount(value: number): QueryAstResult<Record<string, unknown>> {
  return {
    documents: [],
    count: { kind: 'verified', value },
    pageInfo: { hasMore: false },
    coverage: { level: 'local-tracked', partial: false, reasons: [] },
  } as unknown as QueryAstResult<Record<string, unknown>>;
}

const allItems: QueryAst = { version: 2, count: 'exact', allowScan: true, indexName: 'items' };

describe('useIndexQuery', () => {
  afterEach(() => {
    cleanup();
  });

  test('returns undefined until the subscription emits and then the result', () => {
    const { manager, subscriptions } = fakeManager();
    const { result } = renderHook(() => useIndexQuery(manager, allItems));

    expect(result.current).toBeUndefined();
    expect(subscriptions).toHaveLength(1);

    const emitted = resultWithCount(2);
    act(() => subscriptions[0].listener(emitted));

    expect(result.current).toBe(emitted);
  });

  test('returns undefined again when the target index is removed', () => {
    const { manager, subscriptions } = fakeManager();
    const { result } = renderHook(() => useIndexQuery(manager, allItems));
    act(() => subscriptions[0].listener(resultWithCount(2)));

    act(() => subscriptions[0].listener(undefined));

    expect(result.current).toBeUndefined();
  });

  test('drops the previous result and resubscribes when the query changes', () => {
    const { manager, subscriptions } = fakeManager();
    const { result, rerender } = renderHook(
      ({ options }) => useIndexQuery(manager, options),
      { initialProps: { options: allItems } },
    );
    act(() => subscriptions[0].listener(resultWithCount(2)));

    const filtered: QueryAst = {
      ...allItems,
      where: { kind: 'field', path: 'priority', operator: 'gte', value: 5 },
    };
    rerender({ options: filtered });

    expect(result.current).toBeUndefined();
    expect(subscriptions).toHaveLength(2);
    expect(subscriptions[0].active).toBe(false);
    expect(subscriptions[1].options).toEqual(filtered);

    const emitted = resultWithCount(1);
    act(() => subscriptions[1].listener(emitted));
    expect(result.current).toBe(emitted);
  });

  test('keeps the subscription when rerendered with an equal query', () => {
    const { manager, subscriptions } = fakeManager();
    const { result, rerender } = renderHook(
      ({ options }) => useIndexQuery(manager, options),
      { initialProps: { options: allItems } },
    );
    const emitted = resultWithCount(2);
    act(() => subscriptions[0].listener(emitted));

    rerender({ options: { ...allItems } });

    expect(subscriptions).toHaveLength(1);
    expect(result.current).toBe(emitted);
  });

  test('unsubscribes on unmount', () => {
    const { manager, subscriptions } = fakeManager();
    const { unmount } = renderHook(() => useIndexQuery(manager, allItems));

    unmount();

    expect(subscriptions[0].active).toBe(false);
  });
});
