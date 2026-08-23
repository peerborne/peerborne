import { describe, expect, test, jest, afterEach } from '@jest/globals';
import React, { useState } from 'react';
import { render, act, cleanup, waitFor } from '@testing-library/react';
import {
  resetCaches,
  getCacheSizes,
  createMockDocument,
  createMockPeerborne,
  TestProvider,
  TestConsumer,
} from './test-utils.js';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('usePeerborneDocumentState lifecycle', () => {
  afterEach(() => {
    cleanup();
    resetCaches();
  });

  test('subscribe is called on mount', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, { peerborne: mockSwarm, documentPath: '/test-doc' }),
        ),
      );
    });

    await waitFor(() => {
      expect(mockDoc.open).toHaveBeenCalled();
    });

    expect(mockDoc.subscribe).toHaveBeenCalledWith(
      expect.stringMatching(/^usePeerborneDocumentState-/),
      expect.any(Function),
      'all',
    );
  });

  test('unsubscribe is called on unmount', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);

    let unmount: () => void;
    await act(async () => {
      const result = render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, { peerborne: mockSwarm, documentPath: '/test-unsub' }),
        ),
      );
      unmount = result.unmount;
    });

    await waitFor(() => {
      expect(mockDoc.open).toHaveBeenCalled();
    });

    act(() => {
      unmount!();
    });

    expect(mockDoc.unsubscribe).toHaveBeenCalledWith(
      expect.stringMatching(/^usePeerborneDocumentState-/),
    );
  });

  test('opens document and fetches readers/writers', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, { peerborne: mockSwarm, documentPath: '/doc-rw' }),
        ),
      );
    });

    await waitFor(() => {
      expect(mockDoc.getWriters).toHaveBeenCalled();
    });

    expect(mockDoc.open).toHaveBeenCalled();
    expect(mockDoc.getReaders).toHaveBeenCalled();
  });

  test('passes originFilter to subscribe', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/doc-filter',
            originFilter: 'remote',
          }),
        ),
      );
    });

    await waitFor(() => {
      expect(mockDoc.subscribe).toHaveBeenCalled();
    });

    expect(mockDoc.subscribe).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(Function),
      'remote',
    );
  });
});

describe('Cache cleanup on unmount', () => {
  afterEach(() => {
    cleanup();
    resetCaches();
  });

  test('caches are populated after mount and cleared after last subscriber unmounts', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);

    let unmount: () => void;
    await act(async () => {
      const result = render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, { peerborne: mockSwarm, documentPath: '/cache-doc' }),
        ),
      );
      unmount = result.unmount;
    });

    // Wait for the full async chain: open -> getReaders -> getWriters -> cache update.
    await waitFor(() => {
      expect(mockDoc.getWriters).toHaveBeenCalled();
    });

    // After the full open chain completes, caches should be populated.
    await waitFor(() => {
      const sizesAfterMount = getCacheSizes(mockSwarm);
      expect(sizesAfterMount.openTasks).toBeGreaterThanOrEqual(1);
      expect(sizesAfterMount.openTaskResults).toBeGreaterThanOrEqual(1);
      expect(sizesAfterMount.subscriberCounts).toBeGreaterThanOrEqual(1);
    });

    act(() => {
      unmount!();
    });

    // After unmount of the last subscriber, openTaskResults and subscriberCounts
    // should be cleared. openTasks is cleared asynchronously after the promise settles.
    await waitFor(() => {
      const sizesAfterUnmount = getCacheSizes(mockSwarm);
      expect(sizesAfterUnmount.openTaskResults).toBe(0);
      expect(sizesAfterUnmount.subscriberCounts).toBe(0);
    });
  });

  test('document.close is called when last subscriber unmounts', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);

    let unmount: () => void;
    await act(async () => {
      const result = render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, { peerborne: mockSwarm, documentPath: '/close-doc' }),
        ),
      );
      unmount = result.unmount;
    });

    await waitFor(() => {
      expect(mockDoc.open).toHaveBeenCalled();
    });

    act(() => {
      unmount!();
    });

    // The cleanup code calls docRef.close() asynchronously after the openTask promise settles.
    await waitFor(() => {
      expect(mockDoc.close).toHaveBeenCalled();
    });
  });
});

describe('Multiple subscribers to the same document', () => {
  afterEach(() => {
    cleanup();
    resetCaches();
  });

  test('ref-counting: caches persist when one of two subscribers unmounts', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);

    // We render two consumers for the same document path inside a single provider.
    // We need a way to unmount them individually, so we use a parent component with
    // conditional rendering.
    let setShowSecond: (show: boolean) => void;

    function Parent() {
      const [showSecond, _setShowSecond] = useState(true);
      setShowSecond = _setShowSecond;
      return React.createElement(
        TestProvider,
        null,
        React.createElement(TestConsumer, { peerborne: mockSwarm, documentPath: '/shared-doc' }),
        showSecond
          ? React.createElement(TestConsumer, { peerborne: mockSwarm, documentPath: '/shared-doc' })
          : null,
      );
    }

    await act(async () => {
      render(React.createElement(Parent));
    });

    await waitFor(() => {
      // Both consumers should have subscribed (the first opens, the second joins).
      expect(mockDoc.subscribe).toHaveBeenCalled();
    });

    // Two subscribers should be tracked.
    const sizesWithBoth = getCacheSizes(mockSwarm);
    expect(sizesWithBoth.subscriberCounts).toBeGreaterThanOrEqual(1);

    // Unmount one subscriber by hiding the second consumer.
    await act(async () => {
      setShowSecond!(false);
    });

    // Caches should still be populated because one subscriber remains.
    const sizesAfterPartialUnmount = getCacheSizes(mockSwarm);
    expect(sizesAfterPartialUnmount.openTaskResults).toBeGreaterThanOrEqual(1);
    // subscriberCounts entry should still exist (decremented but not zero).
    expect(sizesAfterPartialUnmount.subscriberCounts).toBeGreaterThanOrEqual(1);
  });

  test('each subscriber gets its own subscription ID with expected prefix', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);

    await act(async () => {
      render(
        React.createElement(
          TestProvider,
          null,
          React.createElement(TestConsumer, { peerborne: mockSwarm, documentPath: '/multi-id' }),
          React.createElement(TestConsumer, { peerborne: mockSwarm, documentPath: '/multi-id' }),
        ),
      );
    });

    await waitFor(() => {
      // At least 2 subscribe calls should have been made.
      expect(mockDoc.subscribe.mock.calls.length).toBeGreaterThanOrEqual(2);
    });

    // Verify each subscription ID has the expected prefix format.
    const ids = mockDoc.subscribe.mock.calls.map((call: any[]) => call[0]);
    for (const id of ids) {
      expect(id).toMatch(/^usePeerborneDocumentState-/);
    }
  });

  test('unsubscribe is called for each subscriber on full unmount', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);

    let unmount: () => void;
    await act(async () => {
      const result = render(
        React.createElement(
          TestProvider,
          null,
          React.createElement(TestConsumer, { peerborne: mockSwarm, documentPath: '/full-unmount' }),
          React.createElement(TestConsumer, { peerborne: mockSwarm, documentPath: '/full-unmount' }),
        ),
      );
      unmount = result.unmount;
    });

    await waitFor(() => {
      expect(mockDoc.subscribe).toHaveBeenCalled();
    });

    const subscribeCount = mockDoc.subscribe.mock.calls.length;

    act(() => {
      unmount!();
    });

    // Each subscriber that subscribed should also unsubscribe.
    expect(mockDoc.unsubscribe.mock.calls.length).toBe(subscribeCount);
  });
});

describe('usePeerborneDocumentState return value', () => {
  afterEach(() => {
    cleanup();
    resetCaches();
  });

  test('returns a change function that delegates to docRef.change', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);
    const captureRef = { current: null as any };

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/change-doc',
            captureRef,
          }),
        ),
      );
    });

    await waitFor(() => {
      expect(mockDoc.open).toHaveBeenCalled();
    });

    // The change function should be callable and delegate to docRef.change.
    expect(typeof captureRef.current.changeFn).toBe('function');

    const mockChangeFn = jest.fn();
    captureRef.current.changeFn(mockChangeFn, 'test message');
    expect(mockDoc.change).toHaveBeenCalledWith(mockChangeFn, 'test message');
  });

  test('returns ACL helpers (readers, writers, addReader, etc.)', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);
    const captureRef = { current: null as any };

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/acl-doc',
            captureRef,
          }),
        ),
      );
    });

    await waitFor(() => {
      expect(mockDoc.open).toHaveBeenCalled();
    });

    const acl = captureRef.current.acl;
    expect(acl).toBeDefined();
    expect(typeof acl.addReader).toBe('function');
    expect(typeof acl.removeReader).toBe('function');
    expect(typeof acl.addWriter).toBe('function');
    expect(typeof acl.removeWriter).toBe('function');
  });
});
