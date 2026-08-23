import { describe, expect, test, jest, afterEach } from '@jest/globals';
import React, { useState } from 'react';
import { render, act, cleanup, waitFor } from '@testing-library/react';
import { getPeerborneHookCaches } from './hooks-cache.js';
import {
  resetCaches,
  createMockDocument,
  createMockPeerborne,
  createMockPeerborneMultiDoc,
  TestProvider,
  TestConsumer,
} from './test-utils.js';

// ---------------------------------------------------------------------------
// Tests: Subscription callback behavior
// ---------------------------------------------------------------------------

describe('Subscription callback updates state', () => {
  afterEach(() => {
    cleanup();
    resetCaches();
  });

  test('subscription callback updates document data in context', async () => {
    const mockDoc = createMockDocument({ initial: true });
    const mockSwarm = createMockPeerborne(mockDoc);
    const captureRef = { current: null as any };

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/sub-callback',
            captureRef,
          }),
        ),
      );
    });

    await waitFor(() => {
      expect(mockDoc.subscribe).toHaveBeenCalled();
    });

    // Simulate a document change by calling the subscription handler.
    const subscribeCall = mockDoc.subscribe.mock.calls[0];
    const handler = subscribeCall[1] as Function;

    await act(async () => {
      handler({ updated: true }, ['reader1', 'reader2'], ['writer1', 'writer2']);
    });

    await waitFor(() => {
      expect(captureRef.current.docData).toEqual({ updated: true });
    });

    expect(captureRef.current.acl.readers).toEqual(['reader1', 'reader2']);
    expect(captureRef.current.acl.writers).toEqual(['writer1', 'writer2']);
  });

  test('subscription callback updates readers and writers independently', async () => {
    const mockDoc = createMockDocument({ text: 'hello' });
    const mockSwarm = createMockPeerborne(mockDoc);
    const captureRef = { current: null as any };

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/rw-update',
            captureRef,
          }),
        ),
      );
    });

    await waitFor(() => {
      expect(mockDoc.subscribe).toHaveBeenCalled();
    });

    const handler = mockDoc.subscribe.mock.calls[0][1] as Function;

    // First update: only change readers.
    await act(async () => {
      handler({ text: 'hello' }, ['newReader'], ['writer1']);
    });

    await waitFor(() => {
      expect(captureRef.current.acl.readers).toEqual(['newReader']);
    });

    // Second update: change writers.
    await act(async () => {
      handler({ text: 'hello' }, ['newReader'], ['newWriter']);
    });

    await waitFor(() => {
      expect(captureRef.current.acl.writers).toEqual(['newWriter']);
    });
  });
});

// ---------------------------------------------------------------------------
// Tests: ACL helper functions
// ---------------------------------------------------------------------------

describe('ACL helper functions delegate to docRef', () => {
  afterEach(() => {
    cleanup();
    resetCaches();
  });

  test('addReader calls docRef.addReader with the given key', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);
    const captureRef = { current: null as any };

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/acl-add-reader',
            captureRef,
          }),
        ),
      );
    });

    // Wait for the full open→subscribe→getReaders→getWriters→setDocDataCache
    // cycle to complete so docRef is in docCache and ACL helpers have a live ref.
    await waitFor(() => {
      expect(captureRef.current.docData).toBeDefined();
    });

    await act(async () => {
      await captureRef.current.acl.addReader('newUserPubKey');
    });

    expect(mockDoc.addReader).toHaveBeenCalledWith('newUserPubKey');
  });

  test('removeReader calls docRef.removeReader with the given key', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);
    const captureRef = { current: null as any };

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/acl-rm-reader',
            captureRef,
          }),
        ),
      );
    });

    await waitFor(() => {
      expect(captureRef.current.docData).toBeDefined();
    });

    await act(async () => {
      await captureRef.current.acl.removeReader('oldUserPubKey');
    });

    expect(mockDoc.removeReader).toHaveBeenCalledWith('oldUserPubKey');
  });

  test('addWriter calls docRef.addWriter with the given key', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);
    const captureRef = { current: null as any };

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/acl-add-writer',
            captureRef,
          }),
        ),
      );
    });

    await waitFor(() => {
      expect(captureRef.current.docData).toBeDefined();
    });

    await act(async () => {
      await captureRef.current.acl.addWriter('writerPubKey');
    });

    expect(mockDoc.addWriter).toHaveBeenCalledWith('writerPubKey');
  });

  test('removeWriter calls docRef.removeWriter with the given key', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);
    const captureRef = { current: null as any };

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/acl-rm-writer',
            captureRef,
          }),
        ),
      );
    });

    await waitFor(() => {
      expect(captureRef.current.docData).toBeDefined();
    });

    await act(async () => {
      await captureRef.current.acl.removeWriter('oldWriterPubKey');
    });

    expect(mockDoc.removeWriter).toHaveBeenCalledWith('oldWriterPubKey');
  });
});

// ---------------------------------------------------------------------------
// Tests: Change function edge cases
// ---------------------------------------------------------------------------

describe('Change function edge cases', () => {
  afterEach(() => {
    cleanup();
    resetCaches();
  });

  test('change function does not throw when called without a message', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);
    const captureRef = { current: null as any };

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/change-no-msg',
            captureRef,
          }),
        ),
      );
    });

    // Wait for the full open→subscribe→setDocDataCache cycle so changeFn
    // has a live docRef reference in the context.
    await waitFor(() => {
      expect(captureRef.current.docData).toBeDefined();
    });

    const changeFnArg = jest.fn();
    expect(() => captureRef.current.changeFn(changeFnArg)).not.toThrow();
    expect(mockDoc.change).toHaveBeenCalledWith(changeFnArg, undefined);
  });

  test('change function is a no-op when docRef is not yet in cache', () => {
    // Render without provider setting up docCache - use default context.
    const captureRef = { current: null as any };
    const mockSwarm = { doc: jest.fn() } as any;

    // Suppress async warnings from the hook's effect attempting to open a
    // document with an undefined doc reference.
    const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

    try {
      // Use the default context (no provider) so docCache is empty.
      render(
        React.createElement(TestConsumer, {
          peerborne: mockSwarm,
          documentPath: '/not-loaded',
          captureRef,
        }),
      );

      // changeFn should be defined but should not throw.
      expect(typeof captureRef.current.changeFn).toBe('function');
      expect(() => captureRef.current.changeFn(() => {})).not.toThrow();
    } finally {
      consoleSpy.mockRestore();
    }
  });
});

// ---------------------------------------------------------------------------
// Tests: Multiple different document paths
// ---------------------------------------------------------------------------

describe('Multiple different document paths', () => {
  afterEach(() => {
    cleanup();
    resetCaches();
  });

  test('opening two different documents creates separate entries in caches', async () => {
    const mockDocA = createMockDocument({ doc: 'A' });
    const mockDocB = createMockDocument({ doc: 'B' });
    const mockSwarm = createMockPeerborneMultiDoc({
      '/doc-a': mockDocA,
      '/doc-b': mockDocB,
    });
    const { openTaskResults, subscriberCounts } = getPeerborneHookCaches(mockSwarm);

    const captureA = { current: null as any };
    const captureB = { current: null as any };

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/doc-a',
            captureRef: captureA,
          }),
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/doc-b',
            captureRef: captureB,
          }),
        ),
      );
    });

    await waitFor(() => {
      expect(mockDocA.open).toHaveBeenCalled();
      expect(mockDocB.open).toHaveBeenCalled();
    });

    // Both documents should have their own cache entries.
    // Use waitFor since caches are populated after additional async steps
    // (getReaders/getWriters) following open().
    await waitFor(() => {
      expect(openTaskResults.has('/doc-a')).toBe(true);
      expect(openTaskResults.has('/doc-b')).toBe(true);
      expect(subscriberCounts.get('/doc-a')).toBe(1);
      expect(subscriberCounts.get('/doc-b')).toBe(1);
    });
  });

  test('unmounting one document does not affect the other', async () => {
    const mockDocA = createMockDocument({ doc: 'A' });
    const mockDocB = createMockDocument({ doc: 'B' });
    const mockSwarm = createMockPeerborneMultiDoc({
      '/doc-x': mockDocA,
      '/doc-y': mockDocB,
    });
    const { openTaskResults, subscriberCounts } = getPeerborneHookCaches(mockSwarm);

    let setShowA: (show: boolean) => void;

    function Parent() {
      const [showA, _setShowA] = useState(true);
      setShowA = _setShowA;
      return React.createElement(
        TestProvider,
        null,
        showA
          ? React.createElement(TestConsumer, { peerborne: mockSwarm, documentPath: '/doc-x' })
          : null,
        React.createElement(TestConsumer, { peerborne: mockSwarm, documentPath: '/doc-y' }),
      );
    }

    await act(async () => {
      render(React.createElement(Parent));
    });

    await waitFor(() => {
      expect(mockDocA.open).toHaveBeenCalled();
      expect(mockDocB.open).toHaveBeenCalled();
    });

    // Unmount document A.
    await act(async () => {
      setShowA!(false);
    });

    // Document B should still have cache entries.
    await waitFor(() => {
      expect(openTaskResults.has('/doc-y')).toBe(true);
    });

    // Document A caches should be cleaned up.
    await waitFor(() => {
      expect(subscriberCounts.has('/doc-x')).toBe(false);
      expect(openTaskResults.has('/doc-x')).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// Tests: Error handling
// ---------------------------------------------------------------------------

describe('Error handling', () => {
  afterEach(() => {
    cleanup();
    resetCaches();
  });

  test('peerborne.doc returning null does not throw', async () => {
    const mockSwarm = { doc: jest.fn(() => null) } as any;

    const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

    try {
      await act(async () => {
        render(
          React.createElement(TestProvider, null,
            React.createElement(TestConsumer, { peerborne: mockSwarm, documentPath: '/null-doc' }),
          ),
        );
      });

      // Wait for the async effect to warn about the null document.
      await waitFor(() => {
        expect(consoleSpy).toHaveBeenCalledWith(
          expect.stringContaining('Failed to open/find document'),
        );
      });
    } finally {
      consoleSpy.mockRestore();
    }
  });

  test('a rejected open is handled, evicted on unmount, and retried on remount', async () => {
    const mockDoc = createMockDocument();
    mockDoc.open.mockRejectedValueOnce(new Error('sensitive failure details'));
    const mockSwarm = createMockPeerborne(mockDoc);
    const caches = getPeerborneHookCaches(mockSwarm);
    const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

    try {
      let unmount: () => void;
      await act(async () => {
        const result = render(
          React.createElement(
            TestProvider,
            null,
            React.createElement(TestConsumer, {
              peerborne: mockSwarm,
              documentPath: '/open-retry',
            }),
          ),
        );
        unmount = result.unmount;
      });

      await waitFor(() => {
        expect(consoleSpy).toHaveBeenCalledWith(
          'Failed to open/find document: /open-retry',
        );
      });
      expect(caches.openTasks.has('/open-retry')).toBe(true);
      expect(caches.openTaskResults.has('/open-retry')).toBe(false);

      act(() => {
        unmount!();
      });
      await waitFor(() => {
        expect(caches.openTasks.has('/open-retry')).toBe(false);
        expect(caches.subscriberCounts.has('/open-retry')).toBe(false);
      });

      await act(async () => {
        render(
          React.createElement(
            TestProvider,
            null,
            React.createElement(TestConsumer, {
              peerborne: mockSwarm,
              documentPath: '/open-retry',
            }),
          ),
        );
      });

      await waitFor(() => {
        expect(mockDoc.subscribe).toHaveBeenCalled();
      });
      expect(mockDoc.open).toHaveBeenCalledTimes(2);
    } finally {
      consoleSpy.mockRestore();
    }
  });
});

// ---------------------------------------------------------------------------
// Tests: originFilter variants
// ---------------------------------------------------------------------------

describe('originFilter variants', () => {
  afterEach(() => {
    cleanup();
    resetCaches();
  });

  test('defaults to "all" when originFilter is not specified', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/filter-default',
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
      'all',
    );
  });

  test('passes "remote" originFilter to subscribe', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/filter-remote',
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

  test('passes "local" originFilter to subscribe', async () => {
    const mockDoc = createMockDocument();
    const mockSwarm = createMockPeerborne(mockDoc);

    await act(async () => {
      render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/filter-local',
            originFilter: 'local',
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
      'local',
    );
  });
});

// ---------------------------------------------------------------------------
// Tests: Late joiner (second subscriber awaits existing open task)
// ---------------------------------------------------------------------------

describe('Late joiner subscribes via existing open task', () => {
  afterEach(() => {
    cleanup();
    resetCaches();
  });

  test('second subscriber joins after first has opened the document', async () => {
    const mockDoc = createMockDocument({ shared: true });
    const mockSwarm = createMockPeerborne(mockDoc);
    const captureA = { current: null as any };
    const captureB = { current: null as any };

    let setShowSecond: (show: boolean) => void;

    function Parent() {
      const [showSecond, _setShowSecond] = useState(false);
      setShowSecond = _setShowSecond;
      return React.createElement(
        TestProvider,
        null,
        React.createElement(TestConsumer, {
          peerborne: mockSwarm,
          documentPath: '/late-join',
          captureRef: captureA,
        }),
        showSecond
          ? React.createElement(TestConsumer, {
              peerborne: mockSwarm,
              documentPath: '/late-join',
              captureRef: captureB,
            })
          : null,
      );
    }

    // Mount first subscriber.
    await act(async () => {
      render(React.createElement(Parent));
    });

    await waitFor(() => {
      expect(mockDoc.open).toHaveBeenCalled();
    });

    // Now add the second subscriber after document is already open.
    await act(async () => {
      setShowSecond!(true);
    });

    // Second subscriber should also subscribe.
    await waitFor(() => {
      expect(mockDoc.subscribe.mock.calls.length).toBeGreaterThanOrEqual(2);
    });

    // The document should only have been opened once.
    expect(mockDoc.open).toHaveBeenCalledTimes(1);
  });

  test('late joiners use the latest document and ACL state', async () => {
    const mockDoc = createMockDocument({ version: 'initial' });
    const mockSwarm = createMockPeerborne(mockDoc);
    const captureA = { current: null as any };
    const captureB = { current: null as any };
    let setShowSecond: (show: boolean) => void;

    function Parent() {
      const [showSecond, updateShowSecond] = useState(false);
      setShowSecond = updateShowSecond;
      return React.createElement(
        TestProvider,
        null,
        React.createElement(TestConsumer, {
          peerborne: mockSwarm,
          documentPath: '/late-current-state',
          captureRef: captureA,
        }),
        showSecond
          ? React.createElement(TestConsumer, {
              peerborne: mockSwarm,
              documentPath: '/late-current-state',
              captureRef: captureB,
            })
          : null,
      );
    }

    await act(async () => {
      render(React.createElement(Parent));
    });
    await waitFor(() => {
      expect(mockDoc.subscribe).toHaveBeenCalledTimes(1);
    });

    const handler = mockDoc.subscribe.mock.calls[0][1] as Function;
    await act(async () => {
      handler(
        { version: 'updated' },
        ['updated-reader'],
        ['updated-writer'],
      );
    });
    await waitFor(() => {
      expect(captureA.current.docData).toEqual({ version: 'updated' });
      expect(captureA.current.acl.readers).toEqual(['updated-reader']);
    });

    await act(async () => {
      setShowSecond!(true);
    });

    await waitFor(() => {
      expect(captureB.current.docData).toEqual({ version: 'updated' });
      expect(captureB.current.acl.readers).toEqual(['updated-reader']);
      expect(captureB.current.acl.writers).toEqual(['updated-writer']);
    });
    expect(captureA.current.acl.readers).toEqual(['updated-reader']);
    expect(mockDoc.open).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// Tests: Document data rendering
// ---------------------------------------------------------------------------

describe('Document data rendering', () => {
  afterEach(() => {
    cleanup();
    resetCaches();
  });

  test('renders initial document data after open completes', async () => {
    const mockDoc = createMockDocument({ title: 'My Doc' });
    const mockSwarm = createMockPeerborne(mockDoc);

    let container: HTMLElement;
    await act(async () => {
      const result = render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/render-doc',
          }),
        ),
      );
      container = result.container;
    });

    await waitFor(() => {
      expect(mockDoc.open).toHaveBeenCalled();
    });

    // After caches are populated, the component should render the document data.
    await waitFor(() => {
      const text = container!.textContent || '';
      expect(text).toContain('My Doc');
    });
  });

  test('renders updated data after subscription callback fires', async () => {
    const mockDoc = createMockDocument({ version: 1 });
    const mockSwarm = createMockPeerborne(mockDoc);

    let container: HTMLElement;
    await act(async () => {
      const result = render(
        React.createElement(TestProvider, null,
          React.createElement(TestConsumer, {
            peerborne: mockSwarm,
            documentPath: '/render-update',
          }),
        ),
      );
      container = result.container;
    });

    await waitFor(() => {
      expect(mockDoc.subscribe).toHaveBeenCalled();
    });

    // Trigger subscription callback with new data.
    const handler = mockDoc.subscribe.mock.calls[0][1] as Function;
    await act(async () => {
      handler({ version: 2 }, ['reader1'], ['writer1']);
    });

    await waitFor(() => {
      const text = container!.textContent || '';
      expect(text).toContain('"version":2');
    });
  });
});
