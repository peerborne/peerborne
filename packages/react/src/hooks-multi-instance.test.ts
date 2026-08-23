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

describe('multiple Peerborne instances at the same document path', () => {
  afterEach(() => {
    cleanup();
    resetCaches();
  });

  test('keeps document state, callbacks, and actions isolated in one context provider', async () => {
    const firstDoc = createMockDocument({ identity: 'first' });
    const secondDoc = createMockDocument({ identity: 'second' });
    firstDoc.getReaders.mockResolvedValue(['first-reader']);
    firstDoc.getWriters.mockResolvedValue(['first-writer']);
    secondDoc.getReaders.mockResolvedValue(['second-reader']);
    secondDoc.getWriters.mockResolvedValue(['second-writer']);
    const firstPeerborne = createMockPeerborne(firstDoc);
    const secondPeerborne = createMockPeerborne(secondDoc);
    const firstCapture = { current: null as any };
    const secondCapture = { current: null as any };

    await act(async () => {
      render(
        React.createElement(
          TestProvider,
          null,
          React.createElement(TestConsumer, {
            peerborne: firstPeerborne,
            documentPath: '/shared-path',
            captureRef: firstCapture,
          }),
          React.createElement(TestConsumer, {
            peerborne: secondPeerborne,
            documentPath: '/shared-path',
            captureRef: secondCapture,
          }),
        ),
      );
    });

    await waitFor(() => {
      expect(firstCapture.current.docData).toEqual({ identity: 'first' });
      expect(secondCapture.current.docData).toEqual({ identity: 'second' });
    });

    expect(firstPeerborne.doc).toHaveBeenCalledWith('/shared-path');
    expect(secondPeerborne.doc).toHaveBeenCalledWith('/shared-path');
    expect(firstCapture.current.acl.readers).toEqual(['first-reader']);
    expect(secondCapture.current.acl.readers).toEqual(['second-reader']);

    const firstHandler = firstDoc.subscribe.mock.calls[0][1] as Function;
    await act(async () => {
      firstHandler(
        { identity: 'first-updated' },
        ['first-reader-updated'],
        ['first-writer-updated'],
      );
    });

    await waitFor(() => {
      expect(firstCapture.current.docData).toEqual({ identity: 'first-updated' });
      expect(firstCapture.current.acl.readers).toEqual(['first-reader-updated']);
    });
    expect(secondCapture.current.docData).toEqual({ identity: 'second' });
    expect(secondCapture.current.acl.readers).toEqual(['second-reader']);

    const firstChange = jest.fn();
    const secondChange = jest.fn();
    firstCapture.current.changeFn(firstChange, 'first change');
    secondCapture.current.changeFn(secondChange, 'second change');
    await firstCapture.current.acl.addReader('first-new-reader');
    await secondCapture.current.acl.addWriter('second-new-writer');

    expect(firstDoc.change).toHaveBeenCalledWith(firstChange, 'first change');
    expect(firstDoc.change).not.toHaveBeenCalledWith(secondChange, 'second change');
    expect(secondDoc.change).toHaveBeenCalledWith(secondChange, 'second change');
    expect(secondDoc.change).not.toHaveBeenCalledWith(firstChange, 'first change');
    expect(firstDoc.addReader).toHaveBeenCalledWith('first-new-reader');
    expect(secondDoc.addWriter).toHaveBeenCalledWith('second-new-writer');
  });

  test('unmounting one instance cleans up only its document and cache entries', async () => {
    const firstDoc = createMockDocument({ identity: 'first' });
    const secondDoc = createMockDocument({ identity: 'second' });
    const firstPeerborne = createMockPeerborne(firstDoc);
    const secondPeerborne = createMockPeerborne(secondDoc);
    const secondCapture = { current: null as any };
    let setShowFirst: (show: boolean) => void;

    function Parent() {
      const [showFirst, updateShowFirst] = useState(true);
      setShowFirst = updateShowFirst;
      return React.createElement(
        TestProvider,
        null,
        showFirst
          ? React.createElement(TestConsumer, {
              peerborne: firstPeerborne,
              documentPath: '/shared-lifecycle',
            })
          : null,
        React.createElement(TestConsumer, {
          peerborne: secondPeerborne,
          documentPath: '/shared-lifecycle',
          captureRef: secondCapture,
        }),
      );
    }

    let unmount: () => void;
    await act(async () => {
      const result = render(React.createElement(Parent));
      unmount = result.unmount;
    });

    await waitFor(() => {
      expect(firstDoc.subscribe).toHaveBeenCalled();
      expect(secondCapture.current.docData).toEqual({ identity: 'second' });
    });

    await act(async () => {
      setShowFirst!(false);
    });

    await waitFor(() => {
      expect(firstDoc.unsubscribe).toHaveBeenCalled();
      expect(firstDoc.close).toHaveBeenCalledTimes(1);
      expect(getCacheSizes(firstPeerborne).openTaskResults).toBe(0);
    });
    expect(secondDoc.unsubscribe).not.toHaveBeenCalled();
    expect(secondDoc.close).not.toHaveBeenCalled();
    expect(getCacheSizes(secondPeerborne).openTaskResults).toBe(1);
    expect(getCacheSizes(secondPeerborne).subscriberCounts).toBe(1);

    const secondHandler = secondDoc.subscribe.mock.calls[0][1] as Function;
    await act(async () => {
      secondHandler(
        { identity: 'second-updated' },
        ['second-reader-updated'],
        ['second-writer-updated'],
      );
    });

    await waitFor(() => {
      expect(secondCapture.current.docData).toEqual({ identity: 'second-updated' });
      expect(secondCapture.current.acl.writers).toEqual(['second-writer-updated']);
    });

    const secondChange = jest.fn();
    secondCapture.current.changeFn(secondChange, 'still active');
    expect(secondDoc.change).toHaveBeenCalledWith(secondChange, 'still active');

    act(() => {
      unmount!();
    });
    await waitFor(() => {
      expect(secondDoc.close).toHaveBeenCalledTimes(1);
    });
  });

  test('rerenders when a provider mutates document state in place', async () => {
    const documentState = { version: 1 };
    const readers = ['reader'];
    const writers = ['writer'];
    const mockDoc = createMockDocument(documentState);
    mockDoc.getReaders.mockResolvedValue(readers);
    mockDoc.getWriters.mockResolvedValue(writers);
    const mockPeerborne = createMockPeerborne(mockDoc);
    let container: HTMLElement;

    await act(async () => {
      const result = render(
        React.createElement(
          TestProvider,
          null,
          React.createElement(TestConsumer, {
            peerborne: mockPeerborne,
            documentPath: '/mutable-state',
          }),
        ),
      );
      container = result.container;
    });

    await waitFor(() => {
      expect(container!.textContent).toContain('"version":1');
      expect(mockDoc.subscribe).toHaveBeenCalled();
    });

    documentState.version = 2;
    expect(container!.textContent).toContain('"version":1');

    const handler = mockDoc.subscribe.mock.calls[0][1] as Function;
    await act(async () => {
      handler(documentState, readers, writers);
    });

    await waitFor(() => {
      expect(container!.textContent).toContain('"version":2');
    });
  });
});
