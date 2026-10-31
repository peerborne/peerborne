import { createElement, StrictMode } from 'react';
import { act, render, screen, waitFor } from '@testing-library/react';
import { expect, test } from '@jest/globals';
import { createDocumentStore } from '@peerborne/store';
import { TestDocument } from '../../store/src/test-utils.js';
import { usePeerborneStore } from './store.js';

test('shared store hooks survive StrictMode and render in-place changes without context', async () => {
  const source = new TestDocument();
  const store = createDocumentStore(source);
  function View() {
    const snapshot = usePeerborneStore(store);
    return createElement(
      'output',
      null,
      snapshot.data?.title ?? snapshot.status,
    );
  }
  const ui = render(
    createElement(StrictMode, null, createElement(View), createElement(View)),
  );
  await waitFor(() => expect(screen.getAllByText('Initial')).toHaveLength(2));
  expect(source.openCount).toBe(1);
  expect(source.closeCount).toBe(0);
  await act(async () => {
    await store.change((data) => {
      data.title = 'Updated';
    });
  });
  expect(screen.getAllByText('Updated')).toHaveLength(2);
  ui.unmount();
  await Promise.resolve();
  await store.stop();
  expect(source.closeCount).toBe(1);
  expect(source.handlers.size).toBe(0);
});
