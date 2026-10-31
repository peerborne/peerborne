/** @jest-environment jsdom */
import { expect, test } from '@jest/globals';
import { createApp, h, nextTick } from 'vue';
import { createDocumentStore } from '@peerborne/store';
import { TestDocument } from '../../store/src/test-utils.js';
import { usePeerborneStore } from './index.js';

test('Vue composables update shallow snapshots and release shared documents on unmount', async () => {
  const source = new TestDocument();
  const store = createDocumentStore(source);
  const app = createApp({
    setup() {
      const snapshot = usePeerborneStore(store);
      return () =>
        h('output', snapshot.value.data?.title ?? snapshot.value.status);
    },
  });
  const root = document.createElement('div');
  app.mount(root);
  await store.start();
  await nextTick();
  expect(root.textContent).toBe('Initial');
  await store.change((data) => {
    data.title = 'Changed';
  });
  await nextTick();
  expect(root.textContent).toBe('Changed');
  app.unmount();
  await Promise.resolve();
  await store.stop();
  expect(source.openCount).toBe(1);
  expect(source.closeCount).toBe(1);
});
