/** @jest-environment jsdom */
import { expect, test } from '@jest/globals';
import { createDocumentStore } from '@peerborne/store';
import { TestDocument } from '../../store/src/test-utils.js';
import { peerborneReadable } from './index.js';

test('readables share document ownership and deliver in-place updates synchronously', async () => {
  const source = new TestDocument();
  const store = createDocumentStore(source);
  const readable = peerborneReadable(store);
  const titles: (string | undefined)[] = [];
  const first = readable.subscribe((snapshot) => {
    titles.push(snapshot.data?.title);
  });
  const second = readable.subscribe(() => {});
  await store.start();
  await store.change((data) => {
    data.title = 'Updated';
  });
  expect(titles.at(-1)).toBe('Updated');
  first();
  expect(source.closeCount).toBe(0);
  second();
  await Promise.resolve();
  await store.stop();
  expect(source.openCount).toBe(1);
  expect(source.closeCount).toBe(1);
});
