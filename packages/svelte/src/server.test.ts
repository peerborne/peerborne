import { expect, test } from '@jest/globals';
import { get } from 'svelte/store';
import { createDocumentStore } from '@peerborne/store';
import { TestDocument } from '../../store/src/test-utils.js';
import { peerborneReadable } from './index.js';

test('a server-side Svelte store read has no browser or networking side effects', () => {
  const source = new TestDocument();
  expect(get(peerborneReadable(createDocumentStore(source))).status).toBe(
    'idle',
  );
  expect(source.openCount).toBe(0);
  expect(source.handlers.size).toBe(0);
});
