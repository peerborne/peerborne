import { expect, test } from '@jest/globals';
import { createSSRApp, h } from 'vue';
import { renderToString } from 'vue/server-renderer';
import { createDocumentStore } from '@peerborne/store';
import { TestDocument } from '../../store/src/test-utils.js';
import { usePeerborneStore } from './index.js';

test('server rendering does not open documents', async () => {
  const source = new TestDocument();
  const store = createDocumentStore(source);
  const app = createSSRApp({
    setup() {
      const snapshot = usePeerborneStore(store);
      return () => h('output', snapshot.value.status);
    },
  });
  expect(await renderToString(app)).toContain('idle');
  expect(source.openCount).toBe(0);
});
