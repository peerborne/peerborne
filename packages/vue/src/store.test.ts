/** @jest-environment jsdom */
import { expect, test } from '@jest/globals';
import {
  createApp,
  defineComponent,
  h,
  nextTick,
  shallowRef,
  type PropType,
} from 'vue';
import { createDocumentStore } from '@peerborne/store';
import { TestDocument } from '../../store/src/test-utils.js';
import { usePeerborneStore } from './index.js';

test('Vue composables update shallow snapshots and release shared documents on unmount', async () => {
  const source = new TestDocument();
  const store = createDocumentStore(() => source);
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

test('Vue composables follow a store prop and release the previous store', async () => {
  const first = new TestDocument();
  const second = new TestDocument();
  second.document = { title: 'Second' };
  const stores = [
    createDocumentStore(() => first),
    createDocumentStore(() => second),
  ];
  type Store = (typeof stores)[number];
  const selected = shallowRef(stores[0]);
  const View = defineComponent({
    props: { store: { type: Object as PropType<Store>, required: true } },
    setup(props) {
      const snapshot = usePeerborneStore(() => props.store);
      return () =>
        h('output', snapshot.value.data?.title ?? snapshot.value.status);
    },
  });
  const app = createApp({
    setup: () => () => h(View, { store: selected.value }),
  });
  const root = document.createElement('div');
  app.mount(root);
  await stores[0].start();
  await nextTick();
  expect(root.textContent).toBe('Initial');

  selected.value = stores[1];
  await nextTick();
  await stores[1].start();
  await nextTick();
  expect(root.textContent).toBe('Second');
  await stores[0].stop();
  expect(first.closeCount).toBe(1);
  expect(first.handlers.size).toBe(0);

  await stores[1].change((data) => {
    data.title = 'Changed';
  });
  await nextTick();
  expect(root.textContent).toBe('Changed');
  app.unmount();
  await Promise.resolve();
  await stores[1].stop();
  expect(second.openCount).toBe(1);
  expect(second.closeCount).toBe(1);
});
