import assert from 'node:assert/strict';
import test from 'node:test';
import { isFrameworkModule } from './frameworks.mjs';

test('plain-web acceptance rejects framework internals across POSIX and Windows module paths', () => {
  for (const path of [
    '/app/node_modules/@vue/runtime-core/dist/runtime-core.esm-bundler.js',
    '/app/node_modules/@vue/reactivity/dist/reactivity.esm-bundler.js',
    'C:\\app\\node_modules\\@vue\\runtime-dom\\dist\\runtime-dom.js',
    '/app/node_modules/react/jsx-runtime.js',
    '/app/node_modules/react-dom/client.js',
    '/app/node_modules/vue/dist/vue.js',
    '/app/node_modules/svelte/internal/client/index.js',
    '/app/node_modules/next/client.js',
    '/app/node_modules/react-native/index.js',
  ])
    assert.equal(isFrameworkModule(path), true, path);
  for (const path of [
    '/app/node_modules/@peerborne/store/dist/esm/src/index.js',
    '/app/node_modules/yjs/dist/yjs.mjs',
    '/app/src/reactivity.ts',
    '/app/node_modules/@vueuse/core/index.js',
  ])
    assert.equal(isFrameworkModule(path), false, path);
});
