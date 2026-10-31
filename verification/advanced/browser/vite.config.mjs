import { defineConfig } from 'vite';
import wasm from 'vite-plugin-wasm';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  plugins: [wasm()],
  server: {
    fs: { allow: [fileURLToPath(new URL('../../../', import.meta.url))] },
  },
  optimizeDeps: { exclude: ['@automerge/automerge'] },
});
