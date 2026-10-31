import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { svelte } from '@sveltejs/vite-plugin-svelte';
export default defineConfig({
  plugins: [react(), svelte()],
  resolve: {
    alias: {
      'monaco-editor/esm/vs/editor/editor.api.js':
        'monaco-editor/editor/editor.api.js',
    },
  },
  build: { target: 'esnext' },
});
