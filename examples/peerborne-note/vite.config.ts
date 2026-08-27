import react from '@vitejs/plugin-react';
import { readFileSync } from 'node:fs';
import { defineConfig, loadEnv } from 'vite';
import topLevelAwait from 'vite-plugin-top-level-await';
import wasm from 'vite-plugin-wasm';

function pagesRootHeaders(): Record<string, string> {
  const lines = readFileSync(new URL('./public/_headers', import.meta.url), 'utf8')
    .split(/\r?\n/u);
  const headers: Record<string, string> = {};
  let inRootRule = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (!inRootRule) {
      inRootRule = trimmed === '/*';
      continue;
    }
    if (trimmed.length === 0) break;
    const separator = trimmed.indexOf(':');
    if (separator <= 0) {
      throw new Error('Peerborne Note has a malformed root rule in public/_headers');
    }
    headers[trimmed.slice(0, separator)] = trimmed.slice(separator + 1).trim();
  }
  if (!headers['Content-Security-Policy']) {
    throw new Error('Peerborne Note public/_headers has no root CSP');
  }
  return headers;
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  if (mode === 'deployment') {
    const relay = env.VITE_PEERBORNE_RELAY_MULTIADDR?.trim() ?? '';
    if (
      relay.length > 1024 ||
      !/^\/dns4\/[^/\s]+\/tcp\/443\/wss\/p2p\/[^/\s]+$/u.test(relay)
    ) {
      throw new Error(
        'Deployment requires a complete DNS, TCP 443, WSS, peer-ID-qualified VITE_PEERBORNE_RELAY_MULTIADDR',
      );
    }
  }
  return {
    plugins: [react(), wasm(), topLevelAwait()],
    build: {
      sourcemap: false,
      target: 'es2022',
    },
    preview: {
      headers: pagesRootHeaders(),
    },
  };
});
