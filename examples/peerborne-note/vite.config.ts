import { peerIdFromString } from '@libp2p/peer-id';
import react from '@vitejs/plugin-react';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig, loadEnv } from 'vite';
import topLevelAwait from 'vite-plugin-top-level-await';
import wasm from 'vite-plugin-wasm';
import {
  relayConnectSourceFromMultiaddr,
  renderPagesHeaders,
} from './src/deployment-config.js';

function pagesRootHeaders(source: string): Record<string, string> {
  const lines = source.split(/\r?\n/u);
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
  const relayConnectSource = relayConnectSourceFromMultiaddr(
    env.VITE_PEERBORNE_RELAY_MULTIADDR,
    mode === 'deployment',
    (peerId) => {
      try {
        peerIdFromString(peerId);
        return true;
      } catch {
        return false;
      }
    },
  );
  const renderedPagesHeaders = renderPagesHeaders(
    readFileSync(new URL('./public/_headers', import.meta.url), 'utf8'),
    relayConnectSource,
  );
  return {
    plugins: [
      react(),
      wasm(),
      topLevelAwait(),
      {
        name: 'peerborne-note-pages-headers',
        apply: 'build',
        writeBundle(options) {
          if (!options.dir) {
            throw new Error('Peerborne Note build has no output directory');
          }
          writeFileSync(
            resolve(options.dir, '_headers'),
            renderedPagesHeaders,
            'utf8',
          );
        },
      },
    ],
    build: {
      sourcemap: false,
      target: 'es2022',
    },
    preview: {
      headers: pagesRootHeaders(renderedPagesHeaders),
    },
  };
});
