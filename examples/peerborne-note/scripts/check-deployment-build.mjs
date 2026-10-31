import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { loadEnv } from 'vite';

const root = new URL('../', import.meta.url);
const config = await readFile(new URL('wrangler.toml', root), 'utf8');
if (!/pages_build_output_dir\s*=\s*"\.\/dist-deployment"/u.test(config)) {
  throw new Error('Pages must select the isolated deployment build');
}
const env = loadEnv('deployment', fileURLToPath(root), 'VITE_');
const expected =
  process.env.VITE_PEERBORNE_RELAY_MULTIADDR ??
  env.VITE_PEERBORNE_RELAY_MULTIADDR;
if (!expected)
  throw new Error('Expected public relay configuration is missing');
const folder = new URL('dist-deployment/', root);
const assets = await readdir(new URL('assets/', folder));
const scripts = await Promise.all(
  assets
    .filter((name) => name.endsWith('.js'))
    .map((name) => readFile(new URL('assets/' + name, folder), 'utf8')),
);
if (!scripts.some((script) => script.includes(expected))) {
  throw new Error(
    'Deployment scripts do not contain the configured public relay',
  );
}
const host = /^\/dns4\/([^/]+)\/tcp\/443\/wss\//u.exec(expected)?.[1];
const headers = await readFile(new URL('_headers', folder), 'utf8');
if (!host || !headers.includes('wss://' + host)) {
  throw new Error('Deployment CSP does not permit the configured public relay');
}
console.log(
  'The isolated Pages build retains its public relay and CSP after local builds.',
);
