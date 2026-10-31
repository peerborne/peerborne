import { build, preview } from 'vite';
import { chromium } from '@playwright/test';
import { readFile, writeFile, rm, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { platform, arch } from 'node:os';
import { resolve } from 'node:path';
import { runChecks } from './checks.mjs';

const root = import.meta.dirname;
await rm(resolve(root, 'report.json'), { force: true });
const node = await runChecks();
const optional = [
  '@hpke/chacha20poly1305',
  '@hpke/hybridkem-x-wing',
  '@hpke/dhkem-x448',
  '@hpke/ml-kem',
  '@noble/curves/ed25519.js',
  '@noble/curves/ed448.js',
  '@noble/curves/nist.js',
  '@noble/post-quantum/ml-dsa.js',
];
await build({
  root,
  configFile: false,
  logLevel: 'warn',
  build: {
    target: 'esnext',
    sourcemap: false,
    rolldownOptions: { external: optional },
  },
});
const server = await preview({
  root,
  configFile: false,
  logLevel: 'warn',
  preview: {
    host: '127.0.0.1',
    port: 0,
    headers: {
      'Content-Security-Policy':
        "default-src 'none'; script-src 'self'; connect-src 'self'",
      'Cache-Control': 'no-store',
    },
  },
});
let browser;
let chromiumResult;
let chromiumVersion;
try {
  browser = await chromium.launch();
  chromiumVersion = browser.version();
  const page = await browser.newPage();
  const address = server.httpServer.address();
  await page.goto(`http://127.0.0.1:${address.port}/`, { waitUntil: 'commit' });
  await page.waitForFunction(
    () => window.mlsProviderResult !== undefined,
    undefined,
    { timeout: 60_000 },
  );
  chromiumResult = await page.evaluate(() => window.mlsProviderResult);
  if (chromiumResult.failed) throw new Error('Chromium provider checks failed');
} finally {
  await browser?.close();
  await new Promise((resolve) => server.httpServer.close(resolve));
}
const patchDirectory = resolve(root, '.yarn/patches');
const patchFiles = await readdir(patchDirectory);
const patches = {};
for (const path of patchFiles)
  patches[path] = createHash('sha256')
    .update(await readFile(resolve(patchDirectory, path)))
    .digest('hex');
for (const value of [node, chromiumResult.result]) {
  for (const operation of [
    'sign:Ed25519',
    'verify:Ed25519',
    'deriveBits:X25519',
    'encrypt:AES-GCM',
    'decrypt:AES-GCM',
  ]) {
    if (!value.nativeCrypto[operation])
      throw new Error('Expected native crypto operation was not observed');
  }
}
const report = {
  status: 'experimental-adapter-gates-passed',
  recordedAt: new Date().toISOString(),
  node: process.version,
  chromium: chromiumVersion,
  platform: `${platform()}-${arch()}`,
  upstream: 'ts-mls@1.6.4',
  sourcePatches: patches,
  nodeResult: node,
  browserResult: chromiumResult.result,
  remaining: [
    'broader RFC suites and independent live interoperability',
    'provider/coordinator contract gaps: empty genesis transcript, self-update, terminal removal',
    'document ACL/control/quorum integration',
    'durable browser process recovery with independent rollback anchor',
    'resource qualification and independent security review',
  ],
};
await writeFile(
  resolve(root, 'report.json'),
  JSON.stringify(report, null, 2) + '\n',
);
console.log(JSON.stringify(report, null, 2));
