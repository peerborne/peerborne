import { build, preview } from 'vite';
import { chromium } from '@playwright/test';
import { readFile, writeFile, rm, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { platform, arch } from 'node:os';
import { resolve } from 'node:path';
import { runChecks } from './checks.mjs';

const root = import.meta.dirname;
const evidencePaths = [
  'packages/core/src/coordinated-document.ts',
  'packages/core/dist/esm/src/coordinated-document.js',
  'packages/core/src/document-crdt-session.ts',
  'packages/core/dist/esm/src/document-crdt-session.js',
  'packages/core/src/document-security-wire.ts',
  'packages/core/dist/esm/src/document-security-wire.js',
  'packages/core/src/document-authority-log.ts',
  'packages/core/dist/esm/src/document-authority-log.js',
  'packages/core/src/document-replay-journal.ts',
  'packages/core/dist/esm/src/document-replay-journal.js',
  'packages/core/src/document-journal-store.ts',
  'packages/core/dist/esm/src/document-journal-store.js',
  'packages/core/src/internal/document-binary.ts',
  'packages/core/dist/esm/src/internal/document-binary.js',
  'packages/core/src/policy/document-content.ts',
  'packages/core/dist/esm/src/policy/document-content.js',
  'packages/core/src/policy/document-journal.ts',
  'packages/core/dist/esm/src/policy/document-journal.js',
  'packages/core/src/peerborne-document.ts',
  'packages/core/dist/esm/src/peerborne-document.js',
  'packages/automerge/src/peerborne-automerge.ts',
  'packages/automerge/dist/esm/src/peerborne-automerge.js',
  'packages/yjs/src/peerborne-yjs.ts',
  'packages/yjs/dist/esm/src/peerborne-yjs.js',
  'verification/mls-provider/document-tests.ts',
  'packages/core/src/group-security-coordinator.ts',
  'packages/core/src/group-document-operation.ts',
  'packages/core/src/policy/document-admission.ts',
  'packages/core/src/internal/admission-work.ts',
  'packages/core/src/internal/native-promise-observation.ts',
  'packages/core/dist/esm/src/group-security-coordinator.js',
  'packages/core/dist/esm/src/group-document-operation.js',
  'packages/core/dist/esm/src/internal/admission-work.js',
  'packages/core/dist/esm/src/internal/native-promise-observation.js',
  'packages/core/dist/esm/src/policy/document-admission.js',
  'verification/mls-provider/coordinator-tests.ts',
];
const evidenceHashes = async () =>
  Object.fromEntries(
    await Promise.all(
      evidencePaths.map(async (path) => [
        path,
        createHash('sha256')
          .update(await readFile(resolve(root, '../..', path)))
          .digest('hex'),
      ]),
    ),
  );
const firstPartySources = await evidenceHashes();
await rm(resolve(root, 'report.json'), { force: true });
const node = await runChecks();
const optional = [
  '@hpke/chacha20poly1305',
  '@hpke/hybridkem-x-wing',
  '@hpke/dhkem-x448',
  '@hpke/ml-kem',
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
        "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'",
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
  const initializationFailure = new Promise((_, reject) =>
    page.on('pageerror', (error) =>
      reject(new Error('Browser module failed: ' + error.message)),
    ),
  );
  const address = server.httpServer.address();
  await page.goto(`http://127.0.0.1:${address.port}/`, { waitUntil: 'commit' });
  await Promise.race([
    initializationFailure,
    page.waitForFunction(
      () => window.mlsProviderResult !== undefined,
      undefined,
      { timeout: 60_000 },
    ),
  ]);
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
  firstPartySources,
  nodeResult: node,
  browserResult: chromiumResult.result,
  remaining: [
    'broader RFC suites and independent live interoperability',
    'obsolete checkpoint ciphertext and persistent-keystore erasure',
    'default document ACL/quorum workflows and coordinated content onboarding/anti-entropy',
    'durable browser process recovery with independent rollback anchor',
    'resource qualification and independent security review',
  ],
};
if (
  JSON.stringify(firstPartySources) !== JSON.stringify(await evidenceHashes())
)
  throw new Error(
    'Verification sources or built artifacts changed during execution',
  );
await writeFile(
  resolve(root, 'report.json'),
  JSON.stringify(report, null, 2) + '\n',
);
console.log(JSON.stringify(report, null, 2));
