import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile, writeFile, rm } from 'node:fs/promises';
import { platform, arch, cpus } from 'node:os';
import { resolve, relative, sep } from 'node:path';
import { chromium } from '@playwright/test';
import { runProbe } from './probe.mjs';
import { observeNativeCrypto } from './native-crypto.mjs';

const root = import.meta.dirname;
await rm(resolve(root, 'report.json'), { force: true });
const toolchain = JSON.parse(
  await readFile(resolve(root, 'toolchain.json'), 'utf8'),
);
for (const [name, dependency] of Object.entries(toolchain.dependencies)) {
  const installed = JSON.parse(
    await readFile(resolve(root, 'node_modules', name, 'package.json'), 'utf8'),
  );
  if (installed.version !== dependency.version) {
    throw new Error(
      'Candidate dependency version differs from the pinned toolchain',
    );
  }
}
const native = observeNativeCrypto();
let nodeResult;
try {
  const mls = await import('ts-mls');
  nodeResult = { result: await runProbe(mls), nativeCrypto: native.counts };
} catch {
  throw new Error('Native Node candidate operation failed');
} finally {
  native.restore();
}

const imports = {
  '@noble/hashes/': '/node_modules/@noble/hashes/',
  '@noble/ciphers/': '/node_modules/@noble/ciphers/',
};
for (const name of ['ts-mls', '@hpke/core', '@hpke/common']) {
  const metadata = JSON.parse(
    await readFile(resolve(root, 'node_modules', name, 'package.json'), 'utf8'),
  );
  const entry = metadata.exports['.'].import;
  if (
    typeof entry !== 'string' ||
    !entry.startsWith('./') ||
    entry.includes('..')
  ) {
    throw new Error(
      'Candidate package has no supported public ESM root export',
    );
  }
  imports[name] = `/node_modules/${name}/${entry.slice(2)}`;
}
const importMap = JSON.stringify({ imports });
const hash = createHash('sha256').update(importMap).digest('base64');
const html = `<!doctype html><meta charset="utf-8"><title>MLS candidate verification</title><script type="importmap">${importMap}</script><script type="module" src="/browser.mjs"></script>`;
const server = createServer(async (request, response) => {
  try {
    if (request.method !== 'GET') {
      response.writeHead(405).end();
      return;
    }
    const pathname = new URL(request.url, 'http://localhost').pathname;
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader(
      'Content-Security-Policy',
      `default-src 'none'; script-src 'self' 'sha256-${hash}'; connect-src 'self'`,
    );
    if (pathname === '/') {
      response
        .writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
        .end(html);
      return;
    }
    const path = resolve(root, '.' + decodeURIComponent(pathname));
    const local = relative(root, path);
    if (
      local.startsWith('..' + sep) ||
      local === '..' ||
      (!path.endsWith('.mjs') && !path.endsWith('.js'))
    ) {
      response.writeHead(404).end();
      return;
    }
    response
      .writeHead(200, { 'Content-Type': 'text/javascript' })
      .end(await readFile(path));
  } catch {
    response.writeHead(404).end();
  }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
let browser;
let browserResult;
let chromiumVersion;
try {
  browser = await chromium.launch();
  chromiumVersion = browser.version();
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}/`, {
    waitUntil: 'commit',
  });
  await page.waitForFunction(
    () => window.candidateResult !== undefined,
    undefined,
    { timeout: 30_000 },
  );
  browserResult = await page.evaluate(() => window.candidateResult);
  if (browserResult.failed)
    throw new Error('Chromium candidate operation failed');
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}

for (const environment of [nodeResult, browserResult]) {
  for (const operation of [
    'sign:Ed25519',
    'verify:Ed25519',
    'deriveBits:X25519',
    'encrypt:AES-GCM',
    'decrypt:AES-GCM',
  ]) {
    if (!environment.nativeCrypto[operation])
      throw new Error('Native Web Crypto operation was not observed');
  }
}
const basicGatesPassed = [nodeResult, browserResult].every(
  ({ result }) =>
    result.zeroEpochRetentionHonored &&
    result.commitReplayRejected &&
    result.tamperedCommitRejected &&
    Object.values(result.credentialRejections).every(Boolean),
);
const report = {
  status: basicGatesPassed ? 'additional-gates-required' : 'rejected',
  recordedAt: new Date().toISOString(),
  node: process.version,
  chromium: chromiumVersion,
  platform: `${platform()}-${arch()}`,
  cpu: cpus()[0]?.model,
  sourcePatches: false,
  privatePackageImports: false,
  source: toolchain.source,
  toolchain: toolchain.dependencies,
  nodeResult,
  browserResult,
  untested: [
    'independent MLS interoperability',
    'Peerborne provider/coordinator integration',
    'durable crash recovery',
    'persistent keystore and independent rollback anchor',
    'full malformed-input and credential-policy matrix',
    'partition/fork handling',
    'resource budgets',
    'independent security review',
  ],
};
await writeFile(
  resolve(root, 'report.json'),
  JSON.stringify(report, null, 2) + '\n',
);
console.log(JSON.stringify(report, null, 2));
if (!basicGatesPassed) process.exitCode = 1;
