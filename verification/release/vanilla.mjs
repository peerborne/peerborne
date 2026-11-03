import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { chromium, firefox, webkit, expect } from '@playwright/test';
import { auditConsumer } from './audit.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
if (process.argv.length !== 4)
  throw new Error(
    'Usage: node verification/release/vanilla.mjs <artifact-directory> <temporary-root>',
  );
const artifactsDirectory = resolve(process.argv[2]);
const consumer = await mkdtemp(
  join(resolve(process.argv[3]), 'peerborne-vanilla-consumer-'),
);
const reportDirectory = join(root, 'verification/results/release');
let preview;
const cases = [];
function run(args) {
  const result = spawnSync('npm', args, {
    cwd: consumer,
    stdio: 'inherit',
    env: { ...process.env, NODE_AUTH_TOKEN: undefined, NPM_TOKEN: undefined },
  });
  if (result.error) throw result.error;
  if (result.status !== 0)
    throw new Error('Framework-free release consumer setup failed');
}
try {
  const release = JSON.parse(
    await readFile(join(artifactsDirectory, 'release-manifest.json'), 'utf8'),
  );
  const names = ['@peerborne/core', '@peerborne/yjs', '@peerborne/store'];
  const artifacts = release.artifacts.filter(({ name }) =>
    names.includes(name),
  );
  assert.deepEqual(
    artifacts.map(({ name }) => name),
    names,
  );
  for (const artifact of artifacts) {
    assert.equal(basename(artifact.filename), artifact.filename);
    const bytes = await readFile(join(artifactsDirectory, artifact.filename));
    assert.equal(
      `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
      artifact.integrity,
    );
  }
  await writeFile(
    join(consumer, 'package.json'),
    JSON.stringify({
      name: 'peerborne-plain-web-pilot',
      private: true,
      type: 'module',
    }),
  );
  run([
    'install',
    '--no-audit',
    '--no-fund',
    ...artifacts.map(({ filename }) => join(artifactsDirectory, filename)),
  ]);
  await auditConsumer(consumer, 'framework-free-audit', true);
  run([
    'install',
    '--save-dev',
    '--no-audit',
    '--no-fund',
    'typescript@5.9.3',
    'vite@8.3.5',
    '@types/node@26.6.2',
  ]);
  const lock = JSON.parse(
    await readFile(join(consumer, 'package-lock.json'), 'utf8'),
  );
  const frameworkModule =
    /(?:^|\/)node_modules\/(?:react|react-dom|react-native|vue|svelte|next)(?:\/|$)/u;
  const transitiveFrameworkPackages = Object.keys(lock.packages).filter(
    (name) => frameworkModule.test(name),
  );
  for (const artifact of artifacts)
    assert.equal(
      lock.packages[`node_modules/${artifact.name}`]?.integrity,
      artifact.integrity,
    );
  await cp(join(root, 'verification/release/vanilla'), consumer, {
    recursive: true,
  });
  await writeFile(
    join(consumer, 'tsconfig.json'),
    JSON.stringify({
      compilerOptions: {
        strict: true,
        skipLibCheck: false,
        noEmit: true,
        target: 'ES2022',
        module: 'ESNext',
        moduleResolution: 'Bundler',
        lib: ['ES2024', 'DOM'],
        types: ['node'],
      },
      include: ['main.ts'],
    }),
  );
  run(['exec', '--', 'tsc', '--noEmit']);
  const vite = await import(
    pathToFileURL(join(consumer, 'node_modules/vite/dist/node/index.js')).href
  );
  await vite.build({
    root: consumer,
    configFile: false,
    build: { target: 'esnext' },
    plugins: [
      {
        name: 'reject-framework-modules',
        generateBundle(_options, bundle) {
          for (const output of Object.values(bundle)) {
            if (output.type === 'chunk')
              assert.deepEqual(
                output.moduleIds.filter((name) => frameworkModule.test(name)),
                [],
                'Framework-free application bundled a frontend framework',
              );
          }
        },
      },
    ],
  });
  preview = await vite.preview({
    root: consumer,
    configFile: false,
    preview: { host: '127.0.0.1', port: 0 },
  });
  const { port } = preview.httpServer.address();
  for (const name of (
    process.env.PEERBORNE_RELEASE_BROWSERS ?? 'chromium'
  ).split(',')) {
    const browser = await { chromium, firefox, webkit }[name].launch();
    try {
      const page = await browser.newPage();
      const errors = [];
      page.on('pageerror', () => errors.push('pageerror'));
      await page.goto(`http://127.0.0.1:${port}/`);
      await page.getByRole('button', { name: 'Start local document' }).click();
      await expect(page.locator('#status')).toHaveText('ready', {
        timeout: 30_000,
      });
      for (let index = 0; index < 5; index++) {
        await page
          .getByRole('textbox', { name: 'Title' })
          .fill(`Framework-free edit ${index}`);
        await page.getByRole('button', { name: 'Save title' }).click();
        await expect(page.locator('output')).toHaveText(
          `Framework-free edit ${index}`,
        );
      }
      await page.getByRole('button', { name: 'Close local document' }).click();
      await expect(page.locator('#status')).toHaveText('closed');
      assert.deepEqual(errors, []);
      cases.push({
        browser: name,
        version: browser.version(),
        status: 'passed',
        edits: 5,
      });
    } finally {
      await browser.close();
    }
  }
  await mkdir(reportDirectory, { recursive: true });
  await writeFile(
    join(reportDirectory, 'framework-free.json'),
    `${JSON.stringify({ status: 'passed', frameworksBundled: false, transitiveFrameworkPackages, artifacts: artifacts.map(({ name, version, integrity }) => ({ name, version, integrity })), cases }, null, 2)}\n`,
  );
} finally {
  if (preview)
    await new Promise((resolve) => preview.httpServer.close(resolve));
  if (process.env.PEERBORNE_RELEASE_KEEP_CONSUMER !== '1')
    await rm(consumer, { recursive: true, force: true });
}
