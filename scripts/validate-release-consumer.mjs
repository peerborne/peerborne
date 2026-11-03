import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { packages } from './release-packages.mjs';
import { prepareBrowserConsumer } from '../verification/release/consumer.mjs';
import { auditConsumer } from '../verification/release/audit.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
if (args.length !== 2)
  throw new Error(
    'Usage: node scripts/validate-release-consumer.mjs <artifact-directory> <temporary-root>',
  );
const artifactsDirectory = resolve(args[0]);
const temporaryRoot = resolve(args[1]);
await mkdir(temporaryRoot, { recursive: true });
const consumer = await mkdtemp(
  resolve(temporaryRoot, 'peerborne-release-consumer-'),
);
console.log(`Release consumer: ${consumer}`);
await mkdir(resolve(consumer, 'src'), { recursive: true });

try {
  const release = JSON.parse(
    await readFile(
      resolve(artifactsDirectory, 'release-manifest.json'),
      'utf8',
    ),
  );
  if (
    JSON.stringify(release.packageOrder) !==
    JSON.stringify(packages.map(({ name }) => name))
  ) {
    throw new Error(
      'Release manifest package order does not match the allowlist',
    );
  }
  if (
    !Array.isArray(release.artifacts) ||
    JSON.stringify(release.artifacts.map(({ name }) => name)) !==
      JSON.stringify(release.packageOrder)
  ) {
    throw new Error('Release artifacts do not match the allowlist');
  }
  const tarballs = release.artifacts.map(({ filename }) =>
    resolve(artifactsDirectory, filename),
  );
  await writeFile(
    resolve(consumer, 'package.json'),
    `${JSON.stringify({ name: 'peerborne-release-consumer', private: true, type: 'module' }, null, 2)}\n`,
  );
  run('npm', ['install', '--no-audit', '--no-fund', ...tarballs], consumer);
  await auditConsumer(consumer, 'production-audit', true);
  run(
    'npm',
    [
      'install',
      '--save-dev',
      '--no-audit',
      '--no-fund',
      'typescript@5.9.3',
      'vite@8.3.5',
      '@types/react@19.3.0',
      'vite-plugin-wasm@3.6.0',
    ],
    consumer,
  );

  const specifiers = [
    '@peerborne/core',
    '@peerborne/core/node',
    '@peerborne/core/browser-primitives',
    '@peerborne/core/wire-protocols',
    '@peerborne/automerge',
    '@peerborne/yjs',
    '@peerborne/store',
    '@peerborne/vue',
    '@peerborne/svelte',
    '@peerborne/loro',
    '@peerborne/tanstack-db',
    '@peerborne/yjs/editor',
    '@peerborne/react',
    '@peerborne/react/store',
    '@peerborne/redux',
    '@peerborne/index',
    '@peerborne/index/react',
  ];
  const imports = specifiers
    .map((specifier) => `import '${specifier}';`)
    .join('\n');
  await writeFile(resolve(consumer, 'imports.mjs'), `${imports}\n`);
  run('node', ['imports.mjs'], consumer);

  await writeFile(
    resolve(consumer, 'requires.mjs'),
    `
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
for (const specifier of ${JSON.stringify(specifiers)}) {
  const required = require(specifier);
  const imported = await import(specifier);
  for (const name of Object.keys(imported)) {
    assert.equal(required[name], imported[name], specifier + ': ' + name);
  }
}
`,
  );
  run('node', ['requires.mjs'], consumer);

  await writeFile(
    resolve(consumer, 'src', 'index.ts'),
    `${imports}\nexport const loaded: true = true;\n`,
  );
  await writeFile(
    resolve(consumer, 'src', 'commonjs.cts'),
    `${imports}\nexport const loaded: true = true;\n`,
  );
  await writeFile(
    resolve(consumer, 'tsconfig.json'),
    `${JSON.stringify({ compilerOptions: { target: 'ES2024', lib: ['ES2024', 'DOM'], module: 'NodeNext', moduleResolution: 'NodeNext', strict: true, noEmit: true, skipLibCheck: false }, include: ['src/index.ts', 'src/commonjs.cts'] }, null, 2)}\n`,
  );
  run(
    resolve(consumer, 'node_modules', '.bin', 'tsc'),
    ['-p', 'tsconfig.json'],
    consumer,
  );

  const browserImports = imports
    .split('\n')
    .filter((line) => !line.includes('/node'))
    .join('\n');
  await writeFile(
    resolve(consumer, 'src', 'browser.ts'),
    `${browserImports}\n`,
  );
  await writeFile(
    resolve(consumer, 'vite.config.mjs'),
    "import { defineConfig } from 'vite';\nimport wasm from 'vite-plugin-wasm';\nexport default defineConfig({ plugins: [wasm()], build: { target: 'esnext', lib: { entry: 'src/browser.ts', formats: ['es'] } } });\n",
  );
  run(
    resolve(consumer, 'node_modules', '.bin', 'vite'),
    ['build', '--config', 'vite.config.mjs'],
    consumer,
  );
  await prepareBrowserConsumer(consumer, release.artifacts);
  run(
    process.execPath,
    [resolve(root, 'verification/release/run.mjs'), consumer],
    root,
  );
  run(
    process.execPath,
    [
      resolve(root, 'verification/release/vanilla.mjs'),
      artifactsDirectory,
      temporaryRoot,
    ],
    root,
  );
} finally {
  if (process.env.PEERBORNE_RELEASE_KEEP_CONSUMER !== '1')
    await rm(consumer, { recursive: true, force: true });
}

function run(command, commandArgs, cwd) {
  const result = spawnSync(command, commandArgs, {
    cwd,
    encoding: 'utf8',
    stdio: 'inherit',
    env: { ...process.env, NODE_AUTH_TOKEN: undefined, NPM_TOKEN: undefined },
  });
  if (result.error) throw result.error;
  if (result.status !== 0)
    throw new Error(`${command} failed with status ${result.status}`);
}
