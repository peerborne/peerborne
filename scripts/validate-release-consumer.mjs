import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { packages } from './release-packages.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
if (args.length !== 2) throw new Error('Usage: node scripts/validate-release-consumer.mjs <artifact-directory> <temporary-root>');
const artifactsDirectory = resolve(args[0]);
const temporaryRoot = resolve(args[1]);
const consumer = resolve(temporaryRoot, 'peerborne-release-consumer');
await rm(consumer, { recursive: true, force: true });
await mkdir(resolve(consumer, 'src'), { recursive: true });

try {
  const release = JSON.parse(await readFile(resolve(artifactsDirectory, 'release-manifest.json'), 'utf8'));
  if (JSON.stringify(release.packageOrder) !== JSON.stringify(packages.map(({ name }) => name))) {
    throw new Error('Release manifest package order does not match the allowlist');
  }
  if (!Array.isArray(release.artifacts) || JSON.stringify(release.artifacts.map(({ name }) => name)) !== JSON.stringify(release.packageOrder)) {
    throw new Error('Release artifacts do not match the allowlist');
  }
  const tarballs = release.artifacts.map(({ filename }) => resolve(artifactsDirectory, filename));
  await writeFile(resolve(consumer, 'package.json'), `${JSON.stringify({ name: 'peerborne-release-consumer', private: true, type: 'module' }, null, 2)}\n`);
  run('npm', ['install', '--no-audit', '--no-fund', ...tarballs, 'typescript@5.9.3', 'vite@6.4.3', '@types/react@19.2.3', 'vite-plugin-wasm@3.6.0'], consumer);

  const imports = [
    "import '@peerborne/core';",
    "import '@peerborne/core/node';",
    "import '@peerborne/core/browser-primitives';",
    "import '@peerborne/automerge';",
    "import '@peerborne/yjs';",
    "import '@peerborne/react';",
    "import '@peerborne/redux';",
    "import '@peerborne/index';",
    "import '@peerborne/index/react';",
  ].join('\n');
  await writeFile(resolve(consumer, 'imports.mjs'), `${imports}\n`);
  run('node', ['imports.mjs'], consumer);

  await writeFile(resolve(consumer, 'src', 'index.ts'), `${imports}\nexport const loaded: true = true;\n`);
  await writeFile(resolve(consumer, 'tsconfig.json'), `${JSON.stringify({ compilerOptions: { target: 'ES2024', lib: ['ES2024', 'DOM'], module: 'NodeNext', moduleResolution: 'NodeNext', strict: true, noEmit: true, skipLibCheck: false }, include: ['src/index.ts'] }, null, 2)}\n`);
  run(resolve(consumer, 'node_modules', '.bin', 'tsc'), ['-p', 'tsconfig.json'], consumer);

  const browserImports = imports.split('\n').filter((line) => !line.includes('/node')).join('\n');
  await writeFile(resolve(consumer, 'src', 'browser.ts'), `${browserImports}\n`);
  await writeFile(resolve(consumer, 'vite.config.mjs'), "import { defineConfig } from 'vite';\nimport wasm from 'vite-plugin-wasm';\nexport default defineConfig({ plugins: [wasm()], build: { target: 'esnext', lib: { entry: 'src/browser.ts', formats: ['es'] } } });\n");
  run(resolve(consumer, 'node_modules', '.bin', 'vite'), ['build', '--config', 'vite.config.mjs'], consumer);
} finally {
  await rm(consumer, { recursive: true, force: true });
}

function run(command, commandArgs, cwd) {
  const result = spawnSync(command, commandArgs, { cwd, encoding: 'utf8', stdio: 'inherit', env: { ...process.env, NODE_AUTH_TOKEN: undefined, NPM_TOKEN: undefined } });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} failed with status ${result.status}`);
}
