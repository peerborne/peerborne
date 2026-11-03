import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { packages } from '../../scripts/release-packages.mjs';
import {
  assertInstalledArtifacts,
  assertInstalledFileContents,
} from './consumer.mjs';

const contents = (name, file) =>
  file === 'package.json'
    ? JSON.stringify({ name, version: '0.1.0' })
    : `release fixture ${name} ${file}\n`;
const digest = (value) =>
  `sha512-${createHash('sha512').update(value).digest('base64')}`;
const artifacts = packages.map(({ name, entries, bins }) => ({
  name,
  version: '0.1.0',
  integrity: `sha512-${createHash('sha512').update(name).digest('base64')}`,
  files: ['package.json', 'README.md', 'LICENSE', ...entries, ...bins],
  fileIntegrities: Object.fromEntries(
    ['package.json', 'README.md', 'LICENSE', ...entries, ...bins].map(
      (file) => [file, digest(contents(name, file))],
    ),
  ),
}));

test('release acceptance cannot pass with an empty or partial artifact manifest', async () => {
  for (const invalid of [
    undefined,
    null,
    [],
    artifacts.slice(1),
    [...artifacts].reverse(),
    artifacts.map(() => null),
  ])
    await assert.rejects(
      assertInstalledArtifacts('/unused', invalid),
      /allowlist/u,
    );
});

test('release acceptance rejects missing integrity and inconsistent artifact versions', async () => {
  for (const change of [
    { integrity: undefined },
    { integrity: 'sha512-invalid' },
    { version: '0.0.0' },
    { fileIntegrities: undefined },
    {
      files: ['package.json'],
      fileIntegrities: { 'package.json': digest('fixture') },
    },
  ])
    await assert.rejects(
      assertInstalledArtifacts(
        '/unused',
        artifacts.map((artifact, index) =>
          index === 0 ? { ...artifact, ...change } : artifact,
        ),
      ),
      /metadata/u,
    );
});

test('release acceptance rejects substituted packages and workspace symlinks despite a matching lockfile', async () => {
  const directory = await mkdtemp(
    join(tmpdir(), 'peerborne-release-integrity-'),
  );
  try {
    const lock = { packages: {} };
    for (const artifact of artifacts) {
      const target = join(directory, 'node_modules', artifact.name);
      await mkdir(target, { recursive: true });
      for (const file of artifact.files) {
        await mkdir(dirname(join(target, file)), { recursive: true });
        await writeFile(join(target, file), contents(artifact.name, file));
      }
      lock.packages[`node_modules/${artifact.name}`] = {
        integrity: artifact.integrity,
      };
    }
    await writeFile(join(directory, 'package-lock.json'), JSON.stringify(lock));
    await assertInstalledArtifacts(directory, artifacts);
    const entry = join(
      directory,
      'node_modules/@peerborne/core/dist/esm/src/index.js',
    );
    await writeFile(entry, 'modified installed code');
    await assert.rejects(
      assertInstalledArtifacts(directory, artifacts),
      /file differs/u,
    );
    await writeFile(
      entry,
      contents('@peerborne/core', 'dist/esm/src/index.js'),
    );
    const outside = join(directory, 'outside-index.js');
    await writeFile(
      outside,
      contents('@peerborne/core', 'dist/esm/src/index.js'),
    );
    await rm(entry);
    await symlink(outside, entry);
    await assert.rejects(
      assertInstalledArtifacts(directory, artifacts),
      /regular package file/u,
    );
    await rm(entry);
    await writeFile(
      entry,
      contents('@peerborne/core', 'dist/esm/src/index.js'),
    );
    const alias = `${directory}-alias`;
    try {
      await symlink(directory, alias, 'dir');
      await assertInstalledArtifacts(alias, artifacts);
      await assertInstalledFileContents(
        join(alias, 'node_modules', artifacts[0].name),
        artifacts[0],
      );
    } finally {
      await rm(alias, { force: true });
    }
    lock.packages['node_modules/@peerborne/core'].integrity =
      artifacts[1].integrity;
    await writeFile(join(directory, 'package-lock.json'), JSON.stringify(lock));
    await assert.rejects(
      assertInstalledArtifacts(directory, artifacts),
      /integrity differs/u,
    );
    lock.packages['node_modules/@peerborne/core'].integrity =
      artifacts[0].integrity;
    await writeFile(join(directory, 'package-lock.json'), JSON.stringify(lock));
    const core = join(directory, 'node_modules/@peerborne/core');
    await writeFile(
      join(core, 'package.json'),
      JSON.stringify({ name: '@peerborne/core', version: '0.0.0' }),
    );
    await assert.rejects(
      assertInstalledArtifacts(directory, artifacts),
      /identity/u,
    );
    await rm(core, { recursive: true });
    const workspace = join(directory, 'source-workspace');
    await mkdir(workspace);
    await symlink(workspace, core, 'dir');
    await assert.rejects(
      assertInstalledArtifacts(directory, artifacts),
      /installed packages/u,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
