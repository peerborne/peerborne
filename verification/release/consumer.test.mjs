import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { packages } from '../../scripts/release-packages.mjs';
import { assertInstalledArtifacts } from './consumer.mjs';

const artifacts = packages.map(({ name }) => ({
  name,
  version: '0.1.0',
  integrity: `sha512-${createHash('sha512').update(name).digest('base64')}`,
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
      await writeFile(
        join(target, 'package.json'),
        JSON.stringify({ name: artifact.name, version: artifact.version }),
      );
      lock.packages[`node_modules/${artifact.name}`] = {
        integrity: artifact.integrity,
      };
    }
    await writeFile(join(directory, 'package-lock.json'), JSON.stringify(lock));
    await assertInstalledArtifacts(directory, artifacts);
    const alias = `${directory}-alias`;
    try {
      await symlink(directory, alias, 'dir');
      await assertInstalledArtifacts(alias, artifacts);
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
