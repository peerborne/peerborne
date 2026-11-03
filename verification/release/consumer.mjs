import {
  cp,
  lstat,
  mkdir,
  readFile,
  realpath,
  writeFile,
} from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { packages, strictSemver } from '../../scripts/release-packages.mjs';
import { auditConsumer } from './audit.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const applications = [
  'peerborne-note',
  'integrations',
  'nextjs',
  'tanstack-start',
];
const testDependencies = new Set([
  'jest',
  'ts-jest',
  '@types/jest',
  'fake-indexeddb',
]);

export async function assertInstalledArtifacts(consumer, artifacts) {
  if (
    !Array.isArray(artifacts) ||
    artifacts.length !== packages.length ||
    artifacts.some((artifact, index) => artifact?.name !== packages[index].name)
  )
    throw new Error(
      'Installed release artifacts do not match the exact package allowlist',
    );
  if (
    artifacts.some(
      (artifact) =>
        typeof artifact.version !== 'string' ||
        !strictSemver.test(artifact.version) ||
        artifact.version !== artifacts[0].version ||
        typeof artifact.integrity !== 'string' ||
        !/^sha512-[A-Za-z0-9+/]{86}==$/u.test(artifact.integrity),
    )
  )
    throw new Error('Invalid release artifact identity or integrity metadata');
  consumer = await realpath(consumer);
  const location = relative(root, consumer);
  if (
    location !== '..' &&
    !location.startsWith(`..${sep}`) &&
    !isAbsolute(location)
  )
    throw new Error(
      'Release acceptance requires a consumer outside the checkout',
    );
  const lock = JSON.parse(
    await readFile(join(consumer, 'package-lock.json'), 'utf8'),
  );
  for (const artifact of artifacts) {
    const directory = join(consumer, 'node_modules', artifact.name);
    if (
      (await lstat(directory)).isSymbolicLink() ||
      relative(consumer, await realpath(directory)).startsWith('..')
    )
      throw new Error(
        'Release acceptance requires installed packages outside the repository',
      );
    if (
      lock.packages[`node_modules/${artifact.name}`]?.integrity !==
      artifact.integrity
    )
      throw new Error(
        'Installed release package integrity differs from the validated tarball',
      );
    const manifest = JSON.parse(
      await readFile(join(directory, 'package.json'), 'utf8'),
    );
    if (
      manifest.name !== artifact.name ||
      manifest.version !== artifact.version
    )
      throw new Error(
        'Installed release package identity differs from the validated artifact',
      );
  }
}

export async function prepareBrowserConsumer(consumer, artifacts) {
  await assertInstalledArtifacts(consumer, artifacts);
  const releaseNames = new Set(packages.map(({ name }) => name));
  const dependencies = {};
  const overrides = {};
  for (const application of applications) {
    const source = join(root, 'examples', application);
    const destination = join(consumer, 'applications', application);
    await mkdir(destination, { recursive: true });
    const manifest = JSON.parse(
      await readFile(join(source, 'package.json'), 'utf8'),
    );
    Object.assign(overrides, manifest.overrides ?? {});
    for (const [name, version] of Object.entries({
      ...manifest.dependencies,
      ...manifest.devDependencies,
    })) {
      if (releaseNames.has(name)) continue;
      if (testDependencies.has(name)) continue;
      if (version.startsWith('workspace:'))
        throw new Error('Unexpected workspace dependency in release consumer');
      dependencies[name] = version;
    }
    await writeFile(
      join(destination, 'package.json'),
      JSON.stringify({ private: true, type: 'module' }),
    );
    for (const entry of [
      'src',
      'app',
      'public',
      'index.html',
      'tsconfig.json',
      'vite.config.ts',
      'next.config.mjs',
      'next-env.d.ts',
      'serve.mjs',
    ]) {
      try {
        await cp(join(source, entry), join(destination, entry), {
          recursive: true,
          filter: (path) => !/\.(?:test|spec)\.[^.]+$/u.test(path),
        });
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }
    if (application === 'peerborne-note') {
      const path = join(destination, 'tsconfig.json');
      const configuration = JSON.parse(await readFile(path, 'utf8'));
      delete configuration.references;
      await writeFile(path, JSON.stringify(configuration, null, 2));
    }
  }
  await cp(
    join(root, 'examples/shared'),
    join(consumer, 'applications/shared'),
    {
      recursive: true,
      filter: (path) =>
        !path.includes('node_modules') &&
        !/\.(?:test|spec)\.[^.]+$/u.test(path),
    },
  );
  const manifestPath = join(consumer, 'package.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  for (const name of testDependencies) delete manifest.devDependencies?.[name];
  manifest.overrides = { ...manifest.overrides, ...overrides };
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
  const result = spawnSync(
    'npm',
    [
      'install',
      '--save-dev',
      '--no-audit',
      '--no-fund',
      ...Object.entries(dependencies).map(
        ([name, version]) => `${name}@${version}`,
      ),
    ],
    {
      cwd: consumer,
      stdio: 'inherit',
      env: { ...process.env, NODE_AUTH_TOKEN: undefined, NPM_TOKEN: undefined },
    },
  );
  if (result.error) throw result.error;
  if (result.status !== 0)
    throw new Error('Release browser dependencies could not be installed');
  await assertInstalledArtifacts(consumer, artifacts);
  await auditConsumer(consumer, 'application-audit', false);
  await writeFile(
    join(consumer, 'release-artifacts.json'),
    JSON.stringify({ artifacts }),
  );
}
