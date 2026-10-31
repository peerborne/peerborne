import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { basename, dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertStrictSemver, packages } from './release-packages.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
if (args.length !== 1) throw new Error('Usage: node scripts/prepare-release.mjs <output-directory>');
const output = resolve(args[0]);
if (output === root || !relative(output, root).startsWith('..')) throw new Error('Output directory must not be within the repository tree');
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });

let releaseVersion;
const artifacts = [];
const forbiddenPath = /(?:^|\/)(?:__tests__|__benchmarks__|__mocks__|test|tests|benchmarks?|mocks?|cjs)(?:\/|$)|(?:\.test|\.spec)\.[^/]+$|\.map$|\.tsbuildinfo$/i;
const secretPath = /(?:^|\/)(?:\.env(?:\..*)?|id_rsa|id_ed25519|.*\.(?:pem|key|p12|pfx))(?:$|\/)/i;

for (const entry of packages) {
  const sourceManifest = JSON.parse(await readFile(resolve(root, entry.directory, 'package.json'), 'utf8'));
  if (sourceManifest.name !== entry.name) throw new Error(`Unexpected package name in ${entry.directory}`);
  const version = assertStrictSemver(sourceManifest.version);
  if (releaseVersion === undefined) releaseVersion = version;
  if (version !== releaseVersion) throw new Error(`${entry.name} is ${version}; expected ${releaseVersion}`);
  if (sourceManifest.license !== 'MIT') throw new Error(`${entry.name} must use MIT`);

  const filename = `${entry.name.replace('@', '').replace('/', '-')}-${version}.tgz`;
  const path = resolve(output, filename);
  const packed = spawnSync('yarn', ['workspace', entry.name, 'pack', '--out', path], {
    cwd: root,
    encoding: 'utf8',
  });
  if (packed.error) throw packed.error;
  if (packed.status !== 0) throw new Error(`Packing ${entry.name} failed:\n${packed.stderr}`);

  const listed = spawnSync('tar', ['-tzf', path], { encoding: 'utf8' });
  if (listed.error) throw listed.error;
  if (listed.status !== 0) throw new Error(`Cannot inspect ${filename}`);
  const files = listed.stdout.trim().split('\n').map((file) => file.replace(/^package\//, '')).filter(Boolean);
  for (const required of ['package.json', 'README.md', 'LICENSE', ...entry.entries, ...entry.bins]) {
    if (!files.includes(required)) throw new Error(`${filename} is missing ${required}`);
  }
  const forbidden = files.find((file) => forbiddenPath.test(file) || secretPath.test(file));
  if (forbidden) throw new Error(`${filename} contains forbidden path ${forbidden}`);

  const archive = spawnSync('tar', ['-xOzf', path], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (archive.error) throw archive.error;
  if (archive.status !== 0) throw new Error(`Cannot scan ${filename}`);
  if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|npm_[A-Za-z0-9]{36}|\/\/[\w.-]+\/:_authToken\s*=|(?:NPM|NODE_AUTH)_TOKEN\s*=/.test(archive.stdout)) {
    throw new Error(`${filename} contains secret-like content`);
  }
  if (archive.stdout.includes('workspace:')) throw new Error(`${filename} leaks a workspace protocol`);

  const extracted = spawnSync('tar', ['-xOzf', path, 'package/package.json'], { encoding: 'utf8' });
  if (extracted.error) throw extracted.error;
  if (extracted.status !== 0) throw new Error(`Cannot read package.json from ${filename}`);
  const packedManifest = JSON.parse(extracted.stdout);
  if (packedManifest.name !== entry.name || packedManifest.version !== version || packedManifest.license !== 'MIT') {
    throw new Error(`${filename} has unexpected package metadata`);
  }
  if (JSON.stringify(packedManifest).includes('workspace:')) throw new Error(`${filename} leaks a workspace protocol`);

  const bytes = await readFile(path);
  const integrity = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
  const dryRun = spawnSync(
    'npm',
    ['publish', path, '--access', 'public', '--dry-run', '--json'],
    { encoding: 'utf8', env: { ...process.env, NODE_AUTH_TOKEN: undefined, NPM_TOKEN: undefined } },
  );
  if (dryRun.error) throw dryRun.error;
  if (dryRun.status !== 0) throw new Error(`npm dry-run failed for ${filename}:\n${dryRun.stderr}`);
  const dryRunOutput = JSON.parse(dryRun.stdout);
  const npmReport = dryRunOutput[entry.name] ?? dryRunOutput;
  if (
    npmReport.name !== entry.name ||
    npmReport.version !== version ||
    npmReport.integrity !== integrity
  ) {
    throw new Error(`npm dry-run reported unexpected metadata for ${filename}`);
  }
  const npmFiles = npmReport.files.map(({ path: file }) => file).sort();
  if (JSON.stringify(npmFiles) !== JSON.stringify([...files].sort())) {
    throw new Error(`npm dry-run reported unexpected files for ${filename}`);
  }

  artifacts.push({
    name: entry.name,
    version,
    filename: basename(path),
    integrity,
    files,
  });
}

const unexpected = (await readdir(output)).filter((name) => name !== 'release-manifest.json' && !artifacts.some((item) => item.filename === name));
if (unexpected.length) throw new Error(`Unexpected release artifacts: ${unexpected.join(', ')}`);
await writeFile(resolve(output, 'release-manifest.json'), `${JSON.stringify({ version: releaseVersion, packageOrder: packages.map(({ name }) => name), artifacts }, null, 2)}\n`);
