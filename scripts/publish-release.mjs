import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { basename, resolve } from 'node:path';
import { assertStrictSemver, packages, stagingPattern, RESERVED_TAGS } from './release-packages.mjs';

const args = process.argv.slice(2);
if (args.length !== 3) throw new Error('Usage: node scripts/publish-release.mjs <artifact-directory> <staging-tag> <target-tag>');
const [artifactDirectory, stagingTag, targetTag] = args;
if (!stagingPattern.test(stagingTag) || RESERVED_TAGS.includes(stagingTag)) throw new Error('Invalid staging dist-tag');
if (!RESERVED_TAGS.includes(targetTag)) throw new Error('Target dist-tag must be latest or next');

const release = JSON.parse(await readFile(resolve(artifactDirectory, 'release-manifest.json'), 'utf8'));
if (JSON.stringify(release.packageOrder) !== JSON.stringify(packages.map(({ name }) => name))) throw new Error('Unexpected package order');
if (!Array.isArray(release.artifacts) || JSON.stringify(release.artifacts.map(({ name }) => name)) !== JSON.stringify(release.packageOrder)) {
  throw new Error('Unexpected artifact allowlist or order');
}
const releaseVersion = assertStrictSemver(release.version);
for (const artifact of release.artifacts) {
  if (artifact.version !== releaseVersion || basename(artifact.filename) !== artifact.filename) throw new Error(`Invalid artifact metadata for ${artifact.name}`);
  const bytes = await readFile(resolve(artifactDirectory, artifact.filename));
  const integrity = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
  if (integrity !== artifact.integrity) throw new Error(`${artifact.filename} does not match its release integrity`);
}

for (const artifact of release.artifacts) {
  const existing = registryIntegrity(artifact.name, artifact.version);
  if (existing !== undefined) {
    if (existing !== artifact.integrity) throw new Error(`${artifact.name}@${artifact.version} exists with different integrity`);
    continue;
  }
  run(['publish', resolve(artifactDirectory, artifact.filename), '--access', 'public', '--tag', stagingTag, '--provenance']);
}

for (const artifact of release.artifacts) {
  const existing = registryIntegrity(artifact.name, artifact.version);
  if (existing !== artifact.integrity) throw new Error(`${artifact.name}@${artifact.version} failed registry integrity verification`);
}

for (const artifact of release.artifacts) {
  run(['dist-tag', 'add', `${artifact.name}@${artifact.version}`, targetTag]);
}

function registryIntegrity(name, version) {
  const result = spawnSync('npm', ['view', `${name}@${version}`, 'dist.integrity', '--json'], { encoding: 'utf8', env: process.env });
  if (result.status === 0) {
    const parsed = JSON.parse(result.stdout);
    if (typeof parsed !== 'string') throw new Error(`Malformed registry integrity for ${name}@${version}`);
    return parsed;
  }
  if (/E404|404 Not Found/.test(result.stderr)) return undefined;
  throw new Error(`Registry lookup failed for ${name}@${version}: ${result.stderr.trim()}`);
}

function run(commandArgs) {
  const result = spawnSync('npm', commandArgs, { encoding: 'utf8', stdio: 'inherit', env: process.env });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`npm ${commandArgs[0]} failed with status ${result.status}`);
}
