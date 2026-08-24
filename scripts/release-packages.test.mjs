import assert from 'node:assert/strict';
import test from 'node:test';
import { assertStrictSemver, packages } from './release-packages.mjs';

test('release package allowlist is exact and ordered', () => {
  assert.deepEqual(packages.map(({ name }) => name), [
    '@peerborne/core',
    '@peerborne/automerge',
    '@peerborne/yjs',
    '@peerborne/react',
    '@peerborne/redux',
    '@peerborne/index',
  ]);
});

test('strict SemVer accepts releases and prereleases', () => {
  for (const version of ['0.1.0', '1.2.3-alpha.1', '1.2.3+build.5']) assert.equal(assertStrictSemver(version), version);
});

test('strict SemVer rejects malformed and noncanonical versions', () => {
  for (const version of ['', 'v1.2.3', '1.2', '01.2.3', '1.2.03', '1.2.3-01', '1.2.3-']) {
    assert.throws(() => assertStrictSemver(version));
  }
});
