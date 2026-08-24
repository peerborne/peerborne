export const packages = [
  { name: '@peerborne/core', directory: 'packages/core', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts', 'dist/esm/src/peerborne-node.js', 'dist/esm/src/peerborne-node.d.ts', 'dist/esm/src/browser-primitives.js', 'dist/esm/src/browser-primitives.d.ts', 'dist/cjs/src/index.js', 'dist/cjs/src/peerborne-node.js', 'dist/cjs/src/browser-primitives.js', 'dist/cjs/package.json'], bins: [] },
  { name: '@peerborne/automerge', directory: 'packages/automerge', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts', 'dist/cjs/src/index.js', 'dist/cjs/package.json'], bins: ['dist/esm/bin/peerborne-automerge-d.js'] },
  { name: '@peerborne/yjs', directory: 'packages/yjs', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts', 'dist/cjs/src/index.js', 'dist/cjs/package.json'], bins: ['dist/esm/bin/peerborne-yjs-d.js'] },
  { name: '@peerborne/react', directory: 'packages/react', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts', 'dist/cjs/src/index.js', 'dist/cjs/package.json'], bins: [] },
  { name: '@peerborne/redux', directory: 'packages/redux', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts', 'dist/cjs/src/index.js', 'dist/cjs/package.json'], bins: [] },
  { name: '@peerborne/index', directory: 'packages/index', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts', 'dist/esm/src/react.js', 'dist/esm/src/react.d.ts', 'dist/cjs/src/index.js', 'dist/cjs/src/react.js', 'dist/cjs/package.json'], bins: [] },
];

export const strictSemver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

export const stagingPattern = /^[a-z][a-z0-9._-]*$/;
export const RESERVED_TAGS = ['latest', 'next'];

export function assertStrictSemver(version) {
  if (typeof version !== 'string' || !strictSemver.test(version)) {
    throw new Error(`Invalid strict SemVer: ${String(version)}`);
  }
  return version;
}
