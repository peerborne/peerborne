export const packages = [
  { name: '@peerborne/core', directory: 'packages/core', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts', 'dist/esm/src/peerborne-node.js', 'dist/esm/src/peerborne-node.d.ts', 'dist/esm/src/browser-primitives.js', 'dist/esm/src/browser-primitives.d.ts', 'dist/esm/src/wire-protocols.js', 'dist/esm/src/wire-protocols.d.ts'], bins: [] },
  { name: '@peerborne/automerge', directory: 'packages/automerge', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts'], bins: ['dist/esm/bin/peerborne-automerge-d.js'] },
  { name: '@peerborne/yjs', directory: 'packages/yjs', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts', 'dist/esm/src/editor.js', 'dist/esm/src/editor.d.ts'], bins: ['dist/esm/bin/peerborne-yjs-d.js'] },
  { name: '@peerborne/store', directory: 'packages/store', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts'], bins: [] },
  { name: '@peerborne/react', directory: 'packages/react', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts', 'dist/esm/src/store.js', 'dist/esm/src/store.d.ts'], bins: [] },
  { name: '@peerborne/redux', directory: 'packages/redux', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts'], bins: [] },
  { name: '@peerborne/index', directory: 'packages/index', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts', 'dist/esm/src/react.js', 'dist/esm/src/react.d.ts'], bins: [] },
  { name: '@peerborne/vue', directory: 'packages/vue', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts'], bins: [] },
  { name: '@peerborne/svelte', directory: 'packages/svelte', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts'], bins: [] },
  { name: '@peerborne/loro', directory: 'packages/loro', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts'], bins: [] },
  { name: '@peerborne/tanstack-db', directory: 'packages/tanstack-db', entries: ['dist/esm/src/index.js', 'dist/esm/src/index.d.ts'], bins: [] },
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
