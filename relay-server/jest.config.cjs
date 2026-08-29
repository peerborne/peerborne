/** @type {import('jest').Config} */
module.exports = {
  // The relay and its libp2p dependencies are ESM. Tests use the same module
  // format as production so identity persistence exercises the pinned crypto
  // implementation instead of a mock.
  rootDir: __dirname,
  roots: ['<rootDir>/src'],
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        tsconfig: '<rootDir>/tsconfig.test.json',
        useESM: true,
        diagnostics: { ignoreCodes: [151002] },
      },
    ],
  },
  // Runtime sources use ESM-style relative imports ending in `.js`; rewrite
  // those to the TypeScript sources during tests.
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],
}
