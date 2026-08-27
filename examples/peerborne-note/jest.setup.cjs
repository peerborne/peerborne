require('fake-indexeddb/auto');

const { webcrypto } = require('node:crypto');

Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: webcrypto,
});
