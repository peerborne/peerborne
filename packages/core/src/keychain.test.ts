import { describe, expect, test, jest } from '@jest/globals';
import { Keychain, keychainHistorySinceOrFull } from './keychain.js';

describe('keychainHistorySinceOrFull', () => {
  test('calls historySince when the implementation provides it', async () => {
    const historySinceMock = jest
      .fn<(keyID: Uint8Array) => Promise<string>>()
      .mockResolvedValue('delta-since');
    const keychain: Keychain<string, string> = {
      add: async () => [new Uint8Array(), 'key', 'change'],
      history: () => 'full-history',
      merge: () => {},
      keys: async () => [],
      current: async () => [new Uint8Array(), 'current-key'],
      getKey: () => 'key',
      currentKeyChange: async () => 'current-change',
      addEpochKey: async () => 'epoch-change',
      historySince: historySinceMock as any,
    };
    const fn = keychainHistorySinceOrFull(keychain);
    const keyID = new Uint8Array([1, 2, 3]);
    const result = await fn(keyID);
    expect(historySinceMock).toHaveBeenCalledWith(keyID);
    expect(result).toBe('delta-since');
  });

  test('falls back to history() when historySince is not implemented', async () => {
    const keychain: Keychain<string, string> = {
      add: async () => [new Uint8Array(), 'key', 'change'],
      history: () => 'full-history',
      merge: () => {},
      keys: async () => [],
      current: async () => [new Uint8Array(), 'current-key'],
      getKey: () => 'key',
      currentKeyChange: async () => 'current-change',
      addEpochKey: async () => 'epoch-change',
    };
    const fn = keychainHistorySinceOrFull(keychain);
    const result = await fn(new Uint8Array([1]));
    expect(result).toBe('full-history');
  });
});
