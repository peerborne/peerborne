import { describe, expect, test, jest } from '@jest/globals';
import {
  isTransactionalKeychain,
  Keychain,
  keychainHistorySinceOrFull,
} from './keychain.js';

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

  test('falls back to currentKeyChange() when historySince is not implemented', async () => {
    const history = jest.fn(() => 'full-history');
    const currentKeyChange = jest
      .fn<() => Promise<string>>()
      .mockResolvedValue('current-change');
    const keychain: Keychain<string, string> = {
      add: async () => [new Uint8Array(), 'key', 'change'],
      history,
      merge: () => {},
      keys: async () => [],
      current: async () => [new Uint8Array(), 'current-key'],
      getKey: () => 'key',
      currentKeyChange,
      addEpochKey: async () => 'epoch-change',
    };
    const fn = keychainHistorySinceOrFull(keychain);
    const result = await fn(new Uint8Array([1]));
    expect(result).toBe('current-change');
    expect(currentKeyChange).toHaveBeenCalledTimes(1);
    expect(history).not.toHaveBeenCalled();
  });
});

describe('isTransactionalKeychain', () => {
  const makeKeychain = (): Keychain<string, string> => ({
    add: async () => [new Uint8Array(), 'key', 'change'],
    history: () => 'full-history',
    merge: () => {},
    keys: async () => [],
    current: async () => [new Uint8Array(), 'current-key'],
    getKey: () => 'key',
    currentKeyChange: async () => 'current-change',
    addEpochKey: async () => 'epoch-change',
  });

  test('rejects a legacy keychain that lacks atomic staging', () => {
    expect(isTransactionalKeychain(makeKeychain())).toBe(false);
  });

  test('accepts a keychain with both BeeKEM staging operations', () => {
    const keychain = makeKeychain();
    keychain.prepareEpochKey = async () => ({
      changes: 'change',
      history: 'history',
      currentKeyChange: 'current',
      commit: () => {},
    });
    keychain.prepareMerge = () => ({
      changes: 'change',
      keyIds: [],
      commit: () => {},
    });

    expect(isTransactionalKeychain(keychain)).toBe(true);
  });
});
