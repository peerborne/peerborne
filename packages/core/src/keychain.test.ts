import { describe, expect, test, jest } from '@jest/globals';
import {
  computeKeychainStateCommitment,
  isTransactionalKeychain,
  Keychain,
  keychainHistorySinceOrFull,
  MAX_KEYCHAIN_EPOCHS,
} from './keychain.js';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
}

describe('computeKeychainStateCommitment', () => {
  test('uses the stable domain-separated canonical encoding', async () => {
    expect(toHex(await computeKeychainStateCommitment([]))).toBe(
      'afa90588687d49cacdf36100e04468733207c5544dabe98108d6b572a2fa4d1f',
    );
    const commitment = await computeKeychainStateCommitment([
      [new Uint8Array(32).fill(0x11), new Uint8Array(32).fill(0xaa)],
      [new Uint8Array(32).fill(0x22), new Uint8Array(32).fill(0xbb)],
    ]);
    expect(toHex(commitment)).toBe(
      '52fba32ca5e4a5f95c53a5dd845a138e0f9e6b79cf4071131a5c581839255ce6',
    );
  });

  test('binds order and key material and snapshots input bytes', async () => {
    const firstId = new Uint8Array(32).fill(1);
    const secondId = new Uint8Array(32).fill(2);
    const firstKey = new Uint8Array(32).fill(3);
    const secondKey = new Uint8Array(32).fill(4);
    const pending = computeKeychainStateCommitment([
      [firstId, firstKey],
      [secondId, secondKey],
    ]);
    firstId.fill(9);
    firstKey.fill(9);
    const original = await pending;
    const stableOriginal = new Uint8Array(original);
    original.fill(0xff);
    expect(
      await computeKeychainStateCommitment([
        [new Uint8Array(32).fill(1), new Uint8Array(32).fill(3)],
        [secondId, secondKey],
      ]),
    ).toEqual(stableOriginal);
    const reordered = await computeKeychainStateCommitment([
      [secondId, secondKey],
      [new Uint8Array(32).fill(1), new Uint8Array(32).fill(3)],
    ]);
    const changedMaterial = await computeKeychainStateCommitment([
      [new Uint8Array(32).fill(1), new Uint8Array(32).fill(5)],
      [secondId, secondKey],
    ]);
    expect(reordered).not.toEqual(stableOriginal);
    expect(changedMaterial).not.toEqual(stableOriginal);
  });

  test('rejects malformed, duplicate, and oversized sequences', async () => {
    const id = new Uint8Array(32);
    const key = new Uint8Array(32);
    await expect(
      computeKeychainStateCommitment([
        [id, key],
        [new Uint8Array(id), new Uint8Array(key)],
      ]),
    ).rejects.toThrow('Duplicate keychain commitment key ID');
    await expect(
      computeKeychainStateCommitment([[new Uint8Array(31), key]]),
    ).rejects.toThrow('Keychain commitment key ID has an invalid length');
    await expect(
      computeKeychainStateCommitment([[id, new Uint8Array(31)]]),
    ).rejects.toThrow('Keychain commitment raw key has an invalid length');
    const oversized = Array.from(
      { length: MAX_KEYCHAIN_EPOCHS + 1 },
      () => [id, key] as const,
    );
    await expect(computeKeychainStateCommitment(oversized)).rejects.toThrow(
      'Keychain exceeds the supported epoch limit',
    );
  });
});

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

  test('rejects when historySince is not implemented', async () => {
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
    await expect(fn(new Uint8Array([1]))).rejects.toThrow(
      'Keychain does not support replay-safe history slicing',
    );
    expect(currentKeyChange).not.toHaveBeenCalled();
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
      currentKeyId: undefined,
      hydrateKeys: async () => [],
      getKey: () => undefined,
      commit: () => {},
    });

    expect(isTransactionalKeychain(keychain)).toBe(true);
  });
});
