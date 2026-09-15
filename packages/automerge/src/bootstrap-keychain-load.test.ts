import { describe, expect, jest, test } from '@jest/globals';
import { PeerborneDocument } from '@peerborne/core';

import { AutomergeKeychainProvider } from './peerborne-automerge.js';

function documentWithKeychain(keychain: unknown): any {
  return Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath: '/automerge-bootstrap-keychain',
    swarm: { config: { enableSigning: false } },
    _bootstrapLoadApplicationState: 'pristine',
    _keychain: keychain,
  });
}

describe('Automerge bootstrap keychain application', () => {
  test('treats the canonical non-empty encoding of an empty history as a no-op', async () => {
    const provider = new AutomergeKeychainProvider();
    const source = provider.initialize();
    const target = provider.initialize();
    const emptyHistory = source.history();
    const document = documentWithKeychain(target);
    const beginStateApplication = jest.fn();
    const logicalKeychainChange = jest.fn();
    const noOpCommit = jest.fn();
    const originalPrepareMerge = target.prepareMerge.bind(target);
    const prepareMerge = jest
      .spyOn(target, 'prepareMerge')
      .mockImplementation((changes) => {
        const prepared = originalPrepareMerge(changes);
        const commit = prepared.commit.bind(prepared);
        return {
          ...prepared,
          commit: () => {
            noOpCommit();
            commit();
          },
        };
      });

    expect(emptyHistory).not.toEqual([]);
    await expect(
      document._syncUnlocked(
        {
          documentId: '/automerge-bootstrap-keychain',
          keychainChanges: emptyHistory,
        },
        false,
        beginStateApplication,
        false,
        logicalKeychainChange,
      ),
    ).resolves.toBe(true);

    expect(beginStateApplication).not.toHaveBeenCalled();
    expect(logicalKeychainChange).not.toHaveBeenCalled();
    expect(noOpCommit).toHaveBeenCalledTimes(1);
    await expect(target.keys()).resolves.toEqual([]);

    prepareMerge.mockRestore();
    const [keyId, , dependentChanges] = await source.add();
    await expect(
      document._syncUnlocked(
        {
          documentId: '/automerge-bootstrap-keychain',
          keychainChanges: dependentChanges,
        },
        false,
        beginStateApplication,
        false,
        logicalKeychainChange,
      ),
    ).resolves.toBe(true);
    expect(beginStateApplication).toHaveBeenCalledTimes(1);
    expect(logicalKeychainChange).toHaveBeenCalledTimes(1);
    expect(target.getKey(keyId)).toBeDefined();
    await expect(target.keys()).resolves.toHaveLength(1);
  });
});
