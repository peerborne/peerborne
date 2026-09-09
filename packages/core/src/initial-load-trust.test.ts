import { describe, expect, jest, test } from '@jest/globals';
import {
  captureInitialLoadSignerAuthorities,
  MAX_INITIAL_LOAD_SIGNER_AUTHORITIES,
} from './initial-load-trust.js';

describe('captureInitialLoadSignerAuthorities', () => {
  test('uses existing writers without invoking the bootstrap resolver', async () => {
    const resolver = jest.fn(async () => ['bootstrap']);
    await expect(
      captureInitialLoadSignerAuthorities({
        documentPath: '/doc',
        existingWriterKeys: ['existing'],
        resolveTrustedDocumentWriters: resolver,
        serializePublicKey: async (key) => `id:${key}`,
      }),
    ).resolves.toEqual([
      { authorityId: 'id:existing', publicKey: 'existing' },
    ]);
    expect(resolver).not.toHaveBeenCalled();
  });

  test('snapshots the existing writer list before asynchronous serialization', async () => {
    const existing = ['writer-a'];
    const captured = await captureInitialLoadSignerAuthorities({
      documentPath: '/doc',
      existingWriterKeys: existing,
      serializePublicKey: async (key) => {
        existing.push('late-writer');
        return key;
      },
    });
    expect(captured).toEqual([
      { authorityId: 'writer-a', publicKey: 'writer-a' },
    ]);
  });

  test('calls the bootstrap resolver once and snapshots its returned list', async () => {
    const mutable = ['writer-a', 'writer-b'];
    const resolver = jest.fn(async () => mutable);
    const captured = await captureInitialLoadSignerAuthorities({
      documentPath: '/doc',
      existingWriterKeys: [],
      resolveTrustedDocumentWriters: resolver,
      serializePublicKey: async (key) => key,
    });
    mutable.splice(0, mutable.length, 'attacker');

    expect(resolver).toHaveBeenCalledTimes(1);
    expect(captured).toEqual([
      { authorityId: 'writer-a', publicKey: 'writer-a' },
      { authorityId: 'writer-b', publicKey: 'writer-b' },
    ]);
  });

  test('deduplicates canonical signer authority IDs', async () => {
    await expect(
      captureInitialLoadSignerAuthorities({
        documentPath: '/doc',
        existingWriterKeys: ['same-key-copy-1', 'same-key-copy-2', 'other'],
        serializePublicKey: async (key) =>
          key.startsWith('same-key') ? 'authority-a' : 'authority-b',
      }),
    ).resolves.toEqual([
      { authorityId: 'authority-a', publicKey: 'same-key-copy-1' },
      { authorityId: 'authority-b', publicKey: 'other' },
    ]);
  });

  test('fails closed when no trusted signer authority can be captured', async () => {
    await expect(
      captureInitialLoadSignerAuthorities({
        documentPath: '/doc',
        existingWriterKeys: [],
        serializePublicKey: async (key) => String(key),
      }),
    ).rejects.toThrow(/resolveTrustedDocumentWriters/);

    const resolver = jest.fn(async () => [] as string[]);
    await expect(
      captureInitialLoadSignerAuthorities({
        documentPath: '/doc',
        existingWriterKeys: [],
        resolveTrustedDocumentWriters: resolver,
        serializePublicKey: async (key) => key,
      }),
    ).rejects.toThrow(/no trusted writer authorities/);
    expect(resolver).toHaveBeenCalledTimes(1);
  });

  test.each([
    ['a lone surrogate', `writer-\ud800`],
    ['an oversized UTF-8 identity', 'é'.repeat(513)],
  ])('rejects malformed authority IDs containing %s', async (_name, id) => {
    await expect(
      captureInitialLoadSignerAuthorities({
        documentPath: '/doc',
        existingWriterKeys: ['writer'],
        serializePublicKey: async () => id,
      }),
    ).rejects.toThrow(/well-formed|exceeds/);
  });

  test('rejects an over-limit trust set before serializing it', async () => {
    const serializePublicKey = jest.fn(async (key: number) => String(key));
    await expect(
      captureInitialLoadSignerAuthorities({
        documentPath: '/doc',
        existingWriterKeys: Array.from(
          { length: MAX_INITIAL_LOAD_SIGNER_AUTHORITIES + 1 },
          (_, index) => index,
        ),
        serializePublicKey,
      }),
    ).rejects.toThrow(/authority count exceeds/);
    expect(serializePublicKey).not.toHaveBeenCalled();
  });
});
