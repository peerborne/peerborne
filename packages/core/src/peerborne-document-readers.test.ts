import { describe, expect, jest, test } from '@jest/globals';
import { PeerborneDocument } from './peerborne-document.js';
import { UCANACL } from './ucan-acl.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('multiformats', () => ({ CID: class {} }), { virtual: true });
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({ TopicValidatorResult: { Accept: 'accept', Reject: 'reject' } }),
  { virtual: true },
);
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock('./peerborne.js', () => ({
  MAX_DOCUMENT_PATH_LENGTH: 4096,
  Peerborne: class {},
}));

function fakeDocument(fields: Record<string, unknown>): any {
  return Object.assign(Object.create(PeerborneDocument.prototype), fields);
}

describe('PeerborneDocument reader listing', () => {
  test('deduplicates detached canonical identities without ACL checks', async () => {
    const readers = [
      { id: 'shared', source: 'reader' },
      { id: 'reader-only', source: 'reader' },
    ];
    const writers = [
      { id: 'shared', source: 'writer' },
      { id: 'writer-only', source: 'writer' },
    ];
    const check = jest.fn(() => {
      throw new Error('canonical dedup must not call ACL.check');
    });
    let serializationsInFlight = 0;
    let maximumSerializationsInFlight = 0;
    const serializePublicKey = jest.fn(async (key: { id: string }) => {
      serializationsInFlight++;
      maximumSerializationsInFlight = Math.max(
        maximumSerializationsInFlight,
        serializationsInFlight,
      );
      try {
        await Promise.resolve();
        return key.id;
      } finally {
        serializationsInFlight--;
      }
    });
    const document = fakeDocument({
      _authProvider: { serializePublicKey },
      _readers: {
        users: async () => readers,
        check,
      },
      _writers: { users: async () => writers },
    });

    await expect(document.getReaders()).resolves.toEqual([
      ...readers,
      writers[1],
    ]);
    expect(serializePublicKey).toHaveBeenCalledTimes(
      readers.length + writers.length,
    );
    expect(maximumSerializationsInFlight).toBe(1);
    expect(check).not.toHaveBeenCalled();
  });

  test('propagates canonical serializer failures without ACL fallback', async () => {
    const failure = new Error('serializer failed');
    const check = jest.fn();
    const document = fakeDocument({
      _authProvider: {
        serializePublicKey: async () => {
          throw failure;
        },
      },
      _readers: {
        users: async () => [{ id: 'reader' }],
        check,
      },
      _writers: { users: async () => [{ id: 'writer' }] },
    });

    await expect(document.getReaders()).rejects.toBe(failure);
    expect(check).not.toHaveBeenCalled();
  });

  test('rejects a present non-function canonical serializer', async () => {
    const check = jest.fn();
    const document = fakeDocument({
      _authProvider: { serializePublicKey: 'not-a-function' },
      _readers: {
        users: async () => [{ id: 'reader' }],
        check,
      },
      _writers: { users: async () => [{ id: 'writer' }] },
    });

    await expect(document.getReaders()).rejects.toThrow(
      /serializePublicKey must be a function/,
    );
    expect(check).not.toHaveBeenCalled();
  });

  test.each<[string, unknown, RegExp]>([
    ['an empty identity', '', /non-empty string/],
    ['a non-string identity', 7, /non-empty string/],
    ['an unpaired surrogate', '\ud800', /well-formed UTF-16/],
  ])(
    'rejects %s from the canonical serializer',
    async (_description, identity, expected) => {
      const check = jest.fn();
      const document = fakeDocument({
        _authProvider: {
          serializePublicKey: async () => identity,
        },
        _readers: {
          users: async () => [{ id: 'reader' }],
          check,
        },
        _writers: { users: async () => [{ id: 'writer' }] },
      });

      await expect(document.getReaders()).rejects.toThrow(expected);
      expect(check).not.toHaveBeenCalled();
    },
  );

  test('falls back without a serializer and does not fan out UCAN checks', async () => {
    const readers = [{ id: 'shared' }, { id: 'reader-only' }];
    const writers = [
      { id: 'shared' },
      { id: 'writer-one' },
      { id: 'writer-two' },
    ];
    const backing = {
      add: async () => new Uint8Array(),
      remove: async () => new Uint8Array(),
      current: () => new Uint8Array(),
      merge: () => undefined,
      check: async (key: { id: string }) =>
        readers.some(({ id }) => id === key.id),
      users: async () => readers,
    };
    const readersACL = new UCANACL(
      backing,
      async (key: { id: string }) => key.id,
      async (id) => ({ id }),
    );
    const check = jest.spyOn(readersACL, 'check');
    const document = fakeDocument({
      _authProvider: {},
      _readers: readersACL,
      _writers: { users: async () => writers },
    });

    await expect(document.getReaders()).resolves.toEqual([
      ...readers,
      writers[1],
      writers[2],
    ]);
    expect(check).toHaveBeenCalledTimes(writers.length);
  });

  test('legacy fallback only treats literal true as reader membership', async () => {
    const reader = { id: 'reader' };
    const writer = { id: 'writer' };
    const document = fakeDocument({
      _authProvider: {},
      _readers: {
        users: async () => [reader],
        check: async () => ({ member: true }) as unknown as boolean,
      },
      _writers: { users: async () => [writer] },
    });

    await expect(document.getReaders()).resolves.toEqual([reader, writer]);
  });
});

describe('PeerborneDocument writer removal', () => {
  test('re-removes a writer that a remote change re-added after a local revocation', async () => {
    const members = new Set(['writer']);
    const backing = {
      add: async (key: string) => {
        members.add(key);
        return new Uint8Array([1]);
      },
      remove: async (key: string) => {
        members.delete(key);
        return new Uint8Array([2]);
      },
      prepareRemove: jest.fn(async (key: string) => ({
        changes: new Uint8Array([2]),
        commit: () => {
          members.delete(key);
        },
      })),
      current: () => new Uint8Array(),
      merge: () => {
        members.add('writer');
      },
      check: async (key: string) => members.has(key),
      users: async () => [...members],
    };
    const writersACL = new UCANACL(backing, async (key: string) => key);
    const publish = jest.fn(
      async (prepared: { commit(): void }) => prepared.commit(),
    );
    const document = fakeDocument({
      _readers: { check: async () => true },
      _writers: writersACL,
      _ensureCurrentUserCanWrite: async () => undefined,
      _publishPreparedWriterChange: publish,
    });

    await document._removeWriterUnlocked('writer', true);
    writersACL.merge(new Uint8Array([3]));
    await document._removeWriterUnlocked('writer', true);

    expect(backing.prepareRemove).toHaveBeenCalledTimes(2);
    expect(publish).toHaveBeenCalledTimes(2);
    expect(members.has('writer')).toBe(false);
  });
});
