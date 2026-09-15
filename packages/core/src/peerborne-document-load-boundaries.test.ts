import { describe, expect, jest, test } from '@jest/globals';

import {
  MAX_DOCUMENT_LOAD_RESPONSE_SIZE,
  PeerborneDocument,
} from './peerborne-document.js';
import { tipsHash, tipsHashToHex } from './tips-hash.js';

jest.mock(
  'it-pipe',
  () => ({
    pipe: async (...stages: unknown[]) => {
      let value = stages[0];
      for (const stage of stages.slice(1)) {
        value = await (stage as (input: unknown) => unknown)(value);
      }
      return value;
    },
  }),
  { virtual: true },
);
jest.mock(
  'multiformats',
  () => ({
    CID: class {
      static parse(value: string) {
        return { toString: () => value };
      }
    },
  }),
  { virtual: true },
);
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

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function signedLoadHarness(
  getWriterKeys: () => Promise<string[]>,
  verify: (...args: unknown[]) => Promise<boolean>,
  message: any = { documentId: '/load-race', signature: 'AAAA' },
  serializeSyncMessage: (message: any) => Uint8Array = () =>
    new Uint8Array([8]),
) {
  const document = fakeDocument({
    documentPath: message.documentId,
    swarm: { config: { enableSigning: true, loadQuorumTimeoutMs: 1000 } },
    _keychainProvider: { keyIDLength: 1 },
    _keychain: { getKey: jest.fn(() => ({})) },
    _authProvider: {
      nonceBits: 1,
      decrypt: jest.fn(async () => new Uint8Array([9])),
      verify: jest.fn(verify),
    },
    _syncMessageSerializer: {
      deserializeSyncMessage: jest.fn(() => message),
      serializeSyncMessage: jest.fn(serializeSyncMessage),
    },
    _getWriterKeys: jest.fn(getWriterKeys),
    _mutationQueue: {
      run: (operation: () => Promise<unknown>) => operation(),
    },
    _hashes: new Set<string>(),
  });
  const stream = {
    sink: jest.fn(async () => undefined),
    source: (async function* () {
      yield new Uint8Array([1, 2, 3]);
    })(),
    abort: jest.fn(),
  };
  return { document, stream };
}

describe('document load response boundaries', () => {
  test('rejects a cross-context load response before sync', async () => {
    const syncValidatedProtocolMessage = jest.fn();
    const document = fakeDocument({
      documentPath: '/doc',
      swarm: { config: { loadQuorumTimeoutMs: 1000 } },
      _keychainProvider: { keyIDLength: 1 },
      _authProvider: {
        nonceBits: 1,
        decrypt: jest.fn(async () => new Uint8Array([9])),
      },
      _keychain: { getKey: jest.fn(() => ({})) },
      _syncMessageSerializer: {
        deserializeSyncMessage: jest.fn(() => ({
          documentId: '/doc',
          signatureContext: 'invitation-bootstrap-v1',
        })),
      },
      _syncValidatedProtocolMessage: syncValidatedProtocolMessage,
    });
    const stream = {
      sink: jest.fn(async () => undefined),
      source: (async function* () {
        yield new Uint8Array([1, 2, 3]);
      })(),
      abort: jest.fn(),
    };

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).rejects.toThrow(/signatureContext/);
    expect(syncValidatedProtocolMessage).not.toHaveBeenCalled();
  });

  test('rechecks current writers after an admitted signer is removed', async () => {
    const verificationStarted = deferred<void>();
    const releaseVerification = deferred<boolean>();
    let currentWriters = ['removed-writer'];
    const { document, stream } = signedLoadHarness(
      async () => {
        throw new Error('prototype writer lookup must be used');
      },
      async () => {
        verificationStarted.resolve();
        return releaseVerification.promise;
      },
    );
    delete document._getWriterKeys;
    document._writers = {
      users: jest.fn(async () => [...currentWriters]),
    };
    document._writerMutationsInFlight = 1;
    document._writerKeysVersion = 1;
    document._cachedWriterKeys = null;

    const load = document._sendLoadRequestAndSync(
      stream,
      new Uint8Array([1]),
    );
    await verificationStarted.promise;
    currentWriters = [];
    document._writerMutationsInFlight = 0;
    document._invalidateWriterKeyCache();
    releaseVerification.resolve(true);

    await expect(load).resolves.toBe(false);
    expect(document._writers.users).toHaveBeenCalledTimes(2);
    expect(document._authProvider.verify).toHaveBeenCalledTimes(1);
  });

  test('ends bootstrap trust if a writer exists at queued application', async () => {
    let writerRead = 0;
    const { document, stream } = signedLoadHarness(
      async () => (++writerRead === 1 ? [] : ['current-writer']),
      async () => false,
    );

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).resolves.toBe(false);

    expect(document._getWriterKeys).toHaveBeenCalledTimes(2);
    expect(document._authProvider.verify).toHaveBeenCalledTimes(1);
  });

  test('rechecks original signed bytes after quorum strips inline changes', async () => {
    const message = {
      documentId: '/load-race',
      signature: 'AAAA',
      changeId: 'HEAD',
      tips: ['HEAD'],
      changes: {
        kind: 'document',
        change: { value: 'signed-inline-change' },
      },
    };
    const verifiedRaw: number[][] = [];
    const serialize = jest.fn((unsigned: any) =>
      new Uint8Array([unsigned.changes?.change === undefined ? 0 : 1]),
    );
    const { document, stream } = signedLoadHarness(
      async () => ['current-writer'],
      async (raw) => {
        verifiedRaw.push([...raw as Uint8Array]);
        return (raw as Uint8Array)[0] === 1;
      },
      message,
      serialize,
    );
    document._writers = {
      users: jest.fn(async () => ['current-writer']),
    };
    document.swarm.heliaNode = {
      blockstore: {
        get: jest.fn(async function* () {
          yield new Uint8Array([1]);
        }),
      },
    };
    document._syncUnlocked = jest.fn(
      async (appliedMessage: any, verifySignature: boolean) => {
        expect(verifySignature).toBe(false);
        expect(appliedMessage.changes.change).toBeUndefined();
        document._hashes.add('HEAD');
        return true;
      },
    );
    const expectedTipsHash = tipsHashToHex(await tipsHash(['HEAD']));

    await expect(
      document._sendLoadRequestAndSync(
        stream,
        new Uint8Array([1]),
        expectedTipsHash,
      ),
    ).resolves.toBe(true);

    expect(verifiedRaw).toEqual([[1], [1]]);
    expect(serialize).toHaveBeenCalledTimes(1);
    expect(document._syncUnlocked).toHaveBeenCalledTimes(1);
  });

  test('accepts encrypted-channel bootstrap only for a pristine empty-writer document', async () => {
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => {
        throw new Error('bootstrap must not invoke signature verification');
      },
    );

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).resolves.toBe(true);

    document._hashes.add('existing-change');
    const nextStream = {
      ...stream,
      source: (async function* () {
        yield new Uint8Array([1, 2, 3]);
      })(),
    };
    await expect(
      document._sendLoadRequestAndSync(nextStream, new Uint8Array([1])),
    ).resolves.toBe(false);
    expect(document._authProvider.verify).not.toHaveBeenCalled();
  });

  test('preserves an explicitly pinned load signer outside the writer ACL', async () => {
    const { document, stream } = signedLoadHarness(
      async () => {
        throw new Error('pinned admission must not read the writer ACL');
      },
      async (_raw, key) => key === 'pinned-writer',
    );

    await expect(
      document._sendLoadRequestAndSync(
        stream,
        new Uint8Array([1]),
        null,
        'pinned-writer',
      ),
    ).resolves.toBe(true);

    expect(document._getWriterKeys).not.toHaveBeenCalled();
    expect(document._authProvider.verify).toHaveBeenCalledTimes(1);
  });

  test('bounds ordinary document responses before deserialization', async () => {
    const abort = jest.fn();
    const document = fakeDocument({
      swarm: { config: { loadQuorumTimeoutMs: 1000 } },
    });
    const stream = {
      sink: jest.fn(async () => undefined),
      source: (async function* () {
        yield new Uint8Array(MAX_DOCUMENT_LOAD_RESPONSE_SIZE + 1);
      })(),
      abort,
    };

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).rejects.toThrow(/maximum allowed size/);
    expect(abort).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'Document load response rejected' }),
    );
  });

  test('aborts a normal load whose peer withholds response EOF', async () => {
    jest.useFakeTimers();
    const abort = jest.fn();
    const document = fakeDocument({
      swarm: { config: { loadQuorumTimeoutMs: 25 } },
    });
    const stream = {
      sink: jest.fn(async () => undefined),
      source: {
        [Symbol.asyncIterator]: () => ({
          next: () => new Promise<IteratorResult<Uint8Array>>(() => {}),
        }),
      },
      abort,
    };

    try {
      const result = expect(
        document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
      ).rejects.toThrow(/response deadline exceeded/);
      await jest.advanceTimersByTimeAsync(25);
      await result;
      expect(abort).toHaveBeenCalledTimes(1);
      expect(abort).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Document load response deadline exceeded',
        }),
      );
      expect(jest.getTimerCount()).toBe(0);
    } finally {
      jest.useRealTimers();
    }
  });

  test.each([1, 2])(
    'rejects a tip advertisement serializer that mutates on call %i',
    async (mutationCall) => {
      const rawStream = {
        send: jest.fn(() => true),
        onDrain: jest.fn(async () => undefined),
        close: jest.fn(async () => undefined),
        closeRead: jest.fn(async () => undefined),
        abort: jest.fn(),
        async *[Symbol.asyncIterator]() {
          yield new Uint8Array([1, 2, 3]);
        },
      };
      const message = {
        documentId: '/tip-advertisement',
        signatureContext: 'tip-advertisement-v1',
        tipsHash: new Uint8Array(32).fill(1),
        signature: 'AQ==',
      };
      let serializationCount = 0;
      const document = fakeDocument({
        documentPath: '/tip-advertisement',
        swarm: {
          heliaNode: {
            libp2p: { dialProtocol: jest.fn(async () => rawStream) },
          },
        },
        _keychainProvider: { keyIDLength: 1 },
        _keychain: { getKey: () => ({}) },
        _authProvider: {
          nonceBits: 1,
          decrypt: async () => new Uint8Array([1]),
          verify: async () => true,
        },
        _syncMessageSerializer: {
          deserializeSyncMessage: () => message,
          serializeSyncMessage: (unsigned: typeof message) => {
            serializationCount += 1;
            if (serializationCount === mutationCall) {
              unsigned.tipsHash[0] = 2;
            }
            return new Uint8Array([1]);
          },
        },
        _isSigningEnabled: () => true,
        _deserializeSignature: () => new Uint8Array([1]),
        _getWriterKeys: async () => ['writer'],
      });

      await expect(
        document._probeTipAdvertise({}, new Uint8Array([1])),
      ).resolves.toBeNull();
      expect(serializationCount).toBe(mutationCall);
    },
  );

  test('fully aborts a completed probe even when the peer response ends early', async () => {
    const rawStream = {
      send: jest.fn(() => true),
      onDrain: jest.fn(async () => undefined),
      close: jest.fn(async () => undefined),
      closeRead: jest.fn(async () => undefined),
      abort: jest.fn(),
      async *[Symbol.asyncIterator]() {
        yield new Uint8Array([0xff]);
      },
    };
    const document = fakeDocument({
      swarm: {
        heliaNode: {
          libp2p: { dialProtocol: jest.fn(async () => rawStream) },
        },
      },
    });

    await expect(
      document._probeTipAdvertise({}, new Uint8Array([1])),
    ).resolves.toBe('unknown-doc');
    expect(rawStream.close).toHaveBeenCalledTimes(1);
    expect(rawStream.abort).toHaveBeenCalledTimes(1);
    expect(rawStream.abort).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'tip-advertise probe completed' }),
    );
    expect(rawStream.closeRead).not.toHaveBeenCalled();
  });

  test('treats a cross-context tip advertisement as a non-vote', async () => {
    const verify = jest.fn();
    const rawStream = {
      send: jest.fn(() => true),
      onDrain: jest.fn(async () => undefined),
      close: jest.fn(async () => undefined),
      closeRead: jest.fn(async () => undefined),
      abort: jest.fn(),
      async *[Symbol.asyncIterator]() {
        yield new Uint8Array([1, 2, 3]);
      },
    };
    const document = fakeDocument({
      documentPath: '/doc',
      swarm: {
        heliaNode: {
          libp2p: { dialProtocol: jest.fn(async () => rawStream) },
        },
      },
      _keychainProvider: { keyIDLength: 1 },
      _authProvider: {
        nonceBits: 1,
        decrypt: jest.fn(async () => new Uint8Array([9])),
        verify,
      },
      _keychain: { getKey: jest.fn(() => ({})) },
      _syncMessageSerializer: {
        deserializeSyncMessage: jest.fn(() => ({
          documentId: '/doc',
          signatureContext: 'load-response-v3',
        })),
      },
    });

    await expect(
      document._probeTipAdvertise({}, new Uint8Array([1])),
    ).resolves.toBeNull();
    expect(verify).not.toHaveBeenCalled();
  });
});
