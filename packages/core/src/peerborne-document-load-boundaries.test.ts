import { describe, expect, jest, test } from '@jest/globals';

import {
  MAX_DOCUMENT_LOAD_RESPONSE_SIZE,
  PeerborneDocument,
} from './peerborne-document.js';
import {
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
} from './crdt-change-node.js';
import { withIssuerPinnedInvitationStream } from './invitation-catch-up.js';
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
  () => ({
    TopicValidatorResult: {
      Accept: 'accept',
      Reject: 'reject',
      Ignore: 'ignore',
    },
  }),
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
    _pendingWelcomes: new Map(),
    _pendingBootstrapRemoteUpdateHashes: new Set<string>(),
    _remoteHandlers: {},
    _localHandlers: {},
    _bootstrapLoadApplicationState: 'pristine',
    _bootstrapLoadApplicationRevision: 0,
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
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        onStateApplicationStart?: () => void,
      ) => {
        onStateApplicationStart?.();
        document._hashes.add('bootstrap-head');
        return true;
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

  test('does not restore bootstrap trust after a failed load partially applies ACL state', async () => {
    const firstMessage = {
      documentId: '/load-race',
      signature: 'AAAA',
      changeId: 'document-head',
      changes: {
        kind: crdtDocumentChangeNode,
        change: { document: 'attacker-controlled' },
        children: {
          'reader-acl': {
            kind: crdtReaderChangeNode,
            change: { reader: 'partially-applied' },
          },
        },
      },
    };
    const secondMessage = {
      documentId: '/load-race',
      signature: 'AAAA',
      changeId: 'attacker-head',
      changes: {
        kind: crdtDocumentChangeNode,
        change: { document: 'replacement-bootstrap' },
      },
    };
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => {
        throw new Error('bootstrap must not invoke signature verification');
      },
      firstMessage,
    );
    const mergeReaders = jest.fn();
    document._mergeReaders = mergeReaders;
    document._mergeWriters = jest.fn();
    document._syncDocumentChanges = jest.fn(async () => {
      throw new Error('CRDT provider failed after ACL pre-pass');
    });

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).rejects.toThrow(/provider failed/);
    expect(mergeReaders).toHaveBeenCalledTimes(1);
    expect(document._hashes).toEqual(new Set());
    expect(document._lastSyncMessage).toBeUndefined();
    expect(document._latestSnapshot).toBeUndefined();

    document._syncMessageSerializer.deserializeSyncMessage.mockReturnValue(
      secondMessage,
    );
    const attackerStream = {
      ...stream,
      source: (async function* () {
        yield new Uint8Array([1, 2, 3]);
      })(),
    };
    await expect(
      document._sendLoadRequestAndSync(
        attackerStream,
        new Uint8Array([1]),
      ),
    ).resolves.toBe(false);
    expect(mergeReaders).toHaveBeenCalledTimes(1);
    expect(document._syncDocumentChanges).toHaveBeenCalledTimes(1);
    expect(document._authProvider.verify).not.toHaveBeenCalled();
    await expect(document.load()).rejects.toThrow(
      /failed after state application began/,
    );
  });

  test('does not trust a writer left by a failed bootstrap ACL pre-pass', async () => {
    let currentWriters: string[] = [];
    const firstMessage = {
      documentId: '/load-race',
      signature: 'AAAA',
      changeId: 'document-head',
      changes: {
        kind: crdtDocumentChangeNode,
        change: { document: 'fails-after-acl' },
        children: {
          'writer-acl': {
            kind: crdtWriterChangeNode,
            change: { writer: 'attacker' },
          },
        },
      },
    };
    const secondMessage = {
      documentId: '/load-race',
      signature: 'AAAA',
      changeId: 'attacker-head',
      changes: {
        kind: crdtDocumentChangeNode,
        change: { document: 'attacker-retry' },
      },
    };
    const verify = jest.fn(async (_raw, key) => key === 'attacker');
    const { document, stream } = signedLoadHarness(
      async () => [...currentWriters],
      verify,
      firstMessage,
    );
    document._mergeReaders = jest.fn();
    document._mergeWriters = jest.fn(() => {
      currentWriters = ['attacker'];
    });
    document._syncDocumentChanges = jest.fn(async () => {
      throw new Error('CRDT provider failed after writer ACL pre-pass');
    });

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).rejects.toThrow(/provider failed/);
    expect(currentWriters).toEqual(['attacker']);

    document._syncMessageSerializer.deserializeSyncMessage.mockReturnValue(
      secondMessage,
    );
    const attackerStream = {
      ...stream,
      source: (async function* () {
        yield new Uint8Array([1, 2, 3]);
      })(),
    };
    await expect(
      document._sendLoadRequestAndSync(
        attackerStream,
        new Uint8Array([1]),
      ),
    ).resolves.toBe(false);
    expect(verify).not.toHaveBeenCalled();
    expect(document._syncDocumentChanges).toHaveBeenCalledTimes(1);
  });

  test('keeps bootstrap retryable when a response is rejected before state application', async () => {
    const validMessage = {
      documentId: '/load-race',
      signature: 'AAAA',
      changeId: 'valid-head',
      changes: { kind: crdtDocumentChangeNode },
    };
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => {
        throw new Error('bootstrap must not invoke signature verification');
      },
      validMessage,
    );
    document._syncMessageSerializer.deserializeSyncMessage
      .mockReturnValueOnce({ ...validMessage, documentId: '/wrong-document' })
      .mockReturnValueOnce(validMessage);
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        onStateApplicationStart?: () => void,
      ) => {
        onStateApplicationStart?.();
        document._hashes.add('valid-head');
        return true;
      },
    );

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).resolves.toBe(false);

    const retryStream = {
      ...stream,
      source: (async function* () {
        yield new Uint8Array([1, 2, 3]);
      })(),
    };
    await expect(
      document._sendLoadRequestAndSync(retryStream, new Uint8Array([1])),
    ).resolves.toBe(true);
    expect(document._syncUnlocked).toHaveBeenCalledTimes(1);
  });

  test('keeps bootstrap retryable when sync rejects before mutating state', async () => {
    const unsignedMessage = {
      documentId: '/load-race',
      changeId: 'unsigned-head',
      changes: { kind: crdtDocumentChangeNode },
    };
    const validMessage = {
      ...unsignedMessage,
      signature: 'AAAA',
      changeId: 'valid-head',
    };
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => {
        throw new Error('bootstrap must not invoke signature verification');
      },
      unsignedMessage,
    );

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).resolves.toBe(false);
    expect(document._bootstrapLoadApplicationState).toBe('pristine');

    document._syncMessageSerializer.deserializeSyncMessage.mockReturnValue({
      documentId: '/load-race',
      signature: 'AAAA',
      changes: { kind: crdtDocumentChangeNode },
    });
    const malformedStream = {
      ...stream,
      source: (async function* () {
        yield new Uint8Array([1, 2, 3]);
      })(),
    };
    await expect(
      document._sendLoadRequestAndSync(
        malformedStream,
        new Uint8Array([1]),
      ),
    ).rejects.toThrow(/missing its root CID/);
    expect(document._bootstrapLoadApplicationState).toBe('pristine');

    document._syncMessageSerializer.deserializeSyncMessage.mockReturnValue(
      validMessage,
    );
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        onStateApplicationStart?: () => void,
      ) => {
        onStateApplicationStart?.();
        document._hashes.add('valid-head');
        return true;
      },
    );
    const retryStream = {
      ...stream,
      source: (async function* () {
        yield new Uint8Array([1, 2, 3]);
      })(),
    };
    await expect(
      document._sendLoadRequestAndSync(retryStream, new Uint8Array([1])),
    ).resolves.toBe(true);
  });

  test('allows current-writer loads after bootstrap application completes', async () => {
    let currentWriters: string[] = [];
    const message = {
      documentId: '/load-race',
      signature: 'AAAA',
      changeId: 'valid-head',
      changes: { kind: crdtDocumentChangeNode },
    };
    const verify = jest.fn(async (_raw, key) => key === 'writer');
    const { document, stream } = signedLoadHarness(
      async () => [...currentWriters],
      verify,
      message,
    );
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        onStateApplicationStart?: () => void,
      ) => {
        onStateApplicationStart?.();
        currentWriters = ['writer'];
        document._hashes.add('valid-head');
        return true;
      },
    );

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).resolves.toBe(true);
    expect(document._bootstrapLoadApplicationState).toBe('complete');

    const writerStream = {
      ...stream,
      source: (async function* () {
        yield new Uint8Array([1, 2, 3]);
      })(),
    };
    await expect(
      document._sendLoadRequestAndSync(writerStream, new Uint8Array([1])),
    ).resolves.toBe(true);
    expect(verify).toHaveBeenCalledTimes(2);
    expect(document._syncUnlocked).toHaveBeenCalledTimes(2);
  });

  test('rejects an explicitly pinned load after bootstrap application is incomplete', async () => {
    const { document, stream } = signedLoadHarness(
      async () => {
        throw new Error('pinned admission must not read the writer ACL');
      },
      async (_raw, key) => key === 'pinned-writer',
    );
    document._bootstrapLoadApplicationState = 'pending';

    await expect(
      document._sendLoadRequestAndSync(
        stream,
        new Uint8Array([1]),
        null,
        'pinned-writer',
      ),
    ).resolves.toBe(false);

    expect(stream.sink).not.toHaveBeenCalled();
    expect(stream.abort).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Document load rejected on poisoned instance',
      }),
    );
    expect(document._getWriterKeys).not.toHaveBeenCalled();
    expect(document._authProvider.verify).not.toHaveBeenCalled();
  });

  test('accepts an explicitly pinned load on a pristine invitation document', async () => {
    const { document, stream } = signedLoadHarness(
      async () => {
        throw new Error('pinned admission must not read the writer ACL');
      },
      async (_raw, key) => key === 'pinned-writer',
    );
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        onStateApplicationStart?: () => void,
      ) => {
        onStateApplicationStart?.();
        document._hashes.add('pinned-head');
        return true;
      },
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
    expect(document._syncUnlocked).toHaveBeenCalledTimes(1);
  });

  test('validates an established pinned no-op atomically without a bootstrap transition', async () => {
    const { document, stream } = signedLoadHarness(
      async () => {
        throw new Error('pinned admission must not read the writer ACL');
      },
      async (_raw, key) => key === 'pinned-writer',
      {
        documentId: '/load-race',
        signature: 'AAAA',
        keychainChanges: [],
      },
    );
    document._bootstrapLoadApplicationState = 'complete';
    document._bootstrapLoadApplicationRevision = 2;
    document._hashes.add('existing-head');
    const commit = jest.fn();
    const hydrateKeys = jest.fn(async () => []);
    document._keychain = {
      getKey: jest.fn(() => ({})),
      stateCommitment: jest.fn(async () => new Uint8Array(32).fill(1)),
      prepareMerge: jest.fn(() => ({
        keyIds: [],
        currentKeyId: undefined,
        hydrateKeys,
        getKey: jest.fn(),
        stateCommitment: jest.fn(async () => new Uint8Array(32).fill(1)),
        commit,
      })),
      merge: jest.fn(),
    };
    let queueDepth = 0;
    const run = jest.fn(async (operation: () => Promise<unknown>) => {
      queueDepth += 1;
      try {
        return await operation();
      } finally {
        queueDepth -= 1;
      }
    });
    document._mutationQueue = { run };
    const assertMembership = jest.fn(async () => {
      expect(queueDepth).toBe(1);
      expect(document._bootstrapLoadApplicationState).toBe('complete');
      expect(document._bootstrapLoadApplicationRevision).toBe(2);
    });

    await expect(
      document._sendLoadRequestAndSync(
        stream,
        new Uint8Array([1]),
        null,
        'pinned-writer',
        undefined,
        true,
        undefined,
        assertMembership,
      ),
    ).resolves.toBe(true);

    expect(run).toHaveBeenCalledTimes(1);
    expect(assertMembership).toHaveBeenCalledTimes(1);
    expect(hydrateKeys).not.toHaveBeenCalled();
    expect(commit).toHaveBeenCalledTimes(1);
    expect(document._bootstrapLoadApplicationState).toBe('complete');
    expect(document._bootstrapLoadApplicationRevision).toBe(2);
  });

  test('leaves an incomplete legacy bootstrap pending without notifying subscribers', async () => {
    const message = {
      documentId: '/load-race',
      signature: 'AAAA',
      changeId: 'legacy-head',
      changes: { kind: crdtDocumentChangeNode },
    };
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => {
        throw new Error('bootstrap must not invoke signature verification');
      },
      message,
    );
    const handler = jest.fn();
    document._remoteHandlers.preBootstrap = handler;
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        onStateApplicationStart?: () => void,
      ) => {
        onStateApplicationStart?.();
        await document._fireOrDeferRemoteUpdateHandlers(['legacy-head']);
        return true;
      },
    );

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).rejects.toThrow(/bootstrap state is incomplete/);
    expect(document._bootstrapLoadApplicationState).toBe('pending');
    expect(handler).not.toHaveBeenCalled();
  });

  test('tracks partial state application when signing is disabled', async () => {
    const message = {
      documentId: '/load-race',
      changeId: 'unsigned-head',
      changes: { kind: crdtDocumentChangeNode },
    };
    const { document, stream } = signedLoadHarness(
      async () => {
        throw new Error('unsigned admission must not read the writer ACL');
      },
      async () => {
        throw new Error('unsigned admission must not verify signatures');
      },
      message,
    );
    document.swarm.config.enableSigning = false;
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        onStateApplicationStart?: () => void,
      ) => {
        onStateApplicationStart?.();
        throw new Error('provider failed after unsigned state application');
      },
    );

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).rejects.toThrow(/provider failed/);
    expect(document._bootstrapLoadApplicationState).toBe('pending');
    expect(document._getWriterKeys).not.toHaveBeenCalled();
    expect(document._authProvider.verify).not.toHaveBeenCalled();
  });

  test('tracks and defers an incomplete signer-pinned catch-up', async () => {
    const message = {
      documentId: '/load-race',
      signature: 'AAAA',
      changeId: 'pinned-head',
      changes: { kind: crdtDocumentChangeNode },
    };
    const { document, stream } = signedLoadHarness(
      async () => {
        throw new Error('pinned admission must not read the writer ACL');
      },
      async (_raw, key) => key === 'pinned-writer',
      message,
    );
    const handler = jest.fn();
    document._remoteHandlers.preBootstrap = handler;
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        onStateApplicationStart?: () => void,
      ) => {
        onStateApplicationStart?.();
        await document._fireOrDeferRemoteUpdateHandlers(['pinned-head']);
        return true;
      },
    );

    await expect(
      document._sendLoadRequestAndSync(
        stream,
        new Uint8Array([1]),
        null,
        'pinned-writer',
        undefined,
        true,
      ),
    ).rejects.toThrow(/catch-up state is incomplete/);
    expect(document._bootstrapLoadApplicationState).toBe('pending');
    expect(handler).not.toHaveBeenCalled();
  });

  test('blocks reads and queued public mutations after incomplete bootstrap application', async () => {
    const syncUnlocked = jest.fn(async () => true);
    const changeUnlocked = jest.fn(async () => undefined);
    const addWriterUnlocked = jest.fn(async () => undefined);
    const otherMutation = jest.fn(async () => undefined);
    const document = fakeDocument({
      documentPath: '/poisoned',
      _bootstrapLoadApplicationState: 'pending',
      _document: { value: 'partial' },
      _hashes: new Set(['partial']),
      _latestSnapshot: { state: 'partial' },
      _invitationEpoch: new Uint8Array([1]),
      _mutationQueue: {
        run: (operation: () => Promise<unknown>) => operation(),
      },
      _syncUnlocked: syncUnlocked,
      _changeUnlocked: changeUnlocked,
      _addWriterUnlocked: addWriterUnlocked,
      _removeWriterUnlocked: otherMutation,
      _addReaderUnlocked: otherMutation,
      _removeReaderUnlocked: otherMutation,
      _endChangeUnlocked: otherMutation,
      _snapshotUnlocked: otherMutation,
      _setKemKeyPairUnlocked: otherMutation,
      _buildInvitationBootstrapUnlocked: otherMutation,
      _handleBeeKEMWelcomeRequestDataUnlocked: otherMutation,
      _handleBeeKEMPathUpdateRequestDataUnlocked: otherMutation,
      _handleKeyUpdateRequestDataUnlocked: otherMutation,
    });

    expect(() => document.document).toThrow(/discard this document instance/);
    expect(() => document.historySize()).toThrow(/discard this document instance/);
    expect(() => document.latestSnapshot).toThrow(/discard this document instance/);
    expect(() => document.hasChange('partial')).toThrow(
      /discard this document instance/,
    );
    expect(() => document.invitationEpoch).toThrow(
      /discard this document instance/,
    );
    await expect(document.loadChangeBlock('partial')).rejects.toThrow(
      /discard this document instance/,
    );
    await expect(document.getReaders()).rejects.toThrow(
      /discard this document instance/,
    );
    await expect(document.getWriters()).rejects.toThrow(
      /discard this document instance/,
    );
    await expect(document.sync({ documentId: '/poisoned' })).rejects.toThrow(
      /discard this document instance/,
    );
    await expect(document.change(jest.fn())).rejects.toThrow(
      /discard this document instance/,
    );
    await expect(document.addWriter('writer')).rejects.toThrow(
      /discard this document instance/,
    );
    const otherMutations = [
      () => document.removeWriter('writer'),
      () => document.addReader('reader'),
      () => document.removeReader('reader'),
      () => document.endChange(),
      () => document.snapshot(),
      () => document.setKemKeyPair(undefined),
      () =>
        document.buildInvitationBootstrap(
          'reader',
          new Uint8Array([1]),
          'reader',
        ),
      () => document.handleBeeKEMWelcomeRequestData(new Uint8Array([1])),
      () => document.handleBeeKEMPathUpdateRequestData(new Uint8Array([1])),
      () => document.handleKeyUpdateRequestData(new Uint8Array([1])),
    ];
    for (const mutate of otherMutations) {
      await expect(mutate()).rejects.toThrow(/discard this document instance/);
    }
    expect(() => document.startChange()).toThrow(
      /discard this document instance/,
    );
    expect(() => document.addChange(jest.fn())).toThrow(
      /discard this document instance/,
    );
    expect(() => document.subscribe('handler', jest.fn())).toThrow(
      /discard this document instance/,
    );

    expect(syncUnlocked).not.toHaveBeenCalled();
    expect(changeUnlocked).not.toHaveBeenCalled();
    expect(addWriterUnlocked).not.toHaveBeenCalled();
    expect(otherMutation).not.toHaveBeenCalled();
  });

  test('rechecks bootstrap integrity when an already-queued mutation executes', async () => {
    const queued = deferred<void>();
    const release = deferred<void>();
    const syncUnlocked = jest.fn(async () => true);
    const document = fakeDocument({
      documentPath: '/queued-before-poison',
      _bootstrapLoadApplicationState: 'pristine',
      _mutationQueue: {
        run: async (operation: () => Promise<unknown>) => {
          queued.resolve();
          await release.promise;
          return operation();
        },
      },
      _syncUnlocked: syncUnlocked,
    });

    const sync = document.sync({ documentId: '/queued-before-poison' });
    await queued.promise;
    document._bootstrapLoadApplicationState = 'pending';
    release.resolve();

    await expect(sync).rejects.toThrow(/discard this document instance/);
    expect(syncUnlocked).not.toHaveBeenCalled();
  });

  test('rejects an already-queued bootstrap response before rereading a poisoned ACL', async () => {
    const queued = deferred<void>();
    const release = deferred<void>();
    const getWriterKeys = jest.fn(async () => [] as string[]);
    const { document, stream } = signedLoadHarness(
      getWriterKeys,
      async () => {
        throw new Error('bootstrap must not invoke signature verification');
      },
    );
    document._mutationQueue = {
      run: async (operation: () => Promise<unknown>) => {
        queued.resolve();
        await release.promise;
        return operation();
      },
    };
    document._syncUnlocked = jest.fn(async () => true);

    const load = document._sendLoadRequestAndSync(stream, new Uint8Array([1]));
    await queued.promise;
    document._bootstrapLoadApplicationState = 'pending';
    release.resolve();

    await expect(load).resolves.toBe(false);
    expect(getWriterKeys).toHaveBeenCalledTimes(1);
    expect(document._syncUnlocked).not.toHaveBeenCalled();
  });

  test('rejects a tracked bootstrap response that applies no state', async () => {
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => {
        throw new Error('bootstrap must not invoke signature verification');
      },
    );
    document._syncUnlocked = jest.fn(async () => true);

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).resolves.toBe(false);

    expect(document._syncUnlocked).toHaveBeenCalledTimes(1);
    expect(document._bootstrapLoadApplicationState).toBe('pristine');
  });

  test.each([
    ['empty array', []],
    ['zero-length bytes', new Uint8Array()],
  ])(
    'treats an %s legacy keychain change conservatively',
    async (_name, changes) => {
      const message = {
        documentId: '/load-race',
        signature: 'AAAA',
        keychainChanges: changes,
      };
      const { document, stream } = signedLoadHarness(
        async () => [],
        async () => {
          throw new Error('bootstrap must not invoke signature verification');
        },
        message,
      );
      const merge = jest.fn();
      document._keychain.merge = merge;

      await expect(
        document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
      ).resolves.toBe(false);

      expect(merge).toHaveBeenCalledTimes(1);
      expect(merge).toHaveBeenCalledWith(changes);
      expect(document._hashes).toEqual(new Set());
      expect(document._bootstrapLoadApplicationState).toBe('pending');
    },
  );

  test('commits a provider-semantic no-op without reserving bootstrap state', async () => {
    const message = {
      documentId: '/load-race',
      signature: 'AAAA',
      keychainChanges: { providerEncoding: 'empty' },
    };
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => {
        throw new Error('bootstrap must not invoke signature verification');
      },
      message,
    );
    const commit = jest.fn();
    const merge = jest.fn();
    const hydrateKeys = jest.fn(async () => []);
    document._keychain = {
      getKey: jest.fn(() => ({})),
      stateCommitment: jest.fn(async () => new Uint8Array(32).fill(1)),
      prepareMerge: jest.fn(() => ({
        keyIds: [],
        currentKeyId: undefined,
        hydrateKeys,
        getKey: jest.fn(),
        stateCommitment: jest.fn(async () => new Uint8Array(32).fill(1)),
        commit,
      })),
      merge,
    };

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).resolves.toBe(false);

    expect(document._keychain.prepareMerge).toHaveBeenCalledWith(
      message.keychainChanges,
    );
    expect(commit).toHaveBeenCalledTimes(1);
    expect(hydrateKeys).not.toHaveBeenCalled();
    expect(merge).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('pristine');
  });

  test('hydrates staged logical keychain changes before reservation and redacts failures', async () => {
    const sentinel = new Error('SECRET_KEYCHAIN_SENTINEL');
    const hydrateKeys = jest.fn(async () => {
      throw sentinel;
    });
    const commit = jest.fn();
    const beginStateApplication = jest.fn();
    const document = fakeDocument({
      documentPath: '/keychain-hydration-failure',
      swarm: { config: { enableSigning: false } },
      _bootstrapLoadApplicationState: 'pristine',
      _keychain: {
        stateCommitment: jest.fn(async () => new Uint8Array(32).fill(1)),
        prepareMerge: jest.fn(() => ({
          keyIds: [new Uint8Array([7])],
          currentKeyId: new Uint8Array([7]),
          hydrateKeys,
          getKey: jest.fn(),
          stateCommitment: jest.fn(async () => new Uint8Array(32).fill(2)),
          commit,
        })),
      },
    });
    const consoleError = jest
      .spyOn(console, 'error')
      .mockImplementation(() => undefined);

    try {
      await expect(
        document._syncUnlocked(
          {
            documentId: '/keychain-hydration-failure',
            keychainChanges: { providerEncoding: 'one-key' },
          },
          false,
          beginStateApplication,
        ),
      ).rejects.toBe(sentinel);

      expect(consoleError).toHaveBeenCalledWith(
        'Failed to merge keychain changes in /keychain-hydration-failure',
      );
      expect(consoleError.mock.calls.flat()).not.toContain(sentinel);
    } finally {
      consoleError.mockRestore();
    }
    expect(hydrateKeys).toHaveBeenCalledTimes(1);
    expect(beginStateApplication).not.toHaveBeenCalled();
    expect(commit).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('pristine');
  });

  test('redacts snapshot serialization failures', async () => {
    const sentinel = new Error('SECRET_SNAPSHOT_SENTINEL');
    const document = fakeDocument({
      documentPath: '/snapshot-redaction',
      swarm: { config: { enableSigning: true } },
      _bootstrapLoadApplicationState: 'pristine',
      _keychain: {},
      _latestSnapshot: undefined,
      _changesSerializer: {
        serializeChanges: jest.fn(() => {
          throw sentinel;
        }),
      },
    });
    const consoleWarn = jest
      .spyOn(console, 'warn')
      .mockImplementation(() => undefined);

    try {
      await expect(
        document._syncUnlocked(
          {
            documentId: '/snapshot-redaction',
            signature: 'AAAA',
            snapshot: {
              state: {},
              timestamp: 1,
              compactedCount: 1,
              signature: 'AAAA',
            },
          },
          false,
        ),
      ).resolves.toBe(true);

      expect(consoleWarn.mock.calls.flat()).not.toContain(sentinel);
      expect(consoleWarn.mock.calls.flat().map(String).join(' ')).not.toContain(
        'SECRET_SNAPSHOT_SENTINEL',
      );
    } finally {
      consoleWarn.mockRestore();
    }
  });

  test('redacts errors propagated by failed load transports', async () => {
    const sentinel = new Error('SECRET_LOAD_SENTINEL');
    const peer = { toString: () => '/ip4/127.0.0.1/tcp/4001/p2p/peer-a' };
    const document = fakeDocument({
      documentPath: '/load-redaction',
      swarm: {
        config: { enableSigning: false, loadQuorumEnabled: false },
        heliaNode: {
          libp2p: {
            dialProtocol: jest.fn(async () => {
              throw sentinel;
            }),
          },
        },
      },
      _bootstrapLoadApplicationState: 'pristine',
      _hashes: new Set<string>(),
      _compactionConfig: { enabled: false },
      _shuffledPeers: jest.fn(async () => [peer]),
      _loadMessageSerializer: {
        serializeLoadRequest: jest.fn(() => new Uint8Array([1])),
      },
    });
    const consoleWarn = jest
      .spyOn(console, 'warn')
      .mockImplementation(() => undefined);

    try {
      await expect(document.load()).resolves.toBe(false);
      expect(consoleWarn.mock.calls.flat()).not.toContain(sentinel);
      expect(consoleWarn.mock.calls.flat().map(String).join(' ')).not.toContain(
        'SECRET_LOAD_SENTINEL',
      );
    } finally {
      consoleWarn.mockRestore();
    }
  });

  test.each(['pinned', 'unsigned'] as const)(
    'counts a committed logical keychain change as %s load progress',
    async (admission) => {
      const message = {
        documentId: '/load-race',
        signature: 'AAAA',
        keychainChanges: { providerEncoding: 'one-key' },
      };
      const { document, stream } = signedLoadHarness(
        async () => {
          if (admission === 'pinned') {
            throw new Error('pinned admission must not read the writer ACL');
          }
          return [];
        },
        async () => true,
        message,
      );
      if (admission === 'unsigned') {
        document.swarm.config.enableSigning = false;
      }
      const commit = jest.fn();
      document._keychain = {
        getKey: jest.fn(() => ({})),
        stateCommitment: jest.fn(async () => new Uint8Array(32).fill(1)),
        prepareMerge: jest.fn(() => ({
          keyIds: [new Uint8Array([7])],
          currentKeyId: new Uint8Array([7]),
          hydrateKeys: jest.fn(async () => []),
          getKey: jest.fn(),
          stateCommitment: jest.fn(async () => new Uint8Array(32).fill(2)),
          commit,
        })),
        merge: jest.fn(),
      };

      await expect(
        document._sendLoadRequestAndSync(
          stream,
          new Uint8Array([1]),
          null,
          admission === 'pinned' ? 'pinned-writer' : undefined,
        ),
      ).resolves.toBe(true);

      expect(commit).toHaveBeenCalledTimes(1);
      expect(document._bootstrapLoadApplicationState).toBe('complete');
    },
  );

  test('does not establish unpinned bootstrap authority from a keychain-only change', async () => {
    const message = {
      documentId: '/load-race',
      signature: 'AAAA',
      keychainChanges: { providerEncoding: 'one-key' },
    };
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => {
        throw new Error('bootstrap must not invoke signature verification');
      },
      message,
    );
    const commit = jest.fn();
    document._keychain = {
      getKey: jest.fn(() => ({})),
      stateCommitment: jest.fn(async () => new Uint8Array(32).fill(1)),
      prepareMerge: jest.fn(() => ({
        keyIds: [new Uint8Array([7])],
        currentKeyId: new Uint8Array([7]),
        hydrateKeys: jest.fn(async () => []),
        getKey: jest.fn(),
        stateCommitment: jest.fn(async () => new Uint8Array(32).fill(2)),
        commit,
      })),
      merge: jest.fn(),
    };

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).resolves.toBe(false);

    expect(commit).toHaveBeenCalledTimes(1);
    expect(document._bootstrapLoadApplicationState).toBe('pending');
  });

  test('does not admit bootstrap state on an already-subscribed instance', async () => {
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => {
        throw new Error('bootstrap must not invoke signature verification');
      },
    );
    document._subscribed = true;
    document._syncUnlocked = jest.fn(async () => true);

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).resolves.toBe(false);

    expect(document._syncUnlocked).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('pristine');
  });

  test('rechecks invitation pristine state at its queued application boundary', async () => {
    const queued = deferred<void>();
    const release = deferred<void>();
    const apply = jest.fn(async () => undefined);
    const document = fakeDocument({
      documentPath: '/invitation-overlap',
      _bootstrapLoadApplicationState: 'pristine',
      _hashes: new Set<string>(),
      _lastSyncMessage: undefined,
      _latestSnapshot: undefined,
      _subscribed: false,
      _mutationQueue: {
        run: async (operation: () => Promise<unknown>) => {
          queued.resolve();
          await release.promise;
          return operation();
        },
      },
    });

    const bootstrap = document._runInvitationBootstrapStateApplication(apply);
    await queued.promise;
    document._bootstrapLoadApplicationState = 'pending';
    release.resolve();

    await expect(bootstrap).rejects.toThrow(/requires a pristine document/);
    expect(apply).not.toHaveBeenCalled();
  });

  test('marks invitation application pending before its first live write', async () => {
    const document = fakeDocument({
      documentPath: '/invitation-reservation',
      _bootstrapLoadApplicationState: 'pristine',
      _hashes: new Set<string>(),
      _lastSyncMessage: undefined,
      _latestSnapshot: undefined,
      _subscribed: false,
      _mutationQueue: {
        run: (operation: () => Promise<unknown>) => operation(),
      },
    });

    await expect(
      document._runInvitationBootstrapStateApplication(async () => {
        expect(document._bootstrapLoadApplicationState).toBe('pending');
        throw new Error('live write failed');
      }),
    ).rejects.toThrow(/live write failed/);
    expect(document._bootstrapLoadApplicationState).toBe('pending');
  });

  test('rechecks the invitation KEM key at the queued application boundary', async () => {
    const queued = deferred<void>();
    const release = deferred<void>();
    const originalKemKeyPair = {
      privateKey: {},
      publicKey: {},
    };
    const apply = jest.fn(async () => undefined);
    const document = fakeDocument({
      documentPath: '/invitation-kem-overlap',
      _bootstrapLoadApplicationState: 'pristine',
      _hashes: new Set<string>(),
      _lastSyncMessage: undefined,
      _latestSnapshot: undefined,
      _subscribed: false,
      _kemKeyPair: originalKemKeyPair,
      _mutationQueue: {
        run: async (operation: () => Promise<unknown>) => {
          queued.resolve();
          await release.promise;
          return operation();
        },
      },
    });

    const bootstrap = document._runInvitationBootstrapStateApplication(
      apply,
      () => {
        if (document._kemKeyPair !== originalKemKeyPair) {
          throw new Error('KEM key pair changed');
        }
      },
    );
    await queued.promise;
    document._kemKeyPair = { privateKey: {}, publicKey: {} };
    release.resolve();

    await expect(bootstrap).rejects.toThrow(/KEM key pair changed/);
    expect(apply).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('pristine');
  });

  test('does not return from load after an overlapping bootstrap becomes incomplete', async () => {
    const peersStarted = deferred<void>();
    const releasePeers = deferred<unknown[]>();
    const document = fakeDocument({
      documentPath: '/load-overlap',
      _bootstrapLoadApplicationState: 'pristine',
      _shuffledPeers: jest.fn(async () => {
        peersStarted.resolve();
        return releasePeers.promise;
      }),
    });

    const load = document.load();
    await peersStarted.promise;
    document._bootstrapLoadApplicationState = 'pending';
    releasePeers.resolve([]);

    await expect(load).rejects.toThrow(/discard this document instance/);
  });

  test('does not return an ACL read that overlaps incomplete bootstrap application', async () => {
    const usersStarted = deferred<void>();
    const releaseUsers = deferred<void>();
    const document = fakeDocument({
      documentPath: '/read-overlap',
      _bootstrapLoadApplicationState: 'pristine',
      _writers: {
        users: jest.fn(async () => {
          usersStarted.resolve();
          await releaseUsers.promise;
          return ['partially-applied-writer'];
        }),
      },
    });

    const read = document.getWriters();
    await usersStarted.promise;
    document._bootstrapLoadApplicationState = 'pending';
    releaseUsers.resolve();

    await expect(read).rejects.toThrow(/discard this document instance/);
  });

  test('defers automatic compaction until bootstrap finalization', async () => {
    const maybeCompact = jest.fn(async () => undefined);
    const document = fakeDocument({
      documentPath: '/deferred-compaction',
      _bootstrapLoadApplicationState: 'pending',
      _bootstrapCompactionDeferred: false,
      _pendingWelcomes: new Map(),
      _pendingBootstrapRemoteUpdateHashes: new Set<string>(),
      _remoteHandlers: {},
      _hashes: new Set<string>(),
      _referencedAncestors: new Set<string>(),
      _lastSyncMessage: undefined,
      _mergeSyncTree: jest.fn(async () => []),
      _refreshLastSyncMessageFromSync: jest.fn(),
      _maybeCompact: maybeCompact,
    });

    await document._syncDocumentChanges(undefined, {
      kind: crdtDocumentChangeNode,
    });
    expect(maybeCompact).not.toHaveBeenCalled();
    expect(document._bootstrapCompactionDeferred).toBe(true);

    await document._completeBootstrapStateApplicationUnlocked();
    expect(document._bootstrapLoadApplicationState).toBe('complete');
    expect(maybeCompact).toHaveBeenCalledTimes(1);
  });

  test('keeps public state closed while bootstrap finalization is awaiting internal work', async () => {
    const drainStarted = deferred<void>();
    const releaseDrain = deferred<void>();
    const document = fakeDocument({
      documentPath: '/deferred-finalization',
      _bootstrapLoadApplicationState: 'pending',
      _document: { value: 'verified-but-not-finalized' },
      _pendingWelcomes: new Map([['buffered', {}]]),
      _pendingBootstrapRemoteUpdateHashes: new Set<string>(),
      _bootstrapCompactionDeferred: false,
      _remoteHandlers: {},
      _drainPendingWelcomesUnlocked: jest.fn(async () => {
        drainStarted.resolve();
        await releaseDrain.promise;
      }),
    });

    const completion = document._completeBootstrapStateApplicationUnlocked();
    await drainStarted.promise;

    expect(document._bootstrapLoadApplicationState).toBe('pending');
    expect(() => document.document).toThrow(/discard this document instance/);

    releaseDrain.resolve();
    await expect(completion).resolves.toBeUndefined();
    expect(document._bootstrapLoadApplicationState).toBe('complete');
    expect(document.document).toEqual({ value: 'verified-but-not-finalized' });
  });

  test('isolates deferred observer failures without awaiting or logging their errors', async () => {
    const releaseAsyncHandler = deferred<void>();
    const asyncFailureLogged = deferred<void>();
    let asyncHandlerReleased = false;
    const laterHandler = jest.fn();
    const consoleError = jest
      .spyOn(console, 'error')
      .mockImplementation(() => {
        if (asyncHandlerReleased) asyncFailureLogged.resolve();
      });
    const document = fakeDocument({
      documentPath: '/observer-isolation',
      _bootstrapLoadApplicationState: 'pending',
      _bootstrapLoadApplicationRevision: 1,
      _document: { value: 'complete' },
      _pendingWelcomes: new Map(),
      _pendingBootstrapRemoteUpdateHashes: new Set(['HEAD']),
      _bootstrapCompactionDeferred: false,
      _readers: {
        users: jest.fn(async () => ['reader']),
        check: jest.fn(async () => true),
      },
      _writers: { users: jest.fn(async () => ['writer']) },
      _remoteHandlers: {
        synchronousFailure: () => {
          throw new Error('synchronous document secret');
        },
        asynchronousFailure: async () => {
          await releaseAsyncHandler.promise;
          throw new Error('asynchronous document secret');
        },
        later: laterHandler,
      },
    });

    try {
      await expect(
        document._completeBootstrapStateApplicationUnlocked(),
      ).resolves.toBeUndefined();
      expect(consoleError).toHaveBeenCalledTimes(1);

      asyncHandlerReleased = true;
      releaseAsyncHandler.resolve();
      await asyncFailureLogged.promise;
      expect(consoleError).toHaveBeenCalledTimes(2);
      expect(consoleError.mock.calls).toEqual([
        ['Remote update handler failed for /observer-isolation'],
        ['Remote update handler failed for /observer-isolation'],
      ]);
    } finally {
      consoleError.mockRestore();
    }

    expect(document._bootstrapLoadApplicationState).toBe('complete');
    expect(laterHandler).toHaveBeenCalledTimes(1);
    expect(laterHandler).toHaveBeenCalledWith(
      document._document,
      ['reader'],
      ['writer'],
      ['HEAD'],
    );
    expect(document._pendingBootstrapRemoteUpdateHashes).toEqual(new Set());
  });

  test('keeps bootstrap pending when buffered Welcome finalization partially fails', async () => {
    const liveKeychain = { partiallyMerged: false };
    const drainPendingWelcomes = jest.fn(async () => {
      liveKeychain.partiallyMerged = true;
      throw new Error('Welcome commit failed after merge');
    });
    const document = fakeDocument({
      documentPath: '/failed-welcome-finalization',
      _bootstrapLoadApplicationState: 'pending',
      _document: { value: 'bootstrap' },
      _pendingWelcomes: new Map([['buffered', {}]]),
      _pendingBootstrapRemoteUpdateHashes: new Set<string>(),
      _bootstrapCompactionDeferred: false,
      _remoteHandlers: {},
      _drainPendingWelcomesUnlocked: drainPendingWelcomes,
    });

    await expect(
      document._completeBootstrapStateApplicationUnlocked(),
    ).rejects.toThrow(/Welcome commit failed after merge/);

    expect(drainPendingWelcomes).toHaveBeenCalledWith(true);
    expect(liveKeychain.partiallyMerged).toBe(true);
    expect(document._bootstrapLoadApplicationState).toBe('pending');
    expect(() => document.document).toThrow(/discard this document instance/);
  });

  test('open rechecks pending state after asynchronous path validation', async () => {
    const validationStarted = deferred<void>();
    const releaseValidation = deferred<void>();
    const registerDocument = jest.fn();
    const document = fakeDocument({
      documentPath: '/open-overlap',
      _bootstrapLoadApplicationState: 'pristine',
      _invitationBootstrapReady: false,
      _hashes: new Set<string>(),
      _computeTopic: jest.fn(() => '/topic'),
      _userPublicKey: 'user',
      load: jest.fn(async () => false),
      swarm: {
        config: {
          validateDocumentPath: jest.fn(async () => {
            validationStarted.resolve();
            await releaseValidation.promise;
            return true;
          }),
        },
        registerDocument,
      },
    });

    const open = document.open();
    await validationStarted.promise;
    document._bootstrapLoadApplicationState = 'pending';
    releaseValidation.resolve();

    await expect(open).rejects.toThrow(/discard this document instance/);
    expect(registerDocument).not.toHaveBeenCalled();
  });

  test('topic validation ignores messages while bootstrap state is incomplete', async () => {
    const topicValidators = new Map<string, (...args: any[]) => Promise<unknown>>();
    const order: string[] = [];
    const decrypt = jest.fn(async () => {
      order.push('decrypt');
      return new Uint8Array([1]);
    });
    const deserializeSyncMessage = jest.fn(() => {
      order.push('deserialize');
      return { documentId: '/validator-bootstrap', signature: 'AAAA' };
    });
    const serializeSyncMessage = jest.fn(() => {
      order.push('serialize');
      return new Uint8Array([2]);
    });
    const verifyWriterSignature = jest.fn(async () => {
      order.push('verify');
      return true;
    });
    const document = fakeDocument({
      documentPath: '/validator-bootstrap',
      _bootstrapLoadApplicationState: 'complete',
      _bootstrapLoadApplicationRevision: 2,
      _invitationBootstrapReady: false,
      _hashes: new Set(['HEAD']),
      _computeTopic: jest.fn(() => '/topic'),
      load: jest.fn(async () => true),
      _mutationQueue: {
        run: (operation: () => Promise<unknown>) => {
          order.push('queue');
          return operation();
        },
      },
      _keychain: { getKey: jest.fn(() => ({})) },
      _authProvider: { nonceBits: 1, decrypt },
      _keychainProvider: { keyIDLength: 1 },
      _syncMessageSerializer: {
        deserializeSyncMessage,
        serializeSyncMessage,
      },
      _verifyWriterSignature: verifyWriterSignature,
      swarm: {
        config: { enableSigning: true, enableTopicValidators: true },
        registerDocument: jest.fn(),
        heliaNode: {
          libp2p: {
            services: {
              pubsub: {
                addEventListener: jest.fn(),
                subscribe: jest.fn(),
                topicValidators,
              },
            },
          },
        },
      },
    });

    await expect(document.open()).resolves.toBe(true);
    const validator = topicValidators.get('/topic');
    expect(validator).toBeDefined();

    document._bootstrapLoadApplicationState = 'pending';
    const consoleWarn = jest
      .spyOn(console, 'warn')
      .mockImplementation(() => undefined);
    try {
      await expect(
        validator!({}, { data: new Uint8Array([1, 2, 3]) }),
      ).resolves.toBe('ignore');
    } finally {
      consoleWarn.mockRestore();
    }
    expect(order).toEqual(['decrypt', 'deserialize', 'serialize', 'queue']);
    expect(verifyWriterSignature).not.toHaveBeenCalled();
  });

  test('serializes the topic validator current-writer authorization gate', async () => {
    const topicValidators = new Map<string, (...args: any[]) => Promise<unknown>>();
    const order: string[] = [];
    const document = fakeDocument({
      documentPath: '/validator-authorization',
      _bootstrapLoadApplicationState: 'complete',
      _bootstrapLoadApplicationRevision: 2,
      _invitationBootstrapReady: false,
      _hashes: new Set(['HEAD']),
      _computeTopic: jest.fn(() => '/topic'),
      load: jest.fn(async () => true),
      _mutationQueue: {
        run: async (operation: () => Promise<unknown>) => {
          order.push('queue');
          return operation();
        },
      },
      _keychain: { getKey: jest.fn(() => ({})) },
      _authProvider: {
        nonceBits: 1,
        decrypt: jest.fn(async () => {
          order.push('decrypt');
          return new Uint8Array([1]);
        }),
      },
      _keychainProvider: { keyIDLength: 1 },
      _syncMessageSerializer: {
        deserializeSyncMessage: jest.fn(() => {
          order.push('deserialize');
          return {
            documentId: '/validator-authorization',
            signature: 'AAAA',
          };
        }),
        serializeSyncMessage: jest.fn(() => {
          order.push('serialize');
          return new Uint8Array([2]);
        }),
      },
      _verifyWriterSignature: jest.fn(async () => {
        order.push('verify');
        return true;
      }),
      swarm: {
        config: { enableSigning: true, enableTopicValidators: true },
        registerDocument: jest.fn(),
        heliaNode: {
          libp2p: {
            services: {
              pubsub: {
                addEventListener: jest.fn(),
                subscribe: jest.fn(),
                topicValidators,
              },
            },
          },
        },
      },
    });

    await expect(document.open()).resolves.toBe(true);
    const validator = topicValidators.get('/topic');
    expect(validator).toBeDefined();

    await expect(
      validator!({}, { data: new Uint8Array([1, 2, 3]) }),
    ).resolves.toBe('accept');

    expect(order).toEqual([
      'decrypt',
      'deserialize',
      'serialize',
      'queue',
      'verify',
    ]);
  });

  test('does not send a response assembled across a bootstrap ABA transition', async () => {
    const signingStarted = deferred<void>();
    const releaseSigning = deferred<string>();
    const sink = jest.fn(async () => undefined);
    const document = fakeDocument({
      documentPath: '/response-aba',
      _bootstrapLoadApplicationState: 'complete',
      _bootstrapLoadApplicationRevision: 2,
      swarm: { config: { enableSigning: false } },
      _servedFrontier: jest.fn(() => []),
      _signAsWriter: jest.fn(async () => {
        signingStarted.resolve();
        return releaseSigning.promise;
      }),
      _syncMessageSerializer: {
        serializeSyncMessage: jest.fn(() => new Uint8Array([7])),
      },
      _keychainProvider: { keyIDLength: 1 },
      _keychain: {
        current: jest.fn(async () => [new Uint8Array([1]), {}]),
      },
      _authProvider: {
        nonceBits: 1,
        encrypt: jest.fn(async () => ({
          nonce: new Uint8Array([2]),
          data: new Uint8Array([3]),
        })),
      },
    });

    const response = document.handleTipAdvertiseRequestData(
      { documentId: '/response-aba' },
      { sink },
    );
    await signingStarted.promise;
    document._markBootstrapStateApplicationPending();
    document._markBootstrapStateApplicationComplete();
    releaseSigning.resolve('');

    const consoleError = jest
      .spyOn(console, 'error')
      .mockImplementation(() => undefined);
    try {
      await expect(response).resolves.toBeUndefined();
    } finally {
      consoleError.mockRestore();
    }
    expect(sink).toHaveBeenCalledTimes(1);
    expect(sink).toHaveBeenCalledWith([]);
  });

  test('blocks invitation activation and acceptance on a poisoned instance', async () => {
    const computeTopic = jest.fn(() => '/topic');
    const load = jest.fn(async () => true);
    const document = fakeDocument({
      documentPath: '/poisoned-invitation',
      _bootstrapLoadApplicationState: 'pending',
      _invitationBootstrapReady: true,
      _computeTopic: computeTopic,
      load,
    });

    await expect(document.open()).rejects.toThrow(
      /discard this document instance/,
    );
    await expect(
      document.acceptInvitationBootstrap({}, 'issuer', 'reader', '/founder'),
    ).rejects.toThrow(/requires a pristine document instance/);
    await expect(
      document._loadInvitationCatchUp('/founder', 'issuer'),
    ).rejects.toThrow(/discard this document instance/);
    await expect(document.createInvitation({})).rejects.toThrow(
      /discard this document instance/,
    );
    await expect(document.assertCanCreateInitialInvitation()).rejects.toThrow(
      /discard this document instance/,
    );
    expect(computeTopic).not.toHaveBeenCalled();
    expect(load).not.toHaveBeenCalled();
    expect(document._invitationBootstrapReady).toBe(true);
  });

  test('does not notify a pre-bootstrap subscriber when completeness later fails', async () => {
    const message = {
      documentId: '/load-race',
      signature: 'AAAA',
      changeId: 'HEAD',
      tips: ['HEAD'],
      changes: {
        kind: crdtDocumentChangeNode,
        change: { value: 'partial' },
      },
    };
    const handler = jest.fn();
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => {
        throw new Error('bootstrap must not invoke signature verification');
      },
      message,
    );
    document._remoteHandlers.preBootstrap = handler;
    document._writers = { users: jest.fn(async () => []) };
    document._readers = {
      users: jest.fn(async () => []),
      check: jest.fn(async () => false),
    };
    document._pendingWelcomes.set('buffered', {});
    document._drainPendingWelcomesUnlocked = jest.fn(async () => undefined);
    document.swarm.heliaNode = {
      blockstore: {
        get: jest.fn(async function* () {
          yield new Uint8Array([1]);
        }),
      },
    };
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        onStateApplicationStart?: () => void,
      ) => {
        onStateApplicationStart?.();
        await document._fireOrDeferRemoteUpdateHandlers(['HEAD']);
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
    ).rejects.toThrow(/completed sync.*not retrievable/);

    expect(document._bootstrapLoadApplicationState).toBe('pending');
    expect(document._pendingBootstrapRemoteUpdateHashes).toEqual(
      new Set(['HEAD']),
    );
    expect(handler).not.toHaveBeenCalled();
    expect(document._readers.users).not.toHaveBeenCalled();
    expect(document._drainPendingWelcomesUnlocked).not.toHaveBeenCalled();
  });

  test('validates pinned catch-up membership before completion and notification', async () => {
    const message = {
      documentId: '/load-race',
      signature: 'AAAA',
      keychainChanges: {},
    };
    const handler = jest.fn();
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => true,
      message,
    );
    document._document = { value: 'policy-invalid' };
    document._writers = { users: jest.fn(async () => ['unexpected-writer']) };
    document._readers = { users: jest.fn(async () => ['recipient']) };
    document._remoteHandlers.preBootstrap = handler;
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        onStateApplicationStart?: () => void,
      ) => {
        onStateApplicationStart?.();
        await document._fireOrDeferRemoteUpdateHandlers(['ACL']);
        document._hashes.add('ACL');
        return true;
      },
    );
    const assertMembership = jest.fn(async () => {
      expect(document._bootstrapLoadApplicationState).toBe('pending');
      throw new Error('invitation membership topology is invalid');
    });

    await expect(
      document._sendLoadRequestAndSync(
        stream,
        new Uint8Array([1]),
        null,
        'issuer',
        undefined,
        true,
        undefined,
        assertMembership,
      ),
    ).rejects.toThrow(/membership topology is invalid/);

    expect(assertMembership).toHaveBeenCalledTimes(1);
    expect(document._bootstrapLoadApplicationState).toBe('pending');
    expect(document._pendingBootstrapRemoteUpdateHashes).toEqual(
      new Set(['ACL']),
    );
    expect(handler).not.toHaveBeenCalled();
  });

  test('cancels a post-EOF invitation catch-up before state application', async () => {
    jest.useFakeTimers();
    const message = {
      documentId: '/load-race',
      signature: 'AAAA',
      keychainChanges: { providerEncoding: 'one-key' },
    };
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => true,
      message,
    );
    const hydrationStarted = deferred<void>();
    const releaseHydration = deferred<void>();
    const backgroundFinished = deferred<void>();
    document._bootstrapLoadApplicationState = 'complete';
    document._bootstrapLoadApplicationRevision = 2;
    document._hashes.add('EXISTING');
    const commit = jest.fn();
    document._keychain = {
      getKey: jest.fn(() => ({})),
      stateCommitment: jest.fn(async () => new Uint8Array(32).fill(1)),
      prepareMerge: jest.fn(() => ({
        keyIds: [new Uint8Array([7])],
        currentKeyId: new Uint8Array([7]),
        hydrateKeys: jest.fn(async () => {
          hydrationStarted.resolve();
          await releaseHydration.promise;
          return [];
        }),
        getKey: jest.fn(),
        stateCommitment: jest.fn(async () => new Uint8Array(32).fill(2)),
        commit,
      })),
      merge: jest.fn(),
    };
    const rawStream = {
      ...stream,
      close: jest.fn(async () => undefined),
      closeRead: jest.fn(async () => undefined),
    };
    const consoleError = jest
      .spyOn(console, 'error')
      .mockImplementation(() => undefined);

    try {
      const load = withIssuerPinnedInvitationStream(
        '/ip4/127.0.0.1/tcp/4001',
        async () => rawStream,
        async (openedStream, signal) => {
          try {
            return await document._sendLoadRequestAndSync(
              openedStream,
              new Uint8Array([1]),
              null,
              'issuer',
              undefined,
              true,
              1000,
              undefined,
              signal,
            );
          } finally {
            backgroundFinished.resolve();
          }
        },
        25,
      );

      await hydrationStarted.promise;
      jest.advanceTimersByTime(25);
      await expect(load).rejects.toThrow(/deadline exceeded/);
      releaseHydration.resolve();
      await backgroundFinished.promise;

      expect(commit).not.toHaveBeenCalled();
      expect(document._bootstrapLoadApplicationState).toBe('complete');
    } finally {
      consoleError.mockRestore();
      jest.useRealTimers();
    }
  });

  test('keeps a timed-out post-EOF catch-up pending without late notification', async () => {
    jest.useFakeTimers();
    const message = {
      documentId: '/load-race',
      signature: 'AAAA',
      keychainChanges: { providerEncoding: 'legacy-change' },
    };
    const handler = jest.fn();
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => true,
      message,
    );
    const topologyStarted = deferred<void>();
    const releaseTopology = deferred<void>();
    const backgroundFinished = deferred<void>();
    document._bootstrapLoadApplicationState = 'complete';
    document._bootstrapLoadApplicationRevision = 2;
    document._hashes.add('EXISTING');
    document._remoteHandlers.preBootstrap = handler;
    const merge = jest.fn(() => {
      document._pendingBootstrapRemoteUpdateHashes.add('APPLIED');
    });
    document._keychain = {
      getKey: jest.fn(() => ({})),
      merge,
    };
    const rawStream = {
      ...stream,
      close: jest.fn(async () => undefined),
      closeRead: jest.fn(async () => undefined),
    };

    try {
      const load = withIssuerPinnedInvitationStream(
        '/ip4/127.0.0.1/tcp/4001',
        async () => rawStream,
        async (openedStream, signal) => {
          try {
            return await document._sendLoadRequestAndSync(
              openedStream,
              new Uint8Array([1]),
              null,
              'issuer',
              undefined,
              true,
              1000,
              async () => {
                topologyStarted.resolve();
                await releaseTopology.promise;
              },
              signal,
            );
          } finally {
            backgroundFinished.resolve();
          }
        },
        25,
      );

      await topologyStarted.promise;
      jest.advanceTimersByTime(25);
      await expect(load).rejects.toThrow(/deadline exceeded/);
      releaseTopology.resolve();
      await backgroundFinished.promise;

      expect(merge).toHaveBeenCalledTimes(1);
      expect(document._bootstrapLoadApplicationState).toBe('pending');
      expect(document._pendingBootstrapRemoteUpdateHashes).toEqual(
        new Set(['APPLIED']),
      );
      expect(handler).not.toHaveBeenCalled();
    } finally {
      jest.useRealTimers();
    }
  });

  test('defers buffered Welcome drain while bootstrap state is pending', () => {
    const scheduleDrain = jest.fn();
    const document = fakeDocument({
      _bootstrapLoadApplicationState: 'pending',
      _readers: { merge: jest.fn() },
      _schedulePendingWelcomeDrain: scheduleDrain,
    });

    document._mergeReaders({ reader: 'partial' });

    expect(document._readers.merge).toHaveBeenCalledTimes(1);
    expect(scheduleDrain).not.toHaveBeenCalled();
  });

  test('notifies a pre-bootstrap subscriber once and only after completion', async () => {
    const message = {
      documentId: '/load-race',
      signature: 'AAAA',
      changeId: 'HEAD',
      tips: ['HEAD'],
      changes: {
        kind: crdtDocumentChangeNode,
        change: { value: 'complete' },
      },
    };
    const completionOrder: string[] = [];
    const receivedHashes: string[][] = [];
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => {
        throw new Error('bootstrap must not invoke signature verification');
      },
      message,
    );
    document._document = { value: 'complete' };
    document._writers = { users: jest.fn(async () => ['writer']) };
    document._readers = {
      users: jest.fn(async () => ['reader']),
      check: jest.fn(async () => false),
    };
    document._remoteHandlers.preBootstrap = jest.fn(
      (_state, _readers, _writers, hashes) => {
        expect(document._bootstrapLoadApplicationState).toBe('complete');
        completionOrder.push('notify');
        receivedHashes.push([...hashes]);
      },
    );
    document._pendingWelcomes.set('buffered', {});
    document._drainPendingWelcomesUnlocked = jest.fn(async () => {
      expect(document._bootstrapLoadApplicationState).toBe('pending');
      completionOrder.push('drain');
      document._pendingWelcomes.clear();
    });
    document.swarm.heliaNode = {
      blockstore: {
        get: jest.fn(async function* () {
          yield new Uint8Array([1]);
        }),
      },
    };
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        onStateApplicationStart?: () => void,
      ) => {
        onStateApplicationStart?.();
        await document._fireOrDeferRemoteUpdateHandlers(['HEAD']);
        await document._fireOrDeferRemoteUpdateHandlers(['ACL', 'HEAD']);
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

    expect(document._bootstrapLoadApplicationState).toBe('complete');
    expect(completionOrder).toEqual(['drain', 'notify']);
    expect(receivedHashes).toEqual([['HEAD', 'ACL']]);
    expect(document._remoteHandlers.preBootstrap).toHaveBeenCalledTimes(1);
    expect(document._pendingBootstrapRemoteUpdateHashes).toEqual(new Set());
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
});
