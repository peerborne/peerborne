import { snapshotInvitationBootstrapBundle } from './internal/invitation-bootstrap.js';
import { describe, expect, jest, test } from '@jest/globals';

import {
  MAX_DOCUMENT_LOAD_RESPONSE_SIZE,
  PeerborneDocument,
} from './peerborne-document.js';
import { ACLMergeRejectedError, ACLOperationInProgressError } from './acl.js';
import {
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
} from './crdt-change-node.js';
import { withIssuerPinnedInvitationStream } from './invitation-catch-up.js';
import { INVITATION_STREAM_TIMEOUT_MS } from './invitation-policy.js';
import { InvitationMembershipQueue } from './invitation-membership.js';
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
  return Object.assign(Object.create(PeerborneDocument.prototype), {
    _keychain: { keys: async () => [] },
    ...fields,
  });
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100 && !predicate(); attempt++) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  expect(predicate()).toBe(true);
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
  message: any = {
    documentId: '/load-race',
    signatureContext: 'load-response-v3',
    signature: 'AAAA',
  },
  serializeSyncMessage: (message: any) => Uint8Array = () =>
    new Uint8Array([8]),
) {
  const contextMessage = Object.defineProperties(
    { signatureContext: 'load-response-v3', tips: [] },
    Object.getOwnPropertyDescriptors(message),
  );
  const document = fakeDocument({
    documentPath: message.documentId,
    swarm: {
      config: { enableSigning: true, loadQuorumTimeoutMs: 1000 },
      heliaNode: {
        blockstore: {
          get: jest.fn(async function* () {
            yield new Uint8Array([1]);
          }),
        },
      },
    },
    _keychainProvider: { keyIDLength: 1 },
    _keychain: { getKey: jest.fn(() => ({})) },
    _authProvider: {
      nonceBits: 1,
      decrypt: jest.fn(async () => new Uint8Array([9])),
      verify: jest.fn(verify),
    },
    _syncMessageSerializer: {
      deserializeSyncMessage: jest.fn(() => contextMessage),
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
    ).resolves.toBe(false);
    expect(syncValidatedProtocolMessage).not.toHaveBeenCalled();
  });

  test('rejects keychain-only state at the queued invitation pristine check', async () => {
    const apply = jest.fn(async () => undefined);
    const document = fakeDocument({
      documentPath: '/invitation-keychain-only',
      _bootstrapLoadApplicationState: 'pristine',
      _hashes: new Set(),
      _subscribed: false,
      _keychain: { keys: async () => [[new Uint8Array([1]), {}]] },
      _mutationQueue: new InvitationMembershipQueue(),
    });
    await expect(
      document._runInvitationBootstrapStateApplication(apply),
    ).rejects.toThrow(/pristine.*keychain/);
    expect(apply).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('pristine');
  });

  test('does not apply a late missing block after another worker exceeds the budget', async () => {
    const lateStarted = deferred<void>();
    const internalAbort = deferred<void>();
    const releaseLate = deferred<void>();
    const lateFinished = deferred<void>();
    const remoteChange = jest.fn((state: unknown) => state);
    const document = fakeDocument({
      documentPath: '/internal-fetch-abort',
      _bootstrapLoadApplicationState: 'pending',
      _document: {},
      _hashes: new Set(),
      _referencedAncestors: new Set(),
      _mergeSyncTree: async () => [
        ['LIMIT', crdtDocumentChangeNode, undefined],
        ['LATE', crdtDocumentChangeNode, undefined],
      ],
      _getBlock: async (cid: { toString(): string }, options: any) => {
        if (cid.toString() === 'LIMIT') {
          await lateStarted.promise;
          options.consumeBytes(2);
          throw new Error('unreachable');
        }
        options.signal.addEventListener('abort', () => internalAbort.resolve());
        lateStarted.resolve();
        await releaseLate.promise;
        lateFinished.resolve();
        return { late: true };
      },
      _crdtProvider: { remoteChange },
      _recentTips: [],
      _documentChangeCount: 0,
      _changesSinceSnapshot: 0,
    });
    const syncing = document._syncDocumentChanges(
      'HEAD', { kind: crdtDocumentChangeNode },
      { maxBlockBytes: 1, maxAggregateBlockBytes: 1 },
    );
    const rejected = expect(syncing).rejects.toThrow(/fetch limits exceeded/);
    await internalAbort.promise;
    releaseLate.resolve();
    await lateFinished.promise;
    await rejected;
    expect(remoteChange).not.toHaveBeenCalled();
    expect(document._hashes).toEqual(new Set());
  });

  test.each(['Readers', 'Writers'])(
    'cancels a hung %s ACL conflict without another provider call',
    async (kind) => {
      const controller = new AbortController();
      const settlement = deferred<void>();
      const started = deferred<void>();
      const merge = jest.fn(() => {
        started.resolve();
        throw new ACLOperationInProgressError('merge', settlement.promise);
      });
      const document = fakeDocument({
        _readers: { merge }, _writers: { merge },
        _bootstrapLoadApplicationState: 'pending',
        _writerKeysVersion: 0, _writerMutationsInFlight: 0,
      });
      const assertActive = () => {
        if (controller.signal.aborted) throw controller.signal.reason;
      };
      const work = document[`_merge${kind}`]({}, assertActive, controller.signal);
      const outcome = work.then(() => 'resolved', (error: Error) => error.message);
      try {
        await started.promise;
        controller.abort(new Error('cancelled ACL wait'));
        const result = await Promise.race([
          outcome,
          new Promise<string>((resolve) => setTimeout(() => resolve('still waiting'), 25)),
        ]);
        expect(result).toBe('cancelled ACL wait');
        expect(merge).toHaveBeenCalledTimes(1);
      } finally {
        settlement.resolve();
        await outcome;
      }
    },
  );

  test('does not impose bootstrap fetch limits on an established writer load', async () => {
    const { document, stream } = signedLoadHarness(
      async () => ['writer'], async () => true,
    );
    document._bootstrapLoadApplicationState = 'complete';
    document._syncUnlocked = jest.fn(async (...args: any[]) => {
      const options = args[6];
      expect(options.maxBlockBytes).toBeUndefined();
      expect(options.maxAggregateBlockBytes).toBeUndefined();
      expect(options.aggregateBudget).toBeUndefined();
      return true;
    });
    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).resolves.toBe(true);
  });

  test('cancels post-EOF decryption and releases its enclosing queue', async () => {
    const controller = new AbortController();
    const started = deferred<void>();
    const release = deferred<void>();
    const { document, stream } = signedLoadHarness(
      async () => ['writer'], async () => true,
    );
    document._authProvider.decrypt = async () => {
      started.resolve();
      await release.promise;
      return new Uint8Array([1]);
    };
    const sync = jest.fn(async () => true);
    document._syncUnlocked = sync;
    const queue = new InvitationMembershipQueue();
    const loading = queue.run(() => document._sendLoadRequestAndSync(
      stream, new Uint8Array([1]), null, 'issuer', undefined,
      true, undefined, undefined, controller.signal,
    ));
    const outcome = loading.then(() => 'resolved', (error: Error) => error.message);
    try {
      await started.promise;
      controller.abort(new Error('cancelled decryption'));
      expect(await Promise.race([
        outcome,
        new Promise<string>((resolve) => setTimeout(() => resolve('still waiting'), 25)),
      ])).toBe('cancelled decryption');
      await expect(queue.run(async () => 'released')).resolves.toBe('released');
      expect(sync).not.toHaveBeenCalled();
    } finally {
      release.resolve();
      await outcome;
    }
    expect(sync).not.toHaveBeenCalled();
  });

  test('serializes reader checks while preparing a remote-update audience', async () => {
    const readers = jest.fn(async () => ['reader']);
    const writers = jest.fn(async () => [
      'writer-a',
      'writer-b',
      'writer-c',
    ]);
    let checksInFlight = 0;
    let maximumChecksInFlight = 0;
    const readerCheck = jest.fn(async () => {
      checksInFlight++;
      maximumChecksInFlight = Math.max(
        maximumChecksInFlight,
        checksInFlight,
      );
      await Promise.resolve();
      checksInFlight--;
      return false;
    });
    const handler = jest.fn();
    const document = fakeDocument({
      _document: { ready: true },
      _readers: { users: readers, check: readerCheck },
      _writers: { users: writers },
    });

    await expect(
      document._prepareRemoteUpdateNotification(['HEAD'], [handler]),
    ).resolves.toEqual({
      handlers: [handler],
      document: { ready: true },
      readers: ['reader', 'writer-a', 'writer-b', 'writer-c'],
      writers: ['writer-a', 'writer-b', 'writer-c'],
      hashes: ['HEAD'],
    });
    expect(readers).toHaveBeenCalledTimes(1);
    expect(writers).toHaveBeenCalledTimes(1);
    expect(readerCheck).toHaveBeenCalledTimes(3);
    expect(maximumChecksInFlight).toBe(1);
  });

  test('does not wait on an ACL conflict while preparing a remote-update audience', async () => {
    const settlement = Promise.reject<void>(
      new Error('audience conflict settlement must not be awaited'),
    );
    void settlement.catch(() => undefined);
    const conflict = new ACLOperationInProgressError(
      'reader listing',
      settlement,
    );
    const readers = jest.fn<() => Promise<string[]>>().mockRejectedValue(
      conflict,
    );
    const document = fakeDocument({
      _document: {},
      _readers: { users: readers },
      _writers: { users: jest.fn(async () => []) },
    });

    await expect(
      document._prepareRemoteUpdateNotification(['HEAD'], [jest.fn()]),
    ).rejects.toBe(conflict);
    expect(readers).toHaveBeenCalledTimes(1);
  });

  test.each([
    'reader listing',
    'writer listing',
    'reader membership check',
  ] as const)(
    'retries a %s conflict without retaining the document mutation queue',
    async (conflictPoint) => {
      const settlement = deferred<void>();
      const conflict = new ACLOperationInProgressError(
        conflictPoint,
        settlement.promise,
      );
      let conflictRaised = false;
      const raiseOnce = () => {
        if (conflictRaised) return;
        conflictRaised = true;
        throw conflict;
      };
      const readers = jest.fn(async () => {
        if (conflictPoint === 'reader listing') raiseOnce();
        return ['reader'];
      });
      const writers = jest.fn(async () => {
        if (conflictPoint === 'writer listing') raiseOnce();
        return ['writer'];
      });
      const readerCheck = jest.fn(async () => {
        if (conflictPoint === 'reader membership check') raiseOnce();
        return false;
      });
      const handler = jest.fn();
      const mutationQueue = new InvitationMembershipQueue();
      const refresh = jest.fn();
      const document = fakeDocument({
        documentPath: '/conflicted-notification',
        _bootstrapLoadApplicationState: 'complete',
        _bootstrapLoadApplicationRevision: 2,
        _document: {},
        _hashes: new Set<string>(),
        _referencedAncestors: new Set<string>(),
        _lastSyncMessage: undefined,
        _mergeSyncTree: jest.fn(async () => [
          ['HEAD', crdtDocumentChangeNode, { value: 'remote' }],
        ]),
        _crdtProvider: {
          remoteChange: jest.fn(() => ({ value: 'remote' })),
        },
        _readers: { users: readers, check: readerCheck },
        _writers: { users: writers },
        _documentChangeCount: 0,
        _changesSinceSnapshot: 0,
        _recentTips: [],
        _pendingBootstrapRemoteUpdateHashes: new Set<string>(),
        _remoteHandlers: { subscriber: handler },
        _mutationQueue: mutationQueue,
        _refreshLastSyncMessageFromSync: refresh,
        _bootstrapCompactionDeferred: false,
        _maybeCompact: jest.fn(async () => undefined),
      });

      await expect(
        mutationQueue.run(() =>
          document._syncDocumentChanges('HEAD', {
            kind: crdtDocumentChangeNode,
          }),
        ),
      ).resolves.toBeUndefined();

      expect(refresh).toHaveBeenCalledTimes(1);
      expect(handler).not.toHaveBeenCalled();
      const notificationTail = document._remoteUpdateNotificationTail;
      expect(notificationTail).toBeDefined();
      await expect(
        mutationQueue.run(async () => 'queue released'),
      ).resolves.toBe('queue released');

      settlement.resolve();
      await notificationTail;

      expect(handler).toHaveBeenCalledTimes(1);
      expect(handler).toHaveBeenCalledWith(
        { value: 'remote' },
        ['reader', 'writer'],
        ['writer'],
        ['HEAD'],
      );
      expect(document._remoteUpdateNotificationTail).toBeUndefined();
    },
  );

  test('preserves remote-notification order and batch boundaries across an ACL conflict', async () => {
    const settlement = deferred<void>();
    const readers = jest
      .fn<() => Promise<string[]>>()
      .mockRejectedValueOnce(
        new ACLOperationInProgressError(
          'reader listing',
          settlement.promise,
        ),
      )
      .mockResolvedValue(['reader']);
    const handler = jest.fn();
    const document = fakeDocument({
      documentPath: '/ordered-notifications',
      _bootstrapLoadApplicationState: 'complete',
      _document: {},
      _readers: { users: readers, check: jest.fn(async () => true) },
      _writers: { users: jest.fn(async () => []) },
      _remoteHandlers: { subscriber: handler },
      _mutationQueue: new InvitationMembershipQueue(),
    });

    await document._fireOrDeferRemoteUpdateHandlers(['FIRST']);
    await document._fireOrDeferRemoteUpdateHandlers(['SECOND', 'THIRD']);
    expect(readers).toHaveBeenCalledTimes(1);
    expect(handler).not.toHaveBeenCalled();
    const notificationTail = document._remoteUpdateNotificationTail;

    settlement.resolve();
    await notificationTail;

    expect(handler.mock.calls.map((call: unknown[]) => call[3])).toEqual([
      ['FIRST'],
      ['SECOND', 'THIRD'],
    ]);
    expect(readers).toHaveBeenCalledTimes(3);
  });

  test('continues queued notifications after an audience preparation fails', async () => {
    const handler = jest.fn();
    const document = fakeDocument({
      documentPath: '/notification-recovery',
      _bootstrapLoadApplicationState: 'complete',
      _document: {},
      _readers: {
        users: jest.fn<() => Promise<unknown[]>>()
          .mockRejectedValueOnce(new Error('audience unavailable'))
          .mockResolvedValue([]),
        check: jest.fn(async () => true),
      },
      _writers: { users: jest.fn(async () => []) },
      _mutationQueue: new InvitationMembershipQueue(),
    });
    const consoleError = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      document._enqueueRemoteUpdateNotification(['FIRST'], [handler]);
      document._enqueueRemoteUpdateNotification(['SECOND'], [handler]);
      await document._remoteUpdateNotificationTail;
      expect(handler).toHaveBeenCalledTimes(1);
      expect(handler.mock.calls[0][3]).toEqual(['SECOND']);
      expect(consoleError).toHaveBeenCalledTimes(1);
    } finally {
      consoleError.mockRestore();
    }
  });

  test('redacts a terminal audience failure without suppressing frontier refresh', async () => {
    const secret = 'private-audience-provider-error';
    const handler = jest.fn();
    const refresh = jest.fn();
    const document = fakeDocument({
      documentPath: '/failed-notification-audience',
      _bootstrapLoadApplicationState: 'complete',
      _document: {},
      _hashes: new Set<string>(),
      _referencedAncestors: new Set<string>(),
      _lastSyncMessage: undefined,
      _mergeSyncTree: jest.fn(async () => [
        ['HEAD', crdtDocumentChangeNode, { value: 'remote' }],
      ]),
      _crdtProvider: {
        remoteChange: jest.fn(() => ({ value: 'remote' })),
      },
      _readers: {
        users: jest.fn(async () => {
          throw new Error(secret);
        }),
      },
      _writers: { users: jest.fn(async () => []) },
      _documentChangeCount: 0,
      _changesSinceSnapshot: 0,
      _recentTips: [],
      _pendingBootstrapRemoteUpdateHashes: new Set<string>(),
      _remoteHandlers: { subscriber: handler },
      _refreshLastSyncMessageFromSync: refresh,
      _bootstrapCompactionDeferred: false,
      _maybeCompact: jest.fn(async () => undefined),
    });
    const consoleError = jest
      .spyOn(console, 'error')
      .mockImplementation(() => undefined);

    try {
      await expect(
        document._syncDocumentChanges('HEAD', {
          kind: crdtDocumentChangeNode,
        }),
      ).resolves.toBeUndefined();
      expect(consoleError.mock.calls).toEqual([
        [
          'Failed to prepare remote update notification for /failed-notification-audience',
        ],
      ]);
      expect(JSON.stringify(consoleError.mock.calls)).not.toContain(secret);
    } finally {
      consoleError.mockRestore();
    }

    expect(document._hashes).toEqual(new Set(['HEAD']));
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(handler).not.toHaveBeenCalled();
    expect(document._remoteUpdateNotificationTail).toBeUndefined();
  });

  test('propagates a certified ACL rejection from a missing block without poisoning', async () => {
    const rejection = new ACLMergeRejectedError(
      new Error('malformed deferred writer update'),
    );
    const refresh = jest.fn();
    const trackTip = jest.fn();
    const document = fakeDocument({
      documentPath: '/deferred-acl-rejection',
      _bootstrapLoadApplicationState: 'complete',
      _document: {},
      _hashes: new Set<string>(),
      _referencedAncestors: new Set<string>(['KNOWN']),
      _lastSyncMessage: undefined,
      _mergeSyncTree: jest.fn(async () => [
        ['ACL', crdtWriterChangeNode, undefined],
      ]),
      _getBlock: jest.fn(async () => ({ remote: true })),
      _mergeWriters: jest.fn(async () => {
        throw rejection;
      }),
      _trackTip: trackTip,
      _refreshLastSyncMessageFromSync: refresh,
    });
    const consoleError = jest
      .spyOn(console, 'error')
      .mockImplementation(() => undefined);

    try {
      await expect(
        document._syncDocumentChanges('ACL', {
          kind: crdtWriterChangeNode,
          children: {
            PARENT: { kind: crdtDocumentChangeNode },
            KNOWN: { kind: crdtDocumentChangeNode },
          },
        }),
      ).rejects.toBe(rejection);
      expect(consoleError).not.toHaveBeenCalled();
    } finally {
      consoleError.mockRestore();
    }

    expect(document._mergeWriters).toHaveBeenCalledTimes(1);
    expect(document._hashes).toEqual(new Set());
    expect(document._referencedAncestors).toEqual(new Set(['KNOWN']));
    expect(trackTip).not.toHaveBeenCalled();
    expect(refresh).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('complete');
  });

  test('lets an in-flight sibling ACL merge settle after a certified rejection', async () => {
    const rejection = new ACLMergeRejectedError(
      new Error('malformed deferred writer update'),
    );
    let releaseBad!: () => void;
    const badFetched = new Promise<void>((resolve) => {
      releaseBad = resolve;
    });
    let finishGood!: () => void;
    const goodMerged = new Promise<void>((resolve) => {
      finishGood = resolve;
    });
    const merge = jest.fn((changes: { id: string }) => {
      if (changes.id === 'BAD') throw rejection;
      releaseBad();
      return goodMerged;
    });
    const document = fakeDocument({
      documentPath: '/deferred-sibling-acl',
      _bootstrapLoadApplicationState: 'complete',
      _document: {},
      _hashes: new Set<string>(),
      _referencedAncestors: new Set<string>(),
      _lastSyncMessage: undefined,
      _mergeSyncTree: jest.fn(async () => [
        ['BAD', crdtWriterChangeNode, undefined],
        ['GOOD', crdtWriterChangeNode, undefined],
      ]),
      _getBlock: jest.fn(async (cid: { toString(): string }) => {
        const id = cid.toString();
        if (id === 'BAD') await badFetched;
        return { id };
      }),
      _writers: { merge },
      _writerMutationsInFlight: 0,
      _writerPublicationsInFlight: 0,
      _invalidateWriterKeyCache: jest.fn(),
      _trackTip: jest.fn(),
      _refreshLastSyncMessageFromSync: jest.fn(),
    });

    const syncing = document._syncDocumentChanges('BAD', {
      kind: crdtWriterChangeNode,
    });
    let settled = false;
    void syncing.then(
      () => (settled = true),
      () => (settled = true),
    );
    for (let i = 0; i < 20 && merge.mock.calls.length < 2; i++) {
      await Promise.resolve();
    }
    expect(merge).toHaveBeenCalledTimes(2);
    expect(settled).toBe(false);
    finishGood();

    await expect(syncing).rejects.toBe(rejection);
    expect(document._bootstrapLoadApplicationState).toBe('complete');
    expect(document._hashes).toEqual(new Set(['GOOD']));
    expect(document._refreshLastSyncMessageFromSync).not.toHaveBeenCalled();
  });

  test('withdraws ancestors recorded by a directly rejected ACL change', async () => {
    const rejection = new ACLMergeRejectedError(
      new Error('malformed sent reader update'),
    );
    const document = fakeDocument({
      documentPath: '/sent-acl-rejection',
      _bootstrapLoadApplicationState: 'complete',
      _document: {},
      _hashes: new Set<string>(),
      _referencedAncestors: new Set<string>(['KNOWN']),
      _lastSyncMessage: undefined,
      _mergeSyncTree: jest.fn(async () => [
        ['ACL', crdtReaderChangeNode, { remote: true }],
      ]),
      _mergeReaders: jest.fn(async () => {
        throw rejection;
      }),
      _refreshLastSyncMessageFromSync: jest.fn(),
    });

    await expect(
      document._syncDocumentChanges('ACL', {
        kind: crdtReaderChangeNode,
        children: {
          PARENT: { kind: crdtDocumentChangeNode },
          KNOWN: { kind: crdtDocumentChangeNode },
        },
      }),
    ).rejects.toBe(rejection);

    expect(document._referencedAncestors).toEqual(new Set(['KNOWN']));
    expect(document._hashes).toEqual(new Set());
    expect(document._refreshLastSyncMessageFromSync).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('complete');
  });

  test('keeps bootstrap pending when its deferred audience conflicts', async () => {
    const conflict = new ACLOperationInProgressError(
      'reader listing',
      new Promise<void>(() => undefined),
    );
    const handler = jest.fn();
    const document = fakeDocument({
      documentPath: '/bootstrap-audience-conflict',
      _bootstrapLoadApplicationState: 'pending',
      _bootstrapLoadApplicationRevision: 1,
      _document: {},
      _pendingWelcomes: new Map(),
      _pendingBootstrapRemoteUpdateHashes: new Set(['HEAD']),
      _bootstrapCompactionDeferred: false,
      _readers: {
        users: jest.fn(async () => {
          throw conflict;
        }),
      },
      _writers: { users: jest.fn(async () => []) },
      _remoteHandlers: { subscriber: handler },
    });

    await expect(
      document._completeBootstrapStateApplicationUnlocked(),
    ).rejects.toBe(conflict);
    expect(document._bootstrapLoadApplicationState).toBe('pending');
    expect(document._pendingBootstrapRemoteUpdateHashes).toEqual(
      new Set(['HEAD']),
    );
    expect(handler).not.toHaveBeenCalled();
    expect(document._remoteUpdateNotificationTail).toBeUndefined();
  });

  test('batches applied missing hashes into one remote-update audience', async () => {
    let readerMerged = false;
    let writerMerged = false;
    const notifications: Array<{
      readerMerged: boolean;
      writerMerged: boolean;
      hashes: string[];
    }> = [];
    const handler = jest.fn(
      (
        _state: unknown,
        _readers: string[],
        _writers: string[],
        hashes: string[],
      ) => {
        notifications.push({
          readerMerged,
          writerMerged,
          hashes: [...hashes],
        });
      },
    );
    const readerUsers = jest.fn(async () => ['reader']);
    const writerUsers = jest.fn(async () => ['writer']);
    const readerCheck = jest.fn(async () => false);
    const document = fakeDocument({
      documentPath: '/batched-missing-notifications',
      _bootstrapLoadApplicationState: 'complete',
      _document: {},
      _hashes: new Set<string>(),
      _referencedAncestors: new Set<string>(),
      _lastSyncMessage: undefined,
      _mergeSyncTree: jest.fn(async () => [
        ['DOC', crdtDocumentChangeNode, undefined],
        ['FAILED', crdtDocumentChangeNode, undefined],
        ['READER', crdtReaderChangeNode, undefined],
        ['WRITER', crdtWriterChangeNode, undefined],
      ]),
      _getBlock: jest.fn(async (cid: { toString(): string }) => {
        if (cid.toString() === 'FAILED') throw new Error('missing');
        return { cid: cid.toString() };
      }),
      _crdtProvider: {
        remoteChange: jest.fn((state: unknown) => state),
      },
      _mergeReaders: jest.fn(async () => {
        await Promise.resolve();
        readerMerged = true;
      }),
      _mergeWriters: jest.fn(async () => {
        await Promise.resolve();
        writerMerged = true;
      }),
      _readers: { users: readerUsers, check: readerCheck },
      _writers: { users: writerUsers },
      _documentChangeCount: 0,
      _changesSinceSnapshot: 0,
      _recentTips: [],
      _pendingBootstrapRemoteUpdateHashes: new Set<string>(),
      _remoteHandlers: { subscriber: handler },
      _refreshLastSyncMessageFromSync: jest.fn(),
      _bootstrapCompactionDeferred: false,
      _maybeCompact: jest.fn(async () => undefined),
    });
    const consoleError = jest
      .spyOn(console, 'error')
      .mockImplementation(() => undefined);

    try {
      await expect(
        document._syncDocumentChanges('HEAD', {
          kind: crdtDocumentChangeNode,
        }),
      ).resolves.toBeUndefined();
      expect(consoleError.mock.calls).toEqual([
        ['Failed to fetch missing change from blockstore:', 'FAILED'],
      ]);
    } finally {
      consoleError.mockRestore();
    }

    expect(handler).toHaveBeenCalledTimes(1);
    expect(notifications).toEqual([
      {
        readerMerged: true,
        writerMerged: true,
        hashes: ['DOC', 'READER', 'WRITER'],
      },
    ]);
    expect(readerUsers).toHaveBeenCalledTimes(1);
    expect(writerUsers).toHaveBeenCalledTimes(1);
    expect(readerCheck).toHaveBeenCalledTimes(1);
    expect(document._hashes).toEqual(new Set(['DOC', 'READER', 'WRITER']));
  });

  test('releases the queue when abort races a poisoned missing ACL merge', async () => {
    const secret = 'partially-applied-writer-merge-secret';
    const writers = new Set(['owner']);
    const refresh = jest.fn();
    const mergeMutated = deferred<void>();
    const finishMerge = deferred<void>();
    const stalledFetchStarted = deferred<void>();
    const stalledFetchAborted = deferred<void>();
    const loadController = new AbortController();
    const mutationQueue = new InvitationMembershipQueue();
    const document = fakeDocument({
      documentPath: '/missing-writer-poison',
      _bootstrapLoadApplicationState: 'complete',
      _bootstrapLoadApplicationRevision: 2,
      _document: {},
      _hashes: new Set<string>(),
      _referencedAncestors: new Set<string>(),
      _lastSyncMessage: undefined,
      _mergeSyncTree: jest.fn(async () => [
        ['WRITER', crdtWriterChangeNode, undefined],
        ['STALLED', crdtDocumentChangeNode, undefined],
      ]),
      _getBlock: jest.fn(
        async (
          cid: { toString(): string },
          options: { signal: AbortSignal },
        ) => {
          if (cid.toString() === 'WRITER') {
            return { add: 'injected-writer' };
          }
          stalledFetchStarted.resolve();
          options.signal.addEventListener(
            'abort',
            () => stalledFetchAborted.resolve(),
            { once: true },
          );
          return new Promise<never>(() => undefined);
        },
      ),
      _writers: {
        merge: jest.fn(async () => {
          writers.add('injected-writer');
          mergeMutated.resolve();
          await finishMerge.promise;
          throw new Error(secret);
        }),
        users: jest.fn(async () => [...writers]),
      },
      _writerPublicationsInFlight: 0,
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 0,
      _cachedWriterKeys: null,
      _documentChangeCount: 0,
      _changesSinceSnapshot: 0,
      _recentTips: [],
      _pendingBootstrapRemoteUpdateHashes: new Set<string>(),
      _remoteHandlers: {},
      _mutationQueue: mutationQueue,
      _refreshLastSyncMessageFromSync: refresh,
      _bootstrapCompactionDeferred: false,
      _maybeCompact: jest.fn(async () => undefined),
    });
    const consoleError = jest
      .spyOn(console, 'error')
      .mockImplementation(() => undefined);

    try {
      const syncing = mutationQueue.run(() =>
        document._syncDocumentChanges(
          'HEAD',
          { kind: crdtDocumentChangeNode },
          { signal: loadController.signal },
        ),
      );
      await Promise.all([stalledFetchStarted.promise, mergeMutated.promise]);
      loadController.abort();
      finishMerge.resolve();

      await expect(syncing).rejects.toThrow(
        /indeterminate authorization state/,
      );
      await expect(stalledFetchAborted.promise).resolves.toBeUndefined();
      await expect(
        mutationQueue.run(async () => 'queue released'),
      ).resolves.toBe('queue released');
      expect(JSON.stringify(consoleError.mock.calls)).not.toContain(secret);
    } finally {
      consoleError.mockRestore();
    }

    expect(writers).toContain('injected-writer');
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
    expect(document._hashes).not.toContain('WRITER');
    expect(refresh).not.toHaveBeenCalled();
    await expect(document.getWriters()).rejects.toThrow(
      /discard this document instance/,
    );
  });

  test('retries ACL conflicts while authorizing a load requester', async () => {
    const readers = jest
      .fn<() => Promise<string[]>>()
      .mockRejectedValueOnce(
        new ACLOperationInProgressError('reader listing', Promise.resolve()),
      )
      .mockResolvedValue([]);
    const writers = jest
      .fn<() => Promise<string[]>>()
      .mockRejectedValueOnce(
        new ACLOperationInProgressError('writer listing', Promise.resolve()),
      )
      .mockResolvedValue(['writer']);
    const verify = jest.fn(async () => true);
    const document = fakeDocument({
      swarm: { config: { enableSigning: true } },
      _deserializeSignature: jest.fn(() => new Uint8Array([1])),
      _encoder: new TextEncoder(),
      _readers: { users: readers },
      _writers: { users: writers },
      _authProvider: { verify },
    });

    await expect(
      document._isLoadRequesterAuthorized({
        documentId: '/retry-load-requester',
        signature: 'AAAA',
      }),
    ).resolves.toBe(true);
    expect(readers).toHaveBeenCalledTimes(2);
    expect(writers).toHaveBeenCalledTimes(2);
    expect(verify).toHaveBeenCalledTimes(1);
  });

  test('verifies writers serially with isolated payload and signature bytes', async () => {
    let active = 0;
    let peak = 0;
    const payloads: number[][] = [];
    const signatures: number[][] = [];
    const { document, stream } = signedLoadHarness(
      async () => ['rejecting-writer', 'accepting-writer'],
      async (raw, writer, signature) => {
        active++;
        peak = Math.max(peak, active);
        payloads.push([...raw as Uint8Array]);
        signatures.push([...signature as Uint8Array]);
        (raw as Uint8Array).fill(99);
        (signature as Uint8Array).fill(99);
        await Promise.resolve();
        active--;
        return writer === 'accepting-writer';
      },
    );
    document._bootstrapLoadApplicationState = 'complete';
    document._syncUnlocked = jest.fn(async () => true);
    await expect(document._sendLoadRequestAndSync(stream, new Uint8Array([1])))
      .resolves.toBe(true);
    expect(peak).toBe(1);
    expect(payloads).toEqual([[8], [8], [8], [8]]);
    expect(signatures).toEqual(Array.from({ length: 4 }, () => [0, 0, 0]));
    expect(document._syncUnlocked).toHaveBeenCalledTimes(1);
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
    // The writer revision rejects this stale admission before a second lookup.
    expect(document._writers.users).toHaveBeenCalledTimes(1);
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
      signatureContext: 'load-response-v3',
      tips: [],
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
    document._changesSerializer = {
      deserializeChanges: jest.fn(() => ({ prefetched: true })),
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
    expect(serialize).toHaveBeenCalled();
    for (const [unsigned] of serialize.mock.calls) {
      expect(unsigned.changes.change).toEqual({
        value: 'signed-inline-change',
      });
    }
    expect(document._syncUnlocked).toHaveBeenCalledTimes(1);
  });

  test('reuses a validated prefetched block under one aggregate byte budget', async () => {
    const message = {
      documentId: '/prefetch-cache',
      signatureContext: 'load-response-v3',
      signature: 'AAAA',
      changeId: 'HEAD',
      tips: ['HEAD'],
      changes: { kind: crdtDocumentChangeNode, change: { inline: true } },
    };
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => {
        throw new Error('bootstrap must not invoke signature verification');
      },
      message,
    );
    const get = jest.fn(async function* () {
      yield new Uint8Array([1, 2, 3]);
    });
    const decodedChanges = { value: 'decoded-once' };
    const remoteChange = jest.fn((state: unknown) => state);
    document.swarm.heliaNode = { blockstore: { get } };
    document._writers = { users: jest.fn(async () => []) };
    document._changesSerializer = {
      deserializeChanges: jest.fn(() => decodedChanges),
    };
    document._document = {};
    document._referencedAncestors = new Set<string>();
    document._mergeSyncTree = jest.fn(async () => [
      ['HEAD', crdtDocumentChangeNode, undefined],
    ]);
    document._crdtProvider = { remoteChange };
    document._documentChangeCount = 0;
    document._changesSinceSnapshot = 0;
    document._recentTips = [];
    document._fireOrDeferRemoteUpdateHandlers = jest.fn(async () => undefined);
    document._refreshLastSyncMessageFromSync = jest.fn();
    document._bootstrapCompactionDeferred = false;
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        _context: string,
        onStateApplicationStart: (() => void) | undefined,
        _continuePending: boolean,
        _onLogicalKeychainChange: (() => void) | undefined,
        fetchOptions: any,
      ) => {
        onStateApplicationStart?.();
        await (PeerborneDocument.prototype as any)._syncDocumentChanges.call(
          document,
          'HEAD',
          { kind: crdtDocumentChangeNode },
          fetchOptions,
        );
        return true;
      },
    );
    document._completeBootstrapStateApplicationUnlocked = jest.fn(
      async () => document._markBootstrapStateApplicationComplete(),
    );
    const expectedTipsHash = tipsHashToHex(await tipsHash(['HEAD']));

    await expect(
      document._sendLoadRequestAndSync(
        stream,
        new Uint8Array([1]),
        expectedTipsHash,
        undefined,
        3,
      ),
    ).resolves.toBe(true);

    expect(get).toHaveBeenCalledTimes(1);
    expect(document._changesSerializer.deserializeChanges).toHaveBeenCalledTimes(1);
    expect(remoteChange).toHaveBeenCalledWith(document._document, decodedChanges);
  });

  test.each(['blockstore', 'prefetched'] as const)(
    'decrypts an invitation change block through only the staged key view: %s',
    async (source) => {
      const stagedKey = { staged: true };
      const stagedGetKey = jest.fn(() => stagedKey);
      const liveGetKey = jest.fn(() => {
        throw new Error('live keychain must remain untouched');
      });
      const block = new Uint8Array([7, 8, 9]);
      const get = jest.fn(async function* () {
        yield block;
      });
      const decodedChanges = { value: 'staged-decryption' };
      const decrypt = jest.fn(async () => new Uint8Array([10]));
      const remoteChange = jest.fn(() => decodedChanges);
      const document = fakeDocument({
        documentPath: '/staged-block-decryption',
        _bootstrapLoadApplicationState: 'pending',
        _document: {},
        _hashes: new Set<string>(),
        _referencedAncestors: new Set<string>(),
        _lastSyncMessage: undefined,
        _latestSnapshot: undefined,
        _mergeSyncTree: jest.fn(async () => [
          ['HEAD', crdtDocumentChangeNode, undefined],
        ]),
        _keychainProvider: { keyIDLength: 1 },
        _keychain: { getKey: liveGetKey },
        _authProvider: { nonceBits: 1, decrypt },
        _changesSerializer: {
          deserializeChanges: jest.fn(() => decodedChanges),
        },
        _crdtProvider: { remoteChange },
        _documentChangeCount: 0,
        _changesSinceSnapshot: 0,
        _recentTips: [],
        _pendingBootstrapRemoteUpdateHashes: new Set<string>(),
        _remoteHandlers: {},
        _refreshLastSyncMessageFromSync: jest.fn(),
        _bootstrapCompactionDeferred: false,
        _maybeCompact: jest.fn(async () => undefined),
        swarm: { heliaNode: { blockstore: { get } } },
      });

      await expect(
        document._syncDocumentChanges(
          'HEAD',
          { kind: crdtDocumentChangeNode },
          {
            getKey: stagedGetKey,
            ...(source === 'prefetched'
              ? { prefetchedBlocks: new Map([['HEAD', block]]) }
              : {}),
          },
        ),
      ).resolves.toBeUndefined();

      expect(stagedGetKey).toHaveBeenCalledWith(new Uint8Array([7]));
      expect(liveGetKey).not.toHaveBeenCalled();
      expect(get).toHaveBeenCalledTimes(source === 'blockstore' ? 1 : 0);
      expect(decrypt).toHaveBeenCalledWith(
        new Uint8Array([9]),
        stagedKey,
        new Uint8Array([8]),
      );
      expect(remoteChange).toHaveBeenCalledTimes(1);
      expect(document._hashes).toContain('HEAD');
    },
  );

  test.each(['gc-missing', 'over-budget'] as const)(
    'does not prefetch or budget known compacted history on an established load: %s',
    async (knownBlockMode) => {
      const message = {
        documentId: '/established-prefetch',
        signatureContext: 'load-response-v3',
        signature: 'AAAA',
        changeId: 'HEAD',
        tips: ['HEAD'],
        changes: {
          kind: crdtDocumentChangeNode,
          change: { inline: 'head' },
          children: {
            KNOWN: {
              kind: crdtDocumentChangeNode,
              change: { inline: 'compacted-history' },
            },
          },
        },
      };
      const { document, stream } = signedLoadHarness(
        async () => ['current-writer'],
        async () => true,
        message,
      );
      document._bootstrapLoadApplicationState = 'complete';
      document._bootstrapLoadApplicationRevision = 2;
      document._hashes.add('KNOWN');
      document._writers = { users: jest.fn(async () => ['current-writer']) };
      const get = jest.fn((cid: { toString(): string }) =>
        (async function* () {
          if (cid.toString() === 'KNOWN' && knownBlockMode === 'gc-missing') {
            throw new Error('compacted block was garbage-collected');
          }
          yield new Uint8Array([1, 2, 3]);
        })(),
      );
      document.swarm.heliaNode = { blockstore: { get } };
      document._syncUnlocked = jest.fn(
        async (
          appliedMessage: any,
          _verifySignature: boolean,
          _context: string,
          _onStateApplicationStart: (() => void) | undefined,
          _continuePending: boolean,
          _onLogicalKeychainChange: (() => void) | undefined,
          fetchOptions: any,
        ) => {
          expect(appliedMessage.changes.change).toBeUndefined();
          expect(appliedMessage.changes.children.KNOWN.change).toBeUndefined();
          expect(fetchOptions.prefetchedBlocks.has('HEAD')).toBe(true);
          expect(fetchOptions.prefetchedBlocks.has('KNOWN')).toBe(false);
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
          undefined,
          3,
        ),
      ).resolves.toBe(true);

      expect(get.mock.calls.map(([cid]) => cid.toString())).toEqual(['HEAD']);
      expect(document._hashes).toEqual(new Set(['KNOWN', 'HEAD']));
    },
  );

  test('does not skip prefetch for a transient hash that a queued mutation rolls back', async () => {
    const message = {
      documentId: '/transient-prefetch-hash',
      signatureContext: 'load-response-v3',
      signature: 'AAAA',
      changeId: 'HEAD',
      tips: ['HEAD'],
      changes: {
        kind: crdtDocumentChangeNode,
        change: { inline: 'head' },
      },
    };
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => true,
      message,
    );
    document._bootstrapLoadApplicationState = 'complete';
    document._bootstrapLoadApplicationRevision = 2;
    document._writers = { users: jest.fn(async () => ['issuer']) };
    const queue = new InvitationMembershipQueue();
    const transientHashInstalled = deferred<void>();
    const releaseTransientMutation = deferred<void>();
    let queueAdmissions = 0;
    document._mutationQueue = {
      run: <T>(operation: () => Promise<T>): Promise<T> => {
        queueAdmissions++;
        if (queueAdmissions === 2) releaseTransientMutation.resolve();
        return queue.run(operation);
      },
    };
    const transientMutation = document._mutationQueue.run(async () => {
      document._hashes.add('HEAD');
      transientHashInstalled.resolve();
      await releaseTransientMutation.promise;
      document._hashes.delete('HEAD');
    });
    await transientHashInstalled.promise;

    const get = jest.fn(async function* () {
      yield new Uint8Array([1]);
    });
    document.swarm.heliaNode = { blockstore: { get } };
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        _context: string,
        onStateApplicationStart: (() => void) | undefined,
        _continuePending: boolean,
        _onLogicalKeychainChange: (() => void) | undefined,
        fetchOptions: any,
      ) => {
        expect(fetchOptions.prefetchedBlocks.has('HEAD')).toBe(true);
        onStateApplicationStart?.();
        document._hashes.add('HEAD');
        return true;
      },
    );
    document._completeBootstrapStateApplicationUnlocked = jest.fn(
      async () => document._markBootstrapStateApplicationComplete(),
    );
    const expectedTipsHash = tipsHashToHex(await tipsHash(['HEAD']));

    await expect(
      document._sendLoadRequestAndSync(
        stream,
        new Uint8Array([1]),
        expectedTipsHash,
        'issuer',
      ),
    ).resolves.toBe(true);
    await expect(transientMutation).resolves.toBeUndefined();

    expect(get).toHaveBeenCalledTimes(1);
    expect(document._hashes).toContain('HEAD');
    expect(document._bootstrapLoadApplicationState).toBe('complete');
  });

  test('does not require GC history below an already-applied snapshot boundary', async () => {
    const message = {
      documentId: '/snapshot-prefetch',
      signatureContext: 'load-response-v3',
      signature: 'AAAA',
      changeId: 'HEAD',
      tips: ['HEAD'],
      changes: {
        kind: crdtDocumentChangeNode,
        change: { inline: 'head' },
        children: {
          SNAPSHOT: {
            kind: crdtDocumentChangeNode,
            children: {
              'GC-ANCESTOR': { kind: crdtDocumentChangeNode },
            },
          },
        },
      },
    };
    const { document, stream } = signedLoadHarness(
      async () => ['current-writer'],
      async () => true,
      message,
    );
    document._bootstrapLoadApplicationState = 'complete';
    document._bootstrapLoadApplicationRevision = 2;
    document._hashes.add('SNAPSHOT');
    document._latestSnapshot = { lastChangeNodeCID: 'SNAPSHOT' };
    document._writers = { users: jest.fn(async () => ['current-writer']) };
    const get = jest.fn((cid: { toString(): string }) =>
      (async function* () {
        if (cid.toString() !== 'HEAD') {
          throw new Error('snapshot-covered block was garbage-collected');
        }
        yield new Uint8Array([1]);
      })(),
    );
    document.swarm.heliaNode = { blockstore: { get } };
    document._syncUnlocked = jest.fn(async () => {
      document._hashes.add('HEAD');
      return true;
    });
    const expectedTipsHash = tipsHashToHex(await tipsHash(['HEAD']));

    await expect(
      document._sendLoadRequestAndSync(
        stream,
        new Uint8Array([1]),
        expectedTipsHash,
      ),
    ).resolves.toBe(true);

    expect(get.mock.calls.map(([cid]) => cid.toString())).toEqual(['HEAD']);
    expect(document._hashes.has('GC-ANCESTOR')).toBe(false);
  });

  test('does not classify a prefetch provider RangeError as a byte limit', async () => {
    const secret = 'prefetch-provider-private-sentinel';
    const message = {
      documentId: '/prefetch-provider-range-error',
      signatureContext: 'load-response-v3',
      signature: 'AAAA',
      changeId: 'HEAD',
      tips: ['HEAD'],
      changes: { kind: crdtDocumentChangeNode, change: { inline: true } },
    };
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => {
        throw new Error('bootstrap must not invoke signature verification');
      },
      message,
    );
    document._writers = { users: jest.fn(async () => []) };
    document.swarm.heliaNode = {
      blockstore: {
        get: jest.fn(() => {
          throw new RangeError(secret);
        }),
      },
    };
    const expectedTipsHash = tipsHashToHex(await tipsHash(['HEAD']));
    const consoleWarn = jest
      .spyOn(console, 'warn')
      .mockImplementation(() => undefined);
    let rejection: unknown;

    try {
      await document._sendLoadRequestAndSync(
        stream,
        new Uint8Array([1]),
        expectedTipsHash,
      );
    } catch (error) {
      rejection = error;
    } finally {
      consoleWarn.mockRestore();
    }

    expect(rejection).toBeInstanceOf(Error);
    expect((rejection as Error).message).toMatch(/could not retrieve/);
    expect((rejection as Error).message).not.toMatch(/limits exceeded/);
    expect(document._hashes).toEqual(new Set());
    expect(JSON.stringify(consoleWarn.mock.calls)).not.toContain(secret);
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
        _context: string,
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
      signatureContext: 'load-response-v3',
      tips: [],
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
      signatureContext: 'load-response-v3',
      tips: [],
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
      signatureContext: 'load-response-v3',
      tips: [],
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
      signatureContext: 'load-response-v3',
      tips: [],
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

  test('skips a non-quorum bootstrap peer whose hash-only blocks are unavailable before state application', async () => {
    const message = {
      documentId: '/load-race',
      signatureContext: 'load-response-v3',
      tips: [],
      signature: 'AAAA',
      changeId: 'hash-only-head',
      changes: { kind: crdtDocumentChangeNode },
    };
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => {
        throw new Error('bootstrap must not invoke signature verification');
      },
      message,
    );
    document.swarm.heliaNode.blockstore.get = jest.fn(async function* () {
      throw new Error('block unavailable');
    });
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        _context: string,
        onStateApplicationStart?: () => void,
      ) => {
        onStateApplicationStart?.();
        document._hashes.add('hash-only-head');
        return true;
      },
    );
    const consoleWarn = jest
      .spyOn(console, 'warn')
      .mockImplementation(() => undefined);

    try {
      await expect(
        document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
      ).resolves.toBe(false);
    } finally {
      consoleWarn.mockRestore();
    }
    expect(document._syncUnlocked).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('pristine');
    expect(() => document._assertNoIncompleteBootstrapLoad()).not.toThrow();

    document.swarm.heliaNode.blockstore.get = jest.fn(async function* () {
      yield new Uint8Array([1]);
    });
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
    expect(document._bootstrapLoadApplicationState).toBe('complete');
  });

  test('keeps bootstrap retryable when a response is rejected before state application', async () => {
    const validMessage = {
      documentId: '/load-race',
      signatureContext: 'load-response-v3',
      tips: [],
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
        _context: string,
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
      signatureContext: 'load-response-v3',
      tips: [],
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
      signatureContext: 'load-response-v3',
      tips: [],
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
        _context: string,
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
      signatureContext: 'load-response-v3',
      tips: [],
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
        _context: string,
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
        _context: string,
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
        signatureContext: 'load-response-v3',
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

  test('rejects established pinned catch-up before mutation while an older notification waits', async () => {
    const { document, stream } = signedLoadHarness(
      async () => {
        throw new Error('pinned admission must not read the writer ACL');
      },
      async (_raw, key) => key === 'pinned-writer',
      {
        documentId: '/load-race',
        signatureContext: 'load-response-v3',
        signature: 'AAAA',
        changeId: 'new-head',
        changes: {
          kind: crdtDocumentChangeNode,
          change: { value: 'must-not-apply' },
        },
      },
    );
    const mutationQueue = new InvitationMembershipQueue();
    const conflict = new ACLOperationInProgressError(
      'reader listing',
      new Promise<void>(() => undefined),
    );
    const handler = jest.fn();
    document._bootstrapLoadApplicationState = 'complete';
    document._bootstrapLoadApplicationRevision = 2;
    document._hashes.add('existing-head');
    document._mutationQueue = mutationQueue;
    document._readers = {
      users: jest.fn(async () => {
        throw conflict;
      }),
    };
    document._writers = { users: jest.fn(async () => []) };
    document._remoteHandlers.preCatchUp = handler;
    document._syncUnlocked = jest.fn(async () => {
      document._document = { value: 'mutated' };
      document._hashes.add('new-head');
      document._markBootstrapStateApplicationPending();
      return true;
    });

    await document._fireOrDeferRemoteUpdateHandlers(['older-head']);
    const notificationTail = document._remoteUpdateNotificationTail;
    expect(notificationTail).toBeDefined();

    await expect(
      document._sendLoadRequestAndSync(
        stream,
        new Uint8Array([1]),
        null,
        'pinned-writer',
      ),
    ).resolves.toBe(false);

    expect(document._syncUnlocked).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('complete');
    expect(document._bootstrapLoadApplicationRevision).toBe(2);
    expect(document._hashes).toEqual(new Set(['existing-head']));
    expect(handler).not.toHaveBeenCalled();
    expect(document._remoteUpdateNotificationTail).toBe(notificationTail);
    await expect(
      mutationQueue.run(async () => 'queue released'),
    ).resolves.toBe('queue released');
  });

  test('leaves an incomplete legacy bootstrap pending without notifying subscribers', async () => {
    const message = {
      documentId: '/load-race',
      signatureContext: 'load-response-v3',
      tips: [],
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
        _context: string,
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
      signatureContext: 'load-response-v3',
      tips: [],
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
        _context: string,
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

  test('keeps an established unsigned document usable after a failed catch-up', async () => {
    const message = {
      documentId: '/load-race',
      signatureContext: 'load-response-v3',
      tips: [],
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
    document._bootstrapLoadApplicationState = 'complete';
    document._hashes.add('established-head');
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        _context: string,
        onStateApplicationStart?: () => void,
      ) => {
        expect(onStateApplicationStart).toBeUndefined();
        expect(document._bootstrapLoadApplicationState).toBe('complete');
        throw new Error('provider failed after unsigned state application');
      },
    );

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).rejects.toThrow(/provider failed/);
    expect(document._syncUnlocked).toHaveBeenCalledTimes(1);
    expect(document._bootstrapLoadApplicationState).toBe('complete');
    expect(() => document._assertNoIncompleteBootstrapLoad()).not.toThrow();
  });

  test('applies an established unsigned catch-up without bootstrap fetch caps', async () => {
    const message = {
      documentId: '/load-race',
      signatureContext: 'load-response-v3',
      tips: [],
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
    document._bootstrapLoadApplicationState = 'complete';
    document._hashes.add('established-head');
    document._readBlock = jest.fn(async () => {
      throw new Error('ordinary catch-up must not pre-fetch blocks');
    });
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        _context: string,
        onStateApplicationStart: unknown,
        _continuing: unknown,
        _onKeychain: unknown,
        fetchOptions: Record<string, unknown> | undefined,
      ) => {
        expect(onStateApplicationStart).toBeUndefined();
        expect(fetchOptions?.maxBlockBytes).toBeUndefined();
        expect(fetchOptions?.maxAggregateBlockBytes).toBeUndefined();
        expect(fetchOptions?.aggregateBudget).toBeUndefined();
        document._hashes.add('unsigned-head');
        return true;
      },
    );

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).resolves.toBe(true);
    expect(document._syncUnlocked).toHaveBeenCalledTimes(1);
    expect(document._readBlock).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('complete');
  });

  test('skips an ordinary unsigned catch-up that is no longer established at the queue', async () => {
    const message = {
      documentId: '/load-race',
      signatureContext: 'load-response-v3',
      tips: [],
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
    document._bootstrapLoadApplicationState = 'complete';
    document._hashes.add('established-head');
    document._mutationQueue = {
      run: (operation: () => Promise<unknown>) => {
        document._hashes.clear();
        return operation();
      },
    };
    document._syncUnlocked = jest.fn(async () => true);

    await expect(
      document._sendLoadRequestAndSync(stream, new Uint8Array([1])),
    ).resolves.toBe(false);
    expect(document._syncUnlocked).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('complete');
  });

  test('tracks and defers an incomplete signer-pinned catch-up', async () => {
    const message = {
      documentId: '/load-race',
      signatureContext: 'load-response-v3',
      tips: [],
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
        _context: string,
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
    await expect(document.sync({
        documentId: '/poisoned',
        signatureContext: 'ordinary-sync-v1',
      })).rejects.toThrow(
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

    const sync = document.sync({
      documentId: '/queued-before-poison',
      signatureContext: 'ordinary-sync-v1',
    });
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
        signatureContext: 'load-response-v3',
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

  test.each([false, true])('handles a provider-semantic no-op with commit failure %p', async (commitFails) => {
    const message = {
      documentId: '/load-race',
      signatureContext: 'load-response-v3',
      tips: [],
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
    const commit = jest.fn(() => {
      if (commitFails) throw new Error('indeterminate no-op commit');
    });
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

    const result = document._sendLoadRequestAndSync(stream, new Uint8Array([1]));
    if (commitFails) {
      await expect(result).rejects.toThrow('indeterminate no-op commit');
    } else {
      await expect(result).resolves.toBe(false);
    }

    expect(document._keychain.prepareMerge).toHaveBeenCalledWith(
      message.keychainChanges,
    );
    expect(commit).toHaveBeenCalledTimes(1);
    expect(hydrateKeys).not.toHaveBeenCalled();
    expect(merge).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe(commitFails ? 'pending' : 'pristine');
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
            signatureContext: 'load-response-v3',
            keychainChanges: { providerEncoding: 'one-key' },
          },
          false,
          'load-response-v3',
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

  test('reserves bootstrap state before awaiting the ACL pre-pass', async () => {
    const mergeStarted = deferred<void>();
    const releaseMerge = deferred<void>();
    let reserved = false;
    const beginStateApplication = jest.fn(() => {
      reserved = true;
    });
    const mergeReaders = jest.fn(async () => {
      expect(reserved).toBe(true);
      mergeStarted.resolve();
      await releaseMerge.promise;
    });
    const syncDocumentChanges = jest.fn(async () => undefined);
    const document = fakeDocument({
      documentPath: '/acl-prepass-reservation',
      swarm: { config: { enableSigning: false } },
      _bootstrapLoadApplicationState: 'pristine',
      _keychain: {},
      _latestSnapshot: undefined,
      _mergeReaders: mergeReaders,
      _mergeWriters: jest.fn(async () => undefined),
      _syncDocumentChanges: syncDocumentChanges,
    });

    const sync = document._syncUnlocked(
      {
        documentId: '/acl-prepass-reservation',
        signatureContext: 'load-response-v3',
        changeId: 'READER',
        changes: {
          kind: crdtReaderChangeNode,
          change: { reader: 'partial' },
        },
      },
      false,
      'load-response-v3',
      beginStateApplication,
    );
    await mergeStarted.promise;

    expect(beginStateApplication).toHaveBeenCalledTimes(1);
    expect(syncDocumentChanges).not.toHaveBeenCalled();
    releaseMerge.resolve();
    await expect(sync).resolves.toBe(true);
    expect(mergeReaders).toHaveBeenCalledTimes(1);
    expect(syncDocumentChanges).toHaveBeenCalledTimes(1);
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
            signatureContext: 'load-response-v3',
            signature: 'AAAA',
            snapshot: {
              state: {},
              timestamp: 1,
              compactedCount: 1,
              signature: 'AAAA',
            },
          },
          false,
          'load-response-v3',
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
        signatureContext: 'load-response-v3',
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
      signatureContext: 'load-response-v3',
      tips: [],
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

  test.each([undefined, Symbol('forged-continuation')])(
    'does not let an ordinary pinned load continue a pending bootstrap: %p',
    async (forgedContinuation) => {
      const { document, stream } = signedLoadHarness(
        async () => ['issuer'],
        async () => true,
      );
      document._bootstrapLoadApplicationState = 'pending';
      document._syncUnlocked = jest.fn(async () => true);

      await expect(
        document._sendLoadRequestAndSync(
          stream,
          new Uint8Array([1]),
          null,
          'issuer',
          undefined,
          true,
          undefined,
          undefined,
          undefined,
          forgedContinuation,
        ),
      ).resolves.toBe(false);

      expect(stream.abort).toHaveBeenCalledTimes(1);
      expect(document._syncUnlocked).not.toHaveBeenCalled();
    },
  );

  test('does not resume a deferred load after its invitation continuation is revoked', async () => {
    const continuation = {};
    const sourceStarted = deferred<void>();
    const releaseSource = deferred<void>();
    const { document, stream } = signedLoadHarness(
      async () => ['issuer'],
      async () => true,
    );
    stream.source = (async function* () {
      sourceStarted.resolve();
      await releaseSource.promise;
      yield new Uint8Array([1, 2, 3]);
    })();
    document._bootstrapLoadApplicationState = 'pending';
    document._activeInvitationBootstrapContinuation = continuation;
    document._syncUnlocked = jest.fn(async () => {
      document._hashes.add('STALE');
      return true;
    });

    const staleLoad = document._sendLoadRequestAndSync(
      stream,
      new Uint8Array([1]),
      null,
      'issuer',
      undefined,
      true,
      undefined,
      undefined,
      undefined,
      continuation,
    );
    await sourceStarted.promise;

    // Model the outer deadline path revoking its per-acceptance capability
    // while an underlying Promise.race loser remains alive.
    document._activeInvitationBootstrapContinuation = undefined;
    releaseSource.resolve();

    await expect(staleLoad).resolves.toBe(false);
    expect(document._syncUnlocked).not.toHaveBeenCalled();
    expect(document._hashes).toEqual(new Set());
    expect(document._bootstrapLoadApplicationState).toBe('pending');
  });

  test('stops a multi-entry ACL prepass after a deferred merge loses its continuation', async () => {
    const continuation = {};
    const firstMergeStarted = deferred<void>();
    const releaseFirstMerge = deferred<void>();
    const mergeReader = jest.fn(async () => {
      firstMergeStarted.resolve();
      await releaseFirstMerge.promise;
    });
    const mergeWriter = jest.fn(async () => undefined);
    const syncDocumentChanges = jest.fn(async () => undefined);
    const applySnapshot = jest.fn(() => ({ snapshot: true }));
    const document = fakeDocument({
      documentPath: '/revoked-acl-prepass',
      swarm: { config: { enableSigning: false } },
      _bootstrapLoadApplicationState: 'pending',
      _activeInvitationBootstrapContinuation: continuation,
      _document: {},
      _hashes: new Set<string>(),
      _readers: { merge: mergeReader },
      _writers: { merge: mergeWriter },
      _pendingWelcomes: new Map(),
      _writerMutationsInFlight: 0,
      _cachedWriterKeys: null,
      _writerKeysVersion: 0,
      _collectACLFromTree: jest.fn(() => ({
        aclEntries: [
          { kind: crdtReaderChangeNode, change: { reader: true } },
          { kind: crdtWriterChangeNode, change: { writer: true } },
        ],
        changes: { kind: crdtDocumentChangeNode },
      })),
      _syncDocumentChanges: syncDocumentChanges,
      _latestSnapshot: undefined,
      _crdtProvider: { applySnapshot },
    });
    const assertStillActive = () => {
      if (document._activeInvitationBootstrapContinuation !== continuation) {
        throw new Error('invitation continuation revoked');
      }
    };

    const syncing = document._syncUnlocked(
      {
        documentId: '/revoked-acl-prepass',
        signatureContext: 'load-response-v3',
        changeId: 'HEAD',
        changes: { kind: crdtDocumentChangeNode },
        snapshot: {
          state: { snapshot: true },
          lastChangeNodeCID: 'SNAPSHOT',
          compactedCount: 1,
          signature: 'AAAA',
          timestamp: 1,
        },
      },
      false,
      'load-response-v3',
      undefined,
      true,
      undefined,
      { assertStillActive },
    );
    await firstMergeStarted.promise;

    document._activeInvitationBootstrapContinuation = undefined;
    releaseFirstMerge.resolve();

    await expect(syncing).rejects.toThrow(/continuation revoked/);
    expect(mergeReader).toHaveBeenCalledTimes(1);
    expect(mergeWriter).not.toHaveBeenCalled();
    expect(applySnapshot).not.toHaveBeenCalled();
    expect(syncDocumentChanges).not.toHaveBeenCalled();
    expect(document._hashes).toEqual(new Set());
    expect(document._bootstrapLoadApplicationState).toBe('pending');
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
      document._runInvitationBootstrapStateApplication(async (begin: () => void) => {
        expect(document._bootstrapLoadApplicationState).toBe('pristine');
        begin();
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

  test.each([
    ['Welcome drain', 'drain'],
    ['deferred compaction', 'compact'],
    ['notification preparation', 'prepare'],
  ] as const)(
    'releases the load deadline when %s never settles during finalization',
    async (_label, stage) => {
      const started = deferred<void>();
      const hung = (): Promise<never> => {
        started.resolve();
        return new Promise<never>(() => {});
      };
      const dispatch = jest.fn();
      const document = fakeDocument({
        documentPath: '/hung-finalization',
        _bootstrapLoadApplicationState: 'pending',
        _document: { value: 'bootstrap' },
        _pendingWelcomes: new Map(stage === 'drain' ? [['buffered', {}]] : []),
        _pendingBootstrapRemoteUpdateHashes: new Set<string>(),
        _bootstrapCompactionDeferred: stage === 'compact',
        _remoteHandlers: {},
        _drainPendingWelcomesUnlocked: jest.fn(hung),
        _maybeCompact: jest.fn(hung),
        _prepareDeferredBootstrapRemoteUpdateNotification: jest.fn(
          stage === 'prepare' ? hung : async () => undefined,
        ),
        _dispatchRemoteUpdateHandlers: dispatch,
      });
      const controller = new AbortController();

      const completion = document._completeBootstrapStateApplicationUnlocked(
        undefined,
        controller.signal,
      );
      await started.promise;
      controller.abort(new Error('Invitation stream deadline exceeded'));

      await expect(completion).rejects.toThrow(/deadline exceeded/);
      expect(document._bootstrapLoadApplicationState).toBe('pending');
      expect(() => document.document).toThrow(/discard this document instance/);
      expect(dispatch).not.toHaveBeenCalled();
    },
  );

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
      return {
        documentId: '/validator-bootstrap',
        signatureContext: 'ordinary-sync-v1',
        signature: 'AAAA',
      };
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
            signatureContext: 'ordinary-sync-v1',
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
      'serialize',
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

  test.each([
    'handleLoadRequestData',
    'handleSnapshotLoadRequestData',
    'handleTipAdvertiseRequestData',
  ] as const)(
    '%s rechecks the requester against the queued current ACL before send',
    async (methodName) => {
      const responseConstructionPaused = deferred<void>();
      const releaseResponseConstruction = deferred<void>();
      const mutationQueue = new InvitationMembershipQueue();
      let authorized = true;
      const sink = jest.fn(async () => undefined);
      const document = fakeDocument({
        documentPath: '/response-revocation',
        _bootstrapLoadApplicationState: 'complete',
        _bootstrapLoadApplicationRevision: 2,
        _encoder: new TextEncoder(),
        _mutationQueue: mutationQueue,
        swarm: { config: { enableSigning: true } },
        _readers: {
          users: jest.fn(async () =>
            authorized ? ['revoked-reader'] : [],
          ),
        },
        _writers: { users: jest.fn(async () => []) },
        _createSyncMessage: jest.fn(() => ({
          documentId: '/response-revocation',
        })),
        _keychainChangesForVisibility: jest.fn(async () => ({ keys: [] })),
        _latestSnapshot: { lastChangeNodeCID: 'SNAPSHOT' },
        _servedFrontier: jest.fn(() => []),
        _signAsWriter: jest.fn(async () => {
          responseConstructionPaused.resolve();
          await releaseResponseConstruction.promise;
          return 'response-signature';
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
          verify: jest.fn(async () => true),
          encrypt: jest.fn(async () => ({
            nonce: new Uint8Array([2]),
            data: new Uint8Array([3]),
          })),
        },
      });

      const response = document[methodName](
        { documentId: '/response-revocation', signature: 'AAAA' },
        { sink },
      );
      await responseConstructionPaused.promise;
      await mutationQueue.run(async () => {
        authorized = false;
      });
      releaseResponseConstruction.resolve();
      await expect(response).resolves.toBeUndefined();

      expect(document._readers.users).toHaveBeenCalledTimes(2);
      expect(sink).toHaveBeenCalledTimes(1);
      expect(sink).toHaveBeenCalledWith([]);
    },
  );

  function queuedAuthorizationConflictHarness(
    conflictingACL: 'readers' | 'writers',
    settlement: Promise<void>,
  ) {
    const mutationQueue = new InvitationMembershipQueue();
    let conflictingReads = 0;
    const conflictingUsers = jest.fn(async () => {
      if (++conflictingReads === 2) {
        throw new ACLOperationInProgressError(
          'queued authorization conflict',
          settlement,
        );
      }
      return ['requester'];
    });
    const otherUsers = jest.fn(async () => [] as string[]);
    const sink = jest.fn(async () => undefined);
    const document = fakeDocument({
      documentPath: '/queued-authorization-conflict',
      _bootstrapLoadApplicationState: 'complete',
      _bootstrapLoadApplicationRevision: 2,
      _encoder: new TextEncoder(),
      _mutationQueue: mutationQueue,
      swarm: { config: { enableSigning: true } },
      _readers: {
        users: conflictingACL === 'readers' ? conflictingUsers : otherUsers,
      },
      _writers: {
        users: conflictingACL === 'writers' ? conflictingUsers : otherUsers,
      },
      _servedFrontier: jest.fn(() => []),
      _signAsWriter: jest.fn(async () => 'response-signature'),
      _syncMessageSerializer: {
        serializeSyncMessage: jest.fn(() => new Uint8Array([7])),
      },
      _keychainProvider: { keyIDLength: 1 },
      _keychain: {
        current: jest.fn(async () => [new Uint8Array([1]), {}]),
      },
      _authProvider: {
        nonceBits: 1,
        verify: jest.fn(async () => true),
        encrypt: jest.fn(async () => ({
          nonce: new Uint8Array([2]),
          data: new Uint8Array([3]),
        })),
      },
    });
    return { mutationQueue, conflictingUsers, otherUsers, sink, document };
  }

  test.each(['readers', 'writers'] as const)(
    'retries a queued %s conflict after settlement without retaining the mutation FIFO',
    async (conflictingACL) => {
      const settled = deferred<void>();
      const { mutationQueue, conflictingUsers, otherUsers, sink, document } =
        queuedAuthorizationConflictHarness(conflictingACL, settled.promise);

      const handling = document.handleTipAdvertiseRequestData(
        {
          documentId: '/queued-authorization-conflict',
          signature: 'AAAA',
        },
        { sink },
      );
      await waitFor(() => conflictingUsers.mock.calls.length === 2);
      await expect(
        mutationQueue.run(async () => 'released'),
      ).resolves.toBe('released');
      expect(sink).not.toHaveBeenCalled();

      settled.resolve();
      await expect(handling).resolves.toBeUndefined();

      expect(conflictingUsers).toHaveBeenCalledTimes(3);
      expect(otherUsers).toHaveBeenCalledTimes(3);
      expect(sink).toHaveBeenCalledTimes(1);
      expect(sink).not.toHaveBeenCalledWith([]);
    },
  );

  test('does not respond after a queued authorization conflict outlives the handler', async () => {
    const settled = deferred<void>();
    const { mutationQueue, conflictingUsers, sink, document } =
      queuedAuthorizationConflictHarness('readers', settled.promise);
    let active = true;
    const admission = {
      isActive: () => active,
      runMutation: jest.fn(),
    };

    const handling = document.handleTipAdvertiseRequestData(
      {
        documentId: '/queued-authorization-conflict',
        signature: 'AAAA',
      },
      { sink },
      admission,
    );
    await waitFor(() => conflictingUsers.mock.calls.length === 2);
    active = false;
    settled.resolve();
    await expect(handling).resolves.toBeUndefined();

    expect(conflictingUsers).toHaveBeenCalledTimes(2);
    expect(sink).not.toHaveBeenCalled();
    await expect(
      mutationQueue.run(async () => 'released'),
    ).resolves.toBe('released');
  });

  test('poisons an accepted invitation when activation catch-up fails', async () => {
    const close = jest.fn(async () => undefined);
    const continuation = {};
    const document = fakeDocument({
      documentPath: '/failed-invitation-activation',
      _bootstrapLoadApplicationState: 'pending',
      _bootstrapLoadApplicationRevision: 1,
      _invitationBootstrapReady: true,
      _activeInvitationBootstrapContinuation: continuation,
      _open: jest.fn(async () => true),
      _loadInvitationCatchUp: jest.fn(async () => false),
      _assertAcceptedInvitationMembership: jest.fn(async () => undefined),
      close,
    });

    await expect(
      document._activateAcceptedInvitationBootstrap(
        '/founder',
        'issuer',
        'reader',
        continuation,
      ),
    ).rejects.toThrow(/catch-up load failed/);

    expect(document._bootstrapLoadApplicationState).toBe('pending');
    expect(document._bootstrapLoadApplicationRevision).toBe(1);
    expect(close).toHaveBeenCalledTimes(1);
    // The enclosing invitation transaction clears its one-shot capability in
    // `finally`; this direct activation unit test mirrors that handoff before
    // checking the durable post-failure gate.
    document._activeInvitationBootstrapContinuation = undefined;
    expect(() => document._assertNoIncompleteBootstrapLoad()).toThrow(
      /discard this document instance/,
    );
  });

  test('does not publish invitation completion when final membership fails', async () => {
    const close = jest.fn(async () => undefined);
    const continuation = {};
    const complete = jest.fn(async () => undefined);
    const document = fakeDocument({
      documentPath: '/failed-invitation-membership',
      _bootstrapLoadApplicationState: 'pending',
      _bootstrapLoadApplicationRevision: 1,
      _invitationBootstrapReady: true,
      _activeInvitationBootstrapContinuation: continuation,
      _open: jest.fn(async () => true),
      _loadInvitationCatchUp: jest.fn(async () => true),
      _assertAcceptedInvitationMembership: jest.fn(async () => {
        throw new Error('final membership rejected');
      }),
      _completeBootstrapStateApplicationUnlocked: complete,
      close,
    });

    await expect(
      document._activateAcceptedInvitationBootstrap(
        '/founder',
        'issuer',
        'reader',
        continuation,
      ),
    ).rejects.toThrow(/final membership rejected/);

    expect(complete).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('pending');
    expect(document._bootstrapLoadApplicationRevision).toBe(1);
    expect(close).toHaveBeenCalledTimes(1);
  });

  test.each(['membership', 'finalization'] as const)(
    'bounds a hung post-catch-up invitation %s with a deadline',
    async (stage) => {
      jest.useFakeTimers();
      try {
        const close = jest.fn(async () => undefined);
        const continuation = {};
        const started = deferred<void>();
        const hung = (): Promise<never> => {
          started.resolve();
          return new Promise<never>(() => {});
        };
        const dispatch = jest.fn();
        const document = fakeDocument({
          documentPath: '/hung-invitation-finalization',
          _bootstrapLoadApplicationState: 'pending',
          _bootstrapLoadApplicationRevision: 1,
          _invitationBootstrapReady: true,
          _activeInvitationBootstrapContinuation: continuation,
          _open: jest.fn(async () => true),
          _loadInvitationCatchUp: jest.fn(async () => true),
          _authProvider: {
            serializePublicKey: jest.fn(async (key: string) => key),
          },
          _userPublicKey: 'recipient',
          _readers: {
            users: jest.fn(
              stage === 'membership'
                ? hung
                : async () => ['recipient'],
            ),
          },
          _writers: { users: jest.fn(async () => ['issuer']) },
          _pendingWelcomes: new Map(),
          _pendingBootstrapRemoteUpdateHashes: new Set<string>(),
          _bootstrapCompactionDeferred: false,
          _prepareDeferredBootstrapRemoteUpdateNotification: jest.fn(hung),
          _dispatchRemoteUpdateHandlers: dispatch,
          close,
        });

        const activation = document._activateAcceptedInvitationBootstrap(
          '/founder',
          'issuer',
          'reader',
          continuation,
        );
        const rejection = expect(activation).rejects.toThrow(
          /finalization deadline exceeded/,
        );
        await started.promise;
        await jest.advanceTimersByTimeAsync(INVITATION_STREAM_TIMEOUT_MS);
        await rejection;

        expect(dispatch).not.toHaveBeenCalled();
        expect(document._bootstrapLoadApplicationState).toBe('pending');
        expect(close).toHaveBeenCalledTimes(1);
      } finally {
        jest.useRealTimers();
      }
    },
  );

  test('publishes invitation completion only after open, catch-up, and final membership', async () => {
    const order: string[] = [];
    const close = jest.fn(async () => undefined);
    const continuationCapability = {};
    const document = fakeDocument({
      documentPath: '/successful-invitation-activation',
      _bootstrapLoadApplicationState: 'pending',
      _bootstrapLoadApplicationRevision: 1,
      _invitationBootstrapReady: true,
      _activeInvitationBootstrapContinuation: continuationCapability,
      _hashes: new Set(['HEAD']),
      _computeTopic: jest.fn(() => '/invitation-topic'),
      _keychainProvider: { keyIDLength: 1 },
      _authProvider: { nonceBits: 1 },
      _syncMessageSerializer: { deserializeSyncMessage: jest.fn() },
      swarm: {
        config: { enableSigning: false },
        registerDocument: jest.fn(() => {
          expect(document._bootstrapLoadApplicationState).toBe('pending');
          order.push('open');
        }),
        heliaNode: {
          libp2p: {
            services: {
              pubsub: {
                addEventListener: jest.fn(),
                subscribe: jest.fn(() => {
                  expect(document._bootstrapLoadApplicationState).toBe(
                    'pending',
                  );
                }),
              },
            },
          },
        },
      },
      _loadInvitationCatchUp: jest.fn(
        async (
          _founder: string,
          _issuer: string,
          _role: string,
          continuation: unknown,
        ) => {
          expect(continuation).toBe(continuationCapability);
          expect(document._bootstrapLoadApplicationState).toBe('pending');
          order.push('catch-up');
          return true;
        },
      ),
      _assertAcceptedInvitationMembership: jest.fn(async () => {
        expect(document._bootstrapLoadApplicationState).toBe('pending');
        order.push('membership');
      }),
      _completeBootstrapStateApplicationUnlocked: jest.fn(async () => {
        expect(document._bootstrapLoadApplicationState).toBe('pending');
        expect(
          document._activeInvitationBootstrapContinuation,
        ).toBeUndefined();
        order.push('complete');
        document._markBootstrapStateApplicationComplete();
      }),
      close,
    });

    await expect(
      document._activateAcceptedInvitationBootstrap(
        '/founder',
        'issuer',
        'reader',
        continuationCapability,
      ),
    ).resolves.toBeUndefined();

    expect(order).toEqual(['open', 'catch-up', 'membership', 'complete']);
    expect(document._bootstrapLoadApplicationState).toBe('complete');
    expect(document._bootstrapLoadApplicationRevision).toBe(2);
    expect(close).not.toHaveBeenCalled();
  });

  test('retires invitation continuation before deferred handlers observe completion', async () => {
    const continuation = {};
    const stateSeenByHandler: string[] = [];
    let reentrantDocument: unknown;
    let reentrantError: unknown;
    const handler = jest.fn(() => {
      stateSeenByHandler.push(document._bootstrapLoadApplicationState);
      try {
        reentrantDocument = document.document;
      } catch (error) {
        reentrantError = error;
      }
    });
    const currentDocument = { ready: true };
    const document = fakeDocument({
      documentPath: '/invitation-handler-completion',
      _bootstrapLoadApplicationState: 'pending',
      _bootstrapLoadApplicationRevision: 1,
      _invitationBootstrapReady: true,
      _activeInvitationBootstrapContinuation: continuation,
      _open: jest.fn(async () => true),
      _loadInvitationCatchUp: jest.fn(async () => true),
      _assertAcceptedInvitationMembership: jest.fn(async () => undefined),
      _pendingWelcomes: new Map(),
      _bootstrapCompactionDeferred: false,
      _pendingBootstrapRemoteUpdateHashes: new Set(['HEAD']),
      _remoteHandlers: { subscriber: handler },
      _document: currentDocument,
      _readers: {
        users: jest.fn(async () => ['reader']),
        check: jest.fn(async () => false),
      },
      _writers: { users: jest.fn(async () => ['writer']) },
      close: jest.fn(async () => undefined),
    });

    await expect(
      document._activateAcceptedInvitationBootstrap(
        '/founder',
        'issuer',
        'reader',
        continuation,
      ),
    ).resolves.toBeUndefined();

    expect(handler).toHaveBeenCalledTimes(1);
    expect(stateSeenByHandler).toEqual(['complete']);
    expect(reentrantDocument).toBe(currentDocument);
    expect(reentrantError).toBeUndefined();
    expect(document._activeInvitationBootstrapContinuation).toBeUndefined();
    expect(document._pendingBootstrapRemoteUpdateHashes).toEqual(new Set());
  });

  test('bounds invitation catch-up request signing with the stream deadline', async () => {
    jest.useFakeTimers();
    try {
      const continuation = {};
      const signingStarted = deferred<void>();
      const rawStream = {
        abort: jest.fn(),
        close: jest.fn(async () => undefined),
      };
      const sendLoadRequest = jest.fn(async () => true);
      const document = fakeDocument({
        documentPath: '/hung-invitation-signing',
        _bootstrapLoadApplicationState: 'pending',
        _activeInvitationBootstrapContinuation: continuation,
        _encoder: new TextEncoder(),
        swarm: {
          heliaNode: {
            libp2p: { dialProtocol: jest.fn(async () => rawStream) },
          },
        },
        _authProvider: {
          sign: jest.fn(() => {
            signingStarted.resolve();
            return new Promise<never>(() => {});
          }),
        },
        _sendLoadRequestAndSync: sendLoadRequest,
      });

      const catchUp = document._loadInvitationCatchUp(
        '/founder',
        'issuer',
        'reader',
        continuation,
      );
      const rejection = expect(catchUp).rejects.toThrow(
        /Invitation stream deadline exceeded/,
      );
      await signingStarted.promise;
      await jest.advanceTimersByTimeAsync(INVITATION_STREAM_TIMEOUT_MS);
      await rejection;

      expect(rawStream.abort).toHaveBeenCalled();
      expect(sendLoadRequest).not.toHaveBeenCalled();
    } finally {
      jest.useRealTimers();
    }
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
      signatureContext: 'load-response-v3',
      tips: [],
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
    document._changesSerializer = {
      deserializeChanges: jest.fn(() => ({ prefetched: true })),
    };
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        _context: string,
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
      signatureContext: 'load-response-v3',
      tips: [],
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
        _context: string,
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
      signatureContext: 'load-response-v3',
      tips: [],
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
      await backgroundFinished.promise;
      await expect(
        document._mutationQueue.run(async () => 'released'),
      ).resolves.toBe('released');
      releaseHydration.resolve();

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
      signatureContext: 'load-response-v3',
      tips: [],
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

  test('does not publish completion when the deadline expires while preparing a deferred notification', async () => {
    jest.useFakeTimers();
    const message = {
      documentId: '/load-race',
      signatureContext: 'load-response-v3',
      tips: [],
      signature: 'AAAA',
      keychainChanges: { providerEncoding: 'legacy-change' },
    };
    const handler = jest.fn();
    const { document, stream } = signedLoadHarness(
      async () => [],
      async () => true,
      message,
    );
    const aclReadStarted = deferred<void>();
    const releaseAclRead = deferred<void>();
    const backgroundFinished = deferred<void>();
    document._bootstrapLoadApplicationState = 'complete';
    document._bootstrapLoadApplicationRevision = 2;
    document._hashes.add('EXISTING');
    document._document = { value: 'partially-applied' };
    document._remoteHandlers.preBootstrap = handler;
    document._readers = {
      users: jest.fn(async () => {
        aclReadStarted.resolve();
        await releaseAclRead.promise;
        return ['reader'];
      }),
      check: jest.fn(async () => false),
    };
    document._writers = { users: jest.fn(async () => ['writer']) };
    document._keychain = {
      getKey: jest.fn(() => ({})),
      merge: jest.fn(() => {
        document._pendingBootstrapRemoteUpdateHashes.add('APPLIED');
      }),
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
              async () => undefined,
              signal,
            );
          } finally {
            backgroundFinished.resolve();
          }
        },
        25,
      );

      await aclReadStarted.promise;
      jest.advanceTimersByTime(25);
      await expect(load).rejects.toThrow(/deadline exceeded/);
      releaseAclRead.resolve();
      await backgroundFinished.promise;

      expect(document._bootstrapLoadApplicationState).toBe('pending');
      expect(document._pendingBootstrapRemoteUpdateHashes).toEqual(
        new Set(['APPLIED']),
      );
      expect(handler).not.toHaveBeenCalled();
    } finally {
      jest.useRealTimers();
    }
  });

  test('defers buffered Welcome drain while bootstrap state is pending', async () => {
    const scheduleDrain = jest.fn();
    const document = fakeDocument({
      _bootstrapLoadApplicationState: 'pending',
      _readers: { merge: jest.fn() },
      _schedulePendingWelcomeDrain: scheduleDrain,
    });

    await document._mergeReaders({ reader: 'partial' });

    expect(document._readers.merge).toHaveBeenCalledTimes(1);
    expect(scheduleDrain).not.toHaveBeenCalled();
  });

  test('notifies a pre-bootstrap subscriber once and only after completion', async () => {
    const message = {
      documentId: '/load-race',
      signatureContext: 'load-response-v3',
      tips: [],
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
    document._changesSerializer = {
      deserializeChanges: jest.fn(() => ({ prefetched: true })),
    };
    document._syncUnlocked = jest.fn(
      async (
        _message: unknown,
        _verifySignature: boolean,
        _context: string,
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

  test('cancels and settles the bounded missing-CID worker pool at the invitation deadline', async () => {
    jest.useFakeTimers();
    const fetchesStarted = deferred<void>();
    const backgroundFinished = deferred<void>();
    let activeFetches = 0;
    let maximumActiveFetches = 0;
    let settledFetches = 0;
    const missingEntries = Array.from({ length: 20 }, (_, index) => [
      `CID-${index}`,
      crdtDocumentChangeNode,
      undefined,
    ]);
    const get = jest.fn((_cid: unknown, options?: { signal?: AbortSignal }) =>
      (async function* () {
        const signal = options?.signal;
        activeFetches += 1;
        maximumActiveFetches = Math.max(
          maximumActiveFetches,
          activeFetches,
        );
        if (activeFetches === 8) fetchesStarted.resolve();
        try {
          await new Promise<void>((_resolve, reject) => {
            if (!signal) throw new Error('missing block fetch signal');
            if (signal.aborted) {
              reject(signal.reason);
              return;
            }
            signal.addEventListener(
              'abort',
              () => reject(signal.reason),
              { once: true },
            );
          });
          yield new Uint8Array([1, 2, 3]);
        } finally {
          activeFetches -= 1;
          settledFetches += 1;
        }
      })(),
    );
    const remoteChange = jest.fn();
    const document = fakeDocument({
      documentPath: '/cancel-missing-cids',
      swarm: { heliaNode: { blockstore: { get } } },
      _bootstrapLoadApplicationState: 'pending',
      _document: {},
      _hashes: new Set<string>(),
      _referencedAncestors: new Set<string>(),
      _lastSyncMessage: undefined,
      _mergeSyncTree: jest.fn(async () => missingEntries),
      _keychainProvider: { keyIDLength: 1 },
      _keychain: { getKey: jest.fn(() => ({})) },
      _authProvider: {
        nonceBits: 1,
        decrypt: jest.fn(async () => new Uint8Array([1])),
      },
      _changesSerializer: {
        deserializeChanges: jest.fn(() => ({ value: 'late' })),
      },
      _crdtProvider: { remoteChange },
      _documentChangeCount: 0,
      _changesSinceSnapshot: 0,
      _recentTips: [],
      _pendingBootstrapRemoteUpdateHashes: new Set<string>(),
      _remoteHandlers: {},
    });
    const stream = {
      close: jest.fn(async () => undefined),
      closeRead: jest.fn(async () => undefined),
      abort: jest.fn(),
    };

    try {
      const load = withIssuerPinnedInvitationStream(
        '/ip4/127.0.0.1/tcp/4001',
        async () => stream,
        async (_openedStream, signal) => {
          try {
            await document._syncDocumentChanges(
              'HEAD',
              { kind: crdtDocumentChangeNode },
              {
                signal,
                maxBlockBytes: 64,
                maxAggregateBlockBytes: 64,
              },
            );
          } finally {
            backgroundFinished.resolve();
          }
        },
        25,
      );

      await fetchesStarted.promise;
      jest.advanceTimersByTime(25);
      await expect(load).rejects.toThrow(/deadline exceeded/);
      await backgroundFinished.promise;

      expect(maximumActiveFetches).toBe(8);
      expect(get).toHaveBeenCalledTimes(8);
      expect(settledFetches).toBe(8);
      expect(activeFetches).toBe(0);
      expect(remoteChange).not.toHaveBeenCalled();
      expect(document._hashes).toEqual(new Set());
      expect(document._bootstrapLoadApplicationState).toBe('pending');
      for (const [, options] of get.mock.calls) {
        expect(options?.signal.aborted).toBe(true);
      }
    } finally {
      jest.useRealTimers();
    }
  });

  test('bounds each missing block and the aggregate fetched bytes', async () => {
    const createMissingBlockDocument = (
      entries: Array<[string, string, undefined]>,
      blocks: Record<string, Uint8Array>,
    ) => {
      const remoteChange = jest.fn((state: unknown) => state);
      return fakeDocument({
        documentPath: '/bounded-missing-cids',
        swarm: {
          heliaNode: {
            blockstore: {
              get: jest.fn((cid: { toString(): string }) =>
                (async function* () {
                  yield blocks[cid.toString()]!;
                })(),
              ),
            },
          },
        },
        _bootstrapLoadApplicationState: 'pending',
        _document: {},
        _hashes: new Set<string>(),
        _referencedAncestors: new Set<string>(),
        _lastSyncMessage: undefined,
        _mergeSyncTree: jest.fn(async () => entries),
        _keychainProvider: { keyIDLength: 1 },
        _keychain: { getKey: jest.fn(() => ({})) },
        _authProvider: {
          nonceBits: 1,
          decrypt: jest.fn(async () => new Uint8Array([7])),
        },
        _changesSerializer: {
          deserializeChanges: jest.fn(() => ({ value: 'bounded' })),
        },
        _crdtProvider: { remoteChange },
        _documentChangeCount: 0,
        _changesSinceSnapshot: 0,
        _recentTips: [],
        _pendingBootstrapRemoteUpdateHashes: new Set<string>(),
        _remoteHandlers: {},
      });
    };

    const oversized = createMissingBlockDocument(
      [['OVERSIZED', crdtDocumentChangeNode, undefined]],
      { OVERSIZED: new Uint8Array(5) },
    );
    await expect(
      oversized._syncDocumentChanges(
        'HEAD',
        { kind: crdtDocumentChangeNode },
        { maxBlockBytes: 4, maxAggregateBlockBytes: 8 },
      ),
    ).rejects.toThrow(/fetch limits exceeded/);
    expect(oversized._crdtProvider.remoteChange).not.toHaveBeenCalled();
    expect(oversized._bootstrapLoadApplicationState).toBe('pending');

    await expect(
      oversized._syncDocumentChanges(
        'HEAD',
        { kind: crdtDocumentChangeNode },
        { maxBlockBytes: 0, maxAggregateBlockBytes: 8 },
      ),
    ).rejects.toThrow(/positive safe integer/);

    const aggregate = createMissingBlockDocument(
      [
        ['FIRST', crdtDocumentChangeNode, undefined],
        ['SECOND', crdtDocumentChangeNode, undefined],
      ],
      {
        FIRST: new Uint8Array(3),
        SECOND: new Uint8Array(3),
      },
    );
    await expect(
      aggregate._syncDocumentChanges(
        'HEAD',
        { kind: crdtDocumentChangeNode },
        { maxBlockBytes: 3, maxAggregateBlockBytes: 5 },
      ),
    ).rejects.toThrow(/fetch limits exceeded/);
    expect(aggregate._hashes.size).toBeLessThanOrEqual(1);
    expect(aggregate._bootstrapLoadApplicationState).toBe('pending');
  });

  test('redacts arbitrary missing-block provider and serializer failures', async () => {
    const secret = 'decrypted-document-secret-sentinel';
    const consoleError = jest
      .spyOn(console, 'error')
      .mockImplementation(() => undefined);
    const document = fakeDocument({
      documentPath: '/redacted-missing-cid',
      _bootstrapLoadApplicationState: 'pending',
      _hashes: new Set<string>(),
      _referencedAncestors: new Set<string>(),
      _lastSyncMessage: undefined,
      _mergeSyncTree: jest.fn(async () => [
        ['SECRET-CID', crdtDocumentChangeNode, undefined],
      ]),
      _getBlock: jest.fn(async () => {
        // A provider may use RangeError for malformed decrypted data. It must
        // remain an ordinary redacted block miss even when load limits are
        // active, rather than being confused with the internal limit sentinel.
        throw new RangeError(secret);
      }),
      _pendingBootstrapRemoteUpdateHashes: new Set<string>(),
      _remoteHandlers: {},
      _refreshLastSyncMessageFromSync: jest.fn(),
      _bootstrapCompactionDeferred: false,
    });

    try {
      await expect(
        document._syncDocumentChanges(
          'HEAD',
          { kind: crdtDocumentChangeNode },
          { maxBlockBytes: 64, maxAggregateBlockBytes: 64 },
        ),
      ).resolves.toBeUndefined();
      expect(consoleError.mock.calls).toEqual([
        [
          'Failed to fetch missing change from blockstore:',
          'SECRET-CID',
        ],
      ]);
      expect(JSON.stringify(consoleError.mock.calls)).not.toContain(secret);
    } finally {
      consoleError.mockRestore();
    }
  });

  test('snapshots all invitation bundle bytes once and rejects shared or forged views', () => {
    const welcomeEpochId = new Uint8Array([1]);
    const sealedWelcome = new Uint8Array([2]);
    const encryptedBootstrap = new Uint8Array([1, 3, 4]);
    let propertyReads = 0;
    const input = {
      welcomeEpochId,
      sealedWelcome,
      encryptedBootstrap,
    };
    const snapshot = snapshotInvitationBootstrapBundle(
      new Proxy(input, {
        get() {
          propertyReads += 1;
          throw new Error('invitation bundle property read must not run');
        },
      }),
      1,
      1,
    );
    welcomeEpochId.fill(9);
    sealedWelcome.fill(9);
    encryptedBootstrap.fill(9);

    expect(propertyReads).toBe(0);
    expect([...snapshot.welcomeEpochId]).toEqual([1]);
    expect([...snapshot.sealedWelcome]).toEqual([2]);
    expect([...snapshot.encryptedBootstrap]).toEqual([1, 3, 4]);

    let getterCalls = 0;
    const accessorBundle = {
      sealedWelcome: new Uint8Array([2]),
      encryptedBootstrap: new Uint8Array([1, 3, 4]),
    } as Record<string, unknown>;
    Object.defineProperty(accessorBundle, 'welcomeEpochId', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return new Uint8Array([1]);
      },
    });
    expect(() =>
      snapshotInvitationBootstrapBundle(
        accessorBundle as unknown as Parameters<
          typeof snapshotInvitationBootstrapBundle
        >[0],
        1,
        1,
      ),
    ).toThrow(/enumerable data properties/);
    expect(getterCalls).toBe(0);

    expect(() =>
      snapshotInvitationBootstrapBundle(
        { ...input, extra: new Uint8Array([5]) } as Parameters<
          typeof snapshotInvitationBootstrapBundle
        >[0],
        1,
        1,
      ),
    ).toThrow(/exactly its three byte fields/);
    expect(() =>
      snapshotInvitationBootstrapBundle(
        new Proxy(input, {
          ownKeys() {
            throw new Error('unstable invitation bundle');
          },
        }),
        1,
        1,
      ),
    ).toThrow(/stable own data properties/);
    expect(() =>
      snapshotInvitationBootstrapBundle(input, 0, 1),
    ).toThrow(/positive safe integer/);

    const validBundle = (): Record<string, unknown> => ({
      welcomeEpochId: new Uint8Array([1]),
      sealedWelcome: new Uint8Array([2]),
      encryptedBootstrap: new Uint8Array([1, 3, 4]),
    });
    for (const [field, length] of [
      ['welcomeEpochId', 1],
      ['sealedWelcome', 1],
      ['encryptedBootstrap', 3],
    ] as const) {
      const sharedBundle = validBundle();
      sharedBundle[field] = new Uint8Array(new SharedArrayBuffer(length));
      expect(() =>
        snapshotInvitationBootstrapBundle(
          sharedBundle as unknown as Parameters<
            typeof snapshotInvitationBootstrapBundle
          >[0],
          1,
          1,
        ),
      ).toThrow(/invalid length or backing buffer/);

      const lookalikeBundle = validBundle();
      lookalikeBundle[field] = {
        byteLength: length,
        buffer: new ArrayBuffer(length),
        0: 1,
      };
      expect(() =>
        snapshotInvitationBootstrapBundle(
          lookalikeBundle as unknown as Parameters<
            typeof snapshotInvitationBootstrapBundle
          >[0],
          1,
          1,
        ),
      ).toThrow(/genuine Uint8Array/);
    }
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

  test('rejects invalid load byte limits before protocol I/O', async () => {
    const stream = {
      sink: jest.fn(async () => undefined),
      source: (async function* () {
        yield new Uint8Array([1]);
      })(),
      abort: jest.fn(),
    };
    const document = fakeDocument({
      swarm: { config: { loadQuorumTimeoutMs: 1000 } },
    });

    await expect(
      document._sendLoadRequestAndSync(
        stream,
        new Uint8Array([1]),
        null,
        undefined,
        0,
      ),
    ).rejects.toThrow(/positive safe integer/);
    expect(stream.sink).not.toHaveBeenCalled();
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
        _writerKeysVersion: 0,
        _writerMutationsInFlight: 0,
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


describe('poisoned state and cancellation boundaries', () => {

test('discards deferred and incoming notifications once document state is poisoned', async () => {
  const pending = new Set(['deferred']);
  const notify = jest.fn();
  const document = fakeDocument({
    _bootstrapLoadApplicationState: 'poisoned',
    _pendingBootstrapRemoteUpdateHashes: pending,
    _fireRemoteUpdateHandlers: notify,
  });
  await document._fireOrDeferRemoteUpdateHandlers(['incoming']);
  await document._fireOrDeferRemoteUpdateHandlers(['later']);
  expect(pending.size).toBe(0);
  expect(notify).not.toHaveBeenCalled();
});

test.each([
  ['Readers', true], ['Readers', false],
  ['Writers', true], ['Writers', false],
] as const)('cancellation of %s before invocation=%p preserves the mutation boundary', async (kind, beforeInvocation) => {
  let release!: () => void;
  let entered!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const started = new Promise<void>((resolve) => { entered = resolve; });
  let mutated = false;
  const merge = jest.fn(async () => {
    entered();
    await gate;
    mutated = true;
  });
  const document = fakeDocument({
    documentPath: '/abort-boundary',
    _bootstrapLoadApplicationState: 'pristine',
    _bootstrapLoadApplicationRevision: 0,
    _writerKeysVersion: 0,
    _writerMutationsInFlight: 0,
    _writerPublicationsInFlight: 0,
    _readers: { merge },
    _writers: { merge },
  });
  const controller = new AbortController();
  if (beforeInvocation) controller.abort(new Error('cancelled load'));
  const result = document[`_merge${kind}`]({}, undefined, controller.signal);
  if (!beforeInvocation) {
    await started;
    controller.abort(new Error('cancelled load'));
  }
  try {
    await expect(result).rejects.toThrow('cancelled load');
    expect(document._bootstrapLoadApplicationState).toBe(beforeInvocation ? 'pristine' : 'poisoned');
    expect(merge).toHaveBeenCalledTimes(beforeInvocation ? 0 : 1);
  } finally {
    release();
  }
  if (!beforeInvocation) {
    await merge.mock.results[0].value;
    expect(mutated).toBe(true);
    expect(() => document._assertDocumentStateNotPoisoned()).toThrow(/discard this document instance/);
  }
});

});

test.each([0, -1, 1.5, Infinity, Number.MAX_SAFE_INTEGER + 1])(
  'rejects invalid configured response limit %p before stream work',
  async (limit) => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const sink = jest.fn();
    await expect(document._sendLoadRequestAndSync(
      { sink }, new Uint8Array([1]), null, undefined, limit,
    )).rejects.toThrow(RangeError);
    expect(sink).not.toHaveBeenCalled();
  },
);
