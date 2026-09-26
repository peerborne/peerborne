import { beforeEach, describe, expect, jest, test } from '@jest/globals';

import { PeerborneDocument } from './peerborne-document.js';
import { eciesOpen } from './ecies.js';
import { decodeWelcomeSealedPayload } from './welcome-sealed-payload.js';
import { InvitationMembershipQueue } from './invitation-membership.js';
import { INVITATION_STREAM_TIMEOUT_MS } from './invitation-policy.js';

jest.mock(
  'it-pipe',
  () => ({ pipe: jest.fn() }),
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

jest.mock('./ecies.js', () => ({
  ECIES_P256_PUBLIC_KEY_LENGTH: 65,
  eciesOpen: jest.fn(),
  eciesSeal: jest.fn(),
  importEciesPublicKey: jest.fn(),
}));

jest.mock('./welcome-sealed-payload.js', () => ({
  decodeWelcomeSealedPayload: jest.fn(),
  encodeWelcomeSealedPayload: jest.fn(),
}));

jest.mock('./beekem/beekem.js', () => ({
  BeeKEM: class {
    readonly memberCount = 2;
    readonly myLeafIndex = 2;
    readonly processWelcome = jest.fn(async () => undefined);
  },
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

const welcome = {
  leafIndex: 2,
  pathKeys: [{ nodeIndex: 1 }],
  treeNodePublicKeys: [
    { nodeIndex: 0, publicKey: new Uint8Array([1]) },
  ],
  treeHash: new Uint8Array(32),
};

type InvitationStage =
  | 'keys'
  | 'hydrate'
  | 'decrypt'
  | 'verify'
  | 'sync'
  | 'membership';

function invitationHarness(options: {
  stall?: InvitationStage;
  verify?: boolean;
  sync?: boolean;
  membershipError?: Error;
  bootstrapKeychainBytes?: Uint8Array;
  transactional?: boolean;
  stagedCurrentKeyId?: Uint8Array;
  commitError?: Error;
  onHydrate?: () => void;
  hydrateWait?: Promise<void>;
} = {}) {
  const order: string[] = [];
  const stalled = deferred<void>();
  const stallAt = async (stage: InvitationStage): Promise<void> => {
    if (options.stall !== stage) return;
    stalled.resolve();
    await new Promise<never>(() => {});
  };
  const welcomeKeychainChanges = { source: 'sealed-welcome' };
  const bootstrapKeychainChanges = { source: 'signed-bootstrap' };
  const welcomeKeychainBytes = new Uint8Array([4, 5, 6]);
  const bootstrapKeychainBytes =
    options.bootstrapKeychainBytes ?? welcomeKeychainBytes;
  const epochId = new Uint8Array([7]);
  const stagedKey = { staged: true };
  const stagedCurrentKeyId = options.stagedCurrentKeyId ?? epochId;
  const stagedCurrentKey = { stagedCurrent: true };
  const stagedKeys: [Uint8Array, object][] =
    stagedCurrentKeyId[0] === epochId[0]
      ? [[epochId, stagedKey]]
      : [
          [epochId, stagedKey],
          [stagedCurrentKeyId, stagedCurrentKey],
        ];
  const liveKeychainState = { committed: false };
  const commit = jest.fn(() => {
    order.push('commit');
    liveKeychainState.committed = true;
    if (options.commitError) throw options.commitError;
  });
  const merge = jest.fn(() => order.push('live-merge'));
  const prepareMerge = jest.fn(() => {
    order.push('prepare');
    return {
      changes: welcomeKeychainChanges,
      keyIds: stagedKeys.map(([keyId]) => keyId),
      currentKeyId: stagedCurrentKeyId,
      hydrateKeys: jest.fn(async () => {
        order.push('hydrate');
        options.onHydrate?.();
        await options.hydrateWait;
        await stallAt('hydrate');
        return stagedKeys;
      }),
      getKey: jest.fn((keyId: Uint8Array) => {
        if (keyId[0] === epochId[0]) return stagedKey;
        if (keyId[0] === stagedCurrentKeyId[0]) return stagedCurrentKey;
        return undefined;
      }),
      commit,
    };
  });
  const syncUnlocked = jest.fn(
    async (
      message: Record<string, unknown>,
      _verifySignature: boolean,
      _context: string,
      _onStateApplicationStart: (() => void) | undefined,
      continuePending: boolean,
      _onLogicalKeychainChange: (() => void) | undefined,
      fetchOptions: {
        signal?: AbortSignal;
        getKey?: (keyId: Uint8Array) => unknown;
      },
    ) => {
      order.push('sync');
      expect(message.keychainChanges).toBeUndefined();
      expect(continuePending).toBe(true);
      expect(fetchOptions.getKey?.(epochId)).toBe(stagedKey);
      expect(fetchOptions.signal).toBeInstanceOf(AbortSignal);
      await stallAt('sync');
      return options.sync ?? true;
    },
  );
  const assertMembership = jest.fn(
    async (_issuer: unknown, _role: string, _signal?: AbortSignal) => {
      order.push('membership');
      await stallAt('membership');
      if (options.membershipError) throw options.membershipError;
    },
  );
  const activate = jest.fn(async () => {
    order.push('activate');
  });
  const mutationQueue = {
    run: jest.fn((operation: () => Promise<unknown>) => operation()),
  };
  const document = fakeDocument({
    documentPath: '/transactional-invitation',
    _bootstrapLoadApplicationState: 'pristine',
    _bootstrapLoadApplicationRevision: 0,
    _hashes: new Set<string>(),
    _lastSyncMessage: undefined,
    _latestSnapshot: undefined,
    _subscribed: false,
    _createdLocally: false,
    _kemKeyPair: { privateKey: {}, publicKey: {} },
    _kemPublicKeyRaw: new Uint8Array([8]),
    _keychainProvider: { keyIDLength: 1 },
    _keychain: {
      getKey: jest.fn(),
      keys: jest.fn(async () => {
        await stallAt('keys');
        return [];
      }),
      merge,
      ...(options.transactional === false ? {} : { prepareMerge }),
    },
    _authProvider: {
      nonceBits: 1,
      decrypt: jest.fn(async (_ciphertext, key) => {
        order.push('decrypt');
        expect(key).toBe(stagedKey);
        await stallAt('decrypt');
        return new Uint8Array([9]);
      }),
      verify: jest.fn(async () => {
        order.push('verify');
        await stallAt('verify');
        return options.verify ?? true;
      }),
    },
    _changesSerializer: {
      deserializeChanges: jest.fn(() => welcomeKeychainChanges),
      serializeChanges: jest.fn((changes: unknown) =>
        (changes as { source?: string }).source ===
        bootstrapKeychainChanges.source
          ? bootstrapKeychainBytes
          : welcomeKeychainBytes,
      ),
    },
    _syncMessageSerializer: {
      deserializeSyncMessage: jest.fn(() => ({
        documentId: '/transactional-invitation',
        signatureContext: 'invitation-bootstrap-v1',
        signature: 'AAAA',
        keychainChanges: bootstrapKeychainChanges,
      })),
      serializeSyncMessage: jest.fn(() => new Uint8Array([10])),
    },
    _deserializeSignature: jest.fn(() => new Uint8Array([11])),
    _mutationQueue: mutationQueue,
    _syncUnlocked: syncUnlocked,
    _assertAcceptedInvitationMembership: assertMembership,
    _activateAcceptedInvitationBootstrap: activate,
  });

  return {
    document,
    order,
    stalled,
    commit,
    merge,
    prepareMerge,
    syncUnlocked,
    assertMembership,
    activate,
    mutationQueue,
    epochId,
    liveKeychainState,
  };
}

describe('invitation bootstrap keychain transaction', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.mocked(eciesOpen).mockResolvedValue(new Uint8Array([1]));
    jest.mocked(decodeWelcomeSealedPayload).mockReturnValue({
      keychainChanges: new Uint8Array([4, 5, 6]),
      beekemWelcome: welcome as never,
    });
  });

  test('rejects an invalid inner signature without mutating live keychain state', async () => {
    const harness = invitationHarness({ verify: false });

    await expect(
      harness.document.acceptInvitationBootstrap(
        {
          welcomeEpochId: harness.epochId,
          sealedWelcome: new Uint8Array([1]),
          encryptedBootstrap: new Uint8Array([7, 2, 3]),
        },
        'issuer',
        'reader',
        '/founder',
      ),
    ).rejects.toThrow(/signature does not match/);

    expect(harness.order).toEqual(['prepare', 'hydrate', 'decrypt', 'verify']);
    expect(harness.commit).not.toHaveBeenCalled();
    expect(harness.merge).not.toHaveBeenCalled();
    expect(harness.syncUnlocked).not.toHaveBeenCalled();
    expect(harness.document._bootstrapLoadApplicationState).toBe('pristine');
    expect(
      harness.document._activeInvitationBootstrapContinuation,
    ).toBeUndefined();
  });

  test('blocks public work during detached validation and clears the transient gate on rejection', async () => {
    const hydrationStarted = deferred<void>();
    const releaseHydration = deferred<void>();
    const harness = invitationHarness({
      verify: false,
      onHydrate: () => hydrationStarted.resolve(),
      hydrateWait: releaseHydration.promise,
    });
    harness.document._shuffledPeers = jest.fn(async () => []);

    const acceptance = harness.document.acceptInvitationBootstrap(
      {
        welcomeEpochId: harness.epochId,
        sealedWelcome: new Uint8Array([1]),
        encryptedBootstrap: new Uint8Array([7, 2, 3]),
      },
      'issuer',
      'reader',
      '/founder',
    );
    await hydrationStarted.promise;

    expect(harness.document._bootstrapLoadApplicationState).toBe('pristine');
    await expect(harness.document.open()).rejects.toThrow(
      /invitation bootstrap validation .* in progress/i,
    );
    await expect(harness.document.load()).rejects.toThrow(
      /invitation bootstrap validation .* in progress/i,
    );

    releaseHydration.resolve();
    await expect(acceptance).rejects.toThrow(/signature does not match/);
    expect(harness.document._bootstrapLoadApplicationState).toBe('pristine');
    expect(
      harness.document._activeInvitationBootstrapContinuation,
    ).toBeUndefined();
    await expect(harness.document.load()).resolves.toBe(false);
  });

  test('keeps a completeness rejection detached from the live keychain', async () => {
    const harness = invitationHarness({ sync: false });

    await expect(
      harness.document.acceptInvitationBootstrap(
        {
          welcomeEpochId: harness.epochId,
          sealedWelcome: new Uint8Array([1]),
          encryptedBootstrap: new Uint8Array([7, 2, 3]),
        },
        'issuer',
        'reader',
        '/founder',
      ),
    ).rejects.toThrow(/state was rejected/);

    expect(harness.order).toEqual([
      'prepare',
      'hydrate',
      'decrypt',
      'verify',
      'sync',
    ]);
    expect(harness.commit).not.toHaveBeenCalled();
    expect(harness.merge).not.toHaveBeenCalled();
    expect(harness.document._bootstrapLoadApplicationState).toBe('pending');
  });

  test('does not commit when initial membership validation rejects', async () => {
    const harness = invitationHarness({
      membershipError: new Error('membership topology is invalid'),
    });

    await expect(
      harness.document.acceptInvitationBootstrap(
        {
          welcomeEpochId: harness.epochId,
          sealedWelcome: new Uint8Array([1]),
          encryptedBootstrap: new Uint8Array([7, 2, 3]),
        },
        'issuer',
        'editor',
        '/founder',
      ),
    ).rejects.toThrow(/membership topology is invalid/);

    expect(harness.commit).not.toHaveBeenCalled();
    expect(harness.merge).not.toHaveBeenCalled();
    expect(harness.activate).not.toHaveBeenCalled();
  });

  test('fails closed when the provider cannot stage a merge', async () => {
    const harness = invitationHarness({ transactional: false });

    await expect(
      harness.document.acceptInvitationBootstrap(
        {
          welcomeEpochId: harness.epochId,
          sealedWelcome: new Uint8Array([1]),
          encryptedBootstrap: new Uint8Array([7, 2, 3]),
        },
        'issuer',
        'reader',
        '/founder',
      ),
    ).rejects.toThrow(/transactional keychain merge support/);

    expect(harness.mutationQueue.run).not.toHaveBeenCalled();
    expect(harness.merge).not.toHaveBeenCalled();
    expect(harness.document._bootstrapLoadApplicationState).toBe('pristine');
  });

  test('rejects a mismatch between the signed and sealed keychain deltas', async () => {
    const harness = invitationHarness({
      bootstrapKeychainBytes: new Uint8Array([4, 5, 7]),
    });

    await expect(
      harness.document.acceptInvitationBootstrap(
        {
          welcomeEpochId: harness.epochId,
          sealedWelcome: new Uint8Array([1]),
          encryptedBootstrap: new Uint8Array([7, 2, 3]),
        },
        'issuer',
        'reader',
        '/founder',
      ),
    ).rejects.toThrow(/keychain does not match/);

    expect(harness.commit).not.toHaveBeenCalled();
    expect(harness.merge).not.toHaveBeenCalled();
    expect(harness.syncUnlocked).not.toHaveBeenCalled();
    expect(harness.document._bootstrapLoadApplicationState).toBe('pristine');
  });

  test('rejects an advertised invitation epoch that is not the staged current key', async () => {
    const harness = invitationHarness({
      stagedCurrentKeyId: new Uint8Array([8]),
    });

    await expect(
      harness.document.acceptInvitationBootstrap(
        {
          welcomeEpochId: harness.epochId,
          sealedWelcome: new Uint8Array([1]),
          encryptedBootstrap: new Uint8Array([7, 2, 3]),
        },
        'issuer',
        'reader',
        '/founder',
      ),
    ).rejects.toThrow(/staged keychain current epoch/);

    expect(harness.order).toEqual(['prepare']);
    expect(harness.commit).not.toHaveBeenCalled();
    expect(harness.merge).not.toHaveBeenCalled();
    expect(harness.document._bootstrapLoadApplicationState).toBe('pristine');
  });

  test('commits exactly once after bootstrap checks and before activation', async () => {
    const harness = invitationHarness();

    await expect(
      harness.document.acceptInvitationBootstrap(
        {
          welcomeEpochId: harness.epochId,
          sealedWelcome: new Uint8Array([1]),
          encryptedBootstrap: new Uint8Array([7, 2, 3]),
        },
        'issuer',
        'reader',
        '/founder',
      ),
    ).resolves.toBeUndefined();

    expect(harness.order).toEqual([
      'prepare',
      'hydrate',
      'decrypt',
      'verify',
      'sync',
      'membership',
      'commit',
      'activate',
    ]);
    expect(harness.commit).toHaveBeenCalledTimes(1);
    expect(harness.merge).not.toHaveBeenCalled();
    expect(harness.document._bootstrapLoadApplicationState).toBe('pending');
    expect(
      harness.document._activeInvitationBootstrapContinuation,
    ).toBeUndefined();
  });

  test('keeps an indeterminate throwing keychain commit permanently discard-only', async () => {
    const harness = invitationHarness({
      commitError: new Error('provider commit failed after mutation'),
    });

    await expect(
      harness.document.acceptInvitationBootstrap(
        {
          welcomeEpochId: harness.epochId,
          sealedWelcome: new Uint8Array([1]),
          encryptedBootstrap: new Uint8Array([7, 2, 3]),
        },
        'issuer',
        'reader',
        '/founder',
      ),
    ).rejects.toThrow(/provider commit failed after mutation/);

    expect(harness.liveKeychainState.committed).toBe(true);
    expect(harness.document._bootstrapLoadApplicationState).toBe('pending');
    expect(
      harness.document._activeInvitationBootstrapContinuation,
    ).toBeUndefined();
    expect(harness.document._beekem).toBeUndefined();
    expect(harness.document._beekemInitialized).not.toBe(true);
    expect(harness.document._invitationEpoch).toBeUndefined();
    expect(harness.document._invitationBootstrapReady).not.toBe(true);
    expect(harness.activate).not.toHaveBeenCalled();
    expect(() => harness.document.document).toThrow(/discard this document/);
    await expect(
      harness.document.sync({
        documentId: '/transactional-invitation',
        signatureContext: 'ordinary-sync-v1',
      }),
    ).rejects.toThrow(/discard this document/);
    await expect(harness.document.load()).rejects.toThrow(
      /discard this document/,
    );
  });

  test('retains the mutation FIFO until invitation activation returns', async () => {
    const harness = invitationHarness();
    const activationStarted = deferred<void>();
    const releaseActivation = deferred<void>();
    const mutationQueue = new InvitationMembershipQueue();
    let queuedMutationRan = false;
    harness.document._mutationQueue = mutationQueue;
    harness.activate.mockImplementation(async () => {
      activationStarted.resolve();
      await releaseActivation.promise;
    });

    const acceptance = harness.document.acceptInvitationBootstrap(
      {
        welcomeEpochId: harness.epochId,
        sealedWelcome: new Uint8Array([1]),
        encryptedBootstrap: new Uint8Array([7, 2, 3]),
      },
      'issuer',
      'reader',
      '/founder',
    );
    await activationStarted.promise;
    const queuedMutation = mutationQueue.run(async () => {
      queuedMutationRan = true;
    });
    await Promise.resolve();
    expect(queuedMutationRan).toBe(false);

    releaseActivation.resolve();
    await expect(acceptance).resolves.toBeUndefined();
    await expect(queuedMutation).resolves.toBeUndefined();
    expect(queuedMutationRan).toBe(true);
  });

  test.each([
    ['keys', 'pristine', []],
    ['hydrate', 'pristine', ['prepare', 'hydrate']],
    ['decrypt', 'pristine', ['prepare', 'hydrate', 'decrypt']],
    ['verify', 'pristine', ['prepare', 'hydrate', 'decrypt', 'verify']],
    ['sync', 'pending', ['prepare', 'hydrate', 'decrypt', 'verify', 'sync']],
    [
      'membership',
      'pending',
      ['prepare', 'hydrate', 'decrypt', 'verify', 'sync', 'membership'],
    ],
  ] as const)(
    'releases the mutation FIFO when initial bootstrap %s never settles',
    async (stage, expectedState, expectedOrder) => {
      jest.useFakeTimers();
      try {
        const harness = invitationHarness({ stall: stage });
        const mutationQueue = new InvitationMembershipQueue();
        harness.document._mutationQueue = mutationQueue;
        let queuedMutationRan = false;

        const acceptance = harness.document.acceptInvitationBootstrap(
          {
            welcomeEpochId: harness.epochId,
            sealedWelcome: new Uint8Array([1]),
            encryptedBootstrap: new Uint8Array([7, 2, 3]),
          },
          'issuer',
          'reader',
          '/founder',
        );
        const rejection = expect(acceptance).rejects.toThrow(
          /^Invitation bootstrap deadline exceeded$/,
        );
        await harness.stalled.promise;
        const queuedMutation = mutationQueue.run(async () => {
          queuedMutationRan = true;
        });
        await jest.advanceTimersByTimeAsync(INVITATION_STREAM_TIMEOUT_MS - 1);
        expect(queuedMutationRan).toBe(false);

        await jest.advanceTimersByTimeAsync(1);
        await rejection;
        await expect(queuedMutation).resolves.toBeUndefined();

        expect(queuedMutationRan).toBe(true);
        expect(harness.order).toEqual(expectedOrder);
        expect(harness.commit).not.toHaveBeenCalled();
        expect(harness.merge).not.toHaveBeenCalled();
        expect(harness.activate).not.toHaveBeenCalled();
        expect(harness.document._bootstrapLoadApplicationState).toBe(
          expectedState,
        );
        expect(
          harness.document._activeInvitationBootstrapContinuation,
        ).toBeUndefined();
        expect(harness.document._invitationBootstrapReady).not.toBe(true);
        if (stage === 'sync') {
          const fetchOptions = harness.syncUnlocked.mock.calls[0][6];
          expect(fetchOptions.signal?.aborted).toBe(true);
        }
        if (stage === 'membership') {
          expect(harness.assertMembership.mock.calls[0][2]?.aborted).toBe(
            true,
          );
        }
      } finally {
        jest.useRealTimers();
      }
    },
  );

  test('threads one live initial deadline signal through sync and membership', async () => {
    const harness = invitationHarness();

    await expect(
      harness.document.acceptInvitationBootstrap(
        {
          welcomeEpochId: harness.epochId,
          sealedWelcome: new Uint8Array([1]),
          encryptedBootstrap: new Uint8Array([7, 2, 3]),
        },
        'issuer',
        'editor',
        '/founder',
      ),
    ).resolves.toBeUndefined();

    const signal = harness.syncUnlocked.mock.calls[0][6].signal;
    expect(signal).toBeInstanceOf(AbortSignal);
    expect(harness.assertMembership).toHaveBeenCalledWith(
      'issuer',
      'editor',
      signal,
    );
    expect(signal?.aborted).toBe(false);
  });

  test('clears the initial bootstrap deadline before activation', async () => {
    jest.useFakeTimers();
    try {
      const harness = invitationHarness();
      const activationStarted = deferred<void>();
      const releaseActivation = deferred<void>();
      harness.activate.mockImplementation(async () => {
        activationStarted.resolve();
        await releaseActivation.promise;
      });

      const acceptance = harness.document.acceptInvitationBootstrap(
        {
          welcomeEpochId: harness.epochId,
          sealedWelcome: new Uint8Array([1]),
          encryptedBootstrap: new Uint8Array([7, 2, 3]),
        },
        'issuer',
        'reader',
        '/founder',
      );
      await activationStarted.promise;
      expect(jest.getTimerCount()).toBe(0);

      await jest.advanceTimersByTimeAsync(INVITATION_STREAM_TIMEOUT_MS * 2);
      releaseActivation.resolve();
      await expect(acceptance).resolves.toBeUndefined();
      expect(harness.commit).toHaveBeenCalledTimes(1);
    } finally {
      jest.useRealTimers();
    }
  });
});
