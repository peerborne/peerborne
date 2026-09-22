import { describe, expect, jest, test } from '@jest/globals';
import { PeerborneDocument } from './peerborne-document.js';
import { InvitationMembershipQueue } from './invitation-membership.js';

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

interface Identity {
  id: string;
}

const localUser: Identity = { id: 'local' };
const targetUser: Identity = { id: 'target' };

function kemPublicKey(fill = 7): Uint8Array {
  return new Uint8Array(65).fill(fill);
}

function beekemWelcome(leafIndex = 2) {
  return {
    version: 2 as const,
    generation: 1,
    numLeaves: 2,
    leafIndex,
    pathKeys: [],
    treeNodePublicKeys: [],
    treeHash: new Uint8Array(32).fill(13),
  };
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

async function holdMutationQueue(document: any) {
  const queue = new InvitationMembershipQueue();
  const blockerEntered = deferred<void>();
  const releaseBlocker = deferred<void>();
  const blocker = queue.run(async () => {
    blockerEntered.resolve();
    await releaseBlocker.promise;
  });
  await blockerEntered.promise;

  const operationEnqueued = deferred<void>();
  document._mutationQueue = {
    run: <T>(operation: () => Promise<T>) => {
      operationEnqueued.resolve();
      return queue.run(operation);
    },
  };
  return { blocker, operationEnqueued, releaseBlocker };
}

async function validKemPublicKey(): Promise<Uint8Array> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  )) as CryptoKeyPair;
  return new Uint8Array(
    await crypto.subtle.exportKey('raw', keyPair.publicKey),
  );
}

function fakeDocument(options: {
  readers?: string[];
  writers?: string[];
  beekemInitialized?: boolean;
  liveLeafIndex?: number;
  recordedKemPublicKey?: Uint8Array;
  cachedLeafIndex?: number;
  onlyLocalLiveLeaf?: boolean;
  enableSigning?: boolean;
} = {}): any {
  const readerIds = new Set(options.readers ?? []);
  const writerIds = new Set(options.writers ?? []);
  const serializePublicKey = jest.fn(async (key: Identity) => key.id);
  const deserializePublicKey = jest.fn(async (id: string) => ({ id }));
  const readerCheck = jest.fn(async (key: Identity) => readerIds.has(key.id));
  const writerCheck = jest.fn(async (key: Identity) => writerIds.has(key.id));
  const mergeReaders = jest.fn();
  const readerRemovalFinalize = jest.fn((key: Identity) => {
    readerIds.delete(key.id);
  });
  const readerRemovalClaim = jest.fn((key: Identity) => ({
    finalize: () => readerRemovalFinalize(key),
  }));
  const readerAdditionFinalize = jest.fn((key: Identity) => {
    readerIds.add(key.id);
  });
  const readerAdditionClaim = jest.fn((key: Identity) => ({
    finalize: () => readerAdditionFinalize(key),
  }));
  const prepareReaderAdd = jest.fn(async (key: Identity) => ({
    changes: { addedReader: key.id },
    claimCommit: () => readerAdditionClaim(key),
    commit: () => readerAdditionClaim(key).finalize(),
  }));
  const prepareReaderRemove = jest.fn(async (key: Identity) => ({
    changes: { removedReader: key.id },
    claimCommit: () => readerRemovalClaim(key),
    commit: () => readerRemovalClaim(key).finalize(),
  }));
  const prepareWriterAdd = jest.fn(async (key: Identity) => ({
    changes: { addedWriter: key.id },
    commit: () => writerIds.add(key.id),
  }));
  const prepareWriterRemove = jest.fn(async (key: Identity) => ({
    changes: { removedWriter: key.id },
    commit: () => writerIds.delete(key.id),
  }));
  const findLeafByPublicKey = jest.fn(async () => options.liveLeafIndex);
  const removeMember = jest.fn(async () => ({
    pathUpdate: { generation: 2, nodes: [] },
    rootSecret: new Uint8Array(32).fill(11),
  }));
  const hasOnlyLocalLiveLeaf = jest.fn(
    () => options.onlyLocalLiveLeaf ?? false,
  );
  const stagedBeeKEM = { removeMember };
  const liveBeeKEM = {
    memberCount: 1,
    findLeafByPublicKey,
    hasLiveLeafWithPublicKey: jest.fn(async () => false),
    hasOnlyLocalLiveLeaf,
    clone: jest.fn(() => stagedBeeKEM),
  };
  const makeChange = jest.fn(async () => undefined);
  const publishPreparedWriterChange = jest.fn(
    async (prepared: {
      changes: unknown;
      commit: { receiver: object; method: (...args: unknown[]) => unknown };
    }) => {
      await makeChange(prepared.changes);
      Reflect.apply(prepared.commit.method, prepared.commit.receiver, []);
    },
  );
  let markDocumentPoisoned: () => void = () => undefined;
  const publishPreparedReaderChange = jest.fn(
    async (
      prepared: { changes: unknown; commit(): void },
      _operation: string,
      commit: () => void,
    ) => {
      await makeChange(prepared.changes);
      try {
        commit();
      } catch (error) {
        markDocumentPoisoned();
        throw error;
      }
    },
  );
  const epochKeyCommit = jest.fn();
  const epochKeyClaim = jest.fn(() => ({ finalize: epochKeyCommit }));
  const epochLegacyCommit = jest.fn(() => epochKeyClaim().finalize());
  const prepareEpochKey = jest.fn(async () => ({
    changes: {},
    history: {},
    claimCommit: epochKeyClaim,
    commit: epochLegacyCommit,
  }));
  const readerKemPublicKeys = new Map<string, Uint8Array>();
  if (options.recordedKemPublicKey) {
    readerKemPublicKeys.set('target', options.recordedKemPublicKey);
  }
  const readerLeafIndices = new Map<string, number>();
  if (options.cachedLeafIndex !== undefined) {
    readerLeafIndices.set('target', options.cachedLeafIndex);
  }

  const document = Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath: '/role-transitions',
    swarm: { config: { enableSigning: options.enableSigning ?? true } },
    _userPublicKey: localUser,
    _authProvider: {
      serializePublicKey,
      deserializePublicKey,
      verify: jest.fn(async () => false),
    },
    _mutationQueue: {
      run: (operation: () => Promise<unknown>) => operation(),
    },
    _bootstrapLoadApplicationState: 'complete',
    _bootstrapLoadApplicationRevision: 0,
    _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
    _readers: {
      check: readerCheck,
      users: jest.fn(async () =>
        [...readerIds].map((id) => ({ id })),
      ),
      prepareAdd: prepareReaderAdd,
      prepareRemove: prepareReaderRemove,
      merge: mergeReaders,
    },
    _writers: {
      check: writerCheck,
      users: jest.fn(async () =>
        [...writerIds].map((id) => ({ id })),
      ),
      prepareAdd: prepareWriterAdd,
      prepareRemove: prepareWriterRemove,
    },
    _beekemInitialized: options.beekemInitialized ?? true,
    _beekem:
      options.beekemInitialized === false
        ? null
        : liveBeeKEM,
    _readerKemPublicKeys: readerKemPublicKeys,
    _readerLeafIndices: readerLeafIndices,
    _beekemWelcomeByLeaf: new Map([[2, beekemWelcome()]]),
    _readerPublicationsInFlight: 0,
    _pendingWelcomes: new Map(),
    _makeChange: makeChange,
    _publishPreparedWriterChange: publishPreparedWriterChange,
    _publishPreparedReaderChange: publishPreparedReaderChange,
    _distributeBeeKEMPathUpdate: jest.fn(async () => undefined),
    _keychain: {
      current: jest.fn(async () => {
        throw new Error('removeWriter must not inspect the document key');
      }),
      add: jest.fn(async () => {
        throw new Error('removeWriter must not rotate the document key');
      }),
      addEpochKey: jest.fn(async () => {
        throw new Error('removeReader must use transactional epoch staging');
      }),
      prepareEpochKey,
    },
    _testState: {
      readerIds,
      writerIds,
      readerCheck,
      writerCheck,
      mergeReaders,
      prepareReaderAdd,
      readerAdditionClaim,
      readerAdditionFinalize,
      prepareReaderRemove,
      readerRemovalClaim,
      readerRemovalFinalize,
      prepareWriterAdd,
      prepareWriterRemove,
      findLeafByPublicKey,
      hasOnlyLocalLiveLeaf,
      liveBeeKEM,
      stagedBeeKEM,
      removeMember,
      makeChange,
      publishPreparedWriterChange,
      publishPreparedReaderChange,
      prepareEpochKey,
      epochKeyClaim,
      epochKeyCommit,
      epochLegacyCommit,
      serializePublicKey,
      deserializePublicKey,
    },
  });
  markDocumentPoisoned = () => document._markDocumentStatePoisoned();
  return document;
}

describe('membership call-boundary snapshots', () => {
  test.each(['addReader', 'buildInvitationBootstrap'])(
    '%s rejects shared KEM bytes before queueing or invoking identity codecs',
    async (operation) => {
      const document = fakeDocument();
      document._addReaderUnlocked = jest.fn(async () => null);
      document._buildInvitationBootstrapUnlocked = jest.fn(async () => ({}));
      const queued = jest.spyOn(document._mutationQueue, 'run');
      const key = new Uint8Array(new SharedArrayBuffer(65));
      await expect(document[operation](targetUser, key, 'reader')).rejects.toThrow(
        /backing buffer/i,
      );
      expect(queued).not.toHaveBeenCalled();
      expect(document._testState.serializePublicKey).not.toHaveBeenCalled();
    },
  );

  test.each(['removeReader', 'addWriter'])(
    '%s rejects an identity-bound key that resolves to the local leaf',
    async (operation) => {
      const document = fakeDocument({
        readers: ['target'],
        liveLeafIndex: 0,
        cachedLeafIndex: 0,
        recordedKemPublicKey: kemPublicKey(),
      });
      document._beekem.myLeafIndex = 0;
      await expect(document[operation](targetUser)).rejects.toThrow(/local.*leaf/i);
      expect(document._testState.prepareWriterAdd).not.toHaveBeenCalled();
      expect(document._testState.prepareReaderRemove).not.toHaveBeenCalled();
      expect(document._testState.liveBeeKEM.clone).not.toHaveBeenCalled();
      expect(document._testState.prepareEpochKey).not.toHaveBeenCalled();
      expect(document._testState.readerIds).toContain('target');
    },
  );

  test('queues reader onboarding with a detached identity and KEM copy', async () => {
    const document = fakeDocument();
    const addReaderUnlocked = jest.fn(async () => null);
    document._addReaderUnlocked = addReaderUnlocked;
    const held = await holdMutationQueue(document);
    const reader = { id: 'target' };
    const kem = kemPublicKey(3);

    const addition = document.addReader(reader, kem);
    await held.operationEnqueued.promise;
    reader.id = 'local';
    kem.fill(9);
    held.releaseBlocker.resolve();

    await expect(addition).resolves.toBeNull();
    await held.blocker;
    expect(addReaderUnlocked).toHaveBeenCalledWith(
      { id: 'target' },
      'target',
      new Uint8Array(65).fill(3),
    );
  });

  test('queues writer promotion with a detached canonical identity', async () => {
    const document = fakeDocument();
    const addWriterUnlocked = jest.fn(async () => undefined);
    document._addWriterUnlocked = addWriterUnlocked;
    const held = await holdMutationQueue(document);
    const writer = { id: 'target' };

    const addition = document.addWriter(writer);
    await held.operationEnqueued.promise;
    writer.id = 'local';
    held.releaseBlocker.resolve();

    await expect(addition).resolves.toBeUndefined();
    await held.blocker;
    expect(addWriterUnlocked).toHaveBeenCalledWith(
      { id: 'target' },
      undefined,
      true,
      'target',
    );
  });

  test('queues removals with detached canonical identities', async () => {
    const writerDocument = fakeDocument();
    const removeWriterUnlocked = jest.fn(async () => undefined);
    writerDocument._removeWriterUnlocked = removeWriterUnlocked;
    const heldWriter = await holdMutationQueue(writerDocument);
    const writer = { id: 'target' };

    const writerRemoval = writerDocument.removeWriter(writer);
    await heldWriter.operationEnqueued.promise;
    writer.id = 'local';
    heldWriter.releaseBlocker.resolve();
    await expect(writerRemoval).resolves.toBeUndefined();
    await heldWriter.blocker;
    expect(removeWriterUnlocked).toHaveBeenCalledWith(
      { id: 'target' },
      true,
      'target',
      expect.any(Promise),
    );

    const readerDocument = fakeDocument();
    const removeReaderUnlocked = jest.fn(async () => undefined);
    readerDocument._removeReaderUnlocked = removeReaderUnlocked;
    const heldReader = await holdMutationQueue(readerDocument);
    const reader = { id: 'target' };

    const readerRemoval = readerDocument.removeReader(reader);
    await heldReader.operationEnqueued.promise;
    reader.id = 'local';
    heldReader.releaseBlocker.resolve();
    await expect(readerRemoval).resolves.toBeUndefined();
    await heldReader.blocker;
    expect(removeReaderUnlocked).toHaveBeenCalledWith(
      { id: 'target' },
      'target',
    );
  });

  test('queues invitation bootstrap with detached identity and KEM inputs', async () => {
    const document = fakeDocument();
    const buildUnlocked = jest.fn(async () => ({ bootstrap: true }));
    document._buildInvitationBootstrapUnlocked = buildUnlocked;
    const held = await holdMutationQueue(document);
    const reader = { id: 'target' };
    const kem = kemPublicKey(4);

    const bootstrap = document.buildInvitationBootstrap(
      reader,
      kem,
      'reader',
    );
    await held.operationEnqueued.promise;
    reader.id = 'local';
    kem.fill(8);
    held.releaseBlocker.resolve();

    await expect(bootstrap).resolves.toEqual({ bootstrap: true });
    await held.blocker;
    expect(buildUnlocked).toHaveBeenCalledWith(
      { id: 'target' },
      'target',
      new Uint8Array(65).fill(4),
      'reader',
      undefined,
    );
  });

  test('rejects a deserializer that returns the caller-owned object', async () => {
    const document = fakeDocument();
    const reader = { id: 'target' };
    document._authProvider.deserializePublicKey = jest.fn(async () => reader);

    await expect(document.addWriter(reader)).rejects.toThrow(
      /return a detached identity/,
    );
    expect(document._testState.prepareWriterAdd).not.toHaveBeenCalled();
  });

  test.each(['pending', 'poisoned'] as const)(
    'rejects reader APIs in %s state before invoking identity codecs',
    async (state) => {
      const document = fakeDocument();
      document._bootstrapLoadApplicationState = state;

      await expect(
        document.addReader(targetUser, kemPublicKey()),
      ).rejects.toThrow(/discard this document instance|failed after state application/);
      await expect(document.removeReader(targetUser)).rejects.toThrow(
        /discard this document instance|failed after state application/,
      );

      expect(document._testState.serializePublicKey).not.toHaveBeenCalled();
      expect(document._testState.deserializePublicKey).not.toHaveBeenCalled();
      expect(document._testState.readerCheck).not.toHaveBeenCalled();
    },
  );

  test('rechecks document health when a snapshotted reader operation reaches its queue slot', async () => {
    const document = fakeDocument();
    const addReaderUnlocked = jest.fn(async () => null);
    document._addReaderUnlocked = addReaderUnlocked;
    const held = await holdMutationQueue(document);

    const addition = document.addReader(targetUser, kemPublicKey());
    await held.operationEnqueued.promise;
    document._bootstrapLoadApplicationState = 'poisoned';
    held.releaseBlocker.resolve();

    await expect(addition).rejects.toThrow(/indeterminate authorization state/);
    await held.blocker;
    expect(addReaderUnlocked).not.toHaveBeenCalled();
  });

  test('requires identity codecs even for ACL-only reader onboarding', async () => {
    const document = fakeDocument();
    delete document._authProvider.serializePublicKey;
    delete document._authProvider.deserializePublicKey;

    await expect(document.addReader('target')).rejects.toThrow(
      /requires AuthProvider\.serializePublicKey/,
    );
    expect(document._testState.readerCheck).not.toHaveBeenCalled();
  });
});

describe('reader addition staging', () => {
  test.each([
    ['initialized flag without a tree', true, null],
    ['tree without the initialized flag', false, { memberCount: 1 }],
  ] as const)(
    'rejects inconsistent BeeKEM state (%s) before ACL inspection',
    async (_caseName, initialized, beekem) => {
      const document = fakeDocument();
      document._beekemInitialized = initialized;
      document._beekem = beekem;

      await expect(
        document._addReaderUnlocked(
          targetUser,
          'target',
          kemPublicKey(),
          false,
        ),
      ).rejects.toThrow(/BeeKEM initialization state is internally inconsistent/);

      expect(document._testState.readerCheck).not.toHaveBeenCalled();
      expect(document._testState.prepareReaderAdd).not.toHaveBeenCalled();
      expect(document._testState.makeChange).not.toHaveBeenCalled();
    },
  );

  test('a BeeKEM preparation failure precedes ACL staging and publication', async () => {
    const document = fakeDocument();
    const readerKemPublicKey = await validKemPublicKey();
    const prepareRegistration = jest.fn(async () => {
      throw new Error('BeeKEM preparation failed');
    });
    document._prepareBeeKEMReaderRegistration = prepareRegistration;

    await expect(
      document._addReaderUnlocked(
        targetUser,
        'target',
        readerKemPublicKey,
        false,
      ),
    ).rejects.toThrow('BeeKEM preparation failed');

    expect(prepareRegistration).toHaveBeenCalledTimes(1);
    expect(document._testState.prepareReaderAdd).not.toHaveBeenCalled();
    expect(document._testState.readerAdditionClaim).not.toHaveBeenCalled();
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._testState.readerIds.has('target')).toBe(false);
  });

  test('an ACL staging failure leaves the prepared BeeKEM registration detached', async () => {
    const document = fakeDocument();
    const readerKemPublicKey = await validKemPublicKey();
    const install = jest.fn();
    document._prepareBeeKEMReaderRegistration = jest.fn(async () => ({
      welcome: { leafIndex: 2 },
      install,
    }));
    const prepareAdd = jest.fn(async () => {
      throw new Error('reader ACL staging failed');
    });
    document._readers.prepareAdd = prepareAdd;

    await expect(
      document._addReaderUnlocked(
        targetUser,
        'target',
        readerKemPublicKey,
        false,
      ),
    ).rejects.toThrow('reader ACL staging failed');

    expect(prepareAdd).toHaveBeenCalledTimes(1);
    expect(install).not.toHaveBeenCalled();
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._testState.readerIds.has('target')).toBe(false);
  });

  test('an ACL claim failure precedes publication and BeeKEM installation', async () => {
    const document = fakeDocument();
    const readerKemPublicKey = await validKemPublicKey();
    const install = jest.fn();
    const claimCommit = jest.fn(() => {
      throw new Error('reader ACL claim failed');
    });
    document._prepareBeeKEMReaderRegistration = jest.fn(async () => ({
      welcome: { leafIndex: 2 },
      install,
    }));
    document._readers.prepareAdd = jest.fn(async () => ({
      changes: { addedReader: 'target' },
      claimCommit,
      commit: jest.fn(),
    }));

    await expect(
      document._addReaderUnlocked(
        targetUser,
        'target',
        readerKemPublicKey,
        false,
      ),
    ).rejects.toThrow('reader ACL claim failed');

    expect(claimCommit).toHaveBeenCalledTimes(1);
    expect(install).not.toHaveBeenCalled();
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._testState.readerIds.has('target')).toBe(false);
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
  });

  test('a rejected publication abandons the claim and a fresh retry commits once', async () => {
    const document = fakeDocument();
    const readerKemPublicKey = await validKemPublicKey();
    const install = jest.fn();
    document._prepareBeeKEMReaderRegistration = jest.fn(async () => ({
      welcome: { leafIndex: 2 },
      install,
    }));
    document._testState.makeChange.mockRejectedValueOnce(
      new Error('reader publication rejected'),
    );

    await expect(
      document._addReaderUnlocked(
        targetUser,
        'target',
        readerKemPublicKey,
        false,
      ),
    ).rejects.toThrow('reader publication rejected');

    expect(install).not.toHaveBeenCalled();
    expect(document._testState.readerAdditionFinalize).not.toHaveBeenCalled();
    expect(document._testState.readerIds.has('target')).toBe(false);
    expect(document._bootstrapLoadApplicationState).toBe('complete');

    await expect(
      document._addReaderUnlocked(
        targetUser,
        'target',
        readerKemPublicKey,
        false,
      ),
    ).resolves.toEqual({ leafIndex: 2 });

    expect(document._testState.prepareReaderAdd).toHaveBeenCalledTimes(2);
    expect(document._testState.readerAdditionClaim).toHaveBeenCalledTimes(2);
    expect(document._testState.makeChange).toHaveBeenCalledTimes(2);
    expect(install).toHaveBeenCalledTimes(1);
    expect(document._testState.readerAdditionFinalize).toHaveBeenCalledTimes(1);
    expect(document._testState.readerIds.has('target')).toBe(true);
  });

  test('installs the BeeKEM snapshot before making reader authorization live', async () => {
    const document = fakeDocument();
    const readerKemPublicKey = await validKemPublicKey();
    const order: string[] = [];
    let beekemInstalled = false;
    document._prepareBeeKEMReaderRegistration = jest.fn(async () => {
      order.push('prepare-beekem');
      return {
        welcome: { leafIndex: 2 },
        install: () => {
          order.push('install-beekem');
          beekemInstalled = true;
        },
      };
    });
    document._readers.prepareAdd = jest.fn(async () => {
      order.push('stage-reader');
      return {
        changes: { addedReader: 'target' },
        claimCommit: () => {
          order.push('claim-reader');
          return {
            finalize: () => {
              expect(beekemInstalled).toBe(true);
              order.push('finalize-reader');
              document._testState.readerIds.add('target');
            },
          };
        },
        commit: jest.fn(),
      };
    });
    document._testState.makeChange.mockImplementation(async () => {
      order.push('publish');
    });
    const beginMutation = jest.fn(() => order.push('begin-mutation'));

    await expect(
      document._addReaderUnlocked(
        targetUser,
        'target',
        readerKemPublicKey,
        false,
        beginMutation,
      ),
    ).resolves.toEqual({ leafIndex: 2 });

    expect(order).toEqual([
      'prepare-beekem',
      'stage-reader',
      'claim-reader',
      'begin-mutation',
      'publish',
      'install-beekem',
      'finalize-reader',
    ]);
    expect(document._testState.readerIds.has('target')).toBe(true);
  });

  test('an existing reader can repair a missing BeeKEM cache without a new ACL claim', async () => {
    const document = fakeDocument({ readers: ['target'] });
    const readerKemPublicKey = await validKemPublicKey();
    const order: string[] = [];
    document._prepareBeeKEMReaderRegistration = jest.fn(async () => ({
      welcome: { leafIndex: 2 },
      install: () => {
        order.push('install-beekem');
        document._readerLeafIndices.set('target', 2);
      },
    }));
    const beginMutation = jest.fn(() => order.push('begin-mutation'));

    await expect(
      document._addReaderUnlocked(
        targetUser,
        'target',
        readerKemPublicKey,
        false,
        beginMutation,
      ),
    ).resolves.toEqual({ leafIndex: 2 });

    expect(order).toEqual(['begin-mutation', 'install-beekem']);
    expect(document._readerLeafIndices.get('target')).toBe(2);
    expect(document._testState.prepareReaderAdd).not.toHaveBeenCalled();
    expect(document._testState.readerAdditionClaim).not.toHaveBeenCalled();
    expect(document._testState.publishPreparedReaderChange).not.toHaveBeenCalled();
  });

  test('fails closed when the staged reader ACL does not expose a commit claim', async () => {
    const document = fakeDocument();
    const readerKemPublicKey = await validKemPublicKey();
    const install = jest.fn();
    document._prepareBeeKEMReaderRegistration = jest.fn(async () => ({
      welcome: { leafIndex: 2 },
      install,
    }));
    document._readers.prepareAdd = jest.fn(async () => ({
      changes: { addedReader: 'target' },
      commit: () => document._testState.readerIds.add('target'),
    }));

    await expect(
      document._addReaderUnlocked(
        targetUser,
        'target',
        readerKemPublicKey,
        false,
      ),
    ).rejects.toThrow(/must support commit claims for atomic onboarding/);

    expect(install).not.toHaveBeenCalled();
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._testState.readerIds.has('target')).toBe(false);
    expect(document._bootstrapLoadApplicationState).toBe('complete');
  });

  test('rejects an accessor-backed prepared claim without invoking it', async () => {
    const document = fakeDocument();
    const readerKemPublicKey = await validKemPublicKey();
    const install = jest.fn();
    let claimGetterCalled = false;
    document._prepareBeeKEMReaderRegistration = jest.fn(async () => ({
      welcome: { leafIndex: 2 },
      install,
    }));
    const prepared = {
      changes: { addedReader: 'target' },
      commit: jest.fn(),
    };
    Object.defineProperty(prepared, 'claimCommit', {
      get() {
        claimGetterCalled = true;
        document._testState.readerIds.add('target');
        return jest.fn();
      },
    });
    document._readers.prepareAdd = jest.fn(async () => prepared);

    await expect(
      document._addReaderUnlocked(
        targetUser,
        'target',
        readerKemPublicKey,
        false,
      ),
    ).rejects.toThrow(/claimCommit must be a data property/);

    expect(claimGetterCalled).toBe(false);
    expect(install).not.toHaveBeenCalled();
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._testState.readerIds.has('target')).toBe(false);
    expect(document._bootstrapLoadApplicationState).toBe('complete');
  });

  test.each<
    [string, (onAccessor: () => void) => unknown]
  >([
    ['primitive claim', () => null],
    ['missing finalizer', () => ({})],
    [
      'accessor finalizer',
      (onAccessor) =>
        Object.defineProperty({}, 'finalize', {
          get() {
            onAccessor();
            return jest.fn();
          },
        }),
    ],
  ])('rejects a %s before publication', async (_label, makeClaim) => {
    const document = fakeDocument();
    const readerKemPublicKey = await validKemPublicKey();
    const install = jest.fn();
    let accessorCalled = false;
    document._prepareBeeKEMReaderRegistration = jest.fn(async () => ({
      welcome: { leafIndex: 2 },
      install,
    }));
    document._readers.prepareAdd = jest.fn(async () => ({
      changes: { addedReader: 'target' },
      claimCommit: () =>
        makeClaim(() => {
          accessorCalled = true;
          document._testState.readerIds.add('target');
        }),
      commit: jest.fn(),
    }));

    await expect(
      document._addReaderUnlocked(
        targetUser,
        'target',
        readerKemPublicKey,
        false,
      ),
    ).rejects.toThrow(/invalid claim record|invalid finalizer|data property/);

    expect(accessorCalled).toBe(false);
    expect(install).not.toHaveBeenCalled();
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._testState.readerIds.has('target')).toBe(false);
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
  });

  test('poisons when a hidden-then asynchronous claim can mutate later', async () => {
    const document = fakeDocument();
    const readerKemPublicKey = await validKemPublicKey();
    const install = jest.fn();
    const releaseAsynchronousWork = deferred<void>();
    const finalize = jest.fn(() => {
      document._testState.readerIds.add('target');
    });
    const asynchronousClaim = releaseAsynchronousWork.promise.then(() => {
      document._testState.readerIds.add('attacker');
      return { finalize };
    });
    const asynchronousWorkCompletion = asynchronousClaim.then(() => undefined);
    Object.defineProperties(asynchronousClaim, {
      finalize: { value: finalize },
      then: { value: undefined },
    });
    document._prepareBeeKEMReaderRegistration = jest.fn(async () => ({
      welcome: { leafIndex: 2 },
      install,
    }));
    document._readers.prepareAdd = jest.fn(async () => ({
      changes: { addedReader: 'target' },
      claimCommit: () => asynchronousClaim,
      commit: jest.fn(),
    }));

    await expect(
      document._addReaderUnlocked(
        targetUser,
        'target',
        readerKemPublicKey,
        false,
      ),
    ).rejects.toThrow(/must complete synchronously/);

    expect(finalize).not.toHaveBeenCalled();
    expect(install).not.toHaveBeenCalled();
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._testState.readerIds.has('target')).toBe(false);
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');

    releaseAsynchronousWork.resolve();
    await asynchronousWorkCompletion;
    expect(document._testState.readerIds.has('attacker')).toBe(true);
  });

  test('rejects an accessor-backed claim then without invoking its getter', async () => {
    const document = fakeDocument();
    const readerKemPublicKey = await validKemPublicKey();
    const install = jest.fn();
    const finalize = jest.fn();
    const thenGetter = jest.fn(() => {
      document._testState.readerIds.add('attacker');
      return () => undefined;
    });
    const claim = { finalize };
    Object.defineProperty(claim, 'then', { get: thenGetter });
    document._prepareBeeKEMReaderRegistration = jest.fn(async () => ({
      welcome: { leafIndex: 2 },
      install,
    }));
    document._readers.prepareAdd = jest.fn(async () => ({
      changes: { addedReader: 'target' },
      claimCommit: () => claim,
      commit: jest.fn(),
    }));

    await expect(
      document._addReaderUnlocked(
        targetUser,
        'target',
        readerKemPublicKey,
        false,
      ),
    ).rejects.toThrow(/invalid asynchronous result/);

    expect(thenGetter).not.toHaveBeenCalled();
    expect(finalize).not.toHaveBeenCalled();
    expect(install).not.toHaveBeenCalled();
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._testState.readerIds.has('attacker')).toBe(false);
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
  });

  test('rejects a constructor Proxy without probing its Promise species', async () => {
    const document = fakeDocument();
    const readerKemPublicKey = await validKemPublicKey();
    const install = jest.fn();
    const finalize = jest.fn();
    const speciesDescriptorTrap = jest.fn(
      (_target: object, property: PropertyKey) =>
        property === Symbol.species
          ? {
              configurable: true,
              enumerable: false,
              value: Promise,
              writable: false,
            }
          : undefined,
    );
    const speciesGetTrap = jest.fn(() => {
      throw new Error('hostile Promise species getter');
    });
    const hostileConstructor = new Proxy(
      {},
      {
        getOwnPropertyDescriptor: speciesDescriptorTrap,
        get: speciesGetTrap,
      },
    );
    const asynchronousClaim = Promise.resolve({ finalize }) as Promise<{
      finalize: () => void;
    }> & {
      finalize: () => void;
    };
    Object.setPrototypeOf(asynchronousClaim, null);
    Object.defineProperties(asynchronousClaim, {
      constructor: { value: hostileConstructor },
      finalize: { value: finalize },
    });
    document._prepareBeeKEMReaderRegistration = jest.fn(async () => ({
      welcome: { leafIndex: 2 },
      install,
    }));
    document._readers.prepareAdd = jest.fn(async () => ({
      changes: { addedReader: 'target' },
      claimCommit: () => asynchronousClaim,
      commit: jest.fn(),
    }));

    await expect(
      document._addReaderUnlocked(
        targetUser,
        'target',
        readerKemPublicKey,
        false,
      ),
    ).rejects.toThrow(/invalid asynchronous result/);

    expect(speciesDescriptorTrap).not.toHaveBeenCalled();
    expect(speciesGetTrap).not.toHaveBeenCalled();
    expect(finalize).not.toHaveBeenCalled();
    expect(install).not.toHaveBeenCalled();
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
  });

  test('rejects a Promise with a mutating Proxy prototype before probing it', async () => {
    const document = fakeDocument();
    const readerKemPublicKey = await validKemPublicKey();
    const install = jest.fn();
    const finalize = jest.fn();
    let asynchronousClaim!: Promise<{ finalize: () => void }> & {
      finalize: () => void;
    };
    const descriptorTrap = jest.fn(() => undefined);
    const prototypeTrap = jest.fn(() => null);
    const getTrap = jest.fn((_target: object, property: PropertyKey) => {
      if (property === 'constructor') {
        Object.setPrototypeOf(asynchronousClaim, Object.prototype);
        throw new Error('mutating constructor lookup');
      }
      return undefined;
    });
    const hostilePrototype = new Proxy(
      {},
      {
        getOwnPropertyDescriptor: descriptorTrap,
        getPrototypeOf: prototypeTrap,
        get: getTrap,
      },
    );
    asynchronousClaim = Promise.resolve({ finalize }) as typeof asynchronousClaim;
    Object.setPrototypeOf(asynchronousClaim, hostilePrototype);
    Object.defineProperty(asynchronousClaim, 'finalize', { value: finalize });
    document._prepareBeeKEMReaderRegistration = jest.fn(async () => ({
      welcome: { leafIndex: 2 },
      install,
    }));
    document._readers.prepareAdd = jest.fn(async () => ({
      changes: { addedReader: 'target' },
      claimCommit: () => asynchronousClaim,
      commit: jest.fn(),
    }));

    await expect(
      document._addReaderUnlocked(
        targetUser,
        'target',
        readerKemPublicKey,
        false,
      ),
    ).rejects.toThrow(/plain claim record/);

    expect(descriptorTrap).not.toHaveBeenCalled();
    expect(prototypeTrap).not.toHaveBeenCalled();
    expect(getTrap).not.toHaveBeenCalled();
    expect(Object.getPrototypeOf(asynchronousClaim)).toBe(hostilePrototype);
    expect(finalize).not.toHaveBeenCalled();
    expect(install).not.toHaveBeenCalled();
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
  });

  test('an asynchronous claim finalizer poisons after publication', async () => {
    const document = fakeDocument();
    const readerKemPublicKey = await validKemPublicKey();
    const install = jest.fn();
    const finalize = jest.fn(async () => undefined);
    document._prepareBeeKEMReaderRegistration = jest.fn(async () => ({
      welcome: { leafIndex: 2 },
      install,
    }));
    document._readers.prepareAdd = jest.fn(async () => ({
      changes: { addedReader: 'target' },
      claimCommit: () => ({ finalize }),
      commit: jest.fn(),
    }));

    await expect(
      document._addReaderUnlocked(
        targetUser,
        'target',
        readerKemPublicKey,
        false,
      ),
    ).rejects.toThrow(/finalizer must return undefined/);

    expect(install).toHaveBeenCalledTimes(1);
    expect(finalize).toHaveBeenCalledTimes(1);
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
  });
});

describe('writer promotion preconditions', () => {
  test('rejects a target outside the explicit readers ACL', async () => {
    const document = fakeDocument({
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });

    await expect(document.addWriter(targetUser)).rejects.toThrow(
      /must first be added to the explicit readers ACL/,
    );
    expect(document._testState.findLeafByPublicKey).not.toHaveBeenCalled();
    expect(document._testState.prepareWriterAdd).not.toHaveBeenCalled();
  });

  test('rejects promotion without initialized BeeKEM state', async () => {
    const document = fakeDocument({
      readers: ['target'],
      beekemInitialized: false,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });

    await expect(document.addWriter(targetUser)).rejects.toThrow(
      /local BeeKEM tree has not been initialized/,
    );
    expect(document._testState.prepareWriterAdd).not.toHaveBeenCalled();
  });

  test('rejects a reader without an identity-bound KEM key', async () => {
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      cachedLeafIndex: 2,
    });

    await expect(document.addWriter(targetUser)).rejects.toThrow(
      /no valid identity-bound reader KEM public key/,
    );
    expect(document._testState.findLeafByPublicKey).not.toHaveBeenCalled();
    expect(document._testState.prepareWriterAdd).not.toHaveBeenCalled();
  });

  test('rejects a KEM binding whose BeeKEM leaf is blank or missing', async () => {
    const document = fakeDocument({
      readers: ['target'],
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });

    await expect(document.addWriter(targetUser)).rejects.toThrow(
      /does not resolve to exactly one live, non-blanked BeeKEM leaf/,
    );
    expect(document._testState.prepareWriterAdd).not.toHaveBeenCalled();
  });

  test('rejects a cached leaf that disagrees with the live BeeKEM tree', async () => {
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 4,
    });

    await expect(document.addWriter(targetUser)).rejects.toThrow(
      /cached BeeKEM leaf does not match the live tree/,
    );
    expect(document._testState.prepareWriterAdd).not.toHaveBeenCalled();
  });

  test('does not let an already-writer no-op bless malformed legacy state', async () => {
    const document = fakeDocument({
      readers: ['target'],
      writers: ['target'],
      liveLeafIndex: 2,
      cachedLeafIndex: 2,
    });

    await expect(document.addWriter(targetUser)).rejects.toThrow(
      /no valid identity-bound reader KEM public key/,
    );
    expect(document._testState.writerCheck).not.toHaveBeenCalled();
    expect(document._testState.prepareWriterAdd).not.toHaveBeenCalled();
  });

  test('recovers a missing leaf cache only after resolving live membership', async () => {
    const recordedKemPublicKey = kemPublicKey();
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey,
    });

    await expect(document.addWriter(targetUser)).resolves.toBeUndefined();
    expect(document._testState.findLeafByPublicKey).toHaveBeenCalledWith(
      expect.any(Uint8Array),
    );
    expect(document._readerLeafIndices.get('target')).toBe(2);
    expect(document._testState.prepareWriterAdd).toHaveBeenCalledWith(
      targetUser,
    );
    expect(document._makeChange).toHaveBeenCalledTimes(1);
  });

  test('does not repair the leaf cache when writer staging or publication fails', async () => {
    const stagingFailure = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
    });
    stagingFailure._writers.prepareAdd = jest.fn(async () => {
      throw new Error('staging failed');
    });

    await expect(stagingFailure.addWriter(targetUser)).rejects.toThrow(
      'staging failed',
    );
    expect(stagingFailure._readerLeafIndices.has('target')).toBe(false);

    const publicationFailure = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
    });
    publicationFailure._testState.makeChange.mockRejectedValueOnce(
      new Error('publication failed'),
    );

    await expect(publicationFailure.addWriter(targetUser)).rejects.toThrow(
      'publication failed',
    );
    expect(publicationFailure._readerLeafIndices.has('target')).toBe(false);
    expect(publicationFailure._testState.writerIds.has('target')).toBe(false);
  });

  test('does not mutate the leaf cache for an already-writer no-op', async () => {
    const document = fakeDocument({
      readers: ['target'],
      writers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
    });

    await expect(document.addWriter(targetUser)).resolves.toBeUndefined();
    expect(document._readerLeafIndices.has('target')).toBe(false);
    expect(document._testState.prepareWriterAdd).not.toHaveBeenCalled();
  });

  test('rejects a non-canonical provider identity round trip', async () => {
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
    });
    document._authProvider.deserializePublicKey = jest.fn(
      async () => ({ id: 'different' }),
    );

    await expect(document.addWriter(targetUser)).rejects.toThrow(
      /non-canonical public-key round trip/,
    );
    expect(document._testState.prepareWriterAdd).not.toHaveBeenCalled();
  });
});

describe('reader registration retry', () => {
  test('recovers a lost leaf-index cache from the retained KEM binding', async () => {
    const recordedKemPublicKey = kemPublicKey();
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey,
    });

    const prepared = await document._prepareBeeKEMReaderRegistration(
      'target',
      new Uint8Array(recordedKemPublicKey),
    );
    expect(prepared.welcome).toEqual(beekemWelcome());
    expect(document._readerLeafIndices.has('target')).toBe(false);
    prepared.install();

    expect(document._testState.findLeafByPublicKey).toHaveBeenCalledWith(
      expect.any(Uint8Array),
    );
    expect(document._readerLeafIndices.get('target')).toBe(2);
  });
});

describe('writer and reader removal ordering', () => {
  test('rejects canonical local self-removal before mutating the writer ACL', async () => {
    const document = fakeDocument({
      readers: ['local'],
      writers: ['local'],
    });

    await expect(document.removeWriter({ id: 'local' })).rejects.toThrow(
      /Cannot remove the local writer/,
    );
    expect(document._testState.prepareWriterRemove).not.toHaveBeenCalled();
    expect(document._makeChange).not.toHaveBeenCalled();
  });

  test('uses a reconstructed identity when caller-owned input mutates across await', async () => {
    const mutableTarget = { id: 'other' };
    const document = fakeDocument({
      readers: ['other'],
      writers: ['local', 'other'],
    });
    const serializationStarted = deferred<void>();
    const serializedIdentity = deferred<string>();
    document._authProvider.serializePublicKey = jest.fn(
      async (key: Identity) => {
        if (key === mutableTarget) {
          serializationStarted.resolve();
          return serializedIdentity.promise;
        }
        return key.id;
      },
    );

    const removal = document.removeWriter(mutableTarget);
    await serializationStarted.promise;
    mutableTarget.id = 'local';
    serializedIdentity.resolve('other');
    await expect(removal).resolves.toBeUndefined();

    expect(document._testState.writerIds.has('local')).toBe(true);
    expect(document._testState.writerIds.has('other')).toBe(false);
    expect(document._testState.prepareWriterRemove).toHaveBeenCalledWith({
      id: 'other',
    });
  });

  test('keeps absent writer removal idempotent without identity codecs', async () => {
    const document = fakeDocument();
    delete document._authProvider.serializePublicKey;
    delete document._authProvider.deserializePublicKey;

    await expect(document.removeWriter(targetUser)).resolves.toBeUndefined();
    expect(document._testState.prepareWriterRemove).not.toHaveBeenCalled();
  });

  test('fails closed for a present writer when identity codecs are unavailable', async () => {
    const document = fakeDocument({ writers: ['target'] });
    delete document._authProvider.serializePublicKey;
    delete document._authProvider.deserializePublicKey;

    await expect(document.removeWriter(targetUser)).rejects.toThrow(
      /requires AuthProvider\.serializePublicKey/,
    );
    expect(document._testState.writerIds.has('target')).toBe(true);
    expect(document._testState.prepareWriterRemove).not.toHaveBeenCalled();
  });

  test('rejects downgrade of a legacy writer-only target', async () => {
    const document = fakeDocument({ writers: ['target'] });

    await expect(document.removeWriter(targetUser)).rejects.toThrow(
      /must remain explicitly authorized as a reader/,
    );
    expect(document._testState.writerIds.has('target')).toBe(true);
    expect(document._testState.prepareWriterRemove).not.toHaveBeenCalled();
    expect(document._makeChange).not.toHaveBeenCalled();
  });

  test('requires a writer-only legacy target to be downgraded before reader removal', async () => {
    const document = fakeDocument({ writers: ['target'] });

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /still an authorized writer.*removeWriter first/,
    );
    expect(document._testState.readerCheck).not.toHaveBeenCalled();
    expect(document._testState.prepareReaderRemove).not.toHaveBeenCalled();
  });

  test('supports removeWriter then removeReader without rotating on downgrade', async () => {
    const document = fakeDocument({
      readers: ['target'],
      writers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });

    await expect(document.removeWriter(targetUser)).resolves.toBeUndefined();
    expect(document._testState.writerIds.has('target')).toBe(false);
    expect(document._keychain.current).not.toHaveBeenCalled();
    expect(document._keychain.add).not.toHaveBeenCalled();

    await expect(document.removeReader(targetUser)).resolves.toBeUndefined();
    expect(document._testState.readerIds.has('target')).toBe(false);
    expect(document._testState.prepareWriterRemove).toHaveBeenCalledTimes(1);
    expect(document._testState.prepareReaderRemove).toHaveBeenCalledTimes(1);
    expect(document._testState.removeMember).toHaveBeenCalledWith(2);
    expect(document._distributeBeeKEMPathUpdate).toHaveBeenCalledTimes(1);
    expect(document._testState.prepareEpochKey).toHaveBeenCalledTimes(1);
    expect(document._testState.epochKeyCommit).toHaveBeenCalledTimes(1);
    expect(document._testState.epochLegacyCommit).not.toHaveBeenCalled();
    expect(document._makeChange).toHaveBeenCalledTimes(2);
  });

  test('revokes a live identity-bound leaf even when the reader ACL row is absent', async () => {
    const document = fakeDocument({
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });

    await expect(document.removeReader(targetUser)).resolves.toBeUndefined();

    expect(document._testState.prepareReaderRemove).not.toHaveBeenCalled();
    expect(document._testState.removeMember).toHaveBeenCalledWith(2);
    expect(document._testState.prepareEpochKey).toHaveBeenCalledTimes(1);
    expect(document._testState.epochKeyCommit).toHaveBeenCalledTimes(1);
    expect(document._testState.epochLegacyCommit).not.toHaveBeenCalled();
    expect(document._distributeBeeKEMPathUpdate).toHaveBeenCalledTimes(1);
    expect(document._readerKemPublicKeys.has('target')).toBe(false);
    expect(document._readerLeafIndices.has('target')).toBe(false);
  });

  test('fails closed when absent ACL and caches do not prove cryptographic revocation', async () => {
    const document = fakeDocument({ onlyLocalLiveLeaf: false });

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /live tree does not prove that every remote leaf has already been revoked/,
    );

    expect(document._testState.hasOnlyLocalLiveLeaf).toHaveBeenCalledTimes(1);
    expect(document._testState.liveBeeKEM.clone).not.toHaveBeenCalled();
    expect(document._testState.prepareReaderRemove).not.toHaveBeenCalled();
    expect(document._makeChange).not.toHaveBeenCalled();
  });

  test('keeps absent reader removal idempotent only when the tree has just the local live leaf', async () => {
    const document = fakeDocument({ onlyLocalLiveLeaf: true });

    await expect(document.removeReader(targetUser)).resolves.toBeUndefined();

    expect(document._testState.hasOnlyLocalLiveLeaf).toHaveBeenCalledTimes(1);
    expect(document._testState.liveBeeKEM.clone).not.toHaveBeenCalled();
    expect(document._testState.prepareEpochKey).not.toHaveBeenCalled();
    expect(document._makeChange).not.toHaveBeenCalled();
  });

  test('rejects both removal paths for an unrepaired writer-only target', async () => {
    const document = fakeDocument({
      writers: ['target'],
      onlyLocalLiveLeaf: true,
    });

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /still an authorized writer.*removeWriter first/,
    );
    expect(document._testState.hasOnlyLocalLiveLeaf).not.toHaveBeenCalled();

    await expect(document.removeWriter(targetUser)).rejects.toThrow(
      /must remain explicitly authorized as a reader/,
    );
    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /still an authorized writer.*removeWriter first/,
    );
    expect(document._testState.writerIds.has('target')).toBe(true);
    expect(document._testState.hasOnlyLocalLiveLeaf).not.toHaveBeenCalled();
    expect(document._makeChange).not.toHaveBeenCalled();
  });

  test('rejects reader removal when the cached and live leaves disagree', async () => {
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 4,
    });

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /cached BeeKEM leaf does not match the unique live identity-bound leaf/,
    );
    expect(document._testState.liveBeeKEM.clone).not.toHaveBeenCalled();
    expect(document._testState.prepareReaderRemove).not.toHaveBeenCalled();
  });

  test('leaves live reader ACL, tree, and caches unchanged when publication fails', async () => {
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });
    const originalBeeKEM = document._beekem;
    document._testState.makeChange.mockRejectedValueOnce(
      new Error('publication failed'),
    );

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      'publication failed',
    );

    expect(document._testState.readerIds.has('target')).toBe(true);
    expect(document._beekem).toBe(originalBeeKEM);
    expect(document._readerKemPublicKeys.has('target')).toBe(true);
    expect(document._readerLeafIndices.get('target')).toBe(2);
    expect(document._beekemWelcomeByLeaf.has(2)).toBe(true);
    expect(document._testState.readerRemovalClaim).toHaveBeenCalledTimes(1);
    expect(document._testState.epochKeyClaim).toHaveBeenCalledTimes(1);
    expect(document._testState.readerRemovalFinalize).not.toHaveBeenCalled();
    expect(document._testState.epochKeyCommit).not.toHaveBeenCalled();
    expect(document._distributeBeeKEMPathUpdate).not.toHaveBeenCalled();

    await expect(document.removeReader(targetUser)).resolves.toBeUndefined();
    expect(document._testState.readerIds.has('target')).toBe(false);
    expect(document._beekem).toBe(document._testState.stagedBeeKEM);
    expect(document._testState.readerRemovalFinalize).toHaveBeenCalledTimes(1);
    expect(document._beekemWelcomeByLeaf.has(2)).toBe(false);
    expect(document._testState.readerRemovalClaim).toHaveBeenCalledTimes(2);
    expect(document._testState.epochKeyClaim).toHaveBeenCalledTimes(2);
    expect(document._testState.epochKeyCommit).toHaveBeenCalledTimes(1);
    expect(document._distributeBeeKEMPathUpdate).toHaveBeenCalledTimes(1);
  });

  test('poisons while keeping live state unchanged when the epoch claim fails', async () => {
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });
    const originalBeeKEM = document._beekem;
    document._testState.epochKeyClaim.mockImplementationOnce(() => {
      throw new Error('key claim failed');
    });

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      'key claim failed',
    );

    expect(document._testState.readerIds.has('target')).toBe(true);
    expect(document._beekem).toBe(originalBeeKEM);
    expect(document._readerKemPublicKeys.has('target')).toBe(true);
    expect(document._readerLeafIndices.get('target')).toBe(2);
    expect(document._beekemWelcomeByLeaf.has(2)).toBe(true);
    expect(document._testState.readerRemovalClaim).toHaveBeenCalledTimes(1);
    expect(document._testState.readerRemovalFinalize).not.toHaveBeenCalled();
    expect(document._testState.epochKeyCommit).not.toHaveBeenCalled();
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._distributeBeeKEMPathUpdate).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /indeterminate authorization state/,
    );
    expect(document._testState.epochKeyClaim).toHaveBeenCalledTimes(1);
  });

  test('keeps all live state unchanged when the reader claim fails before the epoch claim', async () => {
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });
    const originalBeeKEM = document._beekem;
    document._testState.readerRemovalClaim.mockImplementationOnce(() => {
      throw new Error('reader claim failed');
    });

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      'reader claim failed',
    );

    expect(document._testState.readerIds.has('target')).toBe(true);
    expect(document._beekem).toBe(originalBeeKEM);
    expect(document._readerKemPublicKeys.has('target')).toBe(true);
    expect(document._readerLeafIndices.get('target')).toBe(2);
    expect(document._beekemWelcomeByLeaf.has(2)).toBe(true);
    expect(document._testState.epochKeyClaim).not.toHaveBeenCalled();
    expect(document._testState.readerRemovalFinalize).not.toHaveBeenCalled();
    expect(document._testState.epochKeyCommit).not.toHaveBeenCalled();
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._distributeBeeKEMPathUpdate).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
  });

  test('claims both providers before publication and either finalizer', async () => {
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });
    const order: string[] = [];
    document._testState.readerRemovalClaim.mockImplementationOnce(
      (key: Identity) => {
        order.push('reader-claim');
        return {
          finalize: () => {
            order.push('reader-finalize');
            document._testState.readerIds.delete(key.id);
          },
        };
      },
    );
    document._testState.epochKeyClaim.mockImplementationOnce(() => {
      order.push('epoch-claim');
      return {
        finalize: () => {
          order.push('epoch-finalize');
        },
      };
    });
    document._testState.makeChange.mockImplementationOnce(async () => {
      order.push('publish');
    });

    await document.removeReader(targetUser);

    expect(order).toEqual([
      'reader-claim',
      'epoch-claim',
      'publish',
      'reader-finalize',
      'epoch-finalize',
    ]);
  });

  test('poisons when a reader finalizer returns a Promise before epoch or tree commit', async () => {
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });
    const originalBeeKEM = document._beekem;
    document._testState.readerRemovalClaim.mockImplementationOnce(
      (key: Identity) => ({
        finalize: () =>
          Promise.resolve().then(() => {
            document._testState.readerIds.delete(key.id);
          }),
      }),
    );

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /Reader ACL commit claim finalizer must return undefined/,
    );

    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
    expect(document._testState.epochKeyCommit).not.toHaveBeenCalled();
    expect(document._beekem).toBe(originalBeeKEM);
    expect(document._readerKemPublicKeys.has('target')).toBe(true);
    expect(document._distributeBeeKEMPathUpdate).not.toHaveBeenCalled();
    await Promise.resolve();
    expect(document._testState.readerIds.has('target')).toBe(false);
    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /indeterminate authorization state/,
    );
  });

  test('poisons when an epoch finalizer returns a custom thenable without assimilating it', async () => {
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });
    const originalBeeKEM = document._beekem;
    const thenGetter = jest.fn(() => {
      throw new Error('custom thenable must not be assimilated');
    });
    const thenable = {};
    Object.defineProperty(thenable, 'then', { get: thenGetter });
    document._testState.epochKeyClaim.mockReturnValueOnce({
      finalize: () => thenable,
    });

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /epoch commit claim finalizer must return undefined/i,
    );

    expect(thenGetter).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
    expect(document._testState.readerIds.has('target')).toBe(false);
    expect(document._beekem).toBe(originalBeeKEM);
    expect(document._readerKemPublicKeys.has('target')).toBe(true);
    expect(document._distributeBeeKEMPathUpdate).not.toHaveBeenCalled();
  });

  test('poisons the ACL-absent recovery path when the epoch finalizer throws', async () => {
    const document = fakeDocument({
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });
    const originalBeeKEM = document._beekem;
    document._testState.epochKeyClaim.mockReturnValueOnce({
      finalize: () => {
        throw new Error('epoch finalizer failed');
      },
    });

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      'epoch finalizer failed',
    );

    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
    expect(document._testState.epochLegacyCommit).not.toHaveBeenCalled();
    expect(document._beekem).toBe(originalBeeKEM);
    expect(document._readerKemPublicKeys.has('target')).toBe(true);
    expect(document._readerLeafIndices.get('target')).toBe(2);
    expect(document._beekemWelcomeByLeaf.has(2)).toBe(true);
    expect(document._distributeBeeKEMPathUpdate).not.toHaveBeenCalled();
  });

  test('poisons while leaving ACL-absent live state unchanged when the epoch claim throws', async () => {
    const document = fakeDocument({
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });
    const originalBeeKEM = document._beekem;
    document._testState.epochKeyClaim.mockImplementationOnce(() => {
      throw new Error('epoch claim failed');
    });

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      'epoch claim failed',
    );
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
    expect(document._beekem).toBe(originalBeeKEM);
    expect(document._readerKemPublicKeys.has('target')).toBe(true);
    expect(document._readerLeafIndices.get('target')).toBe(2);
    expect(document._testState.epochLegacyCommit).not.toHaveBeenCalled();
    expect(document._distributeBeeKEMPathUpdate).not.toHaveBeenCalled();

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /indeterminate authorization state/,
    );
    expect(document._testState.epochKeyClaim).toHaveBeenCalledTimes(1);
    expect(document._testState.epochKeyCommit).not.toHaveBeenCalled();
  });

  test('rejects an accessor-backed epoch claim without invoking its getter', async () => {
    const document = fakeDocument({
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });
    const originalBeeKEM = document._beekem;
    const claimGetter = jest.fn(() => document._testState.epochKeyClaim);
    const preparedEpoch = { changes: {}, history: {} };
    Object.defineProperty(preparedEpoch, 'claimCommit', {
      get: claimGetter,
    });
    document._testState.prepareEpochKey.mockResolvedValueOnce(preparedEpoch);

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /claimCommit must be a data property/,
    );

    expect(claimGetter).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('complete');
    expect(document._beekem).toBe(originalBeeKEM);
    expect(document._readerKemPublicKeys.has('target')).toBe(true);
    expect(document._testState.epochLegacyCommit).not.toHaveBeenCalled();
  });

  test('rejects malformed claims before either provider finalizes', async () => {
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });
    const originalBeeKEM = document._beekem;
    document._testState.epochKeyClaim.mockReturnValueOnce({});

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /commit claim returned an invalid finalizer/,
    );

    expect(document._testState.readerIds.has('target')).toBe(true);
    expect(document._testState.readerRemovalFinalize).not.toHaveBeenCalled();
    expect(document._testState.epochKeyCommit).not.toHaveBeenCalled();
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._beekem).toBe(originalBeeKEM);
    expect(document._readerKemPublicKeys.has('target')).toBe(true);
    expect(document._readerLeafIndices.get('target')).toBe(2);
    expect(document._beekemWelcomeByLeaf.has(2)).toBe(true);
    expect(document._distributeBeeKEMPathUpdate).not.toHaveBeenCalled();
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
  });

  test('fails closed before publication when transactional epoch staging is unavailable', async () => {
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });
    delete document._keychain.prepareEpochKey;

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /does not support transactional epoch-key staging/,
    );

    expect(document._testState.readerIds.has('target')).toBe(true);
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._testState.epochKeyCommit).not.toHaveBeenCalled();
    expect(document._testState.removeMember).toHaveBeenCalledTimes(1);
    expect(document._beekem).toBe(document._testState.liveBeeKEM);
    expect(document._readerKemPublicKeys.has('target')).toBe(true);
    expect(document._readerLeafIndices.get('target')).toBe(2);
  });

  test('fails closed before publication when a custom reader ACL cannot claim a composed commit', async () => {
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });
    document._readers.prepareRemove = jest.fn(async () => ({
      changes: { removedReader: 'target' },
      commit: () => document._testState.readerIds.delete('target'),
    }));

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /ACL and keychain must support composed commit claims/,
    );

    expect(document._testState.readerIds.has('target')).toBe(true);
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._testState.epochKeyClaim).not.toHaveBeenCalled();
    expect(document._beekem).toBe(document._testState.liveBeeKEM);
  });

  test('fails closed before publication when a custom keychain cannot claim a composed commit', async () => {
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });
    document._testState.prepareEpochKey.mockResolvedValueOnce({
      changes: {},
      history: {},
      commit: document._testState.epochKeyCommit,
    });

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /ACL and keychain must support composed commit claims/,
    );

    expect(document._testState.readerIds.has('target')).toBe(true);
    expect(document._testState.makeChange).not.toHaveBeenCalled();
    expect(document._testState.readerRemovalClaim).not.toHaveBeenCalled();
    expect(document._testState.epochKeyCommit).not.toHaveBeenCalled();
    expect(document._beekem).toBe(document._testState.liveBeeKEM);
  });

  test('rejects an out-of-queue reader merge while staged publication is active', async () => {
    const document = fakeDocument();
    document._readerPublicationsInFlight = 1;

    await expect(document._mergeReaders({ remote: true })).rejects.toThrow(
      /staged local reader publication is in flight/,
    );
    expect(document._testState.mergeReaders).not.toHaveBeenCalled();
  });

  test('does not claim adversarial remote-writer revocation when signing is disabled', async () => {
    const document = fakeDocument({
      readers: ['target'],
      writers: ['target'],
      enableSigning: false,
    });
    document._getWriterKeys = jest.fn(async () => []);

    await document.removeWriter(targetUser);

    await expect(
      document._verifyWriterSignature(new Uint8Array([1]), 'forged'),
    ).resolves.toBe(true);
    expect(document._getWriterKeys).not.toHaveBeenCalled();
    expect(document._authProvider.verify).not.toHaveBeenCalled();
  });
});
