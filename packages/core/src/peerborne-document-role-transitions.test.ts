import { describe, expect, jest, test } from '@jest/globals';
import { PeerborneDocument } from './peerborne-document.js';

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

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
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
  const prepareReaderRemove = jest.fn(async (key: Identity) => ({
    changes: { removedReader: key.id },
    commit: () => readerIds.delete(key.id),
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
    findLeafByPublicKey,
    hasOnlyLocalLiveLeaf,
    clone: jest.fn(() => stagedBeeKEM),
  };
  const makeChange = jest.fn(async () => undefined);
  const publishPreparedWriterChange = jest.fn(
    async (prepared: { changes: unknown; commit(): void }) => {
      await makeChange(prepared.changes);
      prepared.commit();
    },
  );
  const publishPreparedReaderChange = jest.fn(
    async (
      prepared: { changes: unknown; commit(): void },
      _operation: string,
      afterCommit: () => void,
    ) => {
      await makeChange(prepared.changes);
      prepared.commit();
      afterCommit();
    },
  );
  const epochKeyCommit = jest.fn();
  const prepareEpochKey = jest.fn(async () => ({
    changes: {},
    history: {},
    commit: epochKeyCommit,
  }));
  const readerKemPublicKeys = new Map<string, Uint8Array>();
  if (options.recordedKemPublicKey) {
    readerKemPublicKeys.set('target', options.recordedKemPublicKey);
  }
  const readerLeafIndices = new Map<string, number>();
  if (options.cachedLeafIndex !== undefined) {
    readerLeafIndices.set('target', options.cachedLeafIndex);
  }

  return Object.assign(Object.create(PeerborneDocument.prototype), {
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
    _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
    _readers: {
      check: readerCheck,
      users: jest.fn(async () =>
        [...readerIds].map((id) => ({ id })),
      ),
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
    _beekemWelcomeByLeaf: new Map([[2, { welcome: true }]]),
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
      prepareReaderRemove,
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
      epochKeyCommit,
      serializePublicKey,
      deserializePublicKey,
    },
  });
}

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

  test('removes write authority from a legacy writer-only target', async () => {
    const document = fakeDocument({ writers: ['target'] });

    await expect(document.removeWriter(targetUser)).resolves.toBeUndefined();
    expect(document._testState.writerIds.has('target')).toBe(false);
    expect(document._testState.prepareWriterRemove).toHaveBeenCalledWith(
      targetUser,
    );
    expect(document._makeChange).toHaveBeenCalledTimes(1);
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
    expect(document._beekem.removeMember).toHaveBeenCalledWith(2);
    expect(document._distributeBeeKEMPathUpdate).toHaveBeenCalledTimes(1);
    expect(document._testState.prepareEpochKey).toHaveBeenCalledTimes(1);
    expect(document._testState.epochKeyCommit).toHaveBeenCalledTimes(1);
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

  test('keeps writer-first ordering for legacy writer-only removal', async () => {
    const document = fakeDocument({
      writers: ['target'],
      onlyLocalLiveLeaf: true,
    });

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      /still an authorized writer.*removeWriter first/,
    );
    expect(document._testState.hasOnlyLocalLiveLeaf).not.toHaveBeenCalled();

    await expect(document.removeWriter(targetUser)).resolves.toBeUndefined();
    await expect(document.removeReader(targetUser)).resolves.toBeUndefined();
    expect(document._testState.writerIds.has('target')).toBe(false);
    expect(document._testState.hasOnlyLocalLiveLeaf).toHaveBeenCalledTimes(1);
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
    expect(document._testState.epochKeyCommit).not.toHaveBeenCalled();
    expect(document._distributeBeeKEMPathUpdate).not.toHaveBeenCalled();
  });

  test('keeps the live tree and identity binding when staged key commit fails', async () => {
    const document = fakeDocument({
      readers: ['target'],
      liveLeafIndex: 2,
      recordedKemPublicKey: kemPublicKey(),
      cachedLeafIndex: 2,
    });
    const originalBeeKEM = document._beekem;
    document._testState.epochKeyCommit.mockImplementationOnce(() => {
      throw new Error('key commit failed');
    });

    await expect(document.removeReader(targetUser)).rejects.toThrow(
      'key commit failed',
    );

    expect(document._testState.readerIds.has('target')).toBe(false);
    expect(document._beekem).toBe(originalBeeKEM);
    expect(document._readerKemPublicKeys.has('target')).toBe(true);
    expect(document._readerLeafIndices.get('target')).toBe(2);
    expect(document._distributeBeeKEMPathUpdate).not.toHaveBeenCalled();
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

  test('rejects an out-of-queue reader merge while staged publication is active', () => {
    const document = fakeDocument();
    document._readerPublicationsInFlight = 1;

    expect(() => document._mergeReaders({ remote: true })).toThrow(
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
