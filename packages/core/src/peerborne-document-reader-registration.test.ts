import { describe, expect, jest, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem';
import type { BeeKEMWelcome, PathUpdateV2 } from './beekem/types';
import { PeerborneDocument } from './peerborne-document';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('./peerborne.js', () => ({ MAX_DOCUMENT_PATH_LENGTH: 4096 }));
jest.mock('multiformats', () => ({ CID: { parse: (value: string) => value } }), {
  virtual: true,
});
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock(
  '@libp2p/gossipsub',
  () => ({ TopicValidatorResult: { Accept: 'accept', Ignore: 'ignore' } }),
  { virtual: true },
);

const ECDH_ALGORITHM = { name: 'ECDH', namedCurve: 'P-256' };

interface ReaderIdentity {
  id: string;
}

type RegistrationResult = {
  welcome: BeeKEMWelcome | null;
  pathUpdate?: PathUpdateV2;
  rootSecret?: Uint8Array;
};

type RegistrationHarness = {
  documentPath: string;
  _authProvider: {
    serializePublicKey(reader: ReaderIdentity): Promise<string>;
  };
  _beekem: BeeKEM;
  _beekemInitialized: boolean;
  _beekemTransitionTail: Promise<void>;
  _beekemTransitionsPending: number;
  _hashes: Set<string>;
  _readerKemPublicKeys: Map<string, Uint8Array>;
  _readerLeafIndices: Map<string, number>;
  _beekemWelcomeByLeaf: Map<number, BeeKEMWelcome>;
  _registerBeeKEMReaderUnderLock(
    reader: ReaderIdentity,
    kemPublicKey: Uint8Array,
  ): Promise<RegistrationResult>;
  _runBeeKEMTransition<T>(operation: () => Promise<T>): Promise<T>;
};

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH_ALGORITHM, true, ['deriveBits']);
}

async function rawPublicKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

async function makeHarness(): Promise<{
  document: RegistrationHarness;
  founder: BeeKEM;
}> {
  const founder = new BeeKEM();
  const founderKeys = await generateKeyPair();
  await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);

  const document = Object.create(
    PeerborneDocument.prototype,
  ) as RegistrationHarness;
  document.documentPath = '/reader-registration-race';
  document._authProvider = {
    serializePublicKey: async reader => {
      await Promise.resolve();
      return reader.id;
    },
  };
  document._beekem = founder;
  document._beekemInitialized = true;
  document._beekemTransitionTail = Promise.resolve();
  document._beekemTransitionsPending = 0;
  document._hashes = new Set();
  document._readerKemPublicKeys = new Map();
  document._readerLeafIndices = new Map();
  document._beekemWelcomeByLeaf = new Map();
  return { document, founder };
}

function registerReader(
  document: RegistrationHarness,
  reader: ReaderIdentity,
  kemPublicKey: Uint8Array,
): Promise<RegistrationResult> {
  return document._runBeeKEMTransition(() =>
    document._registerBeeKEMReaderUnderLock(reader, kemPublicKey),
  );
}

describe('PeerborneDocument BeeKEM reader registration', () => {
  test('concurrent duplicate registration allocates one revocable leaf', async () => {
    const { document, founder } = await makeHarness();
    const reader = { id: 'reader-a' };
    const readerKeys = await generateKeyPair();
    const readerKemPublicKey = await rawPublicKey(readerKeys.publicKey);

    const [first, second] = await Promise.all([
      registerReader(document, reader, readerKemPublicKey),
      registerReader(document, reader, readerKemPublicKey),
    ]);

    expect(first.welcome).not.toBeNull();
    expect(second.welcome).toBe(first.welcome);
    expect(first.pathUpdate).toBeDefined();
    expect(first.rootSecret).toBeDefined();
    expect(second.pathUpdate).toBeUndefined();
    expect(first.welcome?.leafIndex).toBe(2);
    expect(founder.memberCount).toBe(2);
    expect(founder.generation).toBe(1);
    expect(document._readerLeafIndices.get(reader.id)).toBe(2);

    const duplicateCopies = await Promise.all(
      [first.welcome!, second.welcome!].map(async welcome => {
        const copy = new BeeKEM();
        await copy.processWelcome(
          welcome,
          readerKeys.privateKey,
          readerKeys.publicKey,
        );
        return copy;
      }),
    );

    const registeredLeaf = document._readerLeafIndices.get(reader.id)!;
    const { pathUpdate, rootSecret: postRemovalRoot } =
      await founder.removeMember(registeredLeaf);

    for (const copy of duplicateCopies) {
      await expect(copy.processPathUpdate(pathUpdate)).rejects.toThrow();
      expect(await copy.getRootSecret()).not.toEqual(postRemovalRoot);
    }
  });

  test('an existing identity cannot be rebound to a different KEM key', async () => {
    const { document, founder } = await makeHarness();
    const reader = { id: 'reader-a' };
    const originalKeys = await generateKeyPair();
    const replacementKeys = await generateKeyPair();
    const originalPublicKey = await rawPublicKey(originalKeys.publicKey);
    const replacementPublicKey = await rawPublicKey(replacementKeys.publicKey);

    await registerReader(document, reader, originalPublicKey);

    await expect(
      registerReader(document, reader, replacementPublicKey),
    ).rejects.toThrow(/already bound to a different KEM public key/);

    expect(founder.memberCount).toBe(2);
    expect(founder.generation).toBe(1);
    expect(document._readerLeafIndices.get(reader.id)).toBe(2);
    expect(document._readerKemPublicKeys.get(reader.id)).toEqual(
      originalPublicKey,
    );
  });

  test('distinct identities cannot register the same live KEM key', async () => {
    const { document, founder } = await makeHarness();
    const readerKeys = await generateKeyPair();
    const sharedKemPublicKey = await rawPublicKey(readerKeys.publicKey);

    await registerReader(document, { id: 'reader-a' }, sharedKemPublicKey);

    await expect(
      registerReader(document, { id: 'reader-b' }, sharedKemPublicKey),
    ).rejects.toThrow(/KEM public key already belongs to a live BeeKEM leaf/);

    expect(founder.memberCount).toBe(2);
    expect(founder.generation).toBe(1);
    expect(document._readerLeafIndices.has('reader-b')).toBe(false);
    expect(document._readerKemPublicKeys.has('reader-b')).toBe(false);
  });

  test('addReader rejects a duplicate live KEM key before mutating the readers ACL', async () => {
    const { document, founder } = await makeHarness();
    const fullDocument = document as any;
    const readerKeys = await generateKeyPair();
    const sharedKemPublicKey = await rawPublicKey(readerKeys.publicKey);
    await registerReader(
      document,
      { id: 'reader-a' },
      sharedKemPublicKey,
    );
    const addReaderAcl = jest.fn(async () => new Uint8Array([1]));
    Object.assign(fullDocument, {
      _ensureCurrentUserCanWrite: async () => undefined,
      _readers: {
        check: async () => false,
        add: addReaderAcl,
      },
      _keychain: { prepareEpochKey: jest.fn() },
      _pendingBeeKEMAdds: new Map(),
    });

    await expect(
      fullDocument._addReaderUnderBeeKEMLock(
        { id: 'reader-b' },
        sharedKemPublicKey,
      ),
    ).rejects.toThrow(/already belongs to a live BeeKEM leaf/);

    expect(addReaderAcl).not.toHaveBeenCalled();
    expect(founder.memberCount).toBe(2);
    expect(founder.generation).toBe(1);
  });

  test.each([
    ['ACL-only', false],
    ['KEM-bound', true],
  ])(
    '%s addReader retires after an ambiguous ACL rejection without touching BeeKEM',
    async (_label, withKem) => {
      const { document, founder } = await makeHarness();
      const fullDocument = document as any;
      const reader = { id: 'reader-ambiguous-add' };
      const readerKeys = await generateKeyPair();
      const kemPublicKey = withKem
        ? await rawPublicKey(readerKeys.publicKey)
        : undefined;
      const rootBefore = await founder.getRootSecret();
      let readerPresent = false;
      const addReaderAcl = jest.fn(async () => {
        readerPresent = true;
        throw new Error('reader ACL mutated before rejection');
      });
      const prepareChange = jest.fn();
      const publishPreparedChange = jest.fn();
      const registerBeeKEMReader = jest.fn();
      const decryptBlock = jest.fn();
      Object.assign(fullDocument, {
        _ensureCurrentUserCanWrite: async () => undefined,
        _readers: {
          check: async () => readerPresent,
          add: addReaderAcl,
        },
        _keychain: { prepareEpochKey: jest.fn() },
        _pendingBeeKEMAdds: new Map(),
        _pendingBeeKEMRemovals: new Map(),
        _securityProviderMutationFailure: undefined,
        _writerKeysVersion: 0,
        _writerMutationsInFlight: 0,
        _cachedWriterKeys: null,
        _prepareChange: prepareChange,
        _publishPreparedChange: publishPreparedChange,
        _registerBeeKEMReaderUnderLock: registerBeeKEMReader,
        _decryptBlock: decryptBlock,
        close: jest.fn(async () => undefined),
      });

      await expect(
        fullDocument._addReaderUnderBeeKEMLock(reader, kemPublicKey),
      ).rejects.toThrow(
        /addReader\(reader-ambiguous-add\).*ambiguous.*discard this document/,
      );
      const retirement = fullDocument._securityProviderMutationFailure;
      expect(retirement.cause).toEqual(
        new Error('reader ACL mutated before rejection'),
      );
      await expect(
        fullDocument._addReaderUnderBeeKEMLock(reader, kemPublicKey),
      ).rejects.toBe(retirement);

      expect(addReaderAcl).toHaveBeenCalledTimes(1);
      expect(prepareChange).not.toHaveBeenCalled();
      expect(publishPreparedChange).not.toHaveBeenCalled();
      expect(registerBeeKEMReader).not.toHaveBeenCalled();
      expect(founder.generation).toBe(0);
      expect(founder.memberCount).toBe(1);
      expect(await founder.getRootSecret()).toEqual(rootBefore);

      await fullDocument.handleKeyUpdateRequestData(new Uint8Array([1]));
      expect(decryptBlock).not.toHaveBeenCalled();
    },
  );

  test('ACL-only addReader retires when the provider delta is undefined', async () => {
    const { document } = await makeHarness();
    const fullDocument = document as any;
    const reader = { id: 'reader-undefined-delta' };
    let readerPresent = false;
    const addReaderAcl = jest.fn(async () => {
      readerPresent = true;
      return undefined;
    });
    const prepareChange = jest.fn();
    const publishPreparedChange = jest.fn();
    Object.assign(fullDocument, {
      _ensureCurrentUserCanWrite: async () => undefined,
      _readers: {
        check: async () => readerPresent,
        add: addReaderAcl,
      },
      _keychain: {},
      _pendingBeeKEMAdds: new Map(),
      _pendingBeeKEMRemovals: new Map(),
      _prepareChange: prepareChange,
      _publishPreparedChange: publishPreparedChange,
      _enqueueBeeKEMFanout: (operation: () => Promise<void>) => operation(),
    });

    await expect(
      fullDocument._addReaderUnderBeeKEMLock(reader),
    ).rejects.toThrow(/returned an unrepresentable change.*ambiguous/);

    expect(addReaderAcl).toHaveBeenCalledTimes(1);
    expect(prepareChange).not.toHaveBeenCalled();
    expect(publishPreparedChange).not.toHaveBeenCalled();
    expect(fullDocument._pendingBeeKEMAdds.get('reader-undefined-delta')).toEqual(
      expect.objectContaining({ aclAddState: 'started' }),
    );
    expect(fullDocument._securityProviderMutationFailure).toBeInstanceOf(
      Error,
    );
  });

  test('ambiguous removeReader ACL rejection is terminal before tree/key rotation', async () => {
    const { document, founder } = await makeHarness();
    const fullDocument = document as any;
    const reader = { id: 'reader-ambiguous-remove' };
    const readerKeys = await generateKeyPair();
    await registerReader(
      document,
      reader,
      await rawPublicKey(readerKeys.publicKey),
    );
    const rootBefore = await founder.getRootSecret();
    const generationBefore = founder.generation;
    let readerPresent = true;
    const removeReaderAcl = jest.fn(async () => {
      readerPresent = false;
      throw new Error('reader removal mutated before rejection');
    });
    const prepareChange = jest.fn();
    const preparePathUpdate = jest.fn();
    const fanoutDelivery = jest.fn();
    Object.assign(fullDocument, {
      _ensureCurrentUserCanWrite: async () => undefined,
      _readers: {
        check: async () => readerPresent,
        remove: removeReaderAcl,
      },
      _keychain: { prepareEpochKey: jest.fn() },
      _pendingBeeKEMAdds: new Map(),
      _pendingBeeKEMRemovals: new Map(),
      _securityProviderMutationFailure: undefined,
      _writerKeysVersion: 0,
      _writerMutationsInFlight: 0,
      _cachedWriterKeys: null,
      _prepareChange: prepareChange,
      _prepareBeeKEMPathUpdate: preparePathUpdate,
      _fanoutPreparedBeeKEMDelivery: fanoutDelivery,
      close: jest.fn(async () => undefined),
    });

    await expect(
      fullDocument._removeReaderUnderBeeKEMLock(reader),
    ).rejects.toThrow(
      /removeReader\(reader-ambiguous-remove\).*ambiguous.*discard this document/,
    );
    const retirement = fullDocument._securityProviderMutationFailure;
    expect(retirement.cause).toEqual(
      new Error('reader removal mutated before rejection'),
    );
    await expect(
      fullDocument._removeReaderUnderBeeKEMLock(reader),
    ).rejects.toBe(retirement);

    expect(removeReaderAcl).toHaveBeenCalledTimes(1);
    expect(prepareChange).not.toHaveBeenCalled();
    expect(preparePathUpdate).not.toHaveBeenCalled();
    expect(fanoutDelivery).not.toHaveBeenCalled();
    expect(founder.generation).toBe(generationBefore);
    expect(founder.memberCount).toBe(2);
    expect(await founder.getRootSecret()).toEqual(rootBefore);
  });

  test('joined writer fails closed when a pre-existing reader has no identity-to-KEM binding', async () => {
    const { document } = await makeHarness();
    const founderKeys = await generateKeyPair();
    const joinedWriterKeys = await generateKeyPair();
    const founder = new BeeKEM();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
    const { welcome } = await founder.addMember(joinedWriterKeys.publicKey);
    const joinedWriter = new BeeKEM();
    await joinedWriter.processWelcome(
      welcome,
      joinedWriterKeys.privateKey,
      joinedWriterKeys.publicKey,
    );

    const fullDocument = document as any;
    const removeReaderAcl = jest.fn(async () => new Uint8Array([1]));
    Object.assign(fullDocument, {
      _beekem: joinedWriter,
      _beekemInitialized: true,
      _ensureCurrentUserCanWrite: async () => undefined,
      _readers: {
        check: async () => true,
        remove: removeReaderAcl,
      },
      _keychain: { prepareEpochKey: jest.fn() },
      _pendingBeeKEMRemovals: new Map(),
    });
    const generationBefore = joinedWriter.generation;
    const rootBefore = await joinedWriter.getRootSecret();

    await expect(
      fullDocument._removeReaderUnderBeeKEMLock({ id: 'founder' }),
    ).rejects.toThrow(/no BeeKEM leaf recorded.*no KEM public key recorded/);

    expect(removeReaderAcl).not.toHaveBeenCalled();
    expect(joinedWriter.generation).toBe(generationBefore);
    expect(await joinedWriter.getRootSecret()).toEqual(rootBefore);
  });

  test('cache-miss removal fails closed on legacy ambiguous live KEM leaves', async () => {
    const { document, founder } = await makeHarness();
    const fullDocument = document as any;
    const readerKeys = await generateKeyPair();
    const sharedKemPublicKey = await rawPublicKey(readerKeys.publicKey);
    await registerReader(
      document,
      { id: 'reader-a' },
      sharedKemPublicKey,
    );

    const founderInternals = founder as any;
    founderInternals._numLeaves = 3;
    founderInternals._nodes.set(4, {
      type: 'leaf',
      index: 4,
      publicKey: readerKeys.publicKey,
    });
    document._readerLeafIndices.clear();
    document._readerKemPublicKeys.set('reader-c', sharedKemPublicKey);
    const removeReaderAcl = jest.fn(async () => new Uint8Array([1]));
    Object.assign(fullDocument, {
      _ensureCurrentUserCanWrite: async () => undefined,
      _readers: {
        check: async () => true,
        remove: removeReaderAcl,
      },
      _keychain: { prepareEpochKey: jest.fn() },
      _pendingBeeKEMRemovals: new Map(),
    });

    await expect(
      fullDocument._removeReaderUnderBeeKEMLock({ id: 'reader-c' }),
    ).rejects.toThrow(/KEM public key matches multiple live leaves/);

    expect(removeReaderAcl).not.toHaveBeenCalled();
    expect(founder.generation).toBe(1);
    expect(document._readerLeafIndices.has('reader-c')).toBe(false);
  });

  test('failed Welcome/path preparation rolls back membership and retries at the same generation', async () => {
    const { document, founder } = await makeHarness();
    const reader = { id: 'reader-a' };
    const readerKeys = await generateKeyPair();
    const readerKemPublicKey = await rawPublicKey(readerKeys.publicKey);
    const commitFresh = jest
      .fn<(result: any) => Promise<void>>()
      .mockRejectedValueOnce(new Error('injected Welcome sealing failure'))
      .mockResolvedValueOnce();

    await expect(
      (document as any)._registerBeeKEMReaderUnderLock(
        reader,
        readerKemPublicKey,
        commitFresh,
      ),
    ).rejects.toThrow(/injected Welcome sealing failure/);
    expect(founder.generation).toBe(0);
    expect(founder.memberCount).toBe(1);
    expect(document._readerLeafIndices.has(reader.id)).toBe(false);
    expect(document._readerKemPublicKeys.has(reader.id)).toBe(false);

    const retry = await (document as any)._registerBeeKEMReaderUnderLock(
      reader,
      readerKemPublicKey,
      commitFresh,
    );
    expect(retry.welcome?.generation).toBe(1);
    expect(founder.generation).toBe(1);
    expect(founder.memberCount).toBe(2);
    expect(commitFresh).toHaveBeenCalledTimes(2);
  });

  test('a missing leaf-index cache entry is recovered without allocating a duplicate', async () => {
    const { document, founder } = await makeHarness();
    const reader = { id: 'reader-a' };
    const readerKeys = await generateKeyPair();
    const readerKemPublicKey = await rawPublicKey(readerKeys.publicKey);
    const first = await registerReader(
      document,
      reader,
      readerKemPublicKey,
    );

    document._readerLeafIndices.clear();
    const retry = await registerReader(
      document,
      reader,
      readerKemPublicKey,
    );

    expect(retry.welcome).toBe(first.welcome);
    expect(retry.pathUpdate).toBeUndefined();
    expect(document._readerLeafIndices.get(reader.id)).toBe(2);
    expect(founder.memberCount).toBe(2);
    expect(founder.generation).toBe(1);
  });

  test('addReader re-seals and re-sends a cached Welcome at the live generation', async () => {
    const { document, founder } = await makeHarness();
    const fullDocument = document as any;
    const reader = { id: 'reader-a' };
    const readerKeys = await generateKeyPair();
    const readerKemPublicKey = await rawPublicKey(readerKeys.publicKey);
    const initial = await registerReader(
      document,
      reader,
      readerKemPublicKey,
    );
    const generationBeforeRetry = founder.generation;
    const preparedDelivery = {
      protocol: '/test/welcome',
      payload: new Uint8Array([1]),
      label: 'Welcome',
    };
    const prepareWelcome = jest.fn(async () => preparedDelivery);
    const fanoutDelivery = jest.fn(async () => undefined);
    Object.assign(fullDocument, {
      _ensureCurrentUserCanWrite: async () => undefined,
      _readers: {
        check: async () => true,
        add: jest.fn(),
      },
      _keychain: {
        prepareEpochKey: jest.fn(),
      },
      _pendingBeeKEMAdds: new Map(),
      _historyVisibility: 'current_only',
      _prepareBeeKEMWelcome: prepareWelcome,
      _enqueueBeeKEMFanout: (operation: () => Promise<void>) => operation(),
      _fanoutPreparedBeeKEMDelivery: fanoutDelivery,
    });

    const result = await fullDocument._addReaderUnderBeeKEMLock(
      reader,
      readerKemPublicKey,
    );
    await result.fanout;

    expect(prepareWelcome).toHaveBeenCalledWith(
      reader,
      readerKemPublicKey,
      initial.welcome,
    );
    expect(fanoutDelivery).toHaveBeenCalledWith(preparedDelivery);
    expect(founder.generation).toBe(generationBeforeRetry);
    expect(founder.memberCount).toBe(2);
  });

  test('addReader fails closed instead of replaying a stale cached Welcome', async () => {
    const { document, founder } = await makeHarness();
    const fullDocument = document as any;
    const reader = { id: 'reader-a' };
    const readerKeys = await generateKeyPair();
    const readerKemPublicKey = await rawPublicKey(readerKeys.publicKey);
    await registerReader(document, reader, readerKemPublicKey);
    const secondReader = { id: 'reader-b' };
    const secondKeys = await generateKeyPair();
    await registerReader(
      document,
      secondReader,
      await rawPublicKey(secondKeys.publicKey),
    );
    const liveGeneration = founder.generation;
    Object.assign(fullDocument, {
      _ensureCurrentUserCanWrite: async () => undefined,
      _readers: { check: async () => true, add: jest.fn() },
      _keychain: { prepareEpochKey: jest.fn() },
      _pendingBeeKEMAdds: new Map(),
      _historyVisibility: 'current_only',
      _prepareBeeKEMWelcome: jest.fn(),
      _enqueueBeeKEMFanout: jest.fn(),
    });

    await expect(
      fullDocument._addReaderUnderBeeKEMLock(reader, readerKemPublicKey),
    ).rejects.toThrow(/cached Welcome is missing or stale/);
    expect(fullDocument._prepareBeeKEMWelcome).not.toHaveBeenCalled();
    expect(founder.generation).toBe(liveGeneration);
    expect(founder.memberCount).toBe(3);
  });

  test('every add returns the exact next-generation update for existing members', async () => {
    const { document, founder } = await makeHarness();
    const existing = { id: 'reader-a' };
    const existingKeys = await generateKeyPair();
    const first = await registerReader(
      document,
      existing,
      await rawPublicKey(existingKeys.publicKey),
    );
    const existingReplica = new BeeKEM();
    await existingReplica.processWelcome(
      first.welcome!,
      existingKeys.privateKey,
      existingKeys.publicKey,
    );

    const newcomer = { id: 'reader-b' };
    const newcomerKeys = await generateKeyPair();
    const second = await registerReader(
      document,
      newcomer,
      await rawPublicKey(newcomerKeys.publicKey),
    );
    expect(second.pathUpdate?.generation).toBe(2);
    expect(second.rootSecret).toBeDefined();

    await existingReplica.processPathUpdate(second.pathUpdate!);
    const newcomerReplica = new BeeKEM();
    await newcomerReplica.processWelcome(
      second.welcome!,
      newcomerKeys.privateKey,
      newcomerKeys.publicKey,
    );

    expect(await existingReplica.getRootSecret()).toEqual(
      await founder.getRootSecret(),
    );
    expect(await newcomerReplica.getRootSecret()).toEqual(
      await founder.getRootSecret(),
    );
  });
});
