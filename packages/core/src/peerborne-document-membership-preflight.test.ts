import { describe, expect, jest, test } from '@jest/globals';
import type { BeeKEMWelcome } from './beekem/types.js';
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

function fakeDocument(fields: Record<string, unknown>): any {
  return Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath: '/membership-preflight',
    _mutationQueue: {
      run: (operation: () => Promise<unknown>) => operation(),
    },
    _authProvider: {
      serializePublicKey: jest.fn(async (key: unknown) => JSON.stringify(key)),
      deserializePublicKey: jest.fn(async (serialized: string) =>
        JSON.parse(serialized),
      ),
    },
    ...fields,
  });
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

function beekemWelcome(version: 1 | 2 = 1): BeeKEMWelcome {
  const welcome: BeeKEMWelcome = {
    leafIndex: 2,
    pathKeys: [
      {
        nodeIndex: 1,
        publicKey: new Uint8Array([1, 2, 3]),
        encryptedPrivateKey: new Uint8Array([4, 5, 6]),
      },
    ],
    treeNodePublicKeys: [
      { nodeIndex: 0, publicKey: new Uint8Array([7, 8, 9]) },
      { nodeIndex: 3, publicKey: null },
    ],
    treeHash: new Uint8Array([10, 11, 12]),
  };
  if (version === 2) {
    welcome.version = 2;
    welcome.generation = 7;
    welcome.numLeaves = 2;
  }
  return welcome;
}

function corruptWelcome(welcome: BeeKEMWelcome): void {
  welcome.leafIndex = 20;
  welcome.pathKeys[0]!.nodeIndex = 21;
  welcome.pathKeys[0]!.publicKey.fill(21);
  welcome.pathKeys[0]!.encryptedPrivateKey.fill(22);
  welcome.pathKeys.push({
    nodeIndex: 23,
    publicKey: new Uint8Array([23]),
    encryptedPrivateKey: new Uint8Array([23]),
  });
  welcome.treeNodePublicKeys[0]!.nodeIndex = 24;
  welcome.treeNodePublicKeys[0]!.publicKey!.fill(24);
  welcome.treeNodePublicKeys.push({
    nodeIndex: 25,
    publicKey: new Uint8Array([25]),
  });
  welcome.treeHash.fill(26);
  welcome.version = 2;
  welcome.generation = 27;
  welcome.numLeaves = 28;
}

function expectWelcomeFieldPresence(
  actual: BeeKEMWelcome,
  expected: BeeKEMWelcome,
): void {
  for (const field of ['version', 'generation', 'numLeaves'] as const) {
    expect(Object.prototype.hasOwnProperty.call(actual, field)).toBe(
      Object.prototype.hasOwnProperty.call(expected, field),
    );
  }
}

describe('reader membership preflight', () => {
  test('key projection failure precedes ACL and BeeKEM mutation', async () => {
    const readerKemPublicKey = await validKemPublicKey();
    const add = jest.fn();
    const makeChange = jest.fn();
    const prepareBeeKEMReaderRegistration = jest.fn();
    const sendBeeKEMWelcome = jest.fn();
    const document = fakeDocument({
      _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
      _beekemInitialized: true,
      _beekem: {
        memberCount: 1,
        hasLiveLeafWithPublicKey: jest.fn(async () => false),
      },
      _readers: {
        check: jest.fn(async () => false),
        users: jest.fn(async () => []),
        add,
      },
      _keychainChangesForWelcome: jest.fn(async () => {
        throw new Error('Current-key projection is unavailable');
      }),
      _makeChange: makeChange,
      _prepareBeeKEMReaderRegistration: prepareBeeKEMReaderRegistration,
      _sendBeeKEMWelcome: sendBeeKEMWelcome,
    });

    await expect(
      document.addReader({ reader: true }, readerKemPublicKey),
    ).rejects.toThrow(/Current-key projection is unavailable/);
    expect(add).not.toHaveBeenCalled();
    expect(makeChange).not.toHaveBeenCalled();
    expect(prepareBeeKEMReaderRegistration).not.toHaveBeenCalled();
    expect(sendBeeKEMWelcome).not.toHaveBeenCalled();
  });

  test('passes one detached preflight projection to the Welcome sender', async () => {
    const readerKemPublicKey = await validKemPublicKey();
    const reader = { reader: true };
    const serializedProjection = new Uint8Array([1, 2, 3]);
    const welcome = { generation: 1 };
    const keychainChangesForWelcome = jest.fn(async () => ({ key: true }));
    const sendBeeKEMWelcome = jest.fn(async () => undefined);
    const document = fakeDocument({
      _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
      _beekemInitialized: true,
      _beekem: {
        memberCount: 1,
        hasLiveLeafWithPublicKey: jest.fn(async () => false),
      },
      _readers: {
        check: jest.fn(async () => false),
        users: jest.fn(async () => []),
        prepareAdd: jest.fn(async () => ({
          changes: { acl: true },
          claimCommit: () => ({ finalize: () => undefined }),
          commit: jest.fn(),
        })),
      },
      _changesSerializer: {
        serializeChanges: jest.fn(() => serializedProjection),
      },
      _keychainChangesForWelcome: keychainChangesForWelcome,
      _makeChange: jest.fn(async () => {
        serializedProjection.fill(9);
      }),
      _readerPublicationsInFlight: 0,
      _prepareBeeKEMReaderRegistration: jest.fn(async () => ({
        welcome,
        install: () => undefined,
      })),
      _sendBeeKEMWelcome: sendBeeKEMWelcome,
    });

    await expect(document.addReader(reader, readerKemPublicKey)).resolves.toBe(
      welcome,
    );
    expect(keychainChangesForWelcome).toHaveBeenCalledTimes(1);
    expect(sendBeeKEMWelcome).toHaveBeenCalledWith(
      reader,
      readerKemPublicKey,
      welcome,
      new Uint8Array([1, 2, 3]),
    );
  });

  test('rejects base64-expanded Welcome capacity before mutation', async () => {
    const readerKemPublicKey = await validKemPublicKey();
    const add = jest.fn();
    const makeChange = jest.fn();
    const prepareBeeKEMReaderRegistration = jest.fn();
    const sendBeeKEMWelcome = jest.fn();
    const document = fakeDocument({
      _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
      _beekemInitialized: true,
      _beekem: {
        memberCount: 1,
        hasLiveLeafWithPublicKey: jest.fn(async () => false),
      },
      _readers: {
        check: jest.fn(async () => false),
        users: jest.fn(async () => []),
        add,
      },
      _changesSerializer: {
        serializeChanges: jest.fn(() => new Uint8Array(900 * 1024)),
      },
      _keychainChangesForWelcome: jest.fn(async () => ({ key: true })),
      _makeChange: makeChange,
      _prepareBeeKEMReaderRegistration: prepareBeeKEMReaderRegistration,
      _sendBeeKEMWelcome: sendBeeKEMWelcome,
    });

    await expect(
      document.addReader({ reader: true }, readerKemPublicKey),
    ).rejects.toThrow(/too large before onboarding/);
    expect(add).not.toHaveBeenCalled();
    expect(makeChange).not.toHaveBeenCalled();
    expect(prepareBeeKEMReaderRegistration).not.toHaveBeenCalled();
    expect(sendBeeKEMWelcome).not.toHaveBeenCalled();
  });

  test('rejects an unsupported replacement before ACL or BeeKEM mutation', async () => {
    const readerKemPublicKey = await validKemPublicKey();
    const add = jest.fn();
    const makeChange = jest.fn();
    const keychainChangesForWelcome = jest.fn();
    const prepareBeeKEMReaderRegistration = jest.fn();
    const sendBeeKEMWelcome = jest.fn();
    const document = fakeDocument({
      _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
      _beekemInitialized: true,
      _beekem: { memberCount: 2 },
      _readers: {
        check: jest.fn(async () => false),
        users: jest.fn(async () => []),
        add,
      },
      _keychainChangesForWelcome: keychainChangesForWelcome,
      _makeChange: makeChange,
      _prepareBeeKEMReaderRegistration: prepareBeeKEMReaderRegistration,
      _sendBeeKEMWelcome: sendBeeKEMWelcome,
    });

    await expect(
      document.addReader({ replacement: true }, readerKemPublicKey),
    ).rejects.toThrow(/replacement readers are not supported/);
    expect(keychainChangesForWelcome).not.toHaveBeenCalled();
    expect(add).not.toHaveBeenCalled();
    expect(makeChange).not.toHaveBeenCalled();
    expect(prepareBeeKEMReaderRegistration).not.toHaveBeenCalled();
    expect(sendBeeKEMWelcome).not.toHaveBeenCalled();
  });

  test('rejects a KEM key already owned by a live leaf before ACL mutation', async () => {
    const readerKemPublicKey = await validKemPublicKey();
    const add = jest.fn();
    const makeChange = jest.fn();
    const keychainChangesForWelcome = jest.fn();
    const prepareBeeKEMReaderRegistration = jest.fn();
    const hasLiveLeafWithPublicKey = jest.fn(async () => true);
    const document = fakeDocument({
      _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
      _beekemInitialized: true,
      _beekem: { memberCount: 1, hasLiveLeafWithPublicKey },
      _readers: {
        check: jest.fn(async () => false),
        users: jest.fn(async () => []),
        add,
      },
      _keychainChangesForWelcome: keychainChangesForWelcome,
      _makeChange: makeChange,
      _prepareBeeKEMReaderRegistration: prepareBeeKEMReaderRegistration,
      _sendBeeKEMWelcome: jest.fn(),
    });

    await expect(
      document.addReader({ reader: true }, readerKemPublicKey),
    ).rejects.toThrow(/already owned by a live BeeKEM leaf/);

    expect(hasLiveLeafWithPublicKey).toHaveBeenCalledWith(
      expect.any(Uint8Array),
    );
    expect(keychainChangesForWelcome).not.toHaveBeenCalled();
    expect(add).not.toHaveBeenCalled();
    expect(makeChange).not.toHaveBeenCalled();
    expect(prepareBeeKEMReaderRegistration).not.toHaveBeenCalled();
  });

  test('rejects the future founder leaf key before initializing or mutating ACL state', async () => {
    const founderKemPublicKey = await validKemPublicKey();
    const add = jest.fn();
    const makeChange = jest.fn();
    const prepareBeeKEMReaderRegistration = jest.fn();
    const document = fakeDocument({
      _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
      _beekemInitialized: false,
      _beekem: null,
      _createdLocally: true,
      _kemKeyPair: {},
      _kemPublicKeyRaw: new Uint8Array(founderKemPublicKey),
      _readers: {
        check: jest.fn(async () => false),
        users: jest.fn(async () => []),
        add,
      },
      _keychainChangesForWelcome: jest.fn(),
      _makeChange: makeChange,
      _prepareBeeKEMReaderRegistration: prepareBeeKEMReaderRegistration,
      _sendBeeKEMWelcome: jest.fn(),
    });

    await expect(
      document.addReader({ reader: true }, founderKemPublicKey),
    ).rejects.toThrow(/matches the founder's BeeKEM leaf/);

    expect(add).not.toHaveBeenCalled();
    expect(makeChange).not.toHaveBeenCalled();
    expect(prepareBeeKEMReaderRegistration).not.toHaveBeenCalled();
    expect(document._keychainChangesForWelcome).not.toHaveBeenCalled();
  });

  test.each([
    ['v1', 1],
    ['v2', 2],
  ] as const)(
    'returns a detached cached %s Welcome on every exact reader retry',
    async (_label, version) => {
      const readerKemPublicKey = await validKemPublicKey();
      const cachedWelcome = beekemWelcome(version);
      const expectedWelcome = beekemWelcome(version);
      const findLeafByPublicKey = jest.fn(async () => 2);
      const addMember = jest.fn();
      const document = fakeDocument({
        _authProvider: {
          serializePublicKey: jest.fn(async () => 'reader'),
        },
        _beekemInitialized: true,
        _beekem: { findLeafByPublicKey, addMember },
        _readerKemPublicKeys: new Map([
          ['reader', new Uint8Array(readerKemPublicKey)],
        ]),
        _readerLeafIndices: new Map([['reader', 2]]),
        _beekemWelcomeByLeaf: new Map([[2, cachedWelcome]]),
      });

      const first = await document._prepareBeeKEMReaderRegistration(
        'reader',
        new Uint8Array(readerKemPublicKey),
      );
      const firstWelcome = first.welcome as BeeKEMWelcome;
      expect(firstWelcome).toEqual(expectedWelcome);
      expect(firstWelcome).not.toBe(cachedWelcome);
      expect(firstWelcome.pathKeys).not.toBe(cachedWelcome.pathKeys);
      expect(firstWelcome.pathKeys[0]!.publicKey).not.toBe(
        cachedWelcome.pathKeys[0]!.publicKey,
      );
      expect(
        firstWelcome.pathKeys[0]!.encryptedPrivateKey,
      ).not.toBe(cachedWelcome.pathKeys[0]!.encryptedPrivateKey);
      expect(firstWelcome.treeNodePublicKeys).not.toBe(
        cachedWelcome.treeNodePublicKeys,
      );
      expect(firstWelcome.treeNodePublicKeys[0]!.publicKey).not.toBe(
        cachedWelcome.treeNodePublicKeys[0]!.publicKey,
      );
      expect(firstWelcome.treeHash).not.toBe(cachedWelcome.treeHash);
      expectWelcomeFieldPresence(firstWelcome, expectedWelcome);

      corruptWelcome(firstWelcome);
      const second = await document._prepareBeeKEMReaderRegistration(
        'reader',
        new Uint8Array(readerKemPublicKey),
      );
      const secondWelcome = second.welcome as BeeKEMWelcome;

      expect(cachedWelcome).toEqual(expectedWelcome);
      expect(secondWelcome).toEqual(expectedWelcome);
      expect(secondWelcome).not.toBe(firstWelcome);
      expect(secondWelcome.pathKeys[0]!.publicKey).not.toBe(
        firstWelcome.pathKeys[0]!.publicKey,
      );
      expect(secondWelcome.treeNodePublicKeys[0]!.publicKey).not.toBe(
        firstWelcome.treeNodePublicKeys[0]!.publicKey,
      );
      expect(secondWelcome.treeHash).not.toBe(firstWelcome.treeHash);
      expectWelcomeFieldPresence(secondWelcome, expectedWelcome);

      expect(findLeafByPublicKey).toHaveBeenCalledTimes(2);
      expect(findLeafByPublicKey).toHaveBeenCalledWith(
        expect.any(Uint8Array),
      );
      expect(addMember).not.toHaveBeenCalled();
    },
  );

  test('detaches a generated Welcome at cache ingress and the recovered-leaf egress', async () => {
    const readerKemPublicKey = await validKemPublicKey();
    const generatedWelcome = beekemWelcome(2);
    const expectedWelcome = beekemWelcome(2);
    const stagedBeeKEM = {
      memberCount: 1,
      addMember: jest.fn(),
      findLeafByPublicKey: jest.fn(async () => 2),
    };
    const liveBeeKEM = {
      memberCount: 1,
      hasLiveLeafWithPublicKey: jest.fn(async () => false),
      clone: jest.fn(() => stagedBeeKEM),
    };
    stagedBeeKEM.addMember.mockImplementation(async () => {
      stagedBeeKEM.memberCount = 2;
      return { welcome: generatedWelcome };
    });
    const document = fakeDocument({
      _beekemInitialized: true,
      _beekem: liveBeeKEM,
      _readerKemPublicKeys: new Map(),
      _readerLeafIndices: new Map(),
      _beekemWelcomeByLeaf: new Map(),
    });

    const prepared = await document._prepareBeeKEMReaderRegistration(
      'reader',
      new Uint8Array(readerKemPublicKey),
    );
    const preparedWelcome = prepared.welcome as BeeKEMWelcome;
    expect(preparedWelcome).toEqual(expectedWelcome);
    expect(preparedWelcome).not.toBe(generatedWelcome);
    expect(preparedWelcome.pathKeys[0]!.publicKey).not.toBe(
      generatedWelcome.pathKeys[0]!.publicKey,
    );
    expect(preparedWelcome.treeNodePublicKeys[0]!.publicKey).not.toBe(
      generatedWelcome.treeNodePublicKeys[0]!.publicKey,
    );
    expect(preparedWelcome.treeHash).not.toBe(generatedWelcome.treeHash);

    corruptWelcome(generatedWelcome);
    corruptWelcome(preparedWelcome);
    prepared.install();

    const cachedWelcome = document._beekemWelcomeByLeaf.get(
      2,
    ) as BeeKEMWelcome;
    expect(cachedWelcome).toEqual(expectedWelcome);
    expect(cachedWelcome).not.toBe(generatedWelcome);
    expect(cachedWelcome.pathKeys[0]!.publicKey).not.toBe(
      generatedWelcome.pathKeys[0]!.publicKey,
    );
    expect(cachedWelcome.pathKeys[0]!.encryptedPrivateKey).not.toBe(
      generatedWelcome.pathKeys[0]!.encryptedPrivateKey,
    );
    expect(cachedWelcome.treeNodePublicKeys[0]!.publicKey).not.toBe(
      generatedWelcome.treeNodePublicKeys[0]!.publicKey,
    );
    expect(cachedWelcome.treeHash).not.toBe(generatedWelcome.treeHash);
    expectWelcomeFieldPresence(cachedWelcome, expectedWelcome);

    document._readerLeafIndices.delete('reader');
    const recovered = await document._prepareBeeKEMReaderRegistration(
      'reader',
      new Uint8Array(readerKemPublicKey),
    );
    const recoveredWelcome = recovered.welcome as BeeKEMWelcome;
    expect(recoveredWelcome).toEqual(expectedWelcome);
    expect(recoveredWelcome).not.toBe(cachedWelcome);
    expectWelcomeFieldPresence(recoveredWelcome, expectedWelcome);

    corruptWelcome(recoveredWelcome);
    expect(cachedWelcome).toEqual(expectedWelcome);
    recovered.install();
    expect(document._readerLeafIndices.get('reader')).toBe(2);
  });

  test('rejects a cached reader leaf that no longer matches the live tree', async () => {
    const readerKemPublicKey = await validKemPublicKey();
    const addMember = jest.fn();
    const document = fakeDocument({
      _authProvider: {
        serializePublicKey: jest.fn(async () => 'reader'),
      },
      _beekemInitialized: true,
      _beekem: {
        findLeafByPublicKey: jest.fn(async () => 4),
        addMember,
      },
      _readerKemPublicKeys: new Map([
        ['reader', new Uint8Array(readerKemPublicKey)],
      ]),
      _readerLeafIndices: new Map([['reader', 2]]),
      _beekemWelcomeByLeaf: new Map([[2, { generation: 1 }]]),
    });

    await expect(
      document._prepareBeeKEMReaderRegistration(
        'reader',
        new Uint8Array(readerKemPublicKey),
      ),
    ).rejects.toThrow(/cached reader leaf does not match the unique live/);

    expect(addMember).not.toHaveBeenCalled();
    expect(document._readerLeafIndices.get('reader')).toBe(2);
    expect(document._readerKemPublicKeys.get('reader')).toEqual(
      readerKemPublicKey,
    );
  });
});
