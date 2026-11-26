import { describe, expect, jest, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem.js';
import type { BeeKEMWelcomeV2 } from './beekem/types.js';
import { assertInitialInvitationBeeKEMWelcomeShape } from './invitation-capacity.js';
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
    _authProvider: {
      serializePublicKey: async (key: unknown) => JSON.stringify(key),
      deserializePublicKey: async (serialized: string) =>
        JSON.parse(serialized),
    },
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

function beekemWelcome(generation = 1): BeeKEMWelcomeV2 {
  const welcome: BeeKEMWelcomeV2 = {
    version: 2 as const,
    generation,
    numLeaves: 2,
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
  return welcome;
}

function corruptWelcome(welcome: BeeKEMWelcomeV2): void {
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
  actual: BeeKEMWelcomeV2,
  expected: BeeKEMWelcomeV2,
): void {
  for (const field of ['version', 'generation', 'numLeaves'] as const) {
    expect(Object.prototype.hasOwnProperty.call(actual, field)).toBe(
      Object.prototype.hasOwnProperty.call(expected, field),
    );
  }
}

describe('reader membership preflight', () => {
  test.each([
    ['refuses a writer without a Welcome-bootstrapped tree', false, false, true],
    ['allows the local founder to seed the tree', false, true, false],
    ['allows a writer whose tree came from a Welcome', true, false, false],
  ] as const)(
    'founder gate %s',
    async (_label, beekemInitialized, createdLocally, rejects) => {
      const readersCheck = jest.fn(async () => {
        throw new Error('stop after the founder gate');
      });
      const document = fakeDocument({
        _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
        _beekemInitialized: beekemInitialized,
        _beekem: beekemInitialized ? { memberCount: 2 } : null,
        _kemKeyPair: { privateKey: {}, publicKey: {} },
        _createdLocally: createdLocally,
        _readers: { check: readersCheck },
      });

      const addition = document._addReaderUnlocked(
        { reader: true },
        JSON.stringify({ reader: true }),
        await validKemPublicKey(),
        false,
      );

      if (rejects) {
        await expect(addition).rejects.toThrow(
          /no BeeKEM tree bootstrapped from a Welcome/,
        );
        expect(readersCheck).not.toHaveBeenCalled();
      } else {
        await expect(addition).rejects.toThrow('stop after the founder gate');
        expect(readersCheck).toHaveBeenCalledTimes(1);
      }
    },
  );

  test('key projection failure precedes a Welcome resend', async () => {
    const readerKemPublicKey = await validKemPublicKey();
    const prepareAdd = jest.fn();
    const makeChange = jest.fn();
    const prepareBeeKEMReaderRegistration = jest.fn();
    const sendBeeKEMWelcome = jest.fn();
    const document = fakeDocument({
      _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
      _beekemInitialized: true,
      _beekem: {
        memberCount: 2,
        hasLiveLeafWithPublicKey: jest.fn(async () => false),
      },
      _readers: {
        check: jest.fn(async () => true),
        users: jest.fn(async () => []),
        prepareAdd,
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
    expect(prepareAdd).not.toHaveBeenCalled();
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
    const install = jest.fn();
    const makeChange = jest.fn();
    const document = fakeDocument({
      _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
      _beekemInitialized: true,
      _beekem: { memberCount: 2 },
      _readers: {
        check: jest.fn(async () => true),
        users: jest.fn(async () => [reader]),
        prepareAdd: jest.fn(),
      },
      _changesSerializer: {
        serializeChanges: jest.fn(() => serializedProjection),
      },
      _keychainChangesForWelcome: keychainChangesForWelcome,
      _makeChange: makeChange,
      _prepareBeeKEMReaderRegistration: jest.fn(async () => {
        serializedProjection.fill(9);
        return { welcome, install };
      }),
      _sendBeeKEMWelcome: sendBeeKEMWelcome,
    });

    await expect(document.addReader(reader, readerKemPublicKey)).resolves.toBe(
      welcome,
    );
    expect(keychainChangesForWelcome).toHaveBeenCalledTimes(1);
    expect(install).toHaveBeenCalledTimes(1);
    expect(makeChange).not.toHaveBeenCalled();
    expect(document._readers.prepareAdd).not.toHaveBeenCalled();
    expect(sendBeeKEMWelcome).toHaveBeenCalledWith(
      reader,
      readerKemPublicKey,
      welcome,
      new Uint8Array([1, 2, 3]),
    );
  });

  test('rejects base64-expanded Welcome capacity before a resend', async () => {
    const readerKemPublicKey = await validKemPublicKey();
    const prepareAdd = jest.fn();
    const makeChange = jest.fn();
    const prepareBeeKEMReaderRegistration = jest.fn();
    const sendBeeKEMWelcome = jest.fn();
    const document = fakeDocument({
      _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
      _beekemInitialized: true,
      _beekem: {
        memberCount: 2,
        hasLiveLeafWithPublicKey: jest.fn(async () => false),
      },
      _readers: {
        check: jest.fn(async () => true),
        users: jest.fn(async () => []),
        prepareAdd,
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
    expect(prepareAdd).not.toHaveBeenCalled();
    expect(makeChange).not.toHaveBeenCalled();
    expect(prepareBeeKEMReaderRegistration).not.toHaveBeenCalled();
    expect(sendBeeKEMWelcome).not.toHaveBeenCalled();
  });

  test('rejects an unsupported replacement before ACL or BeeKEM mutation', async () => {
    const readerKemPublicKey = await validKemPublicKey();
    const prepareAdd = jest.fn();
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
        prepareAdd,
      },
      _keychainChangesForWelcome: keychainChangesForWelcome,
      _makeChange: makeChange,
      _prepareBeeKEMReaderRegistration: prepareBeeKEMReaderRegistration,
      _sendBeeKEMWelcome: sendBeeKEMWelcome,
    });

    await expect(
      document._addReaderUnlocked(
        { replacement: true },
        JSON.stringify({ replacement: true }),
        readerKemPublicKey,
        false,
      ),
    ).rejects.toThrow(/replacement reader can join only after the founder/);
    expect(keychainChangesForWelcome).not.toHaveBeenCalled();
    expect(prepareAdd).not.toHaveBeenCalled();
    expect(makeChange).not.toHaveBeenCalled();
    expect(prepareBeeKEMReaderRegistration).not.toHaveBeenCalled();
    expect(sendBeeKEMWelcome).not.toHaveBeenCalled();
  });

  test('rejects a KEM key already owned by a live leaf before ACL mutation', async () => {
    const readerKemPublicKey = await validKemPublicKey();
    const prepareAdd = jest.fn();
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
        prepareAdd,
      },
      _keychainChangesForWelcome: keychainChangesForWelcome,
      _makeChange: makeChange,
      _prepareBeeKEMReaderRegistration: prepareBeeKEMReaderRegistration,
      _sendBeeKEMWelcome: jest.fn(),
    });

    await expect(
      document._addReaderUnlocked(
        { reader: true },
        JSON.stringify({ reader: true }),
        readerKemPublicKey,
        false,
      ),
    ).rejects.toThrow(/already owned by a live BeeKEM leaf/);

    expect(hasLiveLeafWithPublicKey).toHaveBeenCalledWith(
      expect.any(Uint8Array),
    );
    expect(keychainChangesForWelcome).not.toHaveBeenCalled();
    expect(prepareAdd).not.toHaveBeenCalled();
    expect(makeChange).not.toHaveBeenCalled();
    expect(prepareBeeKEMReaderRegistration).not.toHaveBeenCalled();
  });

  test('rejects the future founder leaf key before initializing or mutating ACL state', async () => {
    const founderKemPublicKey = await validKemPublicKey();
    const prepareAdd = jest.fn();
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
        prepareAdd,
      },
      _keychainChangesForWelcome: jest.fn(),
      _makeChange: makeChange,
      _prepareBeeKEMReaderRegistration: prepareBeeKEMReaderRegistration,
      _sendBeeKEMWelcome: jest.fn(),
    });

    await expect(
      document._addReaderUnlocked(
        { reader: true },
        JSON.stringify({ reader: true }),
        founderKemPublicKey,
        false,
      ),
    ).rejects.toThrow(/matches the founder's BeeKEM leaf/);

    expect(prepareAdd).not.toHaveBeenCalled();
    expect(makeChange).not.toHaveBeenCalled();
    expect(prepareBeeKEMReaderRegistration).not.toHaveBeenCalled();
    expect(document._keychainChangesForWelcome).not.toHaveBeenCalled();
  });

  test.each([1, 7])(
    'returns a detached cached generation %i Welcome on every exact reader retry',
    async (generation) => {
      const readerKemPublicKey = await validKemPublicKey();
      const cachedWelcome = beekemWelcome(generation);
      const expectedWelcome = beekemWelcome(generation);
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
      const firstWelcome = first.welcome as BeeKEMWelcomeV2;
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
      const secondWelcome = second.welcome as BeeKEMWelcomeV2;

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
    const preparedWelcome = prepared.welcome as BeeKEMWelcomeV2;
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
    ) as BeeKEMWelcomeV2;
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
    const recoveredWelcome = recovered.welcome as BeeKEMWelcomeV2;
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

describe('direct reader onboarding', () => {
  test('addReader rejects an identity that is not already a reader before any onboarding work', async () => {
    const readersUsers = jest.fn(async () => []);
    const prepareAdd = jest.fn();
    const keychainChangesForWelcome = jest.fn();
    const prepareBeeKEMReaderRegistration = jest.fn();
    const sendBeeKEMWelcome = jest.fn();
    const document = fakeDocument({
      _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
      _beekemInitialized: false,
      _beekem: null,
      _createdLocally: true,
      _kemKeyPair: undefined,
      _readers: {
        check: jest.fn(async () => false),
        users: readersUsers,
        prepareAdd,
      },
      _keychainChangesForWelcome: keychainChangesForWelcome,
      _prepareBeeKEMReaderRegistration: prepareBeeKEMReaderRegistration,
      _sendBeeKEMWelcome: sendBeeKEMWelcome,
    });

    await expect(
      document.addReader({ reader: true }, await validKemPublicKey()),
    ).rejects.toThrow(
      /cannot onboard a new identity.*createInvitation\(\).*acceptInvitation\(\)/,
    );
    expect(readersUsers).not.toHaveBeenCalled();
    expect(prepareAdd).not.toHaveBeenCalled();
    expect(keychainChangesForWelcome).not.toHaveBeenCalled();
    expect(prepareBeeKEMReaderRegistration).not.toHaveBeenCalled();
    expect(sendBeeKEMWelcome).not.toHaveBeenCalled();
  });
});

describe('revoked founder tree replacement', () => {
  async function kemKeyPair(): Promise<CryptoKeyPair> {
    return (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    )) as CryptoKeyPair;
  }

  async function revokedTree(founder: CryptoKeyPair): Promise<BeeKEM> {
    const tree = new BeeKEM();
    await tree.initialize(founder.privateKey, founder.publicKey);
    const { welcome } = await tree.addMember((await kemKeyPair()).publicKey);
    await tree.removeMember(welcome.leafIndex);
    return tree;
  }

  async function founderDocument(fields: Record<string, unknown> = {}) {
    const founder = await kemKeyPair();
    const tree = await revokedTree(founder);
    const document = fakeDocument({
      _createdLocally: true,
      _beekemInitialized: true,
      _beekem: tree,
      _kemKeyPair: founder,
      _kemPublicKeyRaw: new Uint8Array(
        await crypto.subtle.exportKey('raw', founder.publicKey),
      ),
      _readerKemPublicKeys: new Map(),
      _readerLeafIndices: new Map(),
      _beekemWelcomeByLeaf: new Map(),
      ...fields,
    });
    return { document, tree };
  }

  test('starts a fresh founder-plus-one tree once every remote leaf is revoked', async () => {
    const { document, tree } = await founderDocument();
    expect(tree.memberCount).toBe(2);
    expect(tree.hasOnlyLocalLiveLeaf()).toBe(true);
    expect(document._invitationBeeKEMMemberCount()).toBe(1);

    const replacementKem = await validKemPublicKey();
    const prepared = await document._prepareBeeKEMReaderRegistration(
      'replacement',
      replacementKem,
    );
    const welcome = prepared.welcome as BeeKEMWelcomeV2;
    expect(() =>
      assertInitialInvitationBeeKEMWelcomeShape(welcome),
    ).not.toThrow();
    expect(document._beekem).toBe(tree);

    prepared.install();
    expect(document._beekem).not.toBe(tree);
    expect(document._beekem.memberCount).toBe(2);
    expect(document._beekem.hasOnlyLocalLiveLeaf()).toBe(false);
    expect(await document._beekem.findLeafByPublicKey(replacementKem)).toBe(2);
    expect(document._readerLeafIndices.get('replacement')).toBe(2);
    expect(tree.hasOnlyLocalLiveLeaf()).toBe(true);
  });

  test('rejects the founder KEM key for the replacement leaf', async () => {
    const { document, tree } = await founderDocument();

    await expect(
      document._prepareBeeKEMReaderRegistration(
        'replacement',
        new Uint8Array(document._kemPublicKeyRaw),
      ),
    ).rejects.toThrow(/matches the founder's BeeKEM leaf/);
    expect(document._beekem).toBe(tree);
  });

  test.each([
    ['a replica that did not found the document', { _createdLocally: false }],
    [
      'a retained identity binding',
      { _readerKemPublicKeys: new Map([['removed', new Uint8Array(65)]]) },
    ],
    [
      'a retained leaf binding',
      { _readerLeafIndices: new Map([['removed', 2]]) },
    ],
  ] as const)('keeps the revoked tree for %s', async (_label, fields) => {
    const { document } = await founderDocument(fields);
    expect(document._canReplaceRevokedFounderTree()).toBe(false);
    expect(document._invitationBeeKEMMemberCount()).toBe(2);
  });

  test('keeps a tree whose remote leaf is still live', async () => {
    const founder = await kemKeyPair();
    const tree = new BeeKEM();
    await tree.initialize(founder.privateKey, founder.publicKey);
    await tree.addMember((await kemKeyPair()).publicKey);
    const document = fakeDocument({
      _createdLocally: true,
      _beekemInitialized: true,
      _beekem: tree,
      _readerKemPublicKeys: new Map(),
      _readerLeafIndices: new Map(),
      _beekemWelcomeByLeaf: new Map(),
    });
    expect(document._canReplaceRevokedFounderTree()).toBe(false);
    expect(document._invitationBeeKEMMemberCount()).toBe(2);
  });
});

describe('unaccepted invitation rollback', () => {
  test.each([
    ['an explicit reader', true, new Map()],
    [
      'a recorded KEM binding',
      false,
      new Map([['"claimant"', new Uint8Array(65)]]),
    ],
  ] as const)(
    'demotes and revokes a claimant with %s',
    async (_label, isReader, bindings) => {
      const calls: string[] = [];
      const document = fakeDocument({
        _readers: { check: jest.fn(async () => isReader) },
        _readerKemPublicKeys: bindings,
        removeWriter: jest.fn(async () => {
          calls.push('removeWriter');
        }),
        removeReader: jest.fn(async () => {
          calls.push('removeReader');
        }),
      });

      await document.revokeUnacceptedInvitationMember('claimant');
      expect(calls).toEqual(['removeWriter', 'removeReader']);
    },
  );

  test('leaves a claimant that is no longer a member alone', async () => {
    const removeWriter = jest.fn();
    const removeReader = jest.fn();
    const document = fakeDocument({
      _readers: { check: jest.fn(async () => false) },
      _readerKemPublicKeys: new Map(),
      removeWriter,
      removeReader,
    });

    await document.revokeUnacceptedInvitationMember('claimant');
    expect(removeWriter).not.toHaveBeenCalled();
    expect(removeReader).not.toHaveBeenCalled();
  });
});
