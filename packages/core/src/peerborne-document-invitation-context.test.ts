import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals';
import { PeerborneDocument } from './peerborne-document.js';

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
jest.mock('./ecies.js', () => ({
  ECIES_P256_PUBLIC_KEY_LENGTH: 65,
  eciesOpen: async () => new Uint8Array([1]),
  eciesSeal: async () => new Uint8Array([1]),
  importEciesPublicKey: async () => ({}),
}));
jest.mock('./welcome-sealed-payload.js', () => ({
  decodeWelcomeSealedPayload: () => ({
    keychainChanges: new Uint8Array([1]),
    beekemWelcome: {
      leafIndex: 2,
      pathKeys: [{ nodeIndex: 1 }],
      treeNodePublicKeys: [{ nodeIndex: 0, publicKey: {} }],
      treeHash: new Uint8Array(32),
    },
  }),
  encodeWelcomeSealedPayload: () => new Uint8Array([1]),
}));
jest.mock('./beekem/beekem.js', () => ({
  BeeKEM: class {
    memberCount = 2;
    myLeafIndex = 2;
    async processWelcome() {}
  },
}));

const documentPath = '/invitation-context';
const keyId = new Uint8Array(32).fill(1);

function fakeDocument(fields: Record<string, unknown>): any {
  return Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath,
    ...fields,
  });
}

function bundle() {
  const encryptedBootstrap = new Uint8Array(34);
  encryptedBootstrap.set(keyId);
  encryptedBootstrap[32] = 7;
  encryptedBootstrap[33] = 8;
  return {
    welcomeEpochId: new Uint8Array(keyId),
    sealedWelcome: new Uint8Array([1]),
    encryptedBootstrap,
  };
}

function invitationHarness(
  decoded: Record<string, unknown> = {
    documentId: documentPath,
    signatureContext: 'invitation-bootstrap-v1',
    tips: [],
    signature: 'AQ==',
  },
) {
  const commit = jest.fn();
  const hydrateKeys = jest.fn(async () => [[new Uint8Array(keyId), {}]]);
  const prepareMerge = jest.fn(() => ({
    changes: { delta: 1 },
    keyIds: [new Uint8Array(keyId)],
    currentKeyId: new Uint8Array(keyId),
    hydrateKeys,
    getKey: () => ({}),
    commit,
  }));
  const liveKeychain = {};
  const invitationKeychain = { prepareMerge };
  const verify = jest.fn(async () => true);
  const syncValidated = jest.fn(async () => true);
  const serializer = {
    deserializeSyncMessage: jest.fn(() => decoded),
    serializeSyncMessage: jest.fn(() => new Uint8Array([1])),
  };
  const close = jest.fn(async () => undefined);
  const document = fakeDocument({
    swarm: {
      isPendingInvitationDocument: jest.fn(() => true),
    },
    _mutationQueue: {
      run: (operation: () => Promise<unknown>) => operation(),
    },
    _hashes: new Set(),
    _subscribed: false,
    _compactionInProgress: false,
    _kemKeyPair: { privateKey: {}, publicKey: {} },
    _kemPublicKeyRaw: new Uint8Array(65),
    _keychainProvider: {
      keyIDLength: 32,
      initialize: jest.fn(() => invitationKeychain),
    },
    _keychain: liveKeychain,
    _changesSerializer: {
      deserializeChanges: jest.fn(() => ({ delta: 1 })),
    },
    _authProvider: {
      nonceBits: 1,
      decrypt: jest.fn(async () => new Uint8Array([2])),
      verify,
    },
    _syncMessageSerializer: serializer,
    _syncUnlocked: syncValidated,
    _assertAcceptedInvitationMembership: jest.fn(async () => undefined),
    open: jest.fn(async () => true),
    close,
    _loadInvitationCatchUp: jest.fn(async () => true),
  });
  return {
    close,
    commit,
    document,
    hydrateKeys,
    invitationKeychain,
    liveKeychain,
    prepareMerge,
    serializer,
    syncValidated,
    verify,
  };
}

let consoleSpies: Array<{ mockRestore(): void }>;

beforeEach(() => {
  consoleSpies = [
    jest.spyOn(console, 'warn').mockImplementation(() => undefined),
    jest.spyOn(console, 'error').mockImplementation(() => undefined),
    jest.spyOn(console, 'log').mockImplementation(() => undefined),
  ];
});

afterEach(() => {
  for (const spy of consoleSpies) spy.mockRestore();
});

describe('invitation-bootstrap V1 confinement', () => {
  test('rejects direct bootstrap use outside Peerborne reservation', async () => {
    const harness = invitationHarness();
    harness.document.swarm.isPendingInvitationDocument.mockReturnValue(false);

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).rejects.toThrow('reserved candidate');

    expect(harness.prepareMerge).not.toHaveBeenCalled();
    expect(harness.serializer.deserializeSyncMessage).not.toHaveBeenCalled();
  });

  test('requires transactional merge support before any bootstrap work', async () => {
    const harness = invitationHarness();
    harness.document._keychainProvider.initialize = () => ({});

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).rejects.toThrow('transactional keychain merge support');

    expect(harness.serializer.deserializeSyncMessage).not.toHaveBeenCalled();
    expect(harness.verify).not.toHaveBeenCalled();
    expect(harness.syncValidated).not.toHaveBeenCalled();
  });

  test('requires the provider to return an isolated staging keychain', async () => {
    const harness = invitationHarness();
    harness.document._keychainProvider.initialize = () =>
      harness.liveKeychain;

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).rejects.toThrow('isolated keychain instance');

    expect(harness.prepareMerge).not.toHaveBeenCalled();
    expect(harness.document._keychain).toBe(harness.liveKeychain);
  });

  test.each([
    ['foreign fields', { welcomeEpochId: new Uint8Array(32) }],
    ['the exact document binding', { documentId: undefined }],
    ['the exact document binding', { documentId: '' }],
    ['the exact document binding', { documentId: '/other' }],
    ['required tips', { tips: undefined }],
    ['well-formed tips', { tips: [1] }],
  ])('rejects %s before committing staged state', async (_label, replacement) => {
    const harness = invitationHarness({
      documentId: documentPath,
      signatureContext: 'invitation-bootstrap-v1',
      tips: [],
      signature: 'AQ==',
      ...replacement,
    });

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).rejects.toThrow();

    expect(harness.commit).not.toHaveBeenCalled();
    expect(harness.syncValidated).not.toHaveBeenCalled();
    expect(harness.document._beekem).toBeUndefined();
  });

  test('rejects an invalid issuer signature before committing staged state', async () => {
    const harness = invitationHarness();
    harness.verify.mockResolvedValue(false);

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).rejects.toThrow('signature does not match');

    expect(harness.commit).not.toHaveBeenCalled();
    expect(harness.syncValidated).not.toHaveBeenCalled();
    expect(harness.document._beekem).toBeUndefined();
  });

  test('rejects a wrong-context bootstrap with zero live mutation and permits a corrected retry', async () => {
    const decoded: Record<string, unknown> = {
      documentId: documentPath,
      signatureContext: 'load-response-v3',
      tips: [],
      signature: 'AQ==',
    };
    const harness = invitationHarness(decoded);
    const originalHashes = harness.document._hashes;

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).rejects.toThrow('cross-context');

    expect(harness.commit).not.toHaveBeenCalled();
    expect(harness.verify).not.toHaveBeenCalled();
    expect(harness.syncValidated).not.toHaveBeenCalled();
    expect(harness.document._assertAcceptedInvitationMembership).not.toHaveBeenCalled();
    expect(harness.document._loadInvitationCatchUp).not.toHaveBeenCalled();
    expect(harness.document.open).not.toHaveBeenCalled();
    expect(harness.close).not.toHaveBeenCalled();
    expect(harness.document._keychain).toBe(harness.liveKeychain);
    expect(harness.document._hashes).toBe(originalHashes);
    expect(harness.document._hashes).toEqual(new Set());
    expect(harness.document._beekem).toBeUndefined();
    expect(harness.document._invitationEpoch).toBeUndefined();

    decoded.signatureContext = 'invitation-bootstrap-v1';
    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).resolves.toBeUndefined();

    expect(harness.commit).toHaveBeenCalledTimes(1);
    expect(harness.syncValidated).toHaveBeenCalledTimes(1);
    expect(harness.document._keychain).toBe(harness.invitationKeychain);
    expect(harness.document.open).toHaveBeenCalledTimes(1);
  });

  test('requires the advertised epoch to be the staged current key', async () => {
    const harness = invitationHarness();
    const laterKeyId = new Uint8Array(32).fill(2);
    harness.prepareMerge.mockReturnValue({
      changes: { delta: 1 },
      keyIds: [new Uint8Array(keyId), laterKeyId],
      currentKeyId: laterKeyId,
      hydrateKeys: async () => undefined,
      getKey: () => ({}),
      commit: harness.commit,
    });

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).rejects.toThrow('advertised epoch as the current key');

    expect(harness.commit).not.toHaveBeenCalled();
    expect(harness.verify).not.toHaveBeenCalled();
    expect(harness.syncValidated).not.toHaveBeenCalled();
    expect(harness.document._keychain).toBe(harness.liveKeychain);
    expect(harness.document._beekem).toBeUndefined();
  });

  test('keeps applied bootstrap state disjoint from serializer aliases', async () => {
    const decoded = {
      documentId: documentPath,
      signatureContext: 'invitation-bootstrap-v1',
      changeId: 'cid',
      changes: { kind: 'document', change: { value: 1 } },
      keychainChanges: { delta: 1 },
      tips: [],
      signature: 'AQ==',
    };
    const harness = invitationHarness(decoded);
    harness.verify.mockImplementation(async (raw) => {
      raw.fill(7);
      decoded.changes.change.value = 8;
      decoded.keychainChanges.delta = 8;
      decoded.tips.push('changed');
      return true;
    });
    harness.syncValidated.mockImplementation(async () => {
      harness.document._hashes.add('cid');
      return true;
    });

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).resolves.toBeUndefined();

    expect(harness.commit).toHaveBeenCalledTimes(1);
    expect(harness.syncValidated).toHaveBeenCalledTimes(1);
    const applied = harness.syncValidated.mock.calls[0][0] as typeof decoded;
    expect(applied.changes.change.value).toBe(1);
    expect(applied.keychainChanges).toBeUndefined();
    expect(applied.tips).toEqual([]);
  });

  test('rejects a bootstrap whose serializer mutates signed content', async () => {
    const decoded = {
      documentId: documentPath,
      signatureContext: 'invitation-bootstrap-v1',
      changeId: 'cid',
      changes: { kind: 'document', change: { value: 1 } },
      tips: [],
      signature: 'AQ==',
    };
    const harness = invitationHarness(decoded);
    let serializations = 0;
    harness.serializer.serializeSyncMessage.mockImplementation(
      (message: typeof decoded) => {
        serializations += 1;
        if (serializations === 2 && message.changes) {
          message.changes.change.value = 9;
        }
        return new Uint8Array([1]);
      },
    );

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).rejects.toThrow(/serialization is unstable/);

    expect(harness.commit).not.toHaveBeenCalled();
    expect(harness.syncValidated).not.toHaveBeenCalled();
  });

  test('detaches the bootstrap bundle before asynchronous processing', async () => {
    const mutableBundle = bundle();
    const harness = invitationHarness();
    harness.hydrateKeys.mockImplementation(async () => {
      mutableBundle.welcomeEpochId.fill(9);
      mutableBundle.encryptedBootstrap.fill(9);
      return [[new Uint8Array(keyId), {}]];
    });

    await expect(
      harness.document.acceptInvitationBootstrap(
        mutableBundle,
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).resolves.toBeUndefined();

    expect(harness.commit).toHaveBeenCalledTimes(1);
  });

  test('rejects malformed bundles before staging keychain state', async () => {
    const harness = invitationHarness();
    const malformed = { ...bundle(), extra: true };

    await expect(
      harness.document.acceptInvitationBootstrap(
        malformed,
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).rejects.toThrow('bundle is malformed');

    expect(harness.prepareMerge).not.toHaveBeenCalled();
    expect(harness.commit).not.toHaveBeenCalled();
  });

  test('rejects a malformed signed tree before committing staged state', async () => {
    const harness = invitationHarness({
      documentId: documentPath,
      signatureContext: 'invitation-bootstrap-v1',
      changes: [] as unknown[],
      tips: [],
      signature: 'AQ==',
    });

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).rejects.toThrow();

    expect(harness.commit).not.toHaveBeenCalled();
    expect(harness.syncValidated).not.toHaveBeenCalled();
    expect(harness.document._keychain).toBe(harness.liveKeychain);
    expect(harness.document._beekem).toBeUndefined();
  });

  test('does not expose candidate state when prepared commit fails', async () => {
    const harness = invitationHarness();
    harness.commit.mockImplementation(() => {
      throw new Error('commit conflict');
    });

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).rejects.toThrow('commit conflict');

    expect(harness.syncValidated).not.toHaveBeenCalled();
    expect(harness.document._keychain).toBe(harness.liveKeychain);
    expect(harness.document._beekem).toBeUndefined();
    expect(harness.document.open).not.toHaveBeenCalled();
  });

  test('restores the live keychain and withholds BeeKEM on sync rejection', async () => {
    const harness = invitationHarness();
    harness.syncValidated.mockResolvedValue(false);

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).rejects.toThrow('state was rejected');

    expect(harness.commit).toHaveBeenCalledTimes(1);
    expect(harness.document._keychain).toBe(harness.liveKeychain);
    expect(harness.document._keychain).not.toBe(harness.invitationKeychain);
    expect(harness.document._beekem).toBeUndefined();
    expect(harness.document.open).not.toHaveBeenCalled();
  });

  test('restores the live keychain after a completeness failure', async () => {
    const harness = invitationHarness({
      documentId: documentPath,
      signatureContext: 'invitation-bootstrap-v1',
      changeId: 'cid',
      changes: { kind: 'document', change: { value: 1 } },
      tips: ['cid'],
      signature: 'AQ==',
    });

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).rejects.toThrow('state is incomplete');

    expect(harness.commit).toHaveBeenCalledTimes(1);
    expect(harness.document._keychain).toBe(harness.liveKeychain);
    expect(harness.document._beekem).toBeUndefined();
  });

  test('does not expose staged keys before queued bootstrap application', async () => {
    const harness = invitationHarness();
    const observedKeychains: unknown[] = [];
    harness.document._mutationQueue = {
      run: async (operation: () => Promise<unknown>) => {
        observedKeychains.push(harness.document._keychain);
        return operation();
      },
    };

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).resolves.toBeUndefined();

    expect(observedKeychains).toEqual([harness.liveKeychain]);
    expect(harness.document._keychain).toBe(harness.invitationKeychain);
  });

  test('rechecks fresh-document admission inside the mutation queue', async () => {
    const harness = invitationHarness();
    harness.document._mutationQueue = {
      run: async (operation: () => Promise<unknown>) => {
        harness.document._hashes.add('concurrent-change');
        return operation();
      },
    };

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).rejects.toThrow('state was rejected');

    expect(harness.syncValidated).not.toHaveBeenCalled();
    expect(harness.document._keychain).toBe(harness.liveKeychain);
    expect(harness.document._beekem).toBeUndefined();
  });

  test('suppresses compaction until catch-up and topology checks complete', async () => {
    const harness = invitationHarness();
    const observed: boolean[] = [];
    harness.syncValidated.mockImplementation(async () => {
      observed.push(harness.document._compactionInProgress);
      return true;
    });
    harness.document.open.mockImplementation(async () => {
      observed.push(harness.document._compactionInProgress);
      return true;
    });
    harness.document._loadInvitationCatchUp.mockImplementation(async () => {
      observed.push(harness.document._compactionInProgress);
      return true;
    });
    harness.document._assertAcceptedInvitationMembership.mockImplementation(
      async () => {
        observed.push(harness.document._compactionInProgress);
      },
    );

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).resolves.toBeUndefined();

    expect(observed.length).toBeGreaterThan(0);
    expect(observed.every(Boolean)).toBe(true);
    expect(harness.document._compactionInProgress).toBe(false);
  });

  test('subscribes before catch-up and completes final topology admission before returning', async () => {
    const harness = invitationHarness();
    const order: string[] = [];
    harness.document._assertAcceptedInvitationMembership.mockImplementation(
      async () => {
        order.push('membership');
      },
    );
    harness.document._loadInvitationCatchUp.mockImplementation(async () => {
      order.push('catch-up');
      return true;
    });
    harness.document.open.mockImplementation(async () => {
      order.push('open');
      return true;
    });

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).resolves.toBeUndefined();

    expect(order).toEqual([
      'membership',
      'open',
      'catch-up',
      'membership',
    ]);
  });

  test('closes and discards a reserved candidate after catch-up failure', async () => {
    const harness = invitationHarness();
    harness.document._loadInvitationCatchUp.mockResolvedValue(false);

    await expect(
      harness.document.acceptInvitationBootstrap(
        bundle(),
        {},
        'reader',
        '/ip4/127.0.0.1/tcp/1',
      ),
    ).rejects.toThrow('catch-up load failed');

    expect(harness.document.open).toHaveBeenCalledTimes(1);
    expect(harness.close).toHaveBeenCalledTimes(1);
    expect(harness.document._invitationBootstrapReady).toBe(false);
    expect(harness.document._compactionInProgress).toBe(false);
  });
});
