import { currentLoadResponse, fixtureSerializeChanges, fixedLoadSession, fixtureLoadChallenge, fixtureLoadCommitments, loadSessionFixture, fixtureLoadDigest } from './__testutils__/load-session.js';
import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals';
import { JSONSerializer } from './json-serializer.js';
import { PeerborneDocument } from './peerborne-document.js';
import { MAX_SHARED_PROTOCOL_REQUEST_BYTES } from './utils.js';

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

const documentPath = '/load-context';
const keyId = new Uint8Array(32).fill(1);

function fakeDocument(fields: Record<string, unknown>): any {
  return Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath,
    _mutationQueue: {
      run: (operation: () => Promise<unknown>) => operation(),
    },
    ...fields,
  });
}

function encryptedPayload(): Uint8Array {
  const payload = new Uint8Array(34);
  payload.set(keyId);
  payload[32] = 7;
  payload[33] = 8;
  return payload;
}

function loadStream(response = encryptedPayload()) {
  return {
    send: () => true,
    onDrain: async () => undefined,
    close: async () => undefined,
    [Symbol.asyncIterator]: async function* () {
      yield response;
    },
  };
}

function tipStream(response = encryptedPayload()) {
  return {
    send: jest.fn(() => true),
    onDrain: jest.fn(async () => undefined),
    close: jest.fn(async () => undefined),
    closeRead: jest.fn(async () => undefined),
    abort: jest.fn(),
    async *[Symbol.asyncIterator]() {
      yield response;
    },
  };
}

function loadHarness(
  decoded: Record<string, unknown> = {
    documentId: documentPath,
    signatureContext: 'load-response-v4',
    tips: [],
    signature: 'AQ==',
  },
) {
  const serializer = new JSONSerializer<any>();
  const verify = jest.fn(async () => true);
  const syncUnlocked = jest.fn(async () => true);
  const deserializeSyncMessage = jest.fn(() => currentLoadResponse(decoded, decoded.signatureContext as string));
  const document = fakeDocument({
    swarm: { config: {} },
    _writerKeysVersion: 4,
    _writerMutationsInFlight: 0,
    _getWriterKeys: async () => [{}],
    _keychainProvider: { keyIDLength: 32 },
    _changesSerializer: { serializeChanges: fixtureSerializeChanges },
    _authProvider: {
      nonceBytes: 1,
      serializePublicKey: async () => 'fixture-writer',
      deserializePublicKey: async () => ({}),
      decrypt: async () => new Uint8Array([1]),
      verify,
    },
    _keychain: { getKey: () => ({}) },
    _syncMessageSerializer: {
      deserializeSyncMessage,
      serializeSyncMessage: serializer.serializeSyncMessage.bind(serializer),
    },
    _isSigningEnabled: () => true,
    _syncUnlocked: syncUnlocked,
  });
  return { deserializeSyncMessage, document, serializer, syncUnlocked, verify };
}

function tipHarness(
  decoded: Record<string, unknown> = {
    documentId: documentPath,
    signatureContext: 'security-advertisement-v1',
    tipsHash: new Uint8Array(32).fill(5),
    signature: 'AQ==',
  },
) {
  const serializer = new JSONSerializer<any>();
  const verify = jest.fn(async () => true);
  const rawStream = tipStream();
  const deserializeSyncMessage = jest.fn(() => currentLoadResponse(decoded, decoded.signatureContext as string));
  const document = fakeDocument({
    _writerKeysVersion: 3,
    _writerMutationsInFlight: 0,
    _getWriterKeys: async () => [{}],
    swarm: {
      heliaNode: {
        libp2p: { dialProtocol: jest.fn(async () => rawStream) },
      },
    },
    _keychainProvider: { keyIDLength: 32 },
    _changesSerializer: { serializeChanges: fixtureSerializeChanges },
    _keychain: { getKey: jest.fn(() => ({})) },
    _authProvider: {
      nonceBytes: 1,
      serializePublicKey: async () => 'fixture-writer',
      deserializePublicKey: async () => ({}),
      decrypt: jest.fn(async () => new Uint8Array([1])),
      verify,
    },
    _syncMessageSerializer: {
      deserializeSyncMessage,
      serializeSyncMessage: serializer.serializeSyncMessage.bind(serializer),
    },
    _isSigningEnabled: () => true,
  });
  return { deserializeSyncMessage, document, rawStream, serializer, verify };
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

test('request serialization cannot replace the captured freshness challenge', async () => {
  const { document } = loadHarness();
  const session = fixedLoadSession(document);
  document._authProvider.sign = async () => new Uint8Array([1]);
  document._loadMessageSerializer = { serializeLoadRequest: (request: any) => {
    request.loadChallenge.fill(0);
    return new Uint8Array([1]);
  } };
  await expect(document._serializeInitialLoadRequest(session)).rejects.toThrow(/changed during serialization/);
  expect(session.challenge).toEqual(fixtureLoadChallenge());
});

test('signs initial load requests when ordinary signing is disabled', async () => {
  const { document } = loadHarness();
  document._isSigningEnabled = () => false;
  const session = fixedLoadSession(document);
  const sign = jest.fn(async () => new Uint8Array([1]));
  document._authProvider.sign = sign;
  document._loadMessageSerializer = {
    serializeLoadRequest: () => new Uint8Array([2]),
  };

  await expect(document._serializeInitialLoadRequest(session)).resolves.toEqual(
    new Uint8Array([2]),
  );
  expect(sign).toHaveBeenCalledTimes(1);
});

describe('load-response V4 confinement', () => {
  test.each([
    ['a foreign field', { welcomeEpochId: new Uint8Array(32) }],
    ['the current challenge', { loadChallenge: new Uint8Array(32).fill(9) }],
    ['the trusted security tuple', { loadSecurityState: { ...fixtureLoadCommitments(), epoch: 2n } }],
    ['the required tips', { tips: undefined }],
    ['well-formed tips', { tips: [1] }],
    ['an exact document ID', { documentId: undefined }],
    ['an exact document ID', { documentId: '' }],
    ['an exact document ID', { documentId: '/other' }],
  ])('rejects a response without %s before sync', async (_label, replacement) => {
    const harness = loadHarness({
      documentId: documentPath,
      signatureContext: 'load-response-v4',
      tips: [],
      signature: 'AQ==',
      ...replacement,
    });

    await expect(
      harness.document._sendLoadRequestAndSync(fixedLoadSession(harness.document), loadStream(), new Uint8Array([1])),
    ).resolves.toBe(false);

    expect(harness.syncUnlocked).not.toHaveBeenCalled();
  });

  test('detaches nested state before deferred verification', async () => {
    const decoded = {
      documentId: documentPath,
      signatureContext: 'load-response-v4',
      changes: { kind: 'document', change: { value: 1 } },
      snapshot: {
        state: { value: 2 },
        lastChangeNodeCID: 'cid',
        compactedCount: 1,
        signature: new Uint8Array([3]),
        timestamp: 4,
      },
      keychainChanges: { delta: 5 },
      tips: ['cid'],
      signature: 'AQ==',
    };
    const harness = loadHarness(decoded);
    harness.verify.mockImplementation(async (raw) => {
      raw.fill(7);
      decoded.changes.change.value = 9;
      decoded.snapshot.state.value = 9;
      decoded.keychainChanges.delta = 9;
      decoded.tips[0] = 'changed';
      return true;
    });

    await expect(
      harness.document._sendLoadRequestAndSync(fixedLoadSession(harness.document), loadStream(), new Uint8Array([1])),
    ).resolves.toBe(true);

    const applied = harness.syncUnlocked.mock.calls[0][0] as typeof decoded;
    expect(applied.changes.change.value).toBe(1);
    expect(applied.snapshot.state.value).toBe(2);
    expect(applied.keychainChanges.delta).toBe(5);
    expect(applied.tips).toEqual(['cid']);
  });

  test('isolates manifest serializers from the authenticated response applied to state', async () => {
    const decoded = {
      documentId: documentPath, signatureContext: 'load-response-v4',
      changeId: 'cid', changes: { kind: 'document', change: { value: 1 } },
      tips: ['cid'], signature: 'AQ==',
    };
    const harness = loadHarness(decoded);
    harness.document._changesSerializer.serializeChanges = (change: any) => {
      const bytes = fixtureSerializeChanges(change);
      change.value = 99;
      return bytes;
    };
    await expect(harness.document._sendLoadRequestAndSync(
      fixedLoadSession(harness.document), loadStream(), new Uint8Array([1]),
    )).resolves.toBe(true);
    expect((harness.syncUnlocked.mock.calls[0][0] as any).changes.change.value).toBe(1);
    expect(decoded.changes.change.value).toBe(1);
  });

  test('rejects a response whose serializer mutates signed content', async () => {
    const decoded = {
      documentId: documentPath,
      signatureContext: 'load-response-v4',
      changes: { kind: 'document', change: { value: 1 } },
      tips: [],
      signature: 'AQ==',
    };
    const harness = loadHarness(decoded);
    let serializations = 0;
    harness.document._syncMessageSerializer.serializeSyncMessage = (
      message: typeof decoded,
    ) => {
      serializations += 1;
      if (serializations === 2 && message.changes) {
        message.changes.change.value = 9;
      }
      return new Uint8Array([1]);
    };

    await expect(
      harness.document._sendLoadRequestAndSync(fixedLoadSession(harness.document), loadStream(), new Uint8Array([1])),
    ).resolves.toBe(false);

    expect(harness.syncUnlocked).not.toHaveBeenCalled();
  });

  test('skips a response without a signature before verification', async () => {
    const harness = loadHarness({
      documentId: documentPath,
      signatureContext: 'load-response-v4',
      tips: [],
    });

    await expect(
      harness.document._sendLoadRequestAndSync(
        fixedLoadSession(harness.document),
        loadStream(),
        new Uint8Array([1]),
      ),
    ).resolves.toBe(false);
    expect(harness.verify).not.toHaveBeenCalled();
    expect(harness.syncUnlocked).not.toHaveBeenCalled();
  });

  test('skips a response whose signature cannot be decoded', async () => {
    const harness = loadHarness();
    harness.document._deserializeSignature = () => {
      throw new TypeError('malformed signature encoding');
    };

    await expect(
      harness.document._sendLoadRequestAndSync(
        fixedLoadSession(harness.document),
        loadStream(),
        new Uint8Array([1]),
      ),
    ).resolves.toBe(false);
    expect(harness.verify).not.toHaveBeenCalled();
    expect(harness.syncUnlocked).not.toHaveBeenCalled();
  });

  test('rejects a response when writer authorization changes during verification', async () => {
    const harness = loadHarness();
    harness.verify.mockImplementation(async () => {
      harness.document._writerKeysVersion += 1;
      return true;
    });

    await expect(
      harness.document._sendLoadRequestAndSync(
        fixedLoadSession(harness.document),
        loadStream(),
        new Uint8Array([1]),
      ),
    ).rejects.toThrow('Writer authorization changed before load application');

    expect(harness.syncUnlocked).not.toHaveBeenCalled();
  });

  test('rechecks writer authorization inside the queued apply', async () => {
    const harness = loadHarness();
    harness.document._mutationQueue = {
      run: async (operation: () => Promise<unknown>) => {
        harness.document._writerKeysVersion += 1;
        return operation();
      },
    };

    await expect(
      harness.document._sendLoadRequestAndSync(
        fixedLoadSession(harness.document),
        loadStream(),
        new Uint8Array([1]),
      ),
    ).rejects.toThrow('Writer authorization changed before load application');

    expect(harness.syncUnlocked).not.toHaveBeenCalled();
  });

  test('rejects queued apply while a writer mutation is in flight', async () => {
    const harness = loadHarness();
    harness.document._mutationQueue = {
      run: async (operation: () => Promise<unknown>) => {
        harness.document._writerMutationsInFlight = 1;
        return operation();
      },
    };

    await expect(
      harness.document._sendLoadRequestAndSync(
        fixedLoadSession(harness.document),
        loadStream(),
        new Uint8Array([1]),
      ),
    ).rejects.toThrow('Writer authorization changed before load application');

    expect(harness.syncUnlocked).not.toHaveBeenCalled();
  });

  test('rejects malformed provider plaintext before deserialization', async () => {
    const harness = loadHarness();
    harness.document._authProvider.decrypt = async () => new Uint8Array(0);

    await expect(
      harness.document._sendLoadRequestAndSync(fixedLoadSession(harness.document), loadStream(), new Uint8Array([1])),
    ).resolves.toBe(false);

    expect(harness.deserializeSyncMessage).not.toHaveBeenCalled();
    expect(harness.syncUnlocked).not.toHaveBeenCalled();
  });

  test('enforces the caller-specific response limit after decryption', async () => {
    const harness = loadHarness();
    harness.document._authProvider.decrypt = async () => new Uint8Array(65);

    await expect(
      harness.document._sendLoadRequestAndSync(fixedLoadSession(harness.document), loadStream(), new Uint8Array([1]), null, 64),
    ).resolves.toBe(false);

    expect(harness.deserializeSyncMessage).not.toHaveBeenCalled();
    expect(harness.syncUnlocked).not.toHaveBeenCalled();
  });

  test('rejects invalid provider framing before decryption', async () => {
    const harness = loadHarness();
    const decrypt = jest.fn();
    harness.document._authProvider.decrypt = decrypt;
    harness.document._authProvider.nonceBytes = 0;

    await expect(
      harness.document._sendLoadRequestAndSync(fixedLoadSession(harness.document), loadStream(), new Uint8Array([1])),
    ).resolves.toBe(false);

    expect(decrypt).not.toHaveBeenCalled();
    expect(harness.deserializeSyncMessage).not.toHaveBeenCalled();
  });

  test('bounds encrypted responses before decryption', async () => {
    const harness = loadHarness();
    const oversizedStream = loadStream(
      new Uint8Array(MAX_SHARED_PROTOCOL_REQUEST_BYTES + 1),
    );

    await expect(
      harness.document._sendLoadRequestAndSync(fixedLoadSession(harness.document), oversizedStream, new Uint8Array([1])),
    ).rejects.toThrow(/maximum allowed size/);

    expect(harness.deserializeSyncMessage).not.toHaveBeenCalled();
  });
});

describe('security-advertisement V1 confinement', () => {
  test.each([
    ['a foreign field', { tips: [] }],
    ['the current challenge', { loadChallenge: new Uint8Array(32).fill(9) }],
    ['the trusted security tuple', { loadSecurityState: { ...fixtureLoadCommitments(), epoch: 2n } }],
    ['an exact document ID', { documentId: undefined }],
    ['an exact document ID', { documentId: '' }],
    ['an exact document ID', { documentId: '/other' }],
    ['an exact hash', { tipsHash: new Uint8Array(31) }],
  ])('rejects a response without %s', async (_label, replacement) => {
    const harness = tipHarness({
      documentId: documentPath,
      signatureContext: 'security-advertisement-v1',
      tipsHash: new Uint8Array(32).fill(5),
      signature: 'AQ==',
      ...replacement,
    });

    await expect(
      harness.document._probeSecurityAdvertise(fixedLoadSession(harness.document), { toString: () => '/peer/one' }, new Uint8Array([1])),
    ).resolves.toBeNull();
  });

  test('returns a detached hash across deferred verification', async () => {
    const advertised = new Uint8Array(32).fill(5);
    const expected = new Uint8Array(advertised);
    const harness = tipHarness({
      documentId: documentPath,
      signatureContext: 'security-advertisement-v1',
      tipsHash: advertised,
      signature: 'AQ==',
    });
    harness.verify.mockImplementation(async (raw) => {
      raw.fill(7);
      advertised.fill(9);
      return true;
    });

    await expect(
      harness.document._probeSecurityAdvertise(fixedLoadSession(harness.document), { toString: () => '/peer/one' }, new Uint8Array([1])),
    ).resolves.toEqual({ hash: expected, signerAuthority: 'fixture-writer' });
  });

  test('rejects a vote whose serializer mutates signed content', async () => {
    const decoded = {
      documentId: documentPath,
      signatureContext: 'security-advertisement-v1',
      tipsHash: new Uint8Array(32).fill(5),
      signature: 'AQ==',
    };
    const harness = tipHarness(decoded);
    let serializations = 0;
    harness.document._syncMessageSerializer.serializeSyncMessage = (
      message: typeof decoded,
    ) => {
      serializations += 1;
      if (serializations === 2) message.tipsHash.fill(9);
      return new Uint8Array([1]);
    };

    await expect(
      harness.document._probeSecurityAdvertise(fixedLoadSession(harness.document), { toString: () => '/peer/one' }, new Uint8Array([1])),
    ).resolves.toBeNull();
  });

  test('invalidates a vote when writer authorization changes', async () => {
    const harness = tipHarness();
    harness.verify.mockImplementation(async () => {
      harness.document._writerKeysVersion += 1;
      return true;
    });

    await expect(
      harness.document._probeSecurityAdvertise(fixedLoadSession(harness.document), { toString: () => '/peer/one' }, new Uint8Array([1])),
    ).resolves.toBeNull();
  });

  test('captures writer authorization before resolving writer keys', async () => {
    const harness = tipHarness();
    harness.document.swarm.resolveLoadSecurityCommitments = fixtureLoadCommitments;
    harness.document._getWriterKeys = async () => {
      harness.document._writerKeysVersion += 1;
      return [{}];
    };

    await expect(
      harness.document._captureLoadSession(),
    ).rejects.toThrow(/Writer authorization changed/);
  });

  test('rejects a vote while a writer mutation is in flight', async () => {
    const harness = tipHarness();
    harness.document._writerMutationsInFlight = 1;

    await expect(
      harness.document._probeSecurityAdvertise(fixedLoadSession(harness.document), { toString: () => '/peer/one' }, new Uint8Array([1])),
    ).resolves.toBeNull();

    expect(harness.verify).not.toHaveBeenCalled();
  });

  test('rejects a vote when a writer mutation starts during key lookup', async () => {
    const harness = tipHarness();
    harness.document.swarm.resolveLoadSecurityCommitments = fixtureLoadCommitments;
    harness.document._getWriterKeys = async () => {
      harness.document._writerMutationsInFlight = 1;
      return [{}];
    };

    await expect(
      harness.document._captureLoadSession(),
    ).rejects.toThrow(/Writer authorization changed/);

    expect(harness.verify).not.toHaveBeenCalled();
  });

  test('rejects malformed provider plaintext before deserialization', async () => {
    const harness = tipHarness();
    harness.document._authProvider.decrypt = async () => new Uint8Array(0);

    await expect(
      harness.document._probeSecurityAdvertise(fixedLoadSession(harness.document), { toString: () => '/peer/one' }, new Uint8Array([1])),
    ).resolves.toBeNull();

    expect(harness.deserializeSyncMessage).not.toHaveBeenCalled();
  });

  test('rejects invalid provider framing before decryption', async () => {
    const harness = tipHarness();
    harness.document._authProvider.nonceBytes = 0;

    await expect(
      harness.document._probeSecurityAdvertise(fixedLoadSession(harness.document), { toString: () => '/peer/one' }, new Uint8Array([1])),
    ).resolves.toBeNull();

    expect(harness.document._authProvider.decrypt).not.toHaveBeenCalled();
    expect(harness.deserializeSyncMessage).not.toHaveBeenCalled();
  });
});

function installSetWriterAcl(document: any, initial: string[]) {
  const writers = new Set(initial);
  document._writers = {
    merge: jest.fn((changes: string[]) => {
      const size = writers.size;
      for (const writer of changes) writers.add(writer);
      return writers.size !== size;
    }),
    current: jest.fn(() => [...writers].sort()),
  };
  document._changesSerializer = new JSONSerializer<any>();
  document._cachedWriterKeys = [{}];
  return writers;
}

function writerDocument(initial: string[]) {
  const document = fakeDocument({
    _writerKeysVersion: 7,
    _writerMutationsInFlight: 0,
  });
  const writers = installSetWriterAcl(document, initial);
  return { document, writers };
}

function sessionWithAuthorities(document: any, writers: readonly unknown[]) {
  return {
    ...fixedLoadSession(document),
    authorities: writers.map((publicKey, index) => ({
      authorityId: `fixture-writer-${index}`,
      publicKey,
    })),
  };
}

describe('security-advertisement writer verification', () => {
  test('verifies each authority sequentially with detached copies', async () => {
    const harness = tipHarness();
    const writers = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
    harness.verify
      .mockImplementationOnce(async () => false)
      .mockImplementationOnce(async () => true)
      .mockImplementationOnce(async () => false);

    await expect(
      harness.document._probeSecurityAdvertise(
        sessionWithAuthorities(harness.document, writers),
        { toString: () => '/peer/one' },
        new Uint8Array([1]),
      ),
    ).resolves.toEqual({
      hash: new Uint8Array(32).fill(5),
      signerAuthority: 'fixture-writer-1',
    });

    expect(harness.verify.mock.calls.map((call: any[]) => call[1])).toEqual(
      writers,
    );
    const [first, second] = harness.verify.mock.calls as any[];
    expect(first[0]).not.toBe(second[0]);
    expect(first[2]).not.toBe(second[2]);
  });

  test('rejects the vote when no writer signed it', async () => {
    const harness = tipHarness();
    harness.verify.mockImplementation(async () => false);

    await expect(
      harness.document._probeSecurityAdvertise(
        sessionWithAuthorities(harness.document, [{}, {}]),
        { toString: () => '/peer/one' },
        new Uint8Array([1]),
      ),
    ).resolves.toBeNull();
    expect(harness.verify).toHaveBeenCalledTimes(2);
  });
});

describe('writer ACL re-merges', () => {
  test('keeps writer authorization stable when a merge changes nothing', async () => {
    const { document } = writerDocument(['founder', 'invitee']);

    await document._mergeWriters(['founder']);
    await document._mergeWriters(['invitee', 'founder']);

    expect(document._writers.merge).toHaveBeenCalledTimes(2);
    expect(document._writerKeysVersion).toBe(7);
    expect(document._writerMutationsInFlight).toBe(0);
    expect(document._cachedWriterKeys).not.toBeNull();
  });

  test('never serializes the ACL to classify a merge', async () => {
    const { document } = writerDocument(['founder']);
    const serialize = jest.spyOn(
      document._changesSerializer,
      'serializeChanges',
    );

    await document._mergeWriters(['founder']);
    await document._mergeWriters(['invitee']);

    expect(document._writers.current).not.toHaveBeenCalled();
    expect(serialize).not.toHaveBeenCalled();
  });

  test('invalidates writer authorization when a merge changes the ACL', async () => {
    const { document } = writerDocument(['founder']);

    await document._mergeWriters(['invitee']);

    expect(document._writerKeysVersion).toBe(8);
    expect(document._cachedWriterKeys).toBeNull();
  });

  test.each([
    ['nothing', undefined],
    ['true', true],
    ['a non-boolean', 0],
  ])(
    'invalidates writer authorization when merge returns %s',
    async (_label, result) => {
      const { document } = writerDocument(['founder']);
      document._writers.merge = jest.fn(() => result);

      await document._mergeWriters(['founder']);

      expect(document._writerKeysVersion).toBe(8);
      expect(document._cachedWriterKeys).toBeNull();
    },
  );

  test('invalidates writer authorization when a merge throws after mutating', async () => {
    const { document, writers } = writerDocument(['founder']);
    document._writers.merge = () => {
      writers.add('partial');
      throw new Error('merge failed');
    };

    await expect(document._mergeWriters(['partial', 'bad'])).rejects.toThrow(
      'merge failed',
    );
    expect(document._writerKeysVersion).toBe(8);
    expect(document._writerMutationsInFlight).toBe(0);
  });

  test('applies a load response after a queued gossip re-merge of known writers', async () => {
    const harness = loadHarness();
    installSetWriterAcl(harness.document, ['founder', 'invitee']);
    harness.document._mutationQueue = {
      run: async (operation: () => Promise<unknown>) => {
        await harness.document._applyCollectedACL([
          { kind: 'writer', change: ['founder'] },
          { kind: 'writer', change: ['invitee'] },
        ]);
        return operation();
      },
    };

    await expect(
      harness.document._sendLoadRequestAndSync(
        fixedLoadSession(harness.document),
        loadStream(),
        new Uint8Array([1]),
      ),
    ).resolves.toBe(true);

    expect(harness.syncUnlocked).toHaveBeenCalledTimes(1);
  });

  test('reports a writer conflict when a queued merge adds a writer', async () => {
    const harness = loadHarness();
    installSetWriterAcl(harness.document, ['founder']);
    harness.document._mutationQueue = {
      run: async (operation: () => Promise<unknown>) => {
        await harness.document._applyCollectedACL([
          { kind: 'writer', change: ['intruder'] },
        ]);
        return operation();
      },
    };

    await expect(
      harness.document._sendLoadRequestAndSync(
        fixedLoadSession(harness.document),
        loadStream(),
        new Uint8Array([1]),
      ),
    ).rejects.toThrow('Writer authorization changed before load application');

    expect(harness.syncUnlocked).not.toHaveBeenCalled();
  });

  test('keeps a security vote when verification races an unchanged re-merge', async () => {
    const harness = tipHarness();
    installSetWriterAcl(harness.document, ['founder']);
    harness.verify.mockImplementation(async () => {
      await harness.document._mergeWriters(['founder']);
      return true;
    });

    await expect(
      harness.document._probeSecurityAdvertise(
        fixedLoadSession(harness.document),
        { toString: () => '/peer/one' },
        new Uint8Array([1]),
      ),
    ).resolves.toEqual({
      hash: new Uint8Array(32).fill(5),
      signerAuthority: 'fixture-writer',
    });
  });
});

describe('load writer conflicts', () => {
  type Outcome = boolean | 'conflict';

  function loadLoopHarness(outcomes: Outcome[], peers = ['/p2p/one']) {
    const document = fakeDocument({
      swarm: {
        config: { loadQuorumEnabled: false },
        heliaNode: {
          libp2p: {
            getConnections: () =>
              peers.map((peer) => ({ remoteAddr: { toString: () => peer } })),
            dialProtocol: jest.fn(async () => ({})),
          },
        },
      },
      _writerKeysVersion: 2,
      _writerMutationsInFlight: 0,
      _compactionConfig: { enabled: true },
    });
    document._captureLoadSession = async () => fixedLoadSession(document);
    document._serializeInitialLoadRequest = async () => new Uint8Array([1]);
    const attempts: string[] = [];
    document._sendLoadRequestAndSync = jest.fn(async () => {
      const outcome = outcomes.shift() ?? false;
      attempts.push(String(outcome));
      if (outcome !== 'conflict') return outcome;
      return document._syncValidatedProtocolMessage(
        {},
        'load-response-v4',
        document._writerKeysVersion - 1,
      );
    });
    return { attempts, document };
  }

  test('surfaces a conflict instead of reporting that no peer served', async () => {
    const { attempts, document } = loadLoopHarness(['conflict', 'conflict']);

    await expect(document.load()).rejects.toThrow(
      'Writer authorization changed before load application',
    );
    expect(attempts).toEqual(['conflict', 'conflict']);
  });

  test('falls back to doc-load after a snapshot-load conflict', async () => {
    const { attempts, document } = loadLoopHarness(['conflict', true]);

    await expect(document.load()).resolves.toBe(true);
    expect(attempts).toEqual(['conflict', 'true']);
  });

  test('loads from a later peer after a conflict', async () => {
    const { document } = loadLoopHarness(
      ['conflict', 'conflict', false, true],
      ['/p2p/one', '/p2p/two'],
    );

    await expect(document.load()).resolves.toBe(true);
  });

  test('still reports a genuine miss as an unserved document', async () => {
    const { attempts, document } = loadLoopHarness([false, false]);

    await expect(document.load()).resolves.toBe(false);
    expect(attempts).toEqual(['false', 'false']);
  });
});

describe('load connection handling', () => {
  const aliceDirect = '/ip4/10.0.0.1/tcp/1/p2p/alice';
  const aliceRelayed = '/ip4/10.0.0.2/tcp/1/p2p/relay/p2p-circuit/p2p/alice';
  const bob = '/ip4/10.0.0.3/tcp/1/p2p/bob';

  function connectionHarness(
    peers: string[],
    config: Record<string, unknown>,
  ) {
    const document = fakeDocument({
      swarm: {
        config,
        heliaNode: {
          libp2p: {
            getConnections: () =>
              peers.map((peer) => ({ remoteAddr: { toString: () => peer } })),
            dialProtocol: jest.fn(async (peer: { toString(): string }) => ({
              peer: peer.toString(),
            })),
          },
        },
      },
      _writerKeysVersion: 2,
      _writerMutationsInFlight: 0,
      _compactionConfig: { enabled: false },
    });
    document._captureLoadSession = async () => fixedLoadSession(document);
    document._serializeInitialLoadRequest = async () => new Uint8Array([1]);
    return document;
  }

  test('tries every connection to one peer when quorum is disabled', async () => {
    const document = connectionHarness([aliceDirect, aliceRelayed], {
      loadQuorumEnabled: false,
    });
    const attempts: string[] = [];
    document._sendLoadRequestAndSync = jest.fn(
      async (_session: unknown, stream: { peer: string }) => {
        attempts.push(stream.peer);
        return attempts.length > 1;
      },
    );

    await expect(document.load()).resolves.toBe(true);
    expect(new Set(attempts)).toEqual(new Set([aliceDirect, aliceRelayed]));
  });

  test('probes each peer id once when quorum is enabled', async () => {
    const document = connectionHarness([aliceDirect, aliceRelayed, bob], {
      loadQuorumK: 2,
      loadQuorumQ: 2,
    });
    const probed: string[] = [];
    document._raceSecurityAdvertiseProbe = jest.fn(
      async (_session: unknown, peer: { toString(): string }) => {
        const peerId = document._peerIdOf(peer);
        probed.push(peerId);
        return {
          hash: new Uint8Array(32).fill(5),
          signerAuthority: `writer:${peerId}`,
        };
      },
    );
    document._sendLoadRequestAndSync = jest.fn(async () => true);

    await expect(document.load()).resolves.toBe(true);
    expect(probed.sort()).toEqual(['alice', 'bob']);
  });
});
