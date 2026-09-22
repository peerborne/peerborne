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
    sink: async () => undefined,
    source: (async function* () {
      yield response;
    })(),
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
    signatureContext: 'load-response-v3',
    tips: [],
    signature: 'AQ==',
  },
) {
  const serializer = new JSONSerializer<any>();
  const verify = jest.fn(async () => true);
  const syncUnlocked = jest.fn(async () => true);
  const deserializeSyncMessage = jest.fn(() => decoded);
  const document = fakeDocument({
    swarm: { config: {} },
    _writerKeysVersion: 4,
    _writerMutationsInFlight: 0,
    _getWriterKeys: async () => [{}],
    _keychainProvider: { keyIDLength: 32 },
    _authProvider: {
      nonceBits: 1,
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
    signatureContext: 'tip-advertisement-v1',
    tipsHash: new Uint8Array(32).fill(5),
    signature: 'AQ==',
  },
) {
  const serializer = new JSONSerializer<any>();
  const verify = jest.fn(async () => true);
  const rawStream = tipStream();
  const deserializeSyncMessage = jest.fn(() => decoded);
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
    _keychain: { getKey: jest.fn(() => ({})) },
    _authProvider: {
      nonceBits: 1,
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

describe('load-response V3 confinement', () => {
  test.each([
    ['a foreign field', { welcomeEpochId: new Uint8Array(32) }],
    ['the required tips', { tips: undefined }],
    ['well-formed tips', { tips: [1] }],
    ['an exact document ID', { documentId: undefined }],
    ['an exact document ID', { documentId: '' }],
    ['an exact document ID', { documentId: '/other' }],
  ])('rejects a response without %s before sync', async (_label, replacement) => {
    const harness = loadHarness({
      documentId: documentPath,
      signatureContext: 'load-response-v3',
      tips: [],
      signature: 'AQ==',
      ...replacement,
    });

    await expect(
      harness.document._sendLoadRequestAndSync(
        loadStream(),
        new Uint8Array([1]),
      ),
    ).resolves.toBe(false);

    expect(harness.syncUnlocked).not.toHaveBeenCalled();
  });

  test('detaches nested state before deferred verification', async () => {
    const decoded = {
      documentId: documentPath,
      signatureContext: 'load-response-v3',
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
      harness.document._sendLoadRequestAndSync(
        loadStream(),
        new Uint8Array([1]),
      ),
    ).resolves.toBe(true);

    const applied = harness.syncUnlocked.mock.calls[0][0] as typeof decoded;
    expect(applied.changes.change.value).toBe(1);
    expect(applied.snapshot.state.value).toBe(2);
    expect(applied.keychainChanges.delta).toBe(5);
    expect(applied.tips).toEqual(['cid']);
  });

  test('rejects serialization that mutates the authenticated snapshot', async () => {
    const decoded = {
      documentId: documentPath,
      signatureContext: 'load-response-v3',
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
      harness.document._sendLoadRequestAndSync(
        loadStream(),
        new Uint8Array([1]),
      ),
    ).resolves.toBe(false);

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
        loadStream(),
        new Uint8Array([1]),
      ),
    ).resolves.toBe(false);

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
        loadStream(),
        new Uint8Array([1]),
      ),
    ).resolves.toBe(false);

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
        loadStream(),
        new Uint8Array([1]),
      ),
    ).resolves.toBe(false);

    expect(harness.syncUnlocked).not.toHaveBeenCalled();
  });

  test('rejects malformed provider plaintext before deserialization', async () => {
    const harness = loadHarness();
    harness.document._authProvider.decrypt = async () => new Uint8Array(0);

    await expect(
      harness.document._sendLoadRequestAndSync(
        loadStream(),
        new Uint8Array([1]),
      ),
    ).resolves.toBe(false);

    expect(harness.deserializeSyncMessage).not.toHaveBeenCalled();
    expect(harness.syncUnlocked).not.toHaveBeenCalled();
  });

  test('enforces the caller-specific response limit after decryption', async () => {
    const harness = loadHarness();
    harness.document._authProvider.decrypt = async () => new Uint8Array(65);

    await expect(
      harness.document._sendLoadRequestAndSync(
        loadStream(),
        new Uint8Array([1]),
        null,
        undefined,
        64,
      ),
    ).resolves.toBe(false);

    expect(harness.deserializeSyncMessage).not.toHaveBeenCalled();
    expect(harness.syncUnlocked).not.toHaveBeenCalled();
  });

  test('rejects invalid provider framing before decryption', async () => {
    const harness = loadHarness();
    const decrypt = jest.fn();
    harness.document._authProvider.decrypt = decrypt;
    harness.document._authProvider.nonceBits = 0;

    await expect(
      harness.document._sendLoadRequestAndSync(
        loadStream(),
        new Uint8Array([1]),
      ),
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
      harness.document._sendLoadRequestAndSync(
        oversizedStream,
        new Uint8Array([1]),
      ),
    ).rejects.toThrow(/maximum allowed size/);

    expect(harness.deserializeSyncMessage).not.toHaveBeenCalled();
  });
});

describe('tip-advertisement V1 confinement', () => {
  test.each([
    ['a foreign field', { tips: [] }],
    ['an exact document ID', { documentId: undefined }],
    ['an exact document ID', { documentId: '' }],
    ['an exact document ID', { documentId: '/other' }],
    ['an exact hash', { tipsHash: new Uint8Array(31) }],
  ])('rejects a response without %s', async (_label, replacement) => {
    const harness = tipHarness({
      documentId: documentPath,
      signatureContext: 'tip-advertisement-v1',
      tipsHash: new Uint8Array(32).fill(5),
      signature: 'AQ==',
      ...replacement,
    });

    await expect(
      harness.document._probeTipAdvertise(
        { toString: () => '/peer/one' },
        new Uint8Array([1]),
      ),
    ).resolves.toBeNull();
  });

  test('returns a detached hash across deferred verification', async () => {
    const advertised = new Uint8Array(32).fill(5);
    const expected = new Uint8Array(advertised);
    const harness = tipHarness({
      documentId: documentPath,
      signatureContext: 'tip-advertisement-v1',
      tipsHash: advertised,
      signature: 'AQ==',
    });
    harness.verify.mockImplementation(async (raw) => {
      raw.fill(7);
      advertised.fill(9);
      return true;
    });

    await expect(
      harness.document._probeTipAdvertise(
        { toString: () => '/peer/one' },
        new Uint8Array([1]),
      ),
    ).resolves.toEqual(expected);
  });

  test('keeps the returned hash disjoint from serializer aliases', async () => {
    const decoded = {
      documentId: documentPath,
      signatureContext: 'tip-advertisement-v1',
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
      harness.document._probeTipAdvertise(
        { toString: () => '/peer/one' },
        new Uint8Array([1]),
      ),
    ).resolves.toEqual(new Uint8Array(32).fill(5));
  });

  test('invalidates a vote when writer authorization changes', async () => {
    const harness = tipHarness();
    harness.verify.mockImplementation(async () => {
      harness.document._writerKeysVersion += 1;
      return true;
    });

    await expect(
      harness.document._probeTipAdvertise(
        { toString: () => '/peer/one' },
        new Uint8Array([1]),
      ),
    ).resolves.toBeNull();
  });

  test('captures writer authorization before resolving writer keys', async () => {
    const harness = tipHarness();
    harness.document._getWriterKeys = async () => {
      harness.document._writerKeysVersion += 1;
      return [{}];
    };

    await expect(
      harness.document._probeTipAdvertise(
        { toString: () => '/peer/one' },
        new Uint8Array([1]),
      ),
    ).resolves.toBeNull();
  });

  test('rejects a vote while a writer mutation is in flight', async () => {
    const harness = tipHarness();
    harness.document._writerMutationsInFlight = 1;

    await expect(
      harness.document._probeTipAdvertise(
        { toString: () => '/peer/one' },
        new Uint8Array([1]),
      ),
    ).resolves.toBeNull();

    expect(harness.verify).not.toHaveBeenCalled();
  });

  test('rejects a vote when a writer mutation starts during key lookup', async () => {
    const harness = tipHarness();
    harness.document._getWriterKeys = async () => {
      harness.document._writerMutationsInFlight = 1;
      return [{}];
    };

    await expect(
      harness.document._probeTipAdvertise(
        { toString: () => '/peer/one' },
        new Uint8Array([1]),
      ),
    ).resolves.toBeNull();

    expect(harness.verify).not.toHaveBeenCalled();
  });

  test('rejects malformed provider plaintext before deserialization', async () => {
    const harness = tipHarness();
    harness.document._authProvider.decrypt = async () => new Uint8Array(0);

    await expect(
      harness.document._probeTipAdvertise(
        { toString: () => '/peer/one' },
        new Uint8Array([1]),
      ),
    ).resolves.toBeNull();

    expect(harness.deserializeSyncMessage).not.toHaveBeenCalled();
  });

  test('rejects invalid provider framing before decryption', async () => {
    const harness = tipHarness();
    harness.document._authProvider.nonceBits = 0;

    await expect(
      harness.document._probeTipAdvertise(
        { toString: () => '/peer/one' },
        new Uint8Array([1]),
      ),
    ).resolves.toBeNull();

    expect(harness.document._authProvider.decrypt).not.toHaveBeenCalled();
    expect(harness.deserializeSyncMessage).not.toHaveBeenCalled();
  });
});
