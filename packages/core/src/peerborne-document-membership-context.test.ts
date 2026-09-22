import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals';
import { pathUpdateFixture } from './__mocks__/beekem-v2.js';
import { serializePathUpdateV2ForWire } from './path-update-wire.js';
import { deriveEpochIdFromRootSecret } from './derive-doc-key.js';
import { JSONSerializer } from './json-serializer.js';
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

const documentPath = '/membership-context';

function fakeDocument(fields: Record<string, unknown>): any {
  return Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath,
    _mutationQueue: {
      run: (operation: () => Promise<unknown>) => operation(),
    },
    ...fields,
  });
}

function validMessage(epochId: Uint8Array) {
  return {
    documentId: documentPath,
    signatureContext: 'beekem-path-update-v2' as const,
    pathUpdate: serializePathUpdateV2ForWire(pathUpdateFixture()),
    pathUpdateEpochId: epochId,
    signature: 'AQ==',
  };
}

function pathHarness(
  decoded: Record<string, unknown>,
  fields: Record<string, unknown> = {},
) {
  const serializer = new JSONSerializer<any>();
  const verify = jest.fn(async () => true);
  const processPathUpdate = jest.fn();
  const addEpochKey = jest.fn();
  const deserializeSyncMessage = jest.fn((bytes: Uint8Array) => bytes.byteLength === 1 ? decoded : serializer.deserializeSyncMessage(bytes));
  const document = fakeDocument({
    _writerKeysVersion: 1,
    _syncMessageSerializer: {
      deserializeSyncMessage,
      serializeSyncMessage: serializer.serializeSyncMessage.bind(serializer),
    },
    _verifyMembershipWriterSignature: verify,
    _beekemInitialized: true,
    _beekem: { clone: () => ({ processPathUpdate }) },
    _keychain: {
      addEpochKey,
      prepareEpochKey: (epoch: Uint8Array, key: unknown) => ({
        claimCommit: () => ({ finalize() { addEpochKey(epoch, key); } }),
      }),
    },
    ...fields,
  });
  return {
    addEpochKey,
    deserializeSyncMessage,
    document,
    processPathUpdate,
    serializer,
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

describe('BeeKEM PathUpdate context confinement', () => {
  test('rejects foreign fields before verification', async () => {
    const harness = pathHarness({
      ...validMessage(new Uint8Array(32)),
      keychainChanges: { delta: 1 },
    });

    await harness.document.handleBeeKEMPathUpdateRequestData(
      new Uint8Array([1]),
    );

    expect(harness.verify).not.toHaveBeenCalled();
    expect(harness.processPathUpdate).not.toHaveBeenCalled();
    expect(harness.addEpochKey).not.toHaveBeenCalled();
  });

  test.each([undefined, '', '/wrong-document'])(
    'requires the exact document ID %#',
    async (documentId) => {
      const harness = pathHarness({
        ...validMessage(new Uint8Array(32)),
        documentId,
      });

      await harness.document.handleBeeKEMPathUpdateRequestData(
        new Uint8Array([1]),
      );

      expect(harness.verify).not.toHaveBeenCalled();
      expect(harness.processPathUpdate).not.toHaveBeenCalled();
    },
  );

  test.each([
    ['path update', { pathUpdate: undefined }],
    ['epoch ID', { pathUpdateEpochId: undefined }],
    ['short epoch ID', { pathUpdateEpochId: new Uint8Array(31) }],
    ['long epoch ID', { pathUpdateEpochId: new Uint8Array(33) }],
    ['signature', { signature: undefined }],
  ])('requires an exact %s before verification', async (_label, replacement) => {
    const harness = pathHarness({
      ...validMessage(new Uint8Array(32)),
      ...replacement,
    });

    await harness.document.handleBeeKEMPathUpdateRequestData(
      new Uint8Array([1]),
    );

    expect(harness.verify).not.toHaveBeenCalled();
    expect(harness.processPathUpdate).not.toHaveBeenCalled();
  });

  test('rejects an empty payload before deserialization', async () => {
    const harness = pathHarness(validMessage(new Uint8Array(32)));

    await harness.document.handleBeeKEMPathUpdateRequestData(
      new Uint8Array(0),
    );

    expect(harness.deserializeSyncMessage).not.toHaveBeenCalled();
    expect(harness.verify).not.toHaveBeenCalled();
  });

  test('detaches nested data before deferred verification', async () => {
    const rootSecret = new Uint8Array(32).fill(7);
    const epochId = await deriveEpochIdFromRootSecret(rootSecret);
    const expectedEpochId = new Uint8Array(epochId);
    const decoded = validMessage(epochId);
    const harness = pathHarness(decoded);
    const stagedBeeKEM = {
      processPathUpdate: harness.processPathUpdate,
    };
    harness.document._beekem = { clone: () => stagedBeeKEM };
    harness.processPathUpdate.mockResolvedValue(rootSecret);
    harness.verify.mockImplementation(async () => {
      decoded.pathUpdate.senderLeafIndex = 9;
      decoded.pathUpdateEpochId.fill(9);
      return true;
    });

    await harness.document.handleBeeKEMPathUpdateRequestData(
      new Uint8Array([1]),
    );

    expect(harness.processPathUpdate).toHaveBeenCalledWith(pathUpdateFixture());
    expect(harness.addEpochKey).toHaveBeenCalledWith(
      expectedEpochId,
      expect.anything(),
    );
    expect(harness.document._beekem).toBe(stagedBeeKEM);
  });

  test('rejects a serializer that cannot preserve the authenticated snapshot', async () => {
    const rootSecret = new Uint8Array(32).fill(7);
    const epochId = await deriveEpochIdFromRootSecret(rootSecret);
    const decoded = validMessage(epochId);
    const harness = pathHarness(decoded);
    let serializationCount = 0;
    harness.document._syncMessageSerializer = {
      deserializeSyncMessage: () => decoded,
      serializeSyncMessage: (message: typeof decoded) => {
        serializationCount += 1;
        if (serializationCount === 2) {
          message.pathUpdate.senderLeafIndex = 9;
        }
        return new Uint8Array([1]);
      },
    };
    harness.processPathUpdate.mockResolvedValue(rootSecret);

    await harness.document.handleBeeKEMPathUpdateRequestData(
      new Uint8Array([1]),
    );

    expect(harness.processPathUpdate).not.toHaveBeenCalled();
    expect(harness.addEpochKey).not.toHaveBeenCalled();
  });

  test('rejects when writer authorization changes during verification', async () => {
    const rootSecret = new Uint8Array(32).fill(7);
    const epochId = await deriveEpochIdFromRootSecret(rootSecret);
    const harness = pathHarness(validMessage(epochId));
    harness.verify.mockImplementation(async () => {
      harness.document._writerKeysVersion += 1;
      return true;
    });

    await harness.document.handleBeeKEMPathUpdateRequestData(
      new Uint8Array([1]),
    );

    expect(harness.processPathUpdate).not.toHaveBeenCalled();
    expect(harness.addEpochKey).not.toHaveBeenCalled();
  });

  test('rejects when writer authorization changes while staging', async () => {
    const rootSecret = new Uint8Array(32).fill(7);
    const epochId = await deriveEpochIdFromRootSecret(rootSecret);
    const harness = pathHarness(validMessage(epochId));
    harness.processPathUpdate.mockImplementation(async () => {
      harness.document._writerKeysVersion += 1;
      return rootSecret;
    });

    await harness.document.handleBeeKEMPathUpdateRequestData(
      new Uint8Array([1]),
    );

    expect(harness.addEpochKey).not.toHaveBeenCalled();
    expect(harness.document._beekem).not.toEqual(
      expect.objectContaining({ processPathUpdate: harness.processPathUpdate }),
    );
  });

  test('rechecks writer authorization inside admission', async () => {
    const rootSecret = new Uint8Array(32).fill(7);
    const epochId = await deriveEpochIdFromRootSecret(rootSecret);
    const harness = pathHarness(validMessage(epochId));
    harness.processPathUpdate.mockResolvedValue(rootSecret);
    const admission = {
      isActive: () => true,
      runMutation: async (operation: () => Promise<unknown>) => {
        harness.document._writerKeysVersion += 1;
        return { admitted: true, value: await operation() };
      },
    };

    await harness.document.handleBeeKEMPathUpdateRequestData(
      new Uint8Array([1]),
      admission,
    );

    expect(harness.addEpochKey).not.toHaveBeenCalled();
  });
});


test('preserves unexpected errors while buffering an authenticated Welcome', () => {
  const failure = new Error('serializer failed');
  const document = fakeDocument({
    _pendingWelcomes: { storeMessage: () => { throw failure; } },
    _syncMessageSerializer: new JSONSerializer<any>(),
    _now: () => 1,
  });
  expect(() => document._bufferPendingWelcome({
    documentId: documentPath,
    welcomeEpochId: new Uint8Array(32).fill(1),
  })).toThrow(failure);
});
