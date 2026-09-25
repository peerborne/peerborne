import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals';
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

const documentPath = '/key-update-v2';
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

function receiverHarness(
  message: Record<string, unknown> = {
    documentId: documentPath,
    signatureContext: 'key-update-v2',
    keychainChanges: { delta: 1 },
    signature: 'AQ==',
  },
) {
  const serializer = new JSONSerializer<any>();
  const raw = serializer.serializeSyncMessage(message as never);
  const decryptBlock = jest.fn(async () => raw);
  const merge = jest.fn();
  const verify = jest.fn(async () => true);
  const deserialize = jest.spyOn(serializer, 'deserializeSyncMessage');
  const document = fakeDocument({
    _writerKeysVersion: 1,
    _authProvider: { nonceBits: 1, verify },
    _keychainProvider: { keyIDLength: 32 },
    _decryptBlock: decryptBlock,
    _syncMessageSerializer: serializer,
    _isSigningEnabled: () => false,
    _getWriterKeys: async () => [{}],
    _keychain: { merge },
  });
  return { decryptBlock, deserialize, document, merge, serializer, verify };
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

describe('legacy document key-update V2 admission', () => {
  test('authenticates signed full-lineage updates when ordinary signing is disabled', async () => {
    const harness = receiverHarness();

    await harness.document.handleKeyUpdateRequestData(encryptedPayload());

    expect(harness.verify).toHaveBeenCalledTimes(1);
    expect(harness.merge).toHaveBeenCalledWith({ delta: 1 });
  });

  test('rejects a cryptographically invalid update without mutation', async () => {
    const harness = receiverHarness();
    harness.verify.mockResolvedValue(false);

    await harness.document.handleKeyUpdateRequestData(encryptedPayload());

    expect(harness.verify).toHaveBeenCalledTimes(1);
    expect(harness.merge).not.toHaveBeenCalled();
  });

  test('rejects an unsigned update without mutation', async () => {
    const harness = receiverHarness({
      documentId: documentPath,
      signatureContext: 'key-update-v2',
      keychainChanges: { delta: 1 },
    });

    await harness.document.handleKeyUpdateRequestData(encryptedPayload());

    expect(harness.verify).not.toHaveBeenCalled();
    expect(harness.merge).not.toHaveBeenCalled();
  });

  test('rejects an update without keychain changes', async () => {
    const harness = receiverHarness({
      documentId: documentPath,
      signatureContext: 'key-update-v2',
      signature: 'AQ==',
    });

    await harness.document.handleKeyUpdateRequestData(encryptedPayload());

    expect(harness.verify).not.toHaveBeenCalled();
    expect(harness.merge).not.toHaveBeenCalled();
  });

  test.each([undefined, '', '/wrong-document'])(
    'requires the exact document ID %#',
    async (documentId) => {
      const harness = receiverHarness({
        documentId,
        signatureContext: 'key-update-v2',
        keychainChanges: { delta: 1 },
        signature: 'AQ==',
      });

      await harness.document.handleKeyUpdateRequestData(encryptedPayload());

      expect(harness.verify).not.toHaveBeenCalled();
      expect(harness.merge).not.toHaveBeenCalled();
    },
  );

  test.each([
    ['Welcome field', { welcomeEpochId: new Uint8Array(32) }],
    ['PathUpdate field', { pathUpdate: {} }],
    ['load-control field', { tips: ['cid'] }],
  ])('rejects a cross-context %s before verification', async (_label, extra) => {
    const harness = receiverHarness({
      documentId: documentPath,
      signatureContext: 'key-update-v2',
      keychainChanges: { delta: 1 },
      signature: 'AQ==',
      ...extra,
    });

    await harness.document.handleKeyUpdateRequestData(encryptedPayload());

    expect(harness.verify).not.toHaveBeenCalled();
    expect(harness.merge).not.toHaveBeenCalled();
  });

  test.each([
    ['short key ID', new Uint8Array(31)],
    ['short nonce', new Uint8Array(32)],
    ['empty ciphertext', new Uint8Array(33)],
  ])('rejects %s framing before decrypting', async (_label, payload) => {
    const harness = receiverHarness();

    await harness.document.handleKeyUpdateRequestData(payload);

    expect(harness.decryptBlock).not.toHaveBeenCalled();
    expect(harness.deserialize).not.toHaveBeenCalled();
    expect(harness.merge).not.toHaveBeenCalled();
  });

  test.each([
    ['zero key ID width', 0, 1],
    ['zero nonce width', 32, 0],
    ['unsafe key ID width', Number.MAX_SAFE_INTEGER, 1],
  ])('rejects %s before decrypting', async (_label, keyIDLength, nonceBits) => {
    const harness = receiverHarness();
    harness.document._keychainProvider.keyIDLength = keyIDLength;
    harness.document._authProvider.nonceBits = nonceBits;

    await harness.document.handleKeyUpdateRequestData(encryptedPayload());

    expect(harness.decryptBlock).not.toHaveBeenCalled();
    expect(harness.deserialize).not.toHaveBeenCalled();
  });

  test.each([new Uint8Array(0), [1]])(
    'rejects malformed decrypted plaintext %# before deserializing',
    async (plaintext) => {
      const harness = receiverHarness();
      harness.decryptBlock.mockResolvedValue(plaintext as Uint8Array);

      await harness.document.handleKeyUpdateRequestData(encryptedPayload());

      expect(harness.deserialize).not.toHaveBeenCalled();
      expect(harness.verify).not.toHaveBeenCalled();
      expect(harness.merge).not.toHaveBeenCalled();
    },
  );

  test('detaches nested changes before asynchronous verification', async () => {
    const harness = receiverHarness();
    const decoded = {
      documentId: documentPath,
      signatureContext: 'key-update-v2',
      keychainChanges: { delta: 1 },
      signature: 'AQ==',
    };
    harness.document._syncMessageSerializer = {
      deserializeSyncMessage: () => decoded,
      serializeSyncMessage: harness.serializer.serializeSyncMessage.bind(
        harness.serializer,
      ),
    };
    harness.verify.mockImplementation(async () => {
      decoded.keychainChanges.delta = 2;
      return true;
    });

    await harness.document.handleKeyUpdateRequestData(encryptedPayload());

    expect(harness.merge).toHaveBeenCalledWith({ delta: 1 });
    expect(harness.merge.mock.calls[0][0]).not.toBe(decoded.keychainChanges);
  });

  test('keeps committed changes disjoint from serializer aliases', async () => {
    const harness = receiverHarness();
    const decoded = {
      documentId: documentPath,
      signatureContext: 'key-update-v2',
      keychainChanges: { delta: 1 },
      signature: 'AQ==',
    };
    let serializationCount = 0;
    harness.document._syncMessageSerializer = {
      deserializeSyncMessage: () => decoded,
      serializeSyncMessage: (message: typeof decoded) => {
        serializationCount += 1;
        if (serializationCount === 2) {
          message.keychainChanges.delta = 2;
        }
        return new Uint8Array([1]);
      },
    };

    await harness.document.handleKeyUpdateRequestData(encryptedPayload());

    expect(harness.merge).toHaveBeenCalledWith({ delta: 1 });
  });

  test('rejects a writer-ACL race before mutation', async () => {
    const harness = receiverHarness();
    harness.verify.mockImplementation(async () => {
      harness.document._writerKeysVersion += 1;
      return true;
    });

    await harness.document.handleKeyUpdateRequestData(encryptedPayload());

    expect(harness.merge).not.toHaveBeenCalled();
  });

  test('rechecks writer authorization inside admission', async () => {
    const harness = receiverHarness();
    const admission = {
      isActive: () => true,
      runMutation: async (operation: () => unknown) => {
        harness.document._writerKeysVersion += 1;
        return { admitted: true, value: await operation() };
      },
    };

    await harness.document.handleKeyUpdateRequestData(
      encryptedPayload(),
      admission,
    );

    expect(harness.merge).not.toHaveBeenCalled();
  });
});
