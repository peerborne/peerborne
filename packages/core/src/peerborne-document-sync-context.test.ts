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
  () => ({
    TopicValidatorResult: {
      Accept: 'accept',
      Ignore: 'ignore',
      Reject: 'reject',
    },
  }),
  { virtual: true },
);
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock('./peerborne.js', () => ({
  MAX_DOCUMENT_PATH_LENGTH: 4096,
  Peerborne: class {},
}));

const documentPath = '/sync-context';
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

describe('ordinary sync-message context confinement', () => {
  test.each([
    ['keychain changes', { keychainChanges: { delta: 1 } }],
    ['Welcome field', { welcomeEpochId: new Uint8Array(32) }],
    ['PathUpdate field', { pathUpdate: {} }],
    ['load-control field', { tipsHash: new Uint8Array(32) }],
  ])('rejects captured %s before mutation', async (_label, extra) => {
    const merge = jest.fn();
    const verify = jest.fn();
    const document = fakeDocument({
      _isSigningEnabled: () => false,
      _verifyWriterSignature: verify,
      _keychain: { merge },
    });

    await expect(
      document.sync({
        documentId: documentPath,
        signatureContext: 'ordinary-sync-v1',
        ...extra,
      }),
    ).resolves.toBe(false);
    expect(verify).not.toHaveBeenCalled();
    expect(merge).not.toHaveBeenCalled();
  });

  test.each([undefined, '', '/another-document'])(
    'requires the exact document ID %# before verification',
    async (documentId) => {
      const verify = jest.fn(async () => true);
      const collectACL = jest.fn();
      const document = fakeDocument({
        _syncMessageSerializer: new JSONSerializer<any>(),
        _isSigningEnabled: () => true,
        _verifyWriterSignature: verify,
        _collectACLFromTree: collectACL,
      });

      await expect(
        document.sync({
          documentId,
          signatureContext: 'ordinary-sync-v1',
          changes: { kind: 'document' },
          signature: 'AQ==',
        }),
      ).resolves.toBe(false);
      expect(verify).not.toHaveBeenCalled();
      expect(collectACL).not.toHaveBeenCalled();
    },
  );

  test('does not expose the internal signature-verification bypass', async () => {
    const verify = jest.fn(async () => false);
    const collectACL = jest.fn();
    const document = fakeDocument({
      _syncMessageSerializer: new JSONSerializer<any>(),
      _isSigningEnabled: () => true,
      _verifyWriterSignature: verify,
      _collectACLFromTree: collectACL,
    });

    await expect(
      (document.sync as (...args: any[]) => Promise<boolean>)(
        {
          documentId: documentPath,
          signatureContext: 'ordinary-sync-v1',
          changes: { kind: 'document' },
          signature: 'AQ==',
        },
        false,
      ),
    ).resolves.toBe(false);
    expect(verify).toHaveBeenCalledTimes(1);
    expect(collectACL).not.toHaveBeenCalled();
  });

  test('detaches nested changes before deferred verification', async () => {
    const serializer = new JSONSerializer<any>();
    const changes = {
      kind: 'document',
      change: { value: 1 },
    };
    const collectACL = jest.fn(() => undefined);
    const document = fakeDocument({
      _syncMessageSerializer: serializer,
      _isSigningEnabled: () => true,
      _verifyWriterSignature: async () => {
        changes.change.value = 9;
        return true;
      },
      _collectACLFromTree: collectACL,
    });

    await expect(
      document.sync({
        documentId: documentPath,
        signatureContext: 'ordinary-sync-v1',
        changeId: 'root',
        changes,
        signature: 'AQ==',
      }),
    ).resolves.toBe(true);

    expect(collectACL).toHaveBeenCalledWith(
      { kind: 'document', change: { value: 1 } },
      'root',
    );
    expect(collectACL.mock.calls[0][0]).not.toBe(changes);
  });

  test('rejects a serializer alias changed during verification', async () => {
    const json = new JSONSerializer<any>();
    let captured:
      | { changes?: { kind: string; change: { value: number } } }
      | undefined;
    const collectACL = jest.fn();
    const document = fakeDocument({
      _syncMessageSerializer: {
        serializeSyncMessage: (message: typeof captured) => {
          captured = message;
          return json.serializeSyncMessage(message as never);
        },
      },
      _isSigningEnabled: () => true,
      _verifyWriterSignature: async () => {
        captured!.changes!.change.value = 9;
        return true;
      },
      _collectACLFromTree: collectACL,
    });

    await expect(
      document.sync({
        documentId: documentPath,
        signatureContext: 'ordinary-sync-v1',
        changeId: 'root',
        changes: { kind: 'document', change: { value: 1 } },
        signature: 'AQ==',
      }),
    ).resolves.toBe(false);
    expect(collectACL).not.toHaveBeenCalled();
  });

  test.each([1, 2])('rejects a serializer that mutates on call %i', async (mutationCall) => {
    let serializationCount = 0;
    const collectACL = jest.fn(() => undefined);
    const document = fakeDocument({
      _syncMessageSerializer: {
        serializeSyncMessage: (message: {
          changes?: { change?: { value: number } };
        }) => {
          serializationCount += 1;
          if (serializationCount === mutationCall) {
            message.changes!.change!.value = 9;
          }
          return new Uint8Array([1]);
        },
      },
      _isSigningEnabled: () => true,
      _verifyWriterSignature: async () => true,
      _collectACLFromTree: collectACL,
    });

    await expect(
      document.sync({
        documentId: documentPath,
        signatureContext: 'ordinary-sync-v1',
        changeId: 'root',
        changes: { kind: 'document', change: { value: 1 } },
        signature: 'AQ==',
      }),
    ).resolves.toBe(false);
    expect(collectACL).not.toHaveBeenCalled();
  });

  test('GossipSub validator rejects a specialized body before signature work', async () => {
    const serializer = new JSONSerializer<any>();
    const validators = new Map<string, (...args: any[]) => Promise<unknown>>();
    const verify = jest.fn();
    const pubsub = {
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      subscribe: jest.fn(),
      unsubscribe: jest.fn(),
      topicValidators: {
        set: (topic: string, validator: (...args: any[]) => Promise<unknown>) =>
          validators.set(topic, validator),
        get: (topic: string) => validators.get(topic),
        delete: (topic: string) => validators.delete(topic),
      },
    };
    const decryptBlock = jest.fn();
    const document = fakeDocument({
      _invitationBootstrapReady: true,
      _hashes: new Set(),
      _computeTopic: () => '/topic',
      _keychainProvider: { keyIDLength: 32 },
      _authProvider: { nonceBytes: 1 },
      _decryptBlock: decryptBlock,
      _syncMessageSerializer: serializer,
      _verifyWriterSignature: verify,
      _isSigningEnabled: () => true,
      swarm: {
        config: { enableSigning: true, enableTopicValidators: true },
        registerDocument: jest.fn(),
        unregisterDocument: jest.fn(),
        heliaNode: { libp2p: { services: { pubsub } } },
      },
    });

    await document.open();
    const validator = validators.get('/topic');
    decryptBlock.mockResolvedValueOnce(
      serializer.serializeSyncMessage({
        documentId: documentPath,
        signatureContext: 'ordinary-sync-v1',
        keychainChanges: { delta: 1 },
        signature: 'AQ==',
      }),
    );
    await expect(
      validator!({}, { data: encryptedPayload() }),
    ).resolves.toBe('reject');
    decryptBlock.mockResolvedValueOnce(
      serializer.serializeSyncMessage({
        documentId: '/another-document',
        signatureContext: 'ordinary-sync-v1',
        changes: { kind: 'document' },
        signature: 'AQ==',
      }),
    );
    await expect(
      validator!({}, { data: encryptedPayload() }),
    ).resolves.toBe('reject');
    expect(verify).not.toHaveBeenCalled();
    await document.close();
  });

  test('pubsub handler rejects specialized bodies when validators are disabled', async () => {
    const serializer = new JSONSerializer<any>();
    let messageHandler: ((event: any) => void) | undefined;
    const pubsub = {
      addEventListener: jest.fn(
        (_type: string, handler: (event: any) => void) => {
          messageHandler = handler;
        },
      ),
      removeEventListener: jest.fn(),
      subscribe: jest.fn(),
      unsubscribe: jest.fn(),
      topicValidators: new Map(),
    };
    const sync = jest.fn(async () => true);
    const decryptBlock = jest.fn();
    const document = fakeDocument({
      _invitationBootstrapReady: true,
      _hashes: new Set(),
      _computeTopic: () => '/topic',
      _keychainProvider: { keyIDLength: 32 },
      _authProvider: { nonceBytes: 1 },
      _decryptBlock: decryptBlock,
      _syncMessageSerializer: serializer,
      _isSigningEnabled: () => false,
      sync,
      swarm: {
        config: { enableSigning: false, enableTopicValidators: false },
        registerDocument: jest.fn(),
        unregisterDocument: jest.fn(),
        heliaNode: { libp2p: { services: { pubsub } } },
      },
    });

    await document.open();
    decryptBlock.mockResolvedValueOnce(
      serializer.serializeSyncMessage({
        documentId: documentPath,
        signatureContext: 'ordinary-sync-v1',
        keychainChanges: { delta: 1 },
      }),
    );
    messageHandler!({
      detail: {
        data: encryptedPayload(),
        topic: '/topic',
        type: 'signed',
        from: { toString: () => 'peer' },
      },
    });
    await Promise.resolve();
    await Promise.resolve();
    decryptBlock.mockResolvedValueOnce(
      serializer.serializeSyncMessage({
        documentId: '/another-document',
        signatureContext: 'ordinary-sync-v1',
        changes: { kind: 'document' },
      }),
    );
    messageHandler!({
      detail: {
        data: encryptedPayload(),
        topic: '/topic',
        type: 'signed',
        from: { toString: () => 'peer' },
      },
    });
    await Promise.resolve();
    await Promise.resolve();

    expect(sync).not.toHaveBeenCalled();
    await document.close();
  });

  test('pubsub handler ignores other topics before decryption or reload', async () => {
    let messageHandler: ((event: any) => void) | undefined;
    const pubsub = {
      addEventListener: jest.fn(
        (_type: string, handler: (event: any) => void) => {
          messageHandler = handler;
        },
      ),
      removeEventListener: jest.fn(),
      subscribe: jest.fn(),
      unsubscribe: jest.fn(),
      topicValidators: new Map(),
    };
    const decryptBlock = jest.fn();
    const load = jest.fn();
    const document = fakeDocument({
      _invitationBootstrapReady: true,
      _hashes: new Set(),
      _computeTopic: () => '/topic',
      _keychainProvider: { keyIDLength: 32 },
      _authProvider: { nonceBytes: 1 },
      _decryptBlock: decryptBlock,
      _isSigningEnabled: () => false,
      load,
      swarm: {
        config: { enableSigning: false, enableTopicValidators: false },
        registerDocument: jest.fn(),
        unregisterDocument: jest.fn(),
        heliaNode: { libp2p: { services: { pubsub } } },
      },
    });

    await document.open();
    messageHandler!({
      detail: {
        data: encryptedPayload(),
        topic: '/other-topic',
        type: 'signed',
        from: { toString: () => 'peer' },
      },
    });

    expect(decryptBlock).not.toHaveBeenCalled();
    expect(load).not.toHaveBeenCalled();
    await document.close();
  });
});
