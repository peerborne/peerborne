import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals';
import { crdtDocumentChangeNode } from './crdt-change-node.js';
import { syncInvitationMessageCompletely } from './invitation-catch-up.js';
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

  test('requires the ordinary context tag in the sync() type', async () => {
    const document = fakeDocument({}) as PeerborneDocument<
      unknown,
      unknown,
      unknown,
      unknown,
      unknown,
      unknown
    >;

    await expect(
      // @ts-expect-error sync() requires signatureContext 'ordinary-sync-v1'
      document.sync({ documentId: documentPath }),
    ).resolves.toBe(false);
    await expect(
      document.sync({
        documentId: documentPath,
        // @ts-expect-error sync() accepts only the ordinary context
        signatureContext: 'load-response-v3',
      }),
    ).resolves.toBe(false);
  });

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

  test('detaches the message before waiting for the mutation queue', async () => {
    const collectACL = jest.fn(() => undefined);
    let releaseQueue!: () => void;
    const queued = new Promise<void>((resolve) => {
      releaseQueue = resolve;
    });
    const document = fakeDocument({
      _mutationQueue: {
        run: async (operation: () => Promise<unknown>) => {
          await queued;
          return operation();
        },
      },
      _syncMessageSerializer: new JSONSerializer<any>(),
      _isSigningEnabled: () => true,
      _verifyWriterSignature: async () => true,
      _collectACLFromTree: collectACL,
    });
    const message: any = {
      documentId: documentPath,
      signatureContext: 'ordinary-sync-v1',
      changeId: 'root',
      changes: { kind: 'document', change: { value: 1 } },
      signature: 'AQ==',
    };

    const result = document.sync(message);
    message.changes.change.value = 9;
    message.keychainChanges = { delta: 1 };
    releaseQueue();

    await expect(result).resolves.toBe(true);
    expect(collectACL).toHaveBeenCalledWith(
      { kind: 'document', change: { value: 1 } },
      'root',
    );
  });

  test('rejects a specialized field before waiting for the mutation queue', async () => {
    const run = jest.fn();
    const document = fakeDocument({ _mutationQueue: { run } });

    await expect(
      document.sync({
        documentId: documentPath,
        welcomeEpochId: new Uint8Array(32),
      }),
    ).resolves.toBe(false);
    expect(run).not.toHaveBeenCalled();
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

  test('membership authentication rejects a serializer that mutates before signing bytes', async () => {
    const verify = jest.fn(async () => true);
    const document = fakeDocument({
      _writerKeysVersion: 0,
      _verifyMembershipWriterSignature: verify,
      _syncMessageSerializer: {
        serializeSyncMessage: (message: {
          pathUpdate?: { delta: number };
        }) => {
          message.pathUpdate!.delta = 9;
          return new Uint8Array([1]);
        },
      },
    });

    await expect(
      document._authenticateMembershipMessage(
        {
          documentId: documentPath,
          signatureContext: 'beekem-path-update-v1',
          pathUpdate: { delta: 1 },
          pathUpdateEpochId: new Uint8Array(32),
          signature: 'AQ==',
        },
        'beekem-path-update-v1',
      ),
    ).resolves.toEqual({ kind: 'malformed' });
    expect(verify).not.toHaveBeenCalled();
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

  test.each([0, 1, 2])(
    'GossipSub validator rejects a serializer that mutates on call %i',
    async (mutationCall) => {
      const json = new JSONSerializer<any>();
      const validators = new Map<string, (...args: any[]) => Promise<unknown>>();
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
      let serializationCount = 0;
      const decryptBlock = jest.fn();
      const document = fakeDocument({
        _invitationBootstrapReady: true,
        _hashes: new Set(),
        _computeTopic: () => '/topic',
        _keychainProvider: { keyIDLength: 32 },
        _authProvider: { nonceBytes: 1 },
        _decryptBlock: decryptBlock,
        _syncMessageSerializer: {
          deserializeSyncMessage: (raw: Uint8Array) =>
            json.deserializeSyncMessage(raw),
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
        _verifyWriterSignature: async () => true,
        _isSigningEnabled: () => true,
        swarm: {
          config: { enableSigning: true, enableTopicValidators: true },
          registerDocument: jest.fn(),
          unregisterDocument: jest.fn(),
          heliaNode: { libp2p: { services: { pubsub } } },
        },
      });

      await document.open();
      decryptBlock.mockResolvedValueOnce(
        json.serializeSyncMessage({
          documentId: documentPath,
          signatureContext: 'ordinary-sync-v1',
          changeId: 'root',
          changes: { kind: 'document', change: { value: 1 } },
          signature: 'AQ==',
        } as never),
      );
      await expect(
        validators.get('/topic')!({}, { data: encryptedPayload() }),
      ).resolves.toBe(mutationCall === 0 ? 'accept' : 'reject');
      await document.close();
    },
  );

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

describe('snapshot-bearing invitation sync', () => {
  function snapshotMessage(context: string) {
    return {
      documentId: documentPath,
      signatureContext: context,
      changeId: 'head-cid',
      changes: {
        kind: crdtDocumentChangeNode,
        children: {
          'recent-cid': {
            kind: crdtDocumentChangeNode,
            children: {
              'boundary-cid': {
                kind: crdtDocumentChangeNode,
                children: {
                  'old-cid': { kind: crdtDocumentChangeNode },
                },
              },
            },
          },
        },
      },
      snapshot: {
        state: new Uint8Array([1, 2, 3]),
        lastChangeNodeCID: 'boundary-cid',
        compactedCount: 10,
        signature: new Uint8Array([4]),
        timestamp: 1,
      },
    } as any;
  }

  function snapshotDocument(latestSnapshot?: unknown): any {
    const hashes = new Set<string>();
    return fakeDocument({
      _hashes: hashes,
      _latestSnapshot: latestSnapshot,
      _documentChangeCount: 0,
      _isSigningEnabled: () => false,
      _crdtProvider: { remoteChange: (_doc: unknown, state: unknown) => state },
      _collectACLFromTree: () => ({ aclEntries: [], changes: [] }),
      _applyCollectedACL: () => undefined,
      _syncDocumentChanges: async () => {
        hashes.add('head-cid');
        hashes.add('recent-cid');
      },
    });
  }

  test.each([
    ['bootstrap', 'invitation-bootstrap-v1'],
    ['catch-up', 'load-response-v4'],
  ] as const)(
    'recognizes the applied detached snapshot during %s',
    async (phase, context) => {
      const document = snapshotDocument();
      const message = snapshotMessage(context);

      await expect(
        syncInvitationMessageCompletely(
          message,
          document._hashes,
          () => document._syncValidatedProtocolMessage(message, context),
          phase,
          { isSnapshotApplied: () => document._isLatestSnapshotFrom(message) },
        ),
      ).resolves.toBe(true);
      expect(document._latestSnapshot).not.toBe(message.snapshot);
      expect(document._latestSnapshot.lastChangeNodeCID).toBe('boundary-cid');
      expect(document._hashes.has('old-cid')).toBe(false);
    },
  );

  test('requires history below a snapshot that was not applied', async () => {
    const document = snapshotDocument({
      lastChangeNodeCID: 'newer-cid',
      compactedCount: 20,
    });
    const message = snapshotMessage('invitation-bootstrap-v1');

    await expect(
      syncInvitationMessageCompletely(
        message,
        document._hashes,
        () =>
          document._syncValidatedProtocolMessage(
            message,
            'invitation-bootstrap-v1',
          ),
        'bootstrap',
        { isSnapshotApplied: () => document._isLatestSnapshotFrom(message) },
      ),
    ).rejects.toThrow(/advertised CIDs were not installed/);
    expect(document._isLatestSnapshotFrom(message)).toBe(false);
  });

  test('does not attribute a snapshot to an ordinary sync source', async () => {
    const document = snapshotDocument();
    const message = snapshotMessage('ordinary-sync-v1');
    delete message.changeId;
    delete message.changes;

    await expect(document.sync(message)).resolves.toBe(true);
    expect(document._latestSnapshot?.lastChangeNodeCID).toBe('boundary-cid');
    expect(document._isLatestSnapshotFrom(message)).toBe(false);
  });
});
