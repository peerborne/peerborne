import { describe, expect, jest, test } from '@jest/globals';
import { Base64 } from 'js-base64';
import { PeerborneDocument } from './peerborne-document.js';
import { InvitationMembershipQueue } from './invitation-membership.js';
import { withIssuerPinnedInvitationStream } from './invitation-catch-up.js';
import { JSONSerializer } from './json-serializer.js';
import { CRDTChangeNode } from './crdt-change-node.js';
import { MAX_SHARED_PROTOCOL_REQUEST_SIZE } from './initial-load-protocols.js';
import {
  loadAdvertisementHash,
  loadAdvertisementHashToHex,
} from './load-advertisement-hash.js';
import { loadResponseManifestHash } from './load-response-manifest.js';
import { LoadQuorumFailedError } from './load-quorum.js';
import type { LoadSecurityCommitments } from './load-security-state.js';
import {
  documentLoadV3,
  documentLoadV4,
  securityAdvertiseV1,
  snapshotLoadV3,
  snapshotLoadV4,
  tipAdvertiseV1,
} from './wire-protocols.js';

jest.mock(
  'it-pipe',
  () => ({
    pipe: async (
      source: Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
      destination: (input: typeof source) => unknown,
    ) => destination(source),
  }),
  { virtual: true },
);
jest.mock('./peerborne.js', () => ({ MAX_DOCUMENT_PATH_LENGTH: 4096 }));
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock(
  'multiformats',
  () => ({ CID: { parse: (value: string) => value } }),
  {
    virtual: true,
  },
);

const harnessMutationQueues = new WeakMap<object, InvitationMembershipQueue>();
Object.defineProperty(PeerborneDocument.prototype, '_mutationQueue', {
  configurable: true,
  get(this: object) {
    let queue = harnessMutationQueues.get(this);
    if (queue === undefined) {
      queue = new InvitationMembershipQueue();
      harnessMutationQueues.set(this, queue);
    }
    return queue;
  },
});
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({ TopicValidatorResult: { Accept: 'accept', Ignore: 'ignore' } }),
  { virtual: true },
);

const bytes = (fill: number) => new Uint8Array(32).fill(fill);
const tuple = (
  overrides: Partial<LoadSecurityCommitments> = {},
): LoadSecurityCommitments => ({
  version: 1,
  controlHead: bytes(1),
  groupId: 'trusted-group',
  epoch: 8n,
  treeHash: bytes(2),
  confirmedTranscriptHash: bytes(3),
  ...overrides,
});

type DocumentHarness = {
  load(): Promise<boolean>;
  [key: string]: any;
};

const peer = (id: string) => ({
  id,
  toString: () => `/ip4/127.0.0.1/tcp/1/p2p/${id}`,
});

function swarmWithCapturedPolicy(
  config: Record<string, any> = {},
  extras: Record<string, any> = {},
) {
  return {
    config,
    enableSigning: config.enableSigning !== false,
    enableTopicValidators: config.enableTopicValidators === true,
    loadQuorumEnabled: config.loadQuorumEnabled !== false,
    loadQuorumK: config.loadQuorumK ?? 3,
    loadQuorumQ: config.loadQuorumQ,
    loadQuorumTimeoutMs: config.loadQuorumTimeoutMs ?? 5_000,
    loadQuorumAllowSinglePeer: config.loadQuorumAllowSinglePeer === true,
    requireAuthenticatedInitialLoad:
      config.requireAuthenticatedInitialLoad === true,
    requireSecurityStateQuorum: config.requireSecurityStateQuorum === true,
    resolveTrustedDocumentWriters: config.resolveTrustedDocumentWriters,
    resolveLoadSecurityCommitments: config.resolveLoadSecurityCommitments,
    validateDocumentPath: config.validateDocumentPath,
    ...extras,
  };
}

function initialLoadRequestHandlerHarness(readers: string[] = ['reader-a']) {
  const document = Object.create(PeerborneDocument.prototype) as any;
  const readerUsers = jest.fn(async () => readers);
  const writerUsers = jest.fn(async () => [] as string[]);
  const verify = jest.fn(async () => false);
  Object.assign(document, {
    documentPath: '/doc',
    swarm: swarmWithCapturedPolicy(),
    _securityProviderMutationFailure: undefined,
    _encoder: new TextEncoder(),
    _readers: { users: readerUsers },
    _writers: { users: writerUsers },
    _authProvider: { verify },
  });
  return { document, readerUsers, writerUsers, verify };
}

async function securityAwareFullLoadHarness(
  changes: CRDTChangeNode<Uint8Array> = { kind: 'document' },
  getBlock: (
    cid: unknown,
    options: { signal: AbortSignal },
  ) => AsyncIterable<Uint8Array> = async function* () {
    yield new Uint8Array([1, 2, 3]);
  },
) {
  const challenge = bytes(8);
  const changeId = 'H';
  const manifest = await loadResponseManifestHash({ changeId, changes });
  const expected = loadAdvertisementHashToHex(
    await loadAdvertisementHash('/doc', [changeId], tuple(), manifest),
  );
  const message = {
    documentId: '/doc',
    changeId,
    changes,
    tips: [changeId],
    loadSecurityState: tuple(),
    loadChallenge: challenge,
    signature: 'signature',
    testSigner: 'writer-a',
  };
  const document = Object.create(PeerborneDocument.prototype) as any;
  Object.assign(document, {
    documentPath: '/doc',
    swarm: swarmWithCapturedPolicy({}, {
      heliaNode: { blockstore: { get: getBlock } },
    }),
    _securityProviderMutationFailure: undefined,
    _writerMutationsInFlight: 0,
    _writerKeysVersion: 0,
    _cachedWriterKeys: null,
    _getWriterKeys: async () => [],
    _writers: { users: async () => ['writer-a'] },
    _authProvider: {
      nonceBits: 1,
      decrypt: async (data: Uint8Array) => data,
      verify: async (raw: Uint8Array, key: string) =>
        new TextDecoder().decode(raw) === key,
    },
    _deserializeSignature: () => new Uint8Array([1]),
    _syncMessageSerializer: {
      deserializeSyncMessage: () => message,
      serializeSyncMessage: (value: { testSigner?: string }) =>
        new TextEncoder().encode(value.testSigner ?? ''),
    },
    _keychainProvider: { keyIDLength: 1 },
    _keychain: { getKey: () => 'document-key' },
    _hashes: new Set<string>(),
    _initialLoadSyncAuthorizations: new WeakMap(),
    close: jest.fn(async () => undefined),
  });
  const stream = {
    sink: jest.fn(async () => undefined),
    async *source() {
      yield new Uint8Array([1, 2, 3]);
    },
  };
  return { challenge, document, expected, message, stream };
}

describe('PeerborneDocument V4 initial-load trust contract', () => {
  test('enforces canonical 4096-byte wire signatures symmetrically', () => {
    const { document } = initialLoadRequestHandlerHarness();
    const maximum = new Uint8Array(4096).fill(7);
    const encoded = document._serializeSignature(maximum);

    expect(encoded.length).toBe(4 * Math.ceil(4096 / 3));
    expect(document._deserializeSignature(encoded)).toEqual(maximum);
    expect(() => document._serializeSignature(new Uint8Array(4097))).toThrow(
      /signature/,
    );
    expect(() =>
      document._deserializeSignature(
        Base64.fromUint8Array(new Uint8Array(4097)),
      ),
    ).toThrow(/signature/);
    expect(() => document._deserializeSignature('AQ')).toThrow(/canonical/);
    expect(() => document._deserializeSignature(' A Q = = ')).toThrow(
      /canonical/,
    );
  });

  test('decodes one bounded initial-load signature before the ACL loop', async () => {
    const { document, verify } = initialLoadRequestHandlerHarness([
      'reader-a',
      'reader-b',
    ]);

    await expect(
      document._authorizeInitialLoadRequest(
        new Uint8Array([1]),
        Base64.fromUint8Array(new Uint8Array([9])),
      ),
    ).resolves.toBe(false);
    expect(verify).toHaveBeenCalledTimes(2);
    expect(verify.mock.calls[0][2]).toBe(verify.mock.calls[1][2]);
  });

  test('preserves unsigned V3 envelope compatibility when signing is disabled', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const verify = jest.fn(async () => false);
    Object.assign(document, {
      swarm: swarmWithCapturedPolicy({ enableSigning: false }),
      _syncMessageSerializer: {
        serializeSyncMessage: () => new Uint8Array([1]),
      },
      _authProvider: { verify },
    });

    await expect(
      document._verifyInitialLoadEnvelope(
        { documentId: '/doc', signature: '' },
        ['writer-a'],
      ),
    ).resolves.toBe(true);
    expect(verify).not.toHaveBeenCalled();
  });

  test.each([
    'handleLoadRequestData',
    'handleSnapshotLoadRequestData',
    'handleTipAdvertiseRequestData',
  ])(
    '%s rejects an oversized signature before reading ACLs',
    async (method) => {
      const { document, readerUsers, writerUsers, verify } =
        initialLoadRequestHandlerHarness();
      const sink = jest.fn(async () => undefined);

      await document[method](
        {
          documentId: '/doc',
          signature: Base64.fromUint8Array(new Uint8Array(4097)),
        },
        { sink },
      );

      expect(readerUsers).not.toHaveBeenCalled();
      expect(writerUsers).not.toHaveBeenCalled();
      expect(verify).not.toHaveBeenCalled();
      expect(sink).toHaveBeenCalledWith([]);
    },
  );

  test.each([
    'handleLoadRequestData',
    'handleSnapshotLoadRequestData',
    'handleTipAdvertiseRequestData',
  ])('%s never logs attacker-controlled request fields', async (method) => {
    const { document } = initialLoadRequestHandlerHarness();
    const sink = jest.fn(async () => undefined);
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const error = jest.spyOn(console, 'error').mockImplementation(() => {});
    const secretDocumentId = '/ATTACKER_DOCUMENT_SECRET';

    await document[method](
      { documentId: secretDocumentId, signature: 'ATTACKER_SIGNATURE_SECRET' },
      { sink },
    );
    await document[method](
      { documentId: '/doc', signature: 'ATTACKER_SIGNATURE_SECRET' },
      { sink },
    );

    const renderedLogs = [
      ...log.mock.calls,
      ...warn.mock.calls,
      ...error.mock.calls,
    ]
      .flat()
      .map(String)
      .join(' ');
    expect(renderedLogs).not.toContain(secretDocumentId);
    expect(renderedLogs).not.toContain('ATTACKER_SIGNATURE_SECRET');
    expect(log).not.toHaveBeenCalled();
    log.mockRestore();
    warn.mockRestore();
    error.mockRestore();
  });

  test('redacts attacker-controlled values and errors across pre-auth sync and membership ingress', async () => {
    const privateMarker = 'PRIVATE-INGRESS-ERROR-MARKER';
    const remoteDocumentId = '/ATTACKER-INGRESS-DOCUMENT-ID';
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const error = jest.spyOn(console, 'error').mockImplementation(() => {});

    const malformedSync = Object.create(PeerborneDocument.prototype) as any;
    Object.assign(malformedSync, {
      documentPath: '/doc',
      _securityProviderMutationFailure: undefined,
      _syncMessageSerializer: {
        serializeSyncMessage: () => {
          throw new Error(privateMarker);
        },
      },
    });
    await expect(
      malformedSync.sync({ documentId: remoteDocumentId }),
    ).resolves.toBe(false);

    const wrongDocumentMessage = { documentId: remoteDocumentId };
    const wrongDocumentSync = Object.create(PeerborneDocument.prototype) as any;
    Object.assign(wrongDocumentSync, {
      documentPath: '/doc',
      _securityProviderMutationFailure: undefined,
      _canonicalSyncMessages: new WeakSet([wrongDocumentMessage]),
    });
    await expect(wrongDocumentSync.sync(wrongDocumentMessage)).resolves.toBe(
      false,
    );

    const membershipIngress = Object.create(PeerborneDocument.prototype) as any;
    Object.assign(membershipIngress, {
      documentPath: '/doc',
      _securityProviderMutationFailure: undefined,
      _runBeeKEMRemoteIngress: async () => {
        throw new Error(privateMarker);
      },
    });
    await expect(
      membershipIngress.handleBeeKEMWelcomeRequestData(new Uint8Array([1])),
    ).resolves.toBeUndefined();
    await expect(
      membershipIngress.handleBeeKEMPathUpdateRequestData(new Uint8Array([1])),
    ).resolves.toBeUndefined();

    const keyUpdate = Object.create(PeerborneDocument.prototype) as any;
    Object.assign(keyUpdate, {
      documentPath: '/doc',
      _securityProviderMutationFailure: undefined,
      _keychainProvider: { keyIDLength: 1 },
      _authProvider: { nonceBits: 1 },
      _decryptBlock: async () => new Uint8Array([1]),
      _syncMessageSerializer: {
        deserializeSyncMessage: () => {
          throw new Error(privateMarker);
        },
      },
    });
    await expect(
      keyUpdate.handleKeyUpdateRequestData(new Uint8Array([1, 2, 3])),
    ).resolves.toBeUndefined();
    keyUpdate._syncMessageSerializer.deserializeSyncMessage = () => ({
      documentId: remoteDocumentId,
    });
    await expect(
      keyUpdate.handleKeyUpdateRequestData(new Uint8Array([1, 2, 3])),
    ).resolves.toBeUndefined();

    const logged = [...warn.mock.calls, ...error.mock.calls]
      .flat()
      .map(String)
      .join(' ');
    expect(logged).not.toContain(privateMarker);
    expect(logged).not.toContain(remoteDocumentId);
    expect(logged).toContain('/doc');
    warn.mockRestore();
    error.mockRestore();
  });

  test('a strict founder with no peers returns new-document without resolving trust', async () => {
    const resolveTuple = jest.fn(async () => tuple());
    const resolveWriters = jest.fn(async () => ['writer-a']);
    const document = Object.create(
      PeerborneDocument.prototype,
    ) as DocumentHarness;
    document.documentPath = '/doc';
    document.swarm = swarmWithCapturedPolicy({
      requireSecurityStateQuorum: true,
      resolveLoadSecurityCommitments: resolveTuple,
      resolveTrustedDocumentWriters: resolveWriters,
    });
    document._shuffledPeers = async () => [];

    await expect(document.load()).resolves.toBe(false);
    expect(resolveTuple).not.toHaveBeenCalled();
    expect(resolveWriters).not.toHaveBeenCalled();
  });

  test('load never returns a boolean after retirement during an awaited peer lookup', async () => {
    const document = Object.create(
      PeerborneDocument.prototype,
    ) as DocumentHarness;
    const retirement = new Error('retired while loading');
    document.documentPath = '/doc';
    document.swarm = swarmWithCapturedPolicy();
    document._securityProviderMutationFailure = undefined;
    document._shuffledPeers = async () => {
      document._securityProviderMutationFailure = retirement;
      return [];
    };

    await expect(document.load()).rejects.toBe(retirement);
  });

  test.each([
    ['missing', undefined],
    ['truthy non-boolean', async () => 'true' as unknown as boolean],
  ])(
    'strict open rejects ambiguous new-document creation with a %s authorizer',
    async (_kind, validateDocumentPath) => {
      const document = Object.create(
        PeerborneDocument.prototype,
      ) as DocumentHarness;
      document.documentPath = '/doc';
      document.swarm = swarmWithCapturedPolicy({
        requireAuthenticatedInitialLoad: true,
        validateDocumentPath,
      });
      document._computeTopic = () => '/topic/doc';
      document._hashes = new Set();
      document._userPublicKey = 'local-user';
      document.load = jest.fn(async () => false);

      await expect(document.open()).rejects.toThrow(
        validateDocumentPath === undefined
          ? /validateDocumentPath is required/
          : /is not allowed/,
      );
    },
  );

  test('a Welcome committed while creation validation awaits converts denial into an existing join', async () => {
    let validationEntered!: () => void;
    const entered = new Promise<void>((resolve) => {
      validationEntered = resolve;
    });
    let releaseValidation!: () => void;
    const released = new Promise<void>((resolve) => {
      releaseValidation = resolve;
    });
    const validateDocumentPath = jest.fn(async () => {
      validationEntered();
      await released;
      return false;
    });
    const pubsub = {
      addEventListener: jest.fn(),
      subscribe: jest.fn(),
      unsubscribe: jest.fn(),
      removeEventListener: jest.fn(),
      topicValidators: new Map(),
    };
    const registerDocument = jest.fn();
    const document = Object.create(PeerborneDocument.prototype) as any;
    Object.assign(document, {
      documentPath: '/doc',
      swarm: swarmWithCapturedPolicy(
        { validateDocumentPath },
        {
          heliaNode: { libp2p: { services: { pubsub } } },
          registerDocument,
          unregisterDocument: jest.fn(),
          unregisterWelcomeRecipient: jest.fn(),
        },
      ),
      _computeTopic: () => '/topic/doc',
      _hashes: new Set(),
      _userPublicKey: 'local-user',
      _invitationEpoch: undefined,
      _beekemInitialized: false,
      _beekemTransitionTail: Promise.resolve(),
      _beekemTransitionsPending: 0,
      _beekemRemoteTransitionsPending: 0,
      _subscribed: false,
      load: jest.fn(async () => false),
      _addWriter: jest.fn(),
      _keychain: { add: jest.fn() },
      _makeChange: jest.fn(),
    });

    const opening = document.open();
    await entered;
    await document._runBeeKEMTransition(async () => {
      document._invitationEpoch = bytes(4);
    });
    releaseValidation();

    await expect(opening).resolves.toBe(true);
    expect(validateDocumentPath).toHaveBeenCalledTimes(1);
    expect(registerDocument).toHaveBeenCalledWith('/doc', document);
    expect(document._addWriter).not.toHaveBeenCalled();
    expect(document._keychain.add).not.toHaveBeenCalled();
  });

  test('open cannot re-register a document retired while creation validation awaits', async () => {
    const retirement = new Error('retired during validation');
    let document: any;
    const validateDocumentPath = jest.fn(async () => {
      document._securityProviderMutationFailure = retirement;
      return true;
    });
    const pubsub = {
      addEventListener: jest.fn(),
      subscribe: jest.fn(),
      unsubscribe: jest.fn(),
      removeEventListener: jest.fn(),
      topicValidators: new Map(),
    };
    const registerDocument = jest.fn();
    document = Object.create(PeerborneDocument.prototype);
    Object.assign(document, {
      documentPath: '/doc',
      swarm: swarmWithCapturedPolicy(
        { validateDocumentPath },
        {
          heliaNode: { libp2p: { services: { pubsub } } },
          registerDocument,
          unregisterDocument: jest.fn(),
          unregisterWelcomeRecipient: jest.fn(),
        },
      ),
      _computeTopic: () => '/topic/doc',
      _hashes: new Set(),
      _userPublicKey: 'local-user',
      _invitationEpoch: undefined,
      _securityProviderMutationFailure: undefined,
      _subscribed: false,
      load: jest.fn(async () => false),
    });

    await expect(document.open()).rejects.toBe(retirement);
    expect(validateDocumentPath).toHaveBeenCalledTimes(1);
    expect(registerDocument).not.toHaveBeenCalled();
    expect(pubsub.subscribe).not.toHaveBeenCalled();
  });

  test('pubsub contains asynchronous decrypt rejection without decoding or syncing', async () => {
    const pubsub = {
      addEventListener: jest.fn(),
      subscribe: jest.fn(),
      unsubscribe: jest.fn(),
      removeEventListener: jest.fn(),
      topicValidators: new Map(),
    };
    const document = Object.create(PeerborneDocument.prototype) as any;
    const deserializeSyncMessage = jest.fn();
    const sync = jest.fn();
    Object.assign(document, {
      documentPath: '/doc',
      swarm: swarmWithCapturedPolicy(
        {},
        {
          heliaNode: { libp2p: { services: { pubsub } } },
          registerDocument: jest.fn(),
          unregisterDocument: jest.fn(),
          unregisterWelcomeRecipient: jest.fn(),
        },
      ),
      _computeTopic: () => '/topic/doc',
      _securityProviderMutationFailure: undefined,
      _subscribed: false,
      load: jest.fn(async () => true),
      _keychainProvider: { keyIDLength: 1 },
      _keychain: { getKey: () => ({}) },
      _authProvider: {
        nonceBits: 1,
        decrypt: jest.fn(async () => {
          throw new Error('invalid ciphertext');
        }),
      },
      _syncMessageSerializer: { deserializeSyncMessage },
      sync,
    });
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      await expect(document.open()).resolves.toBe(true);
      const handler = pubsub.addEventListener.mock.calls[0][1];
      handler({ detail: { data: new Uint8Array([1, 2, 3]) } });
      await new Promise<void>((resolve) => setTimeout(resolve, 0));

      expect(document._authProvider.decrypt).toHaveBeenCalledTimes(1);
      expect(deserializeSyncMessage).not.toHaveBeenCalled();
      expect(sync).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  test.each(['undefined', 'rejection'])(
    'fails closed before dialing when the tuple resolver returns %s',
    async (failureKind) => {
      const resolveTuple = jest.fn(async () => {
        if (failureKind === 'rejection') throw new Error('trust store offline');
        return undefined;
      });
      const resolveWriters = jest.fn(async () => ['writer-a']);
      const dialProtocol = jest.fn();
      const document = Object.create(
        PeerborneDocument.prototype,
      ) as DocumentHarness;
      document.documentPath = '/doc';
      document.swarm = swarmWithCapturedPolicy(
        {
          requireSecurityStateQuorum: true,
          resolveLoadSecurityCommitments: resolveTuple,
          resolveTrustedDocumentWriters: resolveWriters,
        },
        { heliaNode: { libp2p: { dialProtocol } } },
      );
      document._shuffledPeers = async () => [peer('a')];

      await expect(document.load()).rejects.toThrow(
        /resolveLoadSecurityCommitments/,
      );
      expect(resolveTuple).toHaveBeenCalledTimes(1);
      expect(resolveWriters).not.toHaveBeenCalled();
      expect(dialProtocol).not.toHaveBeenCalled();
    },
  );

  test('rejects an oversized streamed full response before any mutation', async () => {
    const document = Object.create(
      PeerborneDocument.prototype,
    ) as DocumentHarness;
    document.documentPath = '/doc';
    document.sync = jest.fn();
    const oneMiB = new Uint8Array(1024 * 1024);
    const responseCap = 2 * oneMiB.byteLength;
    const stream = {
      sink: jest.fn(async () => undefined),
      abort: jest.fn(),
      async *source() {
        for (let index = 0; index < 3; index++) yield oneMiB;
      },
    };

    await expect(
      document._sendLoadRequestAndSync(
        { sink: stream.sink, source: stream.source(), abort: stream.abort },
        new Uint8Array([1]),
        '00'.repeat(32),
        true,
        tuple(),
        { authorities: [], writerVersion: 0 },
        bytes(9),
        undefined,
        undefined,
        undefined,
        responseCap,
      ),
    ).rejects.toThrow(`exceeded ${responseCap} wire bytes`);
    expect(stream.abort).toHaveBeenCalledTimes(1);
    expect(document.sync).not.toHaveBeenCalled();
  });

  test.each(['false', 'throw', 'missing coverage'] as const)(
    'terminally retires after security-aware sync mutation followed by %s',
    async (failure) => {
      const { challenge, document, expected, message, stream } =
        await securityAwareFullLoadHarness();
      document.sync = jest.fn(async (candidate: object) => {
        const authorization =
          document._initialLoadSyncAuthorizations.get(candidate);
        authorization.onStateMutation();
        if (failure === 'throw') throw new Error('injected apply failure');
        if (failure === 'false') return false;
        return true;
      });

      const error = await document
        ._sendLoadRequestAndSync(
          { sink: stream.sink, source: stream.source() },
          new Uint8Array([1]),
          expected,
          true,
          tuple(),
          {
            authorities: [{ authorityId: 'writer-a', publicKey: 'writer-a' }],
            writerVersion: 0,
          },
          challenge,
        )
        .catch((cause: unknown) => cause);

      expect(error).toBe(document._securityProviderMutationFailure);
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).name).not.toBe('_QuorumBindCheckFailedError');
      expect((error as Error).message).toMatch(
        /after live document, snapshot, ACL, or keychain state mutation began/,
      );
      expect((error as Error).message).toMatch(/discard this document/);
      expect(document.close).toHaveBeenCalledTimes(1);
      expect(message.changes.change).toBeUndefined();
    },
  );

  test('terminally retires a V3 quorum load that fails after mutation admission', async () => {
    const expected = loadAdvertisementHashToHex(
      await loadAdvertisementHash('/doc', ['H']),
    );
    const message = {
      documentId: '/doc',
      changeId: 'H',
      changes: { kind: 'document' as const },
      tips: ['H'],
      signature: 'signature',
    };
    const document = Object.create(PeerborneDocument.prototype) as any;
    Object.assign(document, {
      documentPath: '/doc',
      swarm: swarmWithCapturedPolicy({}, {
        heliaNode: {
          blockstore: {
            async *get() {
              yield new Uint8Array([1, 2, 3]);
            },
          },
        },
      }),
      _securityProviderMutationFailure: undefined,
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 0,
      _cachedWriterKeys: null,
      _getWriterKeys: async () => ['writer-a'],
      _writers: { users: async () => ['writer-a'] },
      _verifyInitialLoadEnvelope: async () => true,
      _authProvider: {
        nonceBits: 1,
        decrypt: async (data: Uint8Array) => data,
      },
      _syncMessageSerializer: { deserializeSyncMessage: () => message },
      _keychainProvider: { keyIDLength: 1 },
      _keychain: { getKey: () => 'document-key' },
      _hashes: new Set<string>(),
      _initialLoadSyncAuthorizations: new WeakMap(),
      close: jest.fn(async () => undefined),
    });
    document.sync = jest.fn(async (candidate: object) => {
      document._initialLoadSyncAuthorizations
        .get(candidate)
        .onStateMutation();
      return false;
    });
    const stream = {
      sink: jest.fn(async () => undefined),
      async *source() {
        yield new Uint8Array([1, 2, 3]);
      },
    };

    const error = await document
      ._sendLoadRequestAndSync(
        { sink: stream.sink, source: stream.source() },
        new Uint8Array([1]),
        expected,
      )
      .catch((cause: unknown) => cause);

    expect(error).toBe(document._securityProviderMutationFailure);
    expect((error as Error).name).not.toBe('_QuorumBindCheckFailedError');
    expect((error as Error).message).toMatch(/initial-load application failed/);
  });

  test('terminally retires a quorum-disabled load that fails after mutation admission', async () => {
    const { document, stream } = await securityAwareFullLoadHarness();
    document._verifyInitialLoadEnvelope = async () => true;
    document.sync = jest.fn(async (candidate: object) => {
      document._initialLoadSyncAuthorizations
        .get(candidate)
        .onStateMutation();
      return false;
    });

    const error = await document
      ._sendLoadRequestAndSync(
        { sink: stream.sink, source: stream.source() },
        new Uint8Array([1]),
      )
      .catch((cause: unknown) => cause);

    expect(error).toBe(document._securityProviderMutationFailure);
    expect((error as Error).name).not.toBe('_QuorumBindCheckFailedError');
  });

  test.each(['false', 'throw'] as const)(
    'retires inside the mutation slot before a queued KEM mutation on sync %s',
    async (failure) => {
      const { document, stream } = await securityAwareFullLoadHarness();
      const originalKemKeyPair = { installed: true };
      const unregisterWelcomeRecipient = jest.fn();
      const pendingChange = jest.fn();
      let queuedKemResult: Promise<unknown> | undefined;
      let queuedEndChangeResult: Promise<unknown> | undefined;
      Object.assign(document, {
        swarm: {
          ...document.swarm,
          unregisterWelcomeRecipient,
        },
        _verifyInitialLoadEnvelope: async () => true,
        _document: { applied: 0 },
        _mergeSyncTree: async () =>
          failure === 'false'
            ? [
                ['INLINE', 'document', new Uint8Array([4])],
                ['MISSING', 'document', undefined],
              ]
            : [['INLINE', 'document', new Uint8Array([4])]],
        _referencedAncestors: new Set<string>(),
        _hashes: new Set<string>(),
        _recentTips: [],
        _lastSyncMessage: undefined,
        _documentChangeCount: 0,
        _changesSinceSnapshot: 0,
        _getBlock: jest.fn(async () => {
          throw new Error('injected deferred fetch failure');
        }),
        _crdtProvider: {
          remoteChange: (value: { applied: number }) => {
            value.applied++;
            queuedKemResult = document
              .setKemKeyPair(undefined)
              .catch((cause: unknown) => cause);
            queuedEndChangeResult = document
              .endChange()
              .catch((cause: unknown) => cause);
            if (failure === 'throw') {
              throw new Error('injected remote apply failure');
            }
            return value;
          },
        },
        _fireRemoteUpdateHandlers: async () => undefined,
        _refreshLastSyncMessageFromSync: jest.fn(),
        _maybeCompact: jest.fn(async () => undefined),
        _kemKeyPair: originalKemKeyPair,
        _kemPublicKeyRaw: new Uint8Array([1]),
        _inTransaction: true,
        _committing: false,
        _pendingChangeFns: [pendingChange],
      });
      const log = jest.spyOn(console, 'error').mockImplementation(() => {});
      let loadError: unknown;
      try {
        loadError = await document
          ._sendLoadRequestAndSync(
            { sink: stream.sink, source: stream.source() },
            new Uint8Array([1]),
          )
          .catch((cause: unknown) => cause);
      } finally {
        log.mockRestore();
      }
      const queuedError = await queuedKemResult;
      const queuedEndChangeError = await queuedEndChangeResult;

      expect(loadError).toBe(document._securityProviderMutationFailure);
      expect(queuedError).toBe(loadError);
      expect(queuedEndChangeError).toBe(loadError);
      expect(document._document).toEqual({ applied: 1 });
      expect(document._kemKeyPair).toBe(originalKemKeyPair);
      expect(unregisterWelcomeRecipient).not.toHaveBeenCalled();
      expect(document._inTransaction).toBe(true);
      expect(document._committing).toBe(false);
      expect(document._pendingChangeFns).toEqual([pendingChange]);
      expect(pendingChange).not.toHaveBeenCalled();
    },
  );

  test('retires quorum post-coverage failure before a queued mutation owns the slot', async () => {
    const { challenge, document, expected, stream } =
      await securityAwareFullLoadHarness();
    const originalKemKeyPair = { installed: true };
    const unregisterWelcomeRecipient = jest.fn();
    let queuedKemResult: Promise<unknown> | undefined;
    Object.assign(document, {
      swarm: {
        ...document.swarm,
        unregisterWelcomeRecipient,
      },
      _syncDocumentChanges: jest.fn(
        async (
          _changeId: string,
          _changes: unknown,
          _authorizationLease: unknown,
          _budget: unknown,
          admitStateMutation?: () => void,
        ) => {
          admitStateMutation?.();
          queuedKemResult = document
            .setKemKeyPair(undefined)
            .catch((cause: unknown) => cause);
          return true;
        },
      ),
      _kemKeyPair: originalKemKeyPair,
      _kemPublicKeyRaw: new Uint8Array([1]),
    });

    const loadError = await document
      ._sendLoadRequestAndSync(
        { sink: stream.sink, source: stream.source() },
        new Uint8Array([1]),
        expected,
        true,
        tuple(),
        {
          authorities: [{ authorityId: 'writer-a', publicKey: 'writer-a' }],
          writerVersion: 0,
        },
        challenge,
      )
      .catch((cause: unknown) => cause);
    const queuedError = await queuedKemResult;

    expect(loadError).toBe(document._securityProviderMutationFailure);
    expect((loadError as Error).name).not.toBe('_QuorumBindCheckFailedError');
    expect(queuedError).toBe(loadError);
    expect(document._kemKeyPair).toBe(originalKemKeyPair);
    expect(unregisterWelcomeRecipient).not.toHaveBeenCalled();
  });

  test('retires invitation completeness failure before a queued mutation owns the slot', async () => {
    const { document, stream } = await securityAwareFullLoadHarness();
    const originalKemKeyPair = { installed: true };
    const unregisterWelcomeRecipient = jest.fn();
    const admitInvitationMutation = jest.fn();
    let queuedKemResult: Promise<unknown> | undefined;
    Object.assign(document, {
      swarm: {
        ...document.swarm,
        unregisterWelcomeRecipient,
      },
      _verifyInitialLoadEnvelope: async () => true,
      _syncDocumentChanges: jest.fn(
        async (
          _changeId: string,
          _changes: unknown,
          _authorizationLease: unknown,
          _budget: unknown,
          admitStateMutation?: () => void,
        ) => {
          admitStateMutation?.();
          queuedKemResult = document
            .setKemKeyPair(undefined)
            .catch((cause: unknown) => cause);
          return true;
        },
      ),
      _kemKeyPair: originalKemKeyPair,
      _kemPublicKeyRaw: new Uint8Array([1]),
    });

    const loadError = await document
      ._sendLoadRequestAndSync(
        { sink: stream.sink, source: stream.source() },
        new Uint8Array([1]),
        null,
        false,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        true,
        admitInvitationMutation,
      )
      .catch((cause: unknown) => cause);
    const queuedError = await queuedKemResult;

    expect(loadError).toBe(document._securityProviderMutationFailure);
    expect(queuedError).toBe(loadError);
    expect(admitInvitationMutation).toHaveBeenCalledTimes(1);
    expect(document._kemKeyPair).toBe(originalKemKeyPair);
    expect(unregisterWelcomeRecipient).not.toHaveBeenCalled();
  });

  test('bounds deferred block reads on every initial-load candidate', async () => {
    let observedSignal: AbortSignal | undefined;
    const getBlock = async function* (
      _cid: unknown,
      options: { signal: AbortSignal },
    ) {
      observedSignal = options.signal;
      await new Promise<void>((_resolve, reject) => {
        const rejectForAbort = () => reject(options.signal.reason);
        if (options.signal.aborted) {
          rejectForAbort();
        } else {
          options.signal.addEventListener('abort', rejectForAbort, {
            once: true,
          });
        }
      });
      yield new Uint8Array([1, 2, 3]);
    };
    const { document, stream } = await securityAwareFullLoadHarness(
      { kind: 'document' },
      getBlock,
    );
    document.swarm.loadQuorumTimeoutMs = 1;
    document._verifyInitialLoadEnvelope = async () => true;
    document.sync = jest.fn(async (candidate: object) => {
      const budget = document._initialLoadSyncAuthorizations.get(
        candidate,
      ).deferredBlockBudget;
      await document._getBlock('H', budget);
      return true;
    });

    await expect(
      document._sendLoadRequestAndSync(
        { sink: stream.sink, source: stream.source() },
        new Uint8Array([1]),
      ),
    ).rejects.toThrow(/deferred block fetch timed out/);
    expect(observedSignal?.aborted).toBe(true);
    expect(document._securityProviderMutationFailure).toBeUndefined();
  });

  test('retires and blocks later deferred apply after the candidate deadline', async () => {
    const getBlock = jest.fn(async function* () {
      // Intentionally ignore the supplied AbortSignal. The document must
      // enforce cancellation at its own entry and chunk boundaries too.
      yield new Uint8Array([1, 2, 3]);
    });
    const { document, stream } = await securityAwareFullLoadHarness(
      { kind: 'document' },
      getBlock,
    );
    const remoteChange = jest.fn((value: { applied: number }) => ({
      applied: value.applied + 1,
    }));
    Object.assign(document, {
      swarm: {
        ...document.swarm,
        loadQuorumTimeoutMs: 1,
      },
      _verifyInitialLoadEnvelope: async () => true,
      _document: { applied: 0 },
      _mergeSyncTree: async () => [
        ['CID-0', 'document', undefined],
        ['CID-1', 'document', undefined],
      ],
      _referencedAncestors: new Set<string>(),
      _hashes: new Set<string>(),
      _recentTips: [],
      _lastSyncMessage: undefined,
      _documentChangeCount: 0,
      _changesSinceSnapshot: 0,
      _changesSerializer: {
        deserializeChanges: (value: Uint8Array) => value,
      },
      _crdtProvider: { remoteChange },
      _fireRemoteUpdateHandlers: async () => {
        await new Promise<void>((resolve) => setTimeout(resolve, 5));
      },
      _refreshLastSyncMessageFromSync: jest.fn(),
      _maybeCompact: jest.fn(async () => undefined),
    });
    document.sync = jest.fn(async (candidate: any) => {
      const authorization =
        document._initialLoadSyncAuthorizations.get(candidate);
      return document._syncDocumentChanges(
        candidate.changeId,
        candidate.changes,
        undefined,
        authorization.deferredBlockBudget,
        authorization.onStateMutation,
      );
    });
    const log = jest.spyOn(console, 'error').mockImplementation(() => {});
    let error: unknown;
    try {
      error = await document
        ._sendLoadRequestAndSync(
          { sink: stream.sink, source: stream.source() },
          new Uint8Array([1]),
        )
        .catch((cause: unknown) => cause);
    } finally {
      log.mockRestore();
    }

    expect(error).toBe(document._securityProviderMutationFailure);
    expect((error as Error).message).toMatch(/initial-load application failed/);
    expect(remoteChange).toHaveBeenCalledTimes(1);
    expect(getBlock).toHaveBeenCalledTimes(1);
    expect(document._document).toEqual({ applied: 1 });
  });

  test('checks the deferred deadline at the automatic-compaction mutation boundary', async () => {
    const getBlock = jest.fn(async function* () {
      yield new Uint8Array([1, 2, 3]);
    });
    const { document, stream } = await securityAwareFullLoadHarness(
      { kind: 'document' },
      getBlock,
    );
    const remoteChange = jest.fn((value: { applied: number }) => ({
      applied: value.applied + 1,
    }));
    const getSnapshot = jest.fn(() => new Uint8Array([9]));
    let writerCheckCalls = 0;
    Object.assign(document, {
      swarm: {
        ...document.swarm,
        loadQuorumTimeoutMs: 1,
      },
      _verifyInitialLoadEnvelope: async () => true,
      _document: { applied: 0 },
      _mergeSyncTree: async () => [['CID-0', 'document', undefined]],
      _referencedAncestors: new Set<string>(),
      _hashes: new Set<string>(),
      _recentTips: [],
      _lastSyncMessage: undefined,
      _latestSnapshot: undefined,
      _documentChangeCount: 0,
      _changesSinceSnapshot: 0,
      _changesSerializer: {
        deserializeChanges: (value: Uint8Array) => value,
      },
      _crdtProvider: { remoteChange, getSnapshot },
      _writers: {
        users: async () => ['writer-a'],
        check: async () => {
          writerCheckCalls++;
          if (writerCheckCalls === 2) {
            await new Promise<void>((resolve) => setTimeout(resolve, 5));
          }
          return true;
        },
      },
      _fireRemoteUpdateHandlers: async () => undefined,
      _refreshLastSyncMessageFromSync: jest.fn(),
      _compactionConfig: {
        enabled: true,
        minChangesBeforeSnapshot: 1,
        snapshotInterval: 1,
      },
      _snapshotUnsupported: false,
      _compactionInProgress: false,
    });
    const log = jest.spyOn(console, 'error').mockImplementation(() => {});
    let error: unknown;
    try {
      error = await document
        ._sendLoadRequestAndSync(
          { sink: stream.sink, source: stream.source() },
          new Uint8Array([1]),
        )
        .catch((cause: unknown) => cause);
    } finally {
      log.mockRestore();
    }

    expect(error).toBe(document._securityProviderMutationFailure);
    expect((error as Error).cause).toEqual(
      new Error('initial-load deferred block fetch timed out'),
    );
    expect(remoteChange).toHaveBeenCalledTimes(1);
    expect(writerCheckCalls).toBe(2);
    expect(getSnapshot).not.toHaveBeenCalled();
    expect(document._latestSnapshot).toBeUndefined();
    expect(document._compactionInProgress).toBe(false);
  });

  test.each([
    {
      label: 'single-block',
      changes: { kind: 'document' as const },
      getBlock: async function* () {
        yield new Uint8Array(9);
      },
      diagnostic: /block exceeded 8 encrypted bytes/,
    },
    {
      label: 'aggregate',
      changes: {
        kind: 'document' as const,
        children: { I: { kind: 'document' as const } },
      },
      getBlock: async function* () {
        yield new Uint8Array(5);
      },
      diagnostic: /blocks exceeded 8 aggregate encrypted bytes/,
    },
  ])(
    'rejects $label deferred-block prefetch over budget before sync',
    async ({ changes, getBlock, diagnostic }) => {
      const { challenge, document, expected, stream } =
        await securityAwareFullLoadHarness(changes, getBlock);
      document.sync = jest.fn();

      await expect(
        document._sendLoadRequestAndSync(
          { sink: stream.sink, source: stream.source() },
          new Uint8Array([1]),
          expected,
          true,
          tuple(),
          {
            authorities: [{ authorityId: 'writer-a', publicKey: 'writer-a' }],
            writerVersion: 0,
          },
          challenge,
          undefined,
          undefined,
          undefined,
          8,
        ),
      ).rejects.toThrow(diagnostic);
      expect(document.sync).not.toHaveBeenCalled();
      expect(document._securityProviderMutationFailure).toBeUndefined();
    },
  );

  test('charges quorum prefetch bytes to the candidate encrypted aggregate', async () => {
    const getBlock = jest.fn(async function* () {
      yield new Uint8Array(5);
    });
    const { challenge, document, expected, stream } =
      await securityAwareFullLoadHarness({ kind: 'document' }, getBlock);
    document.sync = jest.fn(async (candidate: object) => {
      const budget = document._initialLoadSyncAuthorizations.get(
        candidate,
      ).deferredBlockBudget;
      await document._getBlock('H', budget);
      return true;
    });

    await expect(
      document._sendLoadRequestAndSync(
        { sink: stream.sink, source: stream.source() },
        new Uint8Array([1]),
        expected,
        true,
        tuple(),
        {
          authorities: [{ authorityId: 'writer-a', publicKey: 'writer-a' }],
          writerVersion: 0,
        },
        challenge,
        undefined,
        undefined,
        undefined,
        8,
      ),
    ).rejects.toThrow(/exceeded 8 aggregate encrypted bytes/);
    expect(getBlock).toHaveBeenCalledTimes(2);
    expect(document._securityProviderMutationFailure).toBeUndefined();
  });

  test('bounds decoded deferred blocks per block and in aggregate before deserialization', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const signal = new AbortController().signal;
    const decodedLengths = [5, 5, 5];
    const deserializeChanges = jest.fn((value: Uint8Array) => value);
    Object.assign(document, {
      documentPath: '/doc',
      swarm: {
        heliaNode: {
          blockstore: {
            async *get() {
              yield new Uint8Array([1, 2, 3]);
            },
          },
        },
      },
      _keychainProvider: { keyIDLength: 1 },
      _keychain: { getKey: () => 'document-key' },
      _authProvider: {
        nonceBits: 1,
        decrypt: async () => new Uint8Array(decodedLengths.shift()!),
      },
      _changesSerializer: { deserializeChanges },
    });

    await expect(
      document._getBlock('per-block', {
        maxEncryptedBlockBytes: 8,
        maxEncryptedAggregateBytes: 8,
        maxDecodedBlockBytes: 4,
        maxDecodedAggregateBytes: 8,
        encryptedBytes: 0,
        decodedBytes: 0,
        signal,
        begin: () => undefined,
      }),
    ).rejects.toThrow(/exceeded 4 decoded bytes/);
    expect(deserializeChanges).not.toHaveBeenCalled();

    const aggregateBudget = {
      maxEncryptedBlockBytes: 8,
      maxEncryptedAggregateBytes: 8,
      maxDecodedBlockBytes: 5,
      maxDecodedAggregateBytes: 8,
      encryptedBytes: 0,
      decodedBytes: 0,
      signal,
      begin: () => undefined,
    };
    await expect(document._getBlock('first', aggregateBudget)).resolves.toEqual(
      new Uint8Array(5),
    );
    await expect(document._getBlock('second', aggregateBudget)).rejects.toThrow(
      /exceeded 8 aggregate decoded bytes/,
    );
    expect(deserializeChanges).toHaveBeenCalledTimes(1);
  });

  test('enforces deferred-block byte limits outside initial load', async () => {
    const decodedLimit = 16 * 1024 * 1024;
    const encryptedLimit = decodedLimit + 64 * 1024;
    let encryptedLength = encryptedLimit + 1;
    let decodedLength = 1;
    const deserializeChanges = jest.fn((value: Uint8Array) => value);
    const document = Object.create(PeerborneDocument.prototype) as any;
    Object.assign(document, {
      documentPath: '/doc',
      swarm: {
        heliaNode: {
          blockstore: {
            async *get() {
              yield new Uint8Array(encryptedLength);
            },
          },
        },
      },
      _keychainProvider: { keyIDLength: 1 },
      _keychain: { getKey: () => 'document-key' },
      _authProvider: {
        nonceBits: 1,
        decrypt: async () => new Uint8Array(decodedLength),
      },
      _changesSerializer: { deserializeChanges },
    });

    await expect(document._getBlock('encrypted')).rejects.toThrow(
      `exceeded ${encryptedLimit} encrypted bytes`,
    );
    encryptedLength = 3;
    decodedLength = decodedLimit + 1;
    await expect(document._getBlock('decoded')).rejects.toThrow(
      `exceeded ${decodedLimit} decoded bytes`,
    );
    expect(deserializeChanges).not.toHaveBeenCalled();
  });

  test('enforces the deferred-block limits symmetrically before publishing', async () => {
    const decodedLimit = 16 * 1024 * 1024;
    const encryptedLimit = decodedLimit + 64 * 1024;
    let decodedLength = decodedLimit;
    let encryptedLength = encryptedLimit;
    const encrypt = jest.fn(async () => ({
      nonce: new Uint8Array([2]),
      data: new Uint8Array(encryptedLength - 2),
    }));
    const addBytes = jest.fn(async () => ({ toString: () => 'CID' }));
    const document = Object.create(PeerborneDocument.prototype) as any;
    Object.assign(document, {
      documentPath: '/doc',
      _keychain: {
        current: async () => [new Uint8Array([1]), 'document-key'],
      },
      _changesSerializer: {
        serializeChanges: () => new Uint8Array(decodedLength),
      },
      _authProvider: { encrypt },
      heliaFs: { addBytes },
    });

    await expect(document._putBlock('change')).resolves.toBe('CID');
    expect(addBytes).toHaveBeenCalledTimes(1);

    decodedLength = decodedLimit + 1;
    encrypt.mockClear();
    await expect(document._putBlock('change')).rejects.toThrow(
      `exceeded ${decodedLimit} decoded bytes`,
    );
    expect(encrypt).not.toHaveBeenCalled();

    decodedLength = 1;
    encryptedLength = encryptedLimit + 1;
    addBytes.mockClear();
    await expect(document._putBlock('change')).rejects.toThrow(
      `exceeded ${encryptedLimit} encrypted bytes`,
    );
    expect(addBytes).not.toHaveBeenCalled();
  });

  test('checks every initial-load mutation while admitting the first only once', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const message = {
      documentId: '/doc',
      keychainChanges: new Uint8Array([1]),
      changes: { kind: 'document' as const },
      signature: 'AQ==',
    };
    const mutationGate = jest.fn();
    const firstMutationAdmission = jest.fn();
    let admitted = false;
    const onStateMutation = () => {
      mutationGate();
      if (admitted) return;
      admitted = true;
      firstMutationAdmission();
    };
    const applyTree = jest.fn(
      async (
        _changeId: string | undefined,
        _changes: unknown,
        _lease: unknown,
        _budget: unknown,
        admitStateMutation: () => void,
      ) => {
        admitStateMutation();
        admitStateMutation();
        return true;
      },
    );
    Object.assign(document, {
      documentPath: '/doc',
      swarm: { enableSigning: true },
      _securityProviderMutationFailure: undefined,
      _canonicalSyncMessages: new WeakSet([message]),
      _initialLoadSyncAuthorizations: new WeakMap([
        [
          message,
          {
            writerKeys: ['writer-a'],
            writerVersion: 3,
            onStateMutation,
          },
        ],
      ]),
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 3,
      _keychain: { merge: jest.fn() },
      _syncDocumentChanges: applyTree,
    });

    await expect(document.sync(message, false)).resolves.toBe(true);
    expect(mutationGate).toHaveBeenCalledTimes(3);
    expect(firstMutationAdmission).toHaveBeenCalledTimes(1);
    expect(applyTree).toHaveBeenCalledTimes(1);
  });

  test('bounds missing-block fetch and decrypt fan-out', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const entries = Array.from({ length: 24 }, (_, index) => [
      `CID-${index}`,
      'document',
      undefined,
    ]);
    let active = 0;
    let maximumActive = 0;
    Object.assign(document, {
      documentPath: '/doc',
      _document: {},
      _mergeSyncTree: async () => entries,
      _referencedAncestors: new Set<string>(),
      _hashes: new Set<string>(),
      _recentTips: [],
      _lastSyncMessage: undefined,
      _documentChangeCount: 0,
      _changesSinceSnapshot: 0,
      _getBlock: jest.fn(async () => {
        active++;
        maximumActive = Math.max(maximumActive, active);
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
        active--;
        return new Uint8Array([1]);
      }),
      _crdtProvider: { remoteChange: (value: unknown) => value },
      _fireRemoteUpdateHandlers: async () => undefined,
      _refreshLastSyncMessageFromSync: jest.fn(),
      _maybeCompact: jest.fn(async () => undefined),
    });
    await expect(
      document._syncDocumentChanges(undefined, { kind: 'document' }),
    ).resolves.toBe(true);

    expect(document._getBlock).toHaveBeenCalledTimes(entries.length);
    expect(maximumActive).toBe(8);
  });

  test('serializes aggregate-budgeted initial-load block fetch and decrypt work', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const entries = Array.from({ length: 12 }, (_, index) => [
      `CID-${index}`,
      'document',
      undefined,
    ]);
    let active = 0;
    let maximumActive = 0;
    Object.assign(document, {
      documentPath: '/doc',
      _document: {},
      _mergeSyncTree: async () => entries,
      _referencedAncestors: new Set<string>(),
      _hashes: new Set<string>(),
      _recentTips: [],
      _lastSyncMessage: undefined,
      _documentChangeCount: 0,
      _changesSinceSnapshot: 0,
      _getBlock: jest.fn(async () => {
        active++;
        maximumActive = Math.max(maximumActive, active);
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
        active--;
        return new Uint8Array([1]);
      }),
      _crdtProvider: { remoteChange: (value: unknown) => value },
      _fireRemoteUpdateHandlers: async () => undefined,
      _refreshLastSyncMessageFromSync: jest.fn(),
      _maybeCompact: jest.fn(async () => undefined),
    });
    const budget = {
      maxEncryptedBlockBytes: 8,
      maxEncryptedAggregateBytes: 128,
      maxDecodedBlockBytes: 8,
      maxDecodedAggregateBytes: 128,
      encryptedBytes: 0,
      decodedBytes: 0,
      signal: new AbortController().signal,
      begin: () => undefined,
    };
    await expect(
      document._syncDocumentChanges(
        undefined,
        { kind: 'document' },
        undefined,
        budget,
        jest.fn(),
      ),
    ).resolves.toBe(true);

    expect(document._getBlock).toHaveBeenCalledTimes(entries.length);
    expect(maximumActive).toBe(1);
  });

  test('stops scheduling deferred blocks after aggregate budget exhaustion', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const entries = Array.from({ length: 24 }, (_, index) => [
      `CID-${index}`,
      'document',
      undefined,
    ]);
    const fetched: string[] = [];
    const decrypt = jest.fn(async () => new Uint8Array(5));
    Object.assign(document, {
      documentPath: '/doc',
      _document: {},
      swarm: {
        heliaNode: {
          blockstore: {
            async *get(cid: string) {
              fetched.push(cid);
              yield new Uint8Array([1, 2, 3]);
            },
          },
        },
      },
      _keychainProvider: { keyIDLength: 1 },
      _keychain: { getKey: () => 'document-key' },
      _authProvider: { nonceBits: 1, decrypt },
      _changesSerializer: { deserializeChanges: (value: Uint8Array) => value },
      _crdtProvider: { remoteChange: (value: unknown) => value },
      _mergeSyncTree: async () => entries,
      _referencedAncestors: new Set<string>(),
      _hashes: new Set<string>(),
      _recentTips: [],
      _lastSyncMessage: undefined,
      _documentChangeCount: 0,
      _changesSinceSnapshot: 0,
      _fireRemoteUpdateHandlers: async () => undefined,
      _refreshLastSyncMessageFromSync: jest.fn(),
      _maybeCompact: jest.fn(async () => undefined),
    });
    const budget = {
      maxEncryptedBlockBytes: 8,
      maxEncryptedAggregateBytes: 128,
      maxDecodedBlockBytes: 5,
      maxDecodedAggregateBytes: 8,
      encryptedBytes: 0,
      decodedBytes: 0,
      signal: new AbortController().signal,
      begin: () => undefined,
    };
    const error = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      await expect(
        document._syncDocumentChanges(
          undefined,
          { kind: 'document' },
          undefined,
          budget,
          jest.fn(),
        ),
      ).resolves.toBe(false);
    } finally {
      error.mockRestore();
    }

    expect(fetched).toHaveLength(2);
    expect(fetched).toEqual(entries.slice(0, 2).map(([cid]) => cid));
    expect(decrypt).toHaveBeenCalledTimes(2);
    expect(document._refreshLastSyncMessageFromSync).not.toHaveBeenCalled();
  });

  test('stops deferred work and rethrows a terminal provider retirement', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const terminal = new Error('discard this retired document');
    const entries = Array.from({ length: 12 }, (_, index) => [
      `CID-${index}`,
      'reader',
      undefined,
    ]);
    const getBlock = jest.fn(async () => new Uint8Array([1]));
    Object.assign(document, {
      documentPath: '/doc',
      _document: {},
      _mergeSyncTree: async () => entries,
      _referencedAncestors: new Set<string>(),
      _hashes: new Set<string>(),
      _lastSyncMessage: undefined,
      _getBlock: getBlock,
      _mergeReaders: () => {
        document._securityProviderMutationFailure = terminal;
        throw terminal;
      },
      _refreshLastSyncMessageFromSync: jest.fn(),
      _maybeCompact: jest.fn(async () => undefined),
    });
    const budget = {
      maxEncryptedBlockBytes: 8,
      maxEncryptedAggregateBytes: 128,
      maxDecodedBlockBytes: 8,
      maxDecodedAggregateBytes: 128,
      encryptedBytes: 0,
      decodedBytes: 0,
      signal: new AbortController().signal,
      begin: () => undefined,
    };

    await expect(
      document._syncDocumentChanges(
        undefined,
        { kind: 'document' },
        undefined,
        budget,
        jest.fn(),
      ),
    ).rejects.toBe(terminal);
    expect(getBlock).toHaveBeenCalledTimes(1);
    expect(document._refreshLastSyncMessageFromSync).not.toHaveBeenCalled();
  });

  test('stops initial-load deferred work after the first apply failure', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const entries = Array.from({ length: 12 }, (_, index) => [
      `CID-${index}`,
      'document',
      undefined,
    ]);
    const getBlock = jest.fn(async () => new Uint8Array([1]));
    const remoteChange = jest.fn(() => {
      throw new Error('injected apply failure');
    });
    Object.assign(document, {
      documentPath: '/doc',
      _document: {},
      _mergeSyncTree: async () => entries,
      _referencedAncestors: new Set<string>(),
      _hashes: new Set<string>(),
      _lastSyncMessage: undefined,
      _getBlock: getBlock,
      _crdtProvider: { remoteChange },
      _refreshLastSyncMessageFromSync: jest.fn(),
      _maybeCompact: jest.fn(async () => undefined),
    });
    const budget = {
      maxEncryptedBlockBytes: 8,
      maxEncryptedAggregateBytes: 128,
      maxDecodedBlockBytes: 8,
      maxDecodedAggregateBytes: 128,
      encryptedBytes: 0,
      decodedBytes: 0,
      signal: new AbortController().signal,
      begin: () => undefined,
    };
    const log = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      await expect(
        document._syncDocumentChanges(
          undefined,
          { kind: 'document' },
          undefined,
          budget,
          jest.fn(),
        ),
      ).resolves.toBe(false);
    } finally {
      log.mockRestore();
    }

    expect(getBlock).toHaveBeenCalledTimes(1);
    expect(remoteChange).toHaveBeenCalledTimes(1);
    expect(document._refreshLastSyncMessageFromSync).not.toHaveBeenCalled();
  });

  test('does not log private codec errors or a mismatched remote document ID before response authentication', async () => {
    const privateMarker = 'PRIVATE-DECRYPTED-RESPONSE-MARKER';
    const remoteDocumentId = '/ATTACKER-RESPONSE-DOCUMENT-ID';
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});

    const run = async (deserializeSyncMessage: () => unknown) => {
      const document = Object.create(PeerborneDocument.prototype) as any;
      Object.assign(document, {
        documentPath: '/doc',
        _securityProviderMutationFailure: undefined,
        _keychainProvider: { keyIDLength: 1 },
        _keychain: { getKey: () => ({}) },
        _authProvider: {
          nonceBits: 8,
          decrypt: async () => new Uint8Array([7]),
        },
        _syncMessageSerializer: { deserializeSyncMessage },
      });
      const stream = {
        sink: jest.fn(async () => undefined),
        async *source() {
          yield new Uint8Array([1, 2, 3]);
        },
      };
      return document._sendLoadRequestAndSync(
        { sink: stream.sink, source: stream.source() },
        new Uint8Array([1]),
      );
    };

    await expect(
      run(() => {
        throw new Error(privateMarker);
      }),
    ).resolves.toBe(false);
    await expect(run(() => ({ documentId: remoteDocumentId }))).resolves.toBe(
      false,
    );

    const logged = warn.mock.calls.flat().join(' ');
    expect(logged).not.toContain(privateMarker);
    expect(logged).not.toContain(remoteDocumentId);
    expect(logged).toContain('/doc');
  });

  test('canonicalizes and re-verifies a signed legacy tree beyond 2048 object levels', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const serializer = new JSONSerializer<unknown>();
    const changes: CRDTChangeNode<unknown> = { kind: 'document' };
    let cursor = changes;
    const depth = 5_000;
    for (let level = 2; level <= depth; level++) {
      const child: CRDTChangeNode<unknown> = { kind: 'document' };
      cursor.children = { [`N${level}`]: child };
      cursor = child;
    }
    const applyTree = jest.fn(async () => true);
    const verify = jest.fn(async () => 7);
    Object.assign(document, {
      documentPath: '/doc',
      _syncMessageSerializer: serializer,
      _securityProviderMutationFailure: undefined,
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 7,
      _syncDocumentChanges: applyTree,
      _isSigningEnabled: () => true,
      _verifyWriterSignatureAtStableVersion: verify,
    });

    await expect(
      document.sync({
        documentId: '/doc',
        changeId: 'ROOT',
        changes,
        signature: 'AQ==',
      }),
    ).resolves.toBe(true);
    expect(verify).toHaveBeenCalledTimes(1);
    expect(applyTree).toHaveBeenCalledTimes(1);
  });

  test('walks and prunes a deep ACL-only legacy subtree without recursion', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const root: CRDTChangeNode<string> = { kind: 'document' };
    let cursor = root;
    const aclDepth = 5_000;
    for (let level = 1; level <= aclDepth; level++) {
      const child: CRDTChangeNode<string> = {
        kind: 'writer',
        change: `acl-${level}`,
      };
      cursor.children = { [`A${level}`]: child };
      cursor = child;
    }
    const candidate = {
      merge: jest.fn(),
      users: jest.fn(async () => ['writer-a']),
    };
    Object.assign(document, {
      documentPath: '/doc',
      _aclProvider: { initialize: () => candidate },
      _writers: { current: () => 'current-writers' },
      _lastSyncMessage: {
        documentId: '/doc',
        changeId: 'ROOT',
        changes: root,
      },
    });

    await expect(document._writerKeysIncludingTree(root)).resolves.toEqual([
      'writer-a',
    ]);
    expect(candidate.merge).toHaveBeenCalledTimes(aclDepth + 1);
    expect(() => document._pruneChanges(1)).not.toThrow();
    expect(Object.keys(root.children)).toHaveLength(aclDepth);
  });

  test('uses the shared 10 MiB cap at the exact public-sync boundary', async () => {
    const run = async (wireLength: number) => {
      const document = Object.create(PeerborneDocument.prototype) as any;
      const message = { documentId: '/doc' };
      Object.assign(document, {
        documentPath: '/doc',
        _securityProviderMutationFailure: undefined,
        _syncMessageSerializer: {
          serializeSyncMessage: () => new Uint8Array(wireLength),
          deserializeSyncMessage: () => message,
        },
        _sync: jest.fn(async () => true),
      });
      return document.sync(message);
    };

    await expect(run(MAX_SHARED_PROTOCOL_REQUEST_SIZE)).resolves.toBe(true);
    await expect(run(MAX_SHARED_PROTOCOL_REQUEST_SIZE + 1)).resolves.toBe(
      false,
    );
  });

  test('preflights the exact encrypted sender boundary before commit', async () => {
    const prepare = async (encryptedLength: number) => {
      const document = Object.create(PeerborneDocument.prototype) as any;
      const decoded = {
        documentId: '/doc',
        changeId: 'HASH',
        changes: { kind: 'document', change: 'delta' },
        signature: '',
      };
      Object.assign(document, {
        documentPath: '/doc',
        _recentTips: [],
        _securityProviderMutationFailure: undefined,
        _syncMessageSerializer: {
          serializeSyncMessage: () => new Uint8Array([1]),
          deserializeSyncMessage: () => decoded,
        },
        _putBlock: jest.fn(async () => 'HASH'),
        _signAsWriter: jest.fn(async () => ''),
        _keychain: {
          current: jest.fn(async () => [new Uint8Array([1]), {}]),
        },
        _authProvider: {
          encrypt: jest.fn(async () => ({
            nonce: new Uint8Array([2]),
            data: new Uint8Array(encryptedLength - 2),
          })),
        },
      });
      return document._prepareChange('delta');
    };

    const atLimit = await prepare(MAX_SHARED_PROTOCOL_REQUEST_SIZE);
    expect(atLimit.encryptedPayload.byteLength).toBe(
      MAX_SHARED_PROTOCOL_REQUEST_SIZE,
    );
    expect(atLimit.committed).toBe(false);
    await expect(prepare(MAX_SHARED_PROTOCOL_REQUEST_SIZE + 1)).rejects.toThrow(
      /outbound encrypted sync message/,
    );
  });

  test('preflights the exact direct key-update request boundary', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    document.documentPath = '/doc';
    document._encoder = new TextEncoder();
    const framingLength = 4 + new TextEncoder().encode('/doc').length;
    const prepare = (payloadLength: number) =>
      document._prepareKeyUpdate({
        encryptedPayload: new Uint8Array(payloadLength),
      });

    const atLimit = await prepare(
      MAX_SHARED_PROTOCOL_REQUEST_SIZE - framingLength,
    );
    expect(atLimit.payload.byteLength).toBe(MAX_SHARED_PROTOCOL_REQUEST_SIZE);
    await expect(
      prepare(MAX_SHARED_PROTOCOL_REQUEST_SIZE - framingLength + 1),
    ).rejects.toThrow(/V2 key-update request/);
  });

  test('full-load apply rejects a signer removed while outer authentication awaits', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const message = {
      documentId: '/doc',
      keychainChanges: new Uint8Array([9]),
      signature: 'AQ==',
    };
    let verificationEntered!: () => void;
    const entered = new Promise<void>((resolve) => {
      verificationEntered = resolve;
    });
    let releaseVerification!: () => void;
    const released = new Promise<void>((resolve) => {
      releaseVerification = resolve;
    });
    const keychainMerge = jest.fn();
    Object.assign(document, {
      documentPath: '/doc',
      swarm: swarmWithCapturedPolicy(),
      _securityProviderMutationFailure: undefined,
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 10,
      _cachedWriterKeys: null,
      _writers: { users: jest.fn(async () => ['writer-a']) },
      _keychainProvider: { keyIDLength: 1 },
      _keychain: {
        getKey: () => ({}),
        merge: keychainMerge,
      },
      _authProvider: {
        nonceBits: 1,
        decrypt: async () => new Uint8Array([7]),
      },
      _syncMessageSerializer: {
        deserializeSyncMessage: () => message,
      },
      _verifyInitialLoadEnvelope: jest.fn(async () => {
        verificationEntered();
        await released;
        return true;
      }),
    });
    const stream = {
      sink: jest.fn(async () => undefined),
      async *source() {
        yield new Uint8Array([1, 2, 3]);
      },
    };

    const loading = document._sendLoadRequestAndSync(
      { sink: stream.sink, source: stream.source() },
      new Uint8Array([1]),
    );
    await entered;
    document._writerKeysVersion = 12;
    document._cachedWriterKeys = ['writer-b'];
    releaseVerification();

    await expect(loading).resolves.toBe(false);
    expect(keychainMerge).not.toHaveBeenCalled();
  });

  test('does not apply invitation catch-up after its deadline fires during authentication', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const message = {
      documentId: '/doc',
      signature: 'AQ==',
    };
    let verificationEntered!: () => void;
    const entered = new Promise<void>((resolve) => {
      verificationEntered = resolve;
    });
    let releaseVerification!: () => void;
    const released = new Promise<void>((resolve) => {
      releaseVerification = resolve;
    });
    let operationSettled!: () => void;
    const settled = new Promise<void>((resolve) => {
      operationSettled = resolve;
    });
    const apply = jest.fn(async () => true);
    const publicSync = jest.fn(async () => true);
    Object.assign(document, {
      documentPath: '/doc',
      swarm: swarmWithCapturedPolicy(),
      _securityProviderMutationFailure: undefined,
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 0,
      _getWriterKeys: async () => ['writer-a'],
      _keychainProvider: { keyIDLength: 1 },
      _keychain: { getKey: () => ({}) },
      _authProvider: {
        nonceBits: 1,
        decrypt: async () => new Uint8Array([7]),
        verify: async () => {
          verificationEntered();
          await released;
          return true;
        },
      },
      _deserializeSignature: () => new Uint8Array([1]),
      _syncMessageSerializer: {
        deserializeSyncMessage: () => message,
        serializeSyncMessage: () => new Uint8Array([1]),
      },
      _verifyInitialLoadEnvelope: async () => true,
      _hashes: new Set<string>(),
      _syncUnlocked: apply,
      sync: publicSync,
    });
    const stream = {
      sink: jest.fn(async () => undefined),
      close: jest.fn(async () => undefined),
      abort: jest.fn((_error: Error) => undefined),
      source: (async function* () {
        yield new Uint8Array([1, 2, 3]);
      })(),
    };

    const loading = withIssuerPinnedInvitationStream(
      '/ip4/127.0.0.1/tcp/4001',
      async () => stream,
      (openedStream, signal, admitStateMutation) =>
        document
          ._sendLoadRequestAndSync(
            openedStream,
            new Uint8Array([1]),
            null,
            false,
            undefined,
            undefined,
            undefined,
            signal,
            undefined,
            'writer-a',
            undefined,
            true,
            admitStateMutation,
          )
          .finally(operationSettled),
      1,
    );
    await entered;
    await expect(loading).rejects.toThrow(/deadline exceeded/);
    releaseVerification();
    await settled;

    expect(stream.abort).toHaveBeenCalledTimes(1);
    expect(publicSync).not.toHaveBeenCalled();
    expect(apply).not.toHaveBeenCalled();
  });

  test('does not mutate when an invitation deadline fires during actual sync validation', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const snapshot = {
      state: new Uint8Array([4]),
      lastChangeNodeCID: 'S',
      compactedCount: 1,
      timestamp: 1,
      signature: new Uint8Array([5]),
    };
    const message = {
      documentId: '/doc',
      snapshot,
      signature: 'AQ==',
    };
    let snapshotValidationEntered!: () => void;
    const entered = new Promise<void>((resolve) => {
      snapshotValidationEntered = resolve;
    });
    let releaseSnapshotValidation!: () => void;
    const released = new Promise<void>((resolve) => {
      releaseSnapshotValidation = resolve;
    });
    let operationSettled!: () => void;
    const settled = new Promise<void>((resolve) => {
      operationSettled = resolve;
    });
    const applySnapshot = jest.fn(() => ({ applied: true }));
    Object.assign(document, {
      documentPath: '/doc',
      swarm: swarmWithCapturedPolicy(),
      _securityProviderMutationFailure: undefined,
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 0,
      _cachedWriterKeys: null,
      _document: { original: true },
      _latestSnapshot: undefined,
      _documentChangeCount: 0,
      _changesSinceSnapshot: 0,
      _hashes: new Set<string>(),
      _getWriterKeys: async () => ['writer-a'],
      _writerKeysIncludingTree: async () => ['writer-a'],
      _keychainProvider: { keyIDLength: 1 },
      _keychain: { getKey: () => ({}) },
      _authProvider: {
        nonceBits: 1,
        decrypt: async () => new Uint8Array([7]),
        verify: async () => true,
      },
      _deserializeSignature: () => new Uint8Array([1]),
      _syncMessageSerializer: {
        deserializeSyncMessage: () => message,
        serializeSyncMessage: () => new Uint8Array([1]),
      },
      _verifyInitialLoadEnvelope: async () => true,
      _buildSnapshotSignPayload: () => new Uint8Array([1]),
      _verifySnapshotSignature: async () => {
        snapshotValidationEntered();
        await released;
        return true;
      },
      _changesSerializer: { serializeChanges: () => new Uint8Array([4]) },
      _crdtProvider: { applySnapshot },
      close: jest.fn(async () => undefined),
    });
    const stream = {
      sink: jest.fn(async () => undefined),
      close: jest.fn(async () => undefined),
      abort: jest.fn((_error: Error) => undefined),
      source: (async function* () {
        yield new Uint8Array([1, 2, 3]);
      })(),
    };

    const loading = withIssuerPinnedInvitationStream(
      '/ip4/127.0.0.1/tcp/4001',
      async () => stream,
      (openedStream, signal, admitStateMutation) =>
        document
          ._sendLoadRequestAndSync(
            openedStream,
            new Uint8Array([1]),
            null,
            false,
            undefined,
            undefined,
            undefined,
            signal,
            undefined,
            'writer-a',
            undefined,
            true,
            admitStateMutation,
          )
          .finally(operationSettled),
      1,
    );
    await entered;
    await expect(loading).rejects.toThrow(/deadline exceeded/);
    releaseSnapshotValidation();
    await settled;

    expect(applySnapshot).not.toHaveBeenCalled();
    expect(document._document).toEqual({ original: true });
    expect(document._latestSnapshot).toBeUndefined();
    expect(document._securityProviderMutationFailure).toBeUndefined();
    expect(stream.abort).toHaveBeenCalledTimes(1);
  });

  test('rechecks catch-up cancellation inside the acquired mutation slot', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const message = {
      documentId: '/doc',
      signature: 'AQ==',
    };
    let queueEntered!: () => void;
    const entered = new Promise<void>((resolve) => {
      queueEntered = resolve;
    });
    let releaseQueue!: () => void;
    const released = new Promise<void>((resolve) => {
      releaseQueue = resolve;
    });
    const apply = jest.fn(async () => true);
    const admitStateMutation = jest.fn();
    Object.assign(document, {
      documentPath: '/doc',
      _securityProviderMutationFailure: undefined,
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 0,
      _getWriterKeys: async () => ['writer-a'],
      _keychainProvider: { keyIDLength: 1 },
      _keychain: { getKey: () => ({}) },
      _authProvider: {
        nonceBits: 1,
        decrypt: async () => new Uint8Array([7]),
        verify: async () => true,
      },
      _deserializeSignature: () => new Uint8Array([1]),
      _syncMessageSerializer: {
        deserializeSyncMessage: () => message,
        serializeSyncMessage: () => new Uint8Array([1]),
      },
      _verifyInitialLoadEnvelope: async () => true,
      _hashes: new Set<string>(),
      _syncUnlocked: apply,
    });
    Object.defineProperty(document, '_mutationQueue', {
      value: {
        run: async (operation: () => Promise<boolean>) => {
          queueEntered();
          await released;
          return operation();
        },
      },
    });
    const stream = {
      sink: jest.fn(async () => undefined),
      source: (async function* () {
        yield new Uint8Array([1, 2, 3]);
      })(),
    };
    const controller = new AbortController();

    const loading = document._sendLoadRequestAndSync(
      stream,
      new Uint8Array([1]),
      null,
      false,
      undefined,
      undefined,
      undefined,
      controller.signal,
      undefined,
      'writer-a',
      undefined,
      true,
      admitStateMutation,
    );
    await entered;
    const deadlineError = new Error('invitation stream deadline exceeded');
    controller.abort(deadlineError);
    releaseQueue();

    await expect(loading).rejects.toBe(deadlineError);
    expect(admitStateMutation).not.toHaveBeenCalled();
    expect(apply).not.toHaveBeenCalled();
  });

  test('rejects a security-aware load when a writer is removed and re-added during the probe round', async () => {
    const dialProtocol = jest.fn();
    const document = Object.create(PeerborneDocument.prototype) as any;
    let currentWriters = ['writer-a'];
    Object.assign(document, {
      documentPath: '/doc',
      swarm: swarmWithCapturedPolicy(
        {
          enableSigning: true,
          requireAuthenticatedInitialLoad: true,
          requireSecurityStateQuorum: true,
          loadQuorumK: 1,
          loadQuorumQ: 1,
          loadQuorumAllowSinglePeer: true,
          resolveLoadSecurityCommitments: async () => tuple(),
          resolveTrustedDocumentWriters: async () => ['bootstrap-writer'],
        },
        { heliaNode: { libp2p: { dialProtocol } } },
      ),
      _securityProviderMutationFailure: undefined,
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 10,
      _cachedWriterKeys: null,
      _writers: { users: jest.fn(async () => [...currentWriters]) },
      _authProvider: {
        sign: jest.fn(async () => new Uint8Array([1])),
        serializePublicKey: jest.fn(async (key: string) => key),
      },
      _encoder: new TextEncoder(),
      _userKey: 'local-key',
      _serializeSignature: jest.fn(() => 'signature'),
      _loadMessageSerializer: {
        serializeLoadRequest: jest.fn(() => new Uint8Array([1])),
      },
      _shuffledPeers: jest.fn(async () => [peer('a')]),
      sync: jest.fn(),
    });
    document._raceTipAdvertiseProbe = jest.fn(async () => {
      await document._runWriterMutation(async () => {
        currentWriters = [];
      });
      await document._runWriterMutation(async () => {
        currentWriters = ['writer-a'];
      });
      return { hash: bytes(7), signerAuthority: 'writer-a' };
    });

    await expect(document.load()).rejects.toThrow(
      /Writer authorization changed during the security-aware initial-load round/,
    );
    expect(currentWriters).toEqual(['writer-a']);
    expect(document._writerKeysVersion).toBe(14);
    expect(dialProtocol).not.toHaveBeenCalled();
    expect(document.sync).not.toHaveBeenCalled();
  });

  test.each(['changes', 'snapshot', 'keychainChanges'] as const)(
    'rejects nested accessor-backed V4 %s before manifest, auth, or sync',
    async (field) => {
      const document = Object.create(
        PeerborneDocument.prototype,
      ) as DocumentHarness;
      document.documentPath = '/doc';
      document._keychainProvider = { keyIDLength: 1 };
      document._keychain = { getKey: () => ({}) };
      document._authProvider = {
        nonceBits: 1,
        decrypt: async () => new Uint8Array([7]),
      };
      let accessorCalls = 0;
      const withAccessor = (base: Record<string, unknown>, property: string) =>
        new Proxy(
          Object.defineProperty(base, property, {
            enumerable: true,
            get() {
              accessorCalls++;
              return new Uint8Array([9]);
            },
          }),
          {
            get(target, key, receiver) {
              accessorCalls++;
              return Reflect.get(target, key, receiver);
            },
          },
        );
      const nested =
        field === 'changes'
          ? withAccessor({ kind: 'document' }, 'change')
          : field === 'snapshot'
            ? withAccessor(
                {
                  lastChangeNodeCID: 'bafy-snapshot',
                  compactedCount: 1,
                  timestamp: 1,
                  signature: new Uint8Array([1]),
                },
                'state',
              )
            : withAccessor({}, 'delta');
      const message: Record<string, unknown> = {
        documentId: '/doc',
        loadChallenge: bytes(9),
        [field]: nested,
      };
      document._syncMessageSerializer = {
        deserializeSyncMessage: () => message,
      };
      document._loadResponseManifestHash = jest.fn();
      document._identifyInitialLoadSignerAuthority = jest.fn();
      document.sync = jest.fn();
      const stream = {
        sink: jest.fn(async () => undefined),
        async *source() {
          yield new Uint8Array([1, 2, 3]);
        },
      };

      await expect(
        document._sendLoadRequestAndSync(
          { sink: stream.sink, source: stream.source() },
          new Uint8Array([1]),
          '00'.repeat(32),
          true,
          tuple(),
          { authorities: [], writerVersion: 0 },
          bytes(9),
        ),
      ).resolves.toBe(false);
      expect(accessorCalls).toBe(0);
      expect(document._loadResponseManifestHash).not.toHaveBeenCalled();
      expect(
        document._identifyInitialLoadSignerAuthority,
      ).not.toHaveBeenCalled();
      expect(document.sync).not.toHaveBeenCalled();
    },
  );

  test('keeps a pooled V4 nested byte graph detached across manifest verification', async () => {
    const document = Object.create(
      PeerborneDocument.prototype,
    ) as DocumentHarness;
    document.documentPath = '/doc';
    document._getWriterKeys = async () => [];
    document._keychainProvider = { keyIDLength: 1 };
    document._keychain = { getKey: () => ({}) };
    document._authProvider = {
      nonceBits: 1,
      decrypt: async () => new Uint8Array([7]),
    };
    const sharedKeychain = new Uint8Array([1, 2, 3]);
    const decoded = {
      documentId: '/doc',
      loadChallenge: bytes(9),
      keychainChanges: sharedKeychain,
    };
    document._syncMessageSerializer = {
      deserializeSyncMessage: () => decoded,
    };
    let manifestEntered!: () => void;
    const entered = new Promise<void>((resolve) => {
      manifestEntered = resolve;
    });
    let releaseManifest!: () => void;
    const released = new Promise<void>((resolve) => {
      releaseManifest = resolve;
    });
    let manifestMessage: any;
    document._loadResponseManifestHash = jest.fn(async (message: any) => {
      manifestMessage = message;
      manifestEntered();
      await released;
      expect(message.keychainChanges).toEqual(new Uint8Array([1, 2, 3]));
      return bytes(6);
    });
    document._identifyInitialLoadSignerAuthority = jest.fn(async () => null);
    document.sync = jest.fn();
    const stream = {
      sink: jest.fn(async () => undefined),
      async *source() {
        yield new Uint8Array([1, 2, 3]);
      },
    };

    const loading = document._sendLoadRequestAndSync(
      { sink: stream.sink, source: stream.source() },
      new Uint8Array([1]),
      '00'.repeat(32),
      true,
      tuple(),
      { authorities: [], writerVersion: 0 },
      bytes(9),
    );
    await entered;
    sharedKeychain[0] = 9;
    releaseManifest();

    await expect(loading).resolves.toBe(false);
    expect(manifestMessage.keychainChanges).toEqual(new Uint8Array([1, 2, 3]));
    expect(manifestMessage.keychainChanges).not.toBe(sharedKeychain);
    expect(document.sync).not.toHaveBeenCalled();
  });

  test.each(['inline change', 'snapshot state', 'keychain delta'])(
    'binds the complete %s in a V4 response before sync',
    async (candidateKind) => {
      const snapshot = {
        state: new Uint8Array([1]),
        lastChangeNodeCID: 'S',
        compactedCount: 1,
        timestamp: 1,
        signature: new Uint8Array([7]),
      };
      const baselineManifest = await loadResponseManifestHash({
        changeId: 'H',
        changes: {
          kind: 'document' as const,
          change:
            candidateKind === 'inline change' ? new Uint8Array([1]) : undefined,
        },
        serializeChange: (value) => value,
        snapshot:
          candidateKind === 'snapshot state'
            ? { ...snapshot, stateBytes: snapshot.state }
            : undefined,
        keychainChangesBytes:
          candidateKind === 'keychain delta' ? new Uint8Array([1]) : undefined,
      });
      const frontier = candidateKind === 'snapshot state' ? ['H', 'S'] : ['H'];
      const expected = loadAdvertisementHashToHex(
        await loadAdvertisementHash(
          '/doc',
          frontier,
          tuple(),
          baselineManifest,
        ),
      );
      const candidate = {
        documentId: '/doc',
        changeId: 'H',
        changes: {
          kind: 'document' as const,
          change:
            candidateKind === 'inline change' ? new Uint8Array([2]) : undefined,
        },
        tips: frontier,
        snapshot:
          candidateKind === 'snapshot state'
            ? { ...snapshot, state: new Uint8Array([2]) }
            : undefined,
        keychainChanges:
          candidateKind === 'keychain delta' ? new Uint8Array([2]) : undefined,
        loadSecurityState: tuple(),
        loadChallenge: bytes(8),
        signature: 'signature',
        testSigner: 'writer-a',
      };
      const document = Object.create(
        PeerborneDocument.prototype,
      ) as DocumentHarness;
      document.documentPath = '/doc';
      document.swarm = swarmWithCapturedPolicy({ enableSigning: true });
      document._getWriterKeys = async () => [];
      document._authProvider = {
        nonceBits: 1,
        decrypt: async (data: Uint8Array) => data,
        verify: async (payload: Uint8Array, key: string) =>
          new TextDecoder().decode(payload) === key,
      };
      document._deserializeSignature = () => new Uint8Array([1]);
      document._syncMessageSerializer = {
        deserializeSyncMessage: () => candidate,
        serializeSyncMessage: (message: { testSigner: string }) =>
          new TextEncoder().encode(message.testSigner),
      };
      document._changesSerializer = {
        serializeChanges: (value: Uint8Array) => value,
      };
      document._keychainProvider = { keyIDLength: 1 };
      document._keychain = { getKey: () => 'document-key' };
      document.sync = jest.fn(async () => true);
      const stream = {
        sink: jest.fn(async () => undefined),
        async *source() {
          yield new Uint8Array([1, 2, 3]);
        },
      };

      await expect(
        document._sendLoadRequestAndSync(
          { sink: stream.sink, source: stream.source() },
          new Uint8Array([1]),
          expected,
          true,
          tuple(),
          {
            authorities: [{ authorityId: 'writer-a', publicKey: 'writer-a' }],
            writerVersion: 0,
          },
          bytes(8),
        ),
      ).rejects.toThrow(/binding mismatch/);
      expect(document.sync).not.toHaveBeenCalled();
    },
  );

  test.each([
    ['advertisement', securityAdvertiseV1],
    ['full-document', documentLoadV4],
    ['snapshot', snapshotLoadV4],
  ])(
    'rejects a hostile %s V4 tuple before sync and never dials V3',
    async (candidateKind, candidateProtocol) => {
      const trustedResolverValue = tuple();
      const resolveTuple = jest.fn(async () => trustedResolverValue);
      const resolveWriters = jest.fn(async () => ['writer-a', 'writer-b']);
      const trustedAdvertisementHash = await loadAdvertisementHash(
        '/doc',
        ['cid-trusted'],
        tuple(),
        new Uint8Array(32).fill(4),
      );
      const messages = new Map<number, Record<string, unknown>>();
      let activeLoadChallenge: Uint8Array | undefined;
      let nextMarker = 1;
      const makeStream = (message: Record<string, unknown>) => {
        const marker = nextMarker++;
        messages.set(marker, message);
        return {
          send: jest.fn(() => true),
          onDrain: jest.fn(async () => undefined),
          close: jest.fn(async () => undefined),
          abort: jest.fn(),
          async *[Symbol.asyncIterator]() {
            yield new Uint8Array([1, 2, marker]);
          },
        };
      };

      const dialedProtocols: string[] = [];
      let resolverValueMutated = false;
      const runtimeConfig: Record<string, unknown> = {
        enableSigning: true,
        requireAuthenticatedInitialLoad: true,
        requireSecurityStateQuorum: true,
        // Emulate post-initialize config mutation below. V4 must still run
        // the quorum and must not degrade to an unquorumed load loop.
        loadQuorumEnabled: false,
        loadQuorumK: 2,
        loadQuorumQ: 2,
        resolveLoadSecurityCommitments: resolveTuple,
        resolveTrustedDocumentWriters: resolveWriters,
      };
      const libp2p = {
        dialProtocol: jest.fn(
          async (remote: ReturnType<typeof peer>, protocols: string[]) => {
            const protocol = protocols[0];
            dialedProtocols.push(protocol);
            if (protocol === securityAdvertiseV1) {
              // Mutation after load() captured the resolver output must not
              // alter the trusted tuple used by this in-flight round.
              if (!resolverValueMutated) {
                resolverValueMutated = true;
                trustedResolverValue.epoch = 1n;
                trustedResolverValue.treeHash.fill(9);
                runtimeConfig.requireSecurityStateQuorum = false;
              }
              return makeStream({
                documentId: '/doc',
                tipsHash: trustedAdvertisementHash,
                loadChallenge: new Uint8Array(activeLoadChallenge!),
                loadSecurityState:
                  candidateKind === 'advertisement'
                    ? tuple({ epoch: 7n, treeHash: bytes(9) })
                    : tuple(),
                signature: 'signature',
                testSigner: `writer-${remote.id.slice(-1)}`,
              });
            }
            if (protocol === candidateProtocol) {
              return makeStream({
                documentId: '/doc',
                loadChallenge: new Uint8Array(activeLoadChallenge!),
                loadSecurityState: tuple({
                  epoch: 7n,
                  confirmedTranscriptHash: bytes(9),
                }),
                signature: 'signature',
                testSigner: `writer-${remote.id.slice(-1)}`,
              });
            }
            throw new Error(`unexpected protocol ${protocol}`);
          },
        ),
      };

      const document = Object.create(
        PeerborneDocument.prototype,
      ) as DocumentHarness;
      document.documentPath = '/doc';
      document.swarm = swarmWithCapturedPolicy(runtimeConfig, {
        heliaNode: { libp2p },
      });
      document._shuffledPeers = async () => [peer('a'), peer('b')];
      document._getWriterKeys = async () => [];
      document._authProvider = {
        nonceBits: 1,
        sign: async () => new Uint8Array([1]),
        verify: async (payload: Uint8Array, key: string) =>
          new TextDecoder().decode(payload) === key,
        decrypt: async (data: Uint8Array) => data,
        serializePublicKey: async (key: string) => key,
      };
      document._encoder = new TextEncoder();
      document._userKey = 'local-key';
      document._serializeSignature = () => 'signature';
      document._deserializeSignature = () => new Uint8Array([1]);
      document._loadMessageSerializer = {
        serializeLoadRequest: (request: { loadChallenge?: Uint8Array }) => {
          activeLoadChallenge = new Uint8Array(request.loadChallenge!);
          return new Uint8Array([1]);
        },
      };
      document._syncMessageSerializer = {
        deserializeSyncMessage: (data: Uint8Array) => messages.get(data[0]),
        serializeSyncMessage: (message: { testSigner: string }) =>
          new TextEncoder().encode(message.testSigner),
      };
      document._keychainProvider = { keyIDLength: 1 };
      document._keychain = { getKey: () => 'document-key' };
      document._compactionConfig = { enabled: candidateKind === 'snapshot' };
      document.sync = jest.fn(async () => {
        throw new Error('sync must not run for an untrusted tuple');
      });

      const error = await document.load().catch((cause: unknown) => cause);
      expect(error).toBeInstanceOf(LoadQuorumFailedError);
      expect(resolveTuple).toHaveBeenCalledTimes(1);
      expect(resolveWriters).toHaveBeenCalledTimes(1);
      expect(document.sync).not.toHaveBeenCalled();
      expect(dialedProtocols).toContain(securityAdvertiseV1);
      expect(dialedProtocols).toContain(candidateProtocol);
      expect(dialedProtocols).not.toContain(documentLoadV3);
      expect(dialedProtocols).not.toContain(snapshotLoadV3);
      expect(dialedProtocols).not.toContain(tipAdvertiseV1);
    },
  );

  test('rejects a complete prior-round V4 replay before sync and never downgrades', async () => {
    const planHash = await loadResponseManifestHash({
      changeId: 'H',
      changes: { kind: 'document' as const },
    });
    const advertisedHash = await loadAdvertisementHash(
      '/doc',
      ['H'],
      tuple(),
      planHash,
    );
    const messages = new Map<number, Record<string, unknown>>();
    let nextMarker = 1;
    const makeStream = (
      message: Record<string, unknown>,
      abort = jest.fn(),
    ) => {
      const marker = nextMarker++;
      messages.set(marker, message);
      return {
        send: jest.fn(() => true),
        onDrain: jest.fn(async () => undefined),
        close: jest.fn(async () => undefined),
        abort,
        async *[Symbol.asyncIterator]() {
          yield new Uint8Array([1, 2, marker]);
        },
      };
    };

    let requestRound = 0;
    let activeLoadChallenge: Uint8Array | undefined;
    const roundChallenges: Uint8Array[] = [];
    const recordedAdvertisements = new Map<string, Record<string, unknown>>();
    let recordedFullResponse: Record<string, unknown> | undefined;
    const dialedProtocols: string[] = [];
    let fullLoadDials = 0;
    const libp2p = {
      dialProtocol: jest.fn(
        async (remote: ReturnType<typeof peer>, protocols: string[]) => {
          const protocol = protocols[0];
          dialedProtocols.push(protocol);
          if (protocol === securityAdvertiseV1) {
            if (requestRound === 1) {
              const advertisement = {
                documentId: '/doc',
                tipsHash: advertisedHash,
                loadSecurityState: tuple(),
                loadChallenge: new Uint8Array(activeLoadChallenge!),
                signature: 'signature',
                testSigner: `writer-${remote.id}`,
              };
              recordedAdvertisements.set(remote.id, advertisement);
              return makeStream(advertisement);
            }
            // Replay the exact Q writer-signed advertisements from round one.
            return makeStream(recordedAdvertisements.get(remote.id)!);
          }
          if (protocol === documentLoadV4) {
            fullLoadDials++;
            if (requestRound === 1) {
              recordedFullResponse = {
                documentId: '/doc',
                changeId: 'H',
                changes: { kind: 'document' },
                tips: ['H'],
                loadSecurityState: tuple(),
                loadChallenge: new Uint8Array(activeLoadChallenge!),
                signature: 'signature',
                testSigner: `writer-${remote.id}`,
              };
            }
            // If a broken quorum implementation accepts the old votes, also
            // replay their matching old full response. The full-response gate
            // independently rejects the stale challenge before sync.
            return makeStream(recordedFullResponse!);
          }
          throw new Error(`unexpected protocol ${protocol}`);
        },
      ),
    };
    const resolveTuple = jest.fn(async () => tuple());
    const resolveWriters = jest.fn(async () => ['writer-a', 'writer-b']);
    const document = Object.create(
      PeerborneDocument.prototype,
    ) as DocumentHarness;
    document.documentPath = '/doc';
    document.swarm = swarmWithCapturedPolicy(
      {
        enableSigning: true,
        requireAuthenticatedInitialLoad: true,
        requireSecurityStateQuorum: true,
        loadQuorumK: 2,
        loadQuorumQ: 2,
        resolveLoadSecurityCommitments: resolveTuple,
        resolveTrustedDocumentWriters: resolveWriters,
      },
      {
        heliaNode: {
          libp2p,
          blockstore: {
            async *get() {
              yield new Uint8Array([1]);
            },
          },
        },
      },
    );
    document._shuffledPeers = async () => [peer('a'), peer('b')];
    document._getWriterKeys = async () => [];
    document._writers = { users: async () => [] };
    document._authProvider = {
      nonceBits: 1,
      sign: async () => new Uint8Array([1]),
      verify: async (payload: Uint8Array, key: string) =>
        new TextDecoder().decode(payload).startsWith(`${key}|`),
      decrypt: async (data: Uint8Array) => data,
      serializePublicKey: async (key: string) => key,
    };
    document._encoder = new TextEncoder();
    document._userKey = 'local-key';
    document._serializeSignature = () => 'signature';
    document._deserializeSignature = () => new Uint8Array([1]);
    document._encoder = new TextEncoder();
    document._loadMessageSerializer = {
      serializeLoadRequest: (request: { loadChallenge?: Uint8Array }) => {
        requestRound++;
        activeLoadChallenge = new Uint8Array(request.loadChallenge!);
        roundChallenges.push(new Uint8Array(activeLoadChallenge));
        return new Uint8Array([requestRound]);
      },
    };
    document._syncMessageSerializer = {
      deserializeSyncMessage: (data: Uint8Array) => messages.get(data[0]),
      // The mock envelope bytes include the echoed challenge, mirroring the
      // real serializers' writer-signature coverage.
      serializeSyncMessage: (message: {
        testSigner?: string;
        loadChallenge?: Uint8Array;
      }) =>
        new TextEncoder().encode(
          `${message.testSigner ?? ''}|${Array.from(
            message.loadChallenge ?? [],
          ).join(',')}`,
        ),
    };
    document._keychainProvider = { keyIDLength: 1 };
    document._keychain = { getKey: () => 'document-key' };
    document._compactionConfig = { enabled: false };
    document._hashes = new Set<string>();
    document.sync = jest.fn(async () => {
      document._hashes.add('H');
      return true;
    });

    await expect(document.load()).resolves.toBe(true);
    expect(document.sync).toHaveBeenCalledTimes(1);
    expect(fullLoadDials).toBe(1);
    document.sync.mockClear();

    const replayError = await document.load().catch((cause: unknown) => cause);
    expect(replayError).toBeInstanceOf(LoadQuorumFailedError);
    expect(roundChallenges).toHaveLength(2);
    expect(roundChallenges[1]).not.toEqual(roundChallenges[0]);
    expect(document.sync).not.toHaveBeenCalled();
    expect(document._hashes).toEqual(new Set(['H']));
    expect(fullLoadDials).toBe(1);
    expect(resolveTuple).toHaveBeenCalledTimes(2);
    expect(resolveWriters).toHaveBeenCalledTimes(2);
    expect(dialedProtocols).not.toContain(documentLoadV3);
    expect(dialedProtocols).not.toContain(snapshotLoadV3);
    expect(dialedProtocols).not.toContain(tipAdvertiseV1);
  });

  test('times out a stalled agreeing full responder and loads from the next honest peer', async () => {
    const planHash = await loadResponseManifestHash({
      changeId: 'H',
      changes: { kind: 'document' as const },
    });
    const advertisedHash = await loadAdvertisementHash(
      '/doc',
      ['H'],
      tuple(),
      planHash,
    );
    const messages = new Map<number, Record<string, unknown>>();
    let nextMarker = 1;
    let activeLoadChallenge: Uint8Array | undefined;
    const makeStream = (
      message: Record<string, unknown>,
      abort = jest.fn(),
    ) => {
      const marker = nextMarker++;
      messages.set(marker, message);
      return {
        send: jest.fn(() => true),
        onDrain: jest.fn(async () => undefined),
        close: jest.fn(async () => undefined),
        abort,
        async *[Symbol.asyncIterator]() {
          yield new Uint8Array([1, 2, marker]);
        },
      };
    };
    let releaseStalled!: () => void;
    const stalledReleased = new Promise<void>((resolve) => {
      releaseStalled = resolve;
    });
    const stalledAbort = jest.fn(() => releaseStalled());
    const honestFullAbort = jest.fn();
    const stalledStream = {
      send: jest.fn(() => true),
      onDrain: jest.fn(async () => undefined),
      close: jest.fn(async () => undefined),
      abort: stalledAbort,
      async *[Symbol.asyncIterator]() {
        await stalledReleased;
      },
    };
    const fullAttempts: string[] = [];
    const libp2p = {
      dialProtocol: jest.fn(
        async (remote: ReturnType<typeof peer>, protocols: string[]) => {
          const protocol = protocols[0];
          if (protocol === securityAdvertiseV1) {
            return makeStream({
              documentId: '/doc',
              tipsHash: advertisedHash,
              loadSecurityState: tuple(),
              loadChallenge: new Uint8Array(activeLoadChallenge!),
              signature: 'signature',
              testSigner: `writer-${remote.id}`,
            });
          }
          if (protocol === documentLoadV4) {
            fullAttempts.push(remote.id);
            if (remote.id === 'a') return stalledStream;
            return makeStream(
              {
                documentId: '/doc',
                changeId: 'H',
                changes: { kind: 'document' },
                tips: ['H'],
                loadSecurityState: tuple(),
                loadChallenge: new Uint8Array(activeLoadChallenge!),
                signature: 'signature',
                testSigner: `writer-${remote.id}`,
              },
              honestFullAbort,
            );
          }
          throw new Error(`unexpected protocol ${protocol}`);
        },
      ),
    };
    const resolveTuple = jest.fn(async () => tuple());
    const resolveWriters = jest.fn(async () => ['writer-a', 'writer-b']);
    const document = Object.create(
      PeerborneDocument.prototype,
    ) as DocumentHarness;
    document.documentPath = '/doc';
    document.swarm = swarmWithCapturedPolicy(
      {
        enableSigning: true,
        requireAuthenticatedInitialLoad: true,
        requireSecurityStateQuorum: true,
        loadQuorumK: 2,
        loadQuorumQ: 2,
        loadQuorumTimeoutMs: 20,
        resolveLoadSecurityCommitments: resolveTuple,
        resolveTrustedDocumentWriters: resolveWriters,
      },
      {
        heliaNode: {
          libp2p,
          blockstore: {
            async *get() {
              yield new Uint8Array([1]);
            },
          },
        },
      },
    );
    document._shuffledPeers = async () => [peer('a'), peer('b')];
    document._getWriterKeys = async () => [];
    document._writers = { users: async () => [] };
    document._authProvider = {
      nonceBits: 1,
      sign: async () => new Uint8Array([1]),
      verify: async (payload: Uint8Array, key: string) =>
        new TextDecoder().decode(payload).startsWith(`${key}|`),
      decrypt: async (data: Uint8Array) => data,
      serializePublicKey: async (key: string) => key,
    };
    document._encoder = new TextEncoder();
    document._userKey = 'local-key';
    document._serializeSignature = () => 'signature';
    document._deserializeSignature = () => new Uint8Array([1]);
    document._loadMessageSerializer = {
      serializeLoadRequest: (request: { loadChallenge?: Uint8Array }) => {
        activeLoadChallenge = new Uint8Array(request.loadChallenge!);
        return new Uint8Array([1]);
      },
    };
    document._syncMessageSerializer = {
      deserializeSyncMessage: (data: Uint8Array) => messages.get(data[0]),
      serializeSyncMessage: (message: {
        testSigner?: string;
        loadChallenge?: Uint8Array;
      }) =>
        new TextEncoder().encode(
          `${message.testSigner ?? ''}|${Array.from(
            message.loadChallenge ?? [],
          ).join(',')}`,
        ),
    };
    document._keychainProvider = { keyIDLength: 1 };
    document._keychain = { getKey: () => 'document-key' };
    document._compactionConfig = { enabled: false };
    document._hashes = new Set<string>();
    document.sync = jest.fn(async () => {
      document._hashes.add('H');
      return true;
    });

    await expect(document.load()).resolves.toBe(true);
    expect(fullAttempts).toEqual(['a', 'b']);
    expect(stalledAbort).toHaveBeenCalledTimes(1);
    expect(honestFullAbort).toHaveBeenCalledTimes(1);
    expect(document.sync).toHaveBeenCalledTimes(1);
  });

  test('bounds V4 block prefetch after the response-body deadline is disarmed', async () => {
    const challenge = bytes(8);
    const manifest = await loadResponseManifestHash({
      changeId: 'H',
      changes: { kind: 'document' as const },
    });
    const expected = loadAdvertisementHashToHex(
      await loadAdvertisementHash('/doc', ['H'], tuple(), manifest),
    );
    const message = {
      documentId: '/doc',
      changeId: 'H',
      changes: { kind: 'document' as const },
      tips: ['H'],
      loadSecurityState: tuple(),
      loadChallenge: challenge,
      signature: 'signature',
      testSigner: 'writer-a',
    };
    let prefetchSignal: AbortSignal | undefined;
    const document = Object.create(PeerborneDocument.prototype) as any;
    document.documentPath = '/doc';
    document.swarm = swarmWithCapturedPolicy(
      { loadQuorumTimeoutMs: 10 },
      {
        heliaNode: {
          blockstore: {
            async *get(_cid: unknown, options: { signal: AbortSignal }) {
              prefetchSignal = options.signal;
              await new Promise<void>((resolve) =>
                options.signal.addEventListener('abort', () => resolve(), {
                  once: true,
                }),
              );
              throw options.signal.reason;
            },
          },
        },
      },
    );
    document._authProvider = {
      nonceBits: 1,
      decrypt: async (data: Uint8Array) => data,
      verify: async (raw: Uint8Array, key: string) =>
        new TextDecoder().decode(raw) === key,
    };
    document._deserializeSignature = () => new Uint8Array([1]);
    document._syncMessageSerializer = {
      deserializeSyncMessage: () => message,
      serializeSyncMessage: (value: { testSigner?: string }) =>
        new TextEncoder().encode(value.testSigner ?? ''),
    };
    document._keychainProvider = { keyIDLength: 1 };
    document._keychain = { getKey: () => 'document-key' };
    document._writers = { users: async () => ['writer-a'] };
    document.sync = jest.fn(async () => true);
    const stream = {
      sink: jest.fn(async () => undefined),
      async *source() {
        yield new Uint8Array([1, 2, 3]);
      },
    };

    await expect(
      document._sendLoadRequestAndSync(
        { sink: stream.sink, source: stream.source() },
        new Uint8Array([1]),
        expected,
        true,
        tuple(),
        {
          authorities: [{ authorityId: 'writer-a', publicKey: 'writer-a' }],
          writerVersion: 0,
        },
        challenge,
      ),
    ).rejects.toThrow(/pre-fetch exceeded 10ms/);
    expect(prefetchSignal?.aborted).toBe(true);
    expect(document.sync).not.toHaveBeenCalled();
  });

  test('legacy load keeps the full-response deadline when quorum is disabled', async () => {
    const messages = new Map<number, Record<string, unknown>>();
    let nextMarker = 1;
    const honestAbort = jest.fn();
    const makeStream = (
      message: Record<string, unknown>,
      abort = jest.fn(),
    ) => {
      const marker = nextMarker++;
      messages.set(marker, message);
      return {
        send: jest.fn(() => true),
        onDrain: jest.fn(async () => undefined),
        close: jest.fn(async () => undefined),
        abort,
        async *[Symbol.asyncIterator]() {
          yield new Uint8Array([1, 2, marker]);
        },
      };
    };
    let releaseStalled!: () => void;
    const stalledReleased = new Promise<void>((resolve) => {
      releaseStalled = resolve;
    });
    const stalledAbort = jest.fn(() => releaseStalled());
    const stalledStream = {
      send: jest.fn(() => true),
      onDrain: jest.fn(async () => undefined),
      close: jest.fn(async () => undefined),
      abort: stalledAbort,
      async *[Symbol.asyncIterator]() {
        await stalledReleased;
      },
    };
    const attempts: string[] = [];
    const libp2p = {
      dialProtocol: jest.fn(
        async (remote: ReturnType<typeof peer>, protocols: string[]) => {
          expect(protocols[0]).toBe(documentLoadV3);
          attempts.push(remote.id);
          if (remote.id === 'a') return stalledStream;
          return makeStream(
            {
              documentId: '/legacy-doc',
              changeId: 'H',
              changes: { kind: 'document' },
              signature: 'signature',
              testSigner: 'writer',
            },
            honestAbort,
          );
        },
      ),
    };
    const document = Object.create(
      PeerborneDocument.prototype,
    ) as DocumentHarness;
    document.documentPath = '/legacy-doc';
    document.swarm = swarmWithCapturedPolicy(
      {
        enableSigning: true,
        loadQuorumEnabled: false,
        loadQuorumTimeoutMs: 20,
      },
      { heliaNode: { libp2p } },
    );
    document._shuffledPeers = async () => [peer('a'), peer('b')];
    document._getWriterKeys = async () => ['writer'];
    document._writers = { users: async () => ['writer'] };
    document._authProvider = {
      nonceBits: 1,
      verify: async (payload: Uint8Array, key: string) =>
        new TextDecoder().decode(payload) === key,
      decrypt: async (data: Uint8Array) => data,
      sign: async () => new Uint8Array([1]),
    };
    document._deserializeSignature = () => new Uint8Array([1]);
    document._serializeSignature = () => 'signature';
    document._encoder = new TextEncoder();
    document._loadMessageSerializer = {
      serializeLoadRequest: () => new Uint8Array([1]),
    };
    document._syncMessageSerializer = {
      deserializeSyncMessage: (data: Uint8Array) => messages.get(data[0]),
      serializeSyncMessage: (message: { testSigner: string }) =>
        new TextEncoder().encode(message.testSigner),
    };
    document._keychainProvider = { keyIDLength: 1 };
    document._keychain = { getKey: () => 'document-key' };
    document._compactionConfig = { enabled: false };
    document._hashes = new Set<string>();
    document.sync = jest.fn(async () => true);

    await expect(document.load()).resolves.toBe(true);
    expect(attempts).toEqual(['a', 'b']);
    expect(stalledAbort).toHaveBeenCalledTimes(1);
    expect(honestAbort).toHaveBeenCalledTimes(1);
    expect(document.sync).toHaveBeenCalledTimes(1);
  });

  test('rejects same-frontier closure smuggling before sync and never falls back to V3', async () => {
    const honestPlanHash = await loadResponseManifestHash({
      changeId: 'H',
      changes: { kind: 'document' as const },
    });
    const advertisedHash = await loadAdvertisementHash(
      '/doc',
      ['H'],
      tuple(),
      honestPlanHash,
    );
    const messages = new Map<number, Record<string, unknown>>();
    let activeLoadChallenge: Uint8Array | undefined;
    let nextMarker = 1;
    const makeStream = (message: Record<string, unknown>) => {
      const marker = nextMarker++;
      messages.set(marker, message);
      return {
        send: jest.fn(() => true),
        onDrain: jest.fn(async () => undefined),
        close: jest.fn(async () => undefined),
        abort: jest.fn(),
        async *[Symbol.asyncIterator]() {
          yield new Uint8Array([1, 2, marker]);
        },
      };
    };
    const dialedProtocols: string[] = [];
    const libp2p = {
      dialProtocol: jest.fn(
        async (remote: ReturnType<typeof peer>, protocols: string[]) => {
          const protocol = protocols[0];
          dialedProtocols.push(protocol);
          if (protocol === securityAdvertiseV1) {
            return makeStream({
              documentId: '/doc',
              tipsHash: advertisedHash,
              loadChallenge: new Uint8Array(activeLoadChallenge!),
              loadSecurityState: tuple(),
              signature: 'signature',
              testSigner: `writer-${remote.id}`,
            });
          }
          if (protocol === documentLoadV4) {
            return makeStream({
              documentId: '/doc',
              loadChallenge: new Uint8Array(activeLoadChallenge!),
              changeId: 'H',
              changes: {
                kind: 'document',
                // X is an ancestor, so the served frontier remains exactly
                // {H}; only the complete manifest exposes the smuggling.
                children: { X: { kind: 'writer' } },
              },
              tips: ['H'],
              loadSecurityState: tuple(),
              signature: 'signature',
              testSigner: `writer-${remote.id}`,
            });
          }
          throw new Error(`unexpected protocol ${protocol}`);
        },
      ),
    };
    const resolveTuple = jest.fn(async () => tuple());
    const resolveWriters = jest.fn(async () => ['writer-a', 'writer-b']);
    const document = Object.create(
      PeerborneDocument.prototype,
    ) as DocumentHarness;
    document.documentPath = '/doc';
    document.swarm = swarmWithCapturedPolicy(
      {
        enableSigning: true,
        requireAuthenticatedInitialLoad: true,
        requireSecurityStateQuorum: true,
        loadQuorumK: 2,
        loadQuorumQ: 2,
        resolveLoadSecurityCommitments: resolveTuple,
        resolveTrustedDocumentWriters: resolveWriters,
      },
      { heliaNode: { libp2p } },
    );
    document._shuffledPeers = async () => [peer('a'), peer('b')];
    document._getWriterKeys = async () => [];
    document._authProvider = {
      nonceBits: 1,
      sign: async () => new Uint8Array([1]),
      verify: async (payload: Uint8Array, key: string) =>
        new TextDecoder().decode(payload) === key,
      decrypt: async (data: Uint8Array) => data,
      serializePublicKey: async (key: string) => key,
    };
    document._encoder = new TextEncoder();
    document._userKey = 'local-key';
    document._serializeSignature = () => 'signature';
    document._deserializeSignature = () => new Uint8Array([1]);
    document._loadMessageSerializer = {
      serializeLoadRequest: (request: { loadChallenge?: Uint8Array }) => {
        activeLoadChallenge = new Uint8Array(request.loadChallenge!);
        return new Uint8Array([1]);
      },
    };
    document._syncMessageSerializer = {
      deserializeSyncMessage: (data: Uint8Array) => messages.get(data[0]),
      serializeSyncMessage: (message: { testSigner: string }) =>
        new TextEncoder().encode(message.testSigner),
    };
    document._keychainProvider = { keyIDLength: 1 };
    document._keychain = { getKey: () => 'document-key' };
    document._compactionConfig = { enabled: false };
    document.sync = jest.fn(async () => true);

    const error = await document.load().catch((cause: unknown) => cause);
    expect(error).toBeInstanceOf(LoadQuorumFailedError);
    expect(error).toMatchObject({
      reason: 'bind-check-failed-all-agreeing-peers',
    });
    expect(document.sync).not.toHaveBeenCalled();
    expect(dialedProtocols).toContain(securityAdvertiseV1);
    expect(dialedProtocols).toContain(documentLoadV4);
    expect(dialedProtocols).not.toContain(documentLoadV3);
    expect(dialedProtocols).not.toContain(snapshotLoadV3);
    expect(dialedProtocols).not.toContain(tipAdvertiseV1);
  });
});
