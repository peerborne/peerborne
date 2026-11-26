import { expect, jest, test } from '@jest/globals';
import { DEFAULT_DOCUMENT_OPERATION_COUNT } from './group-document-operation.js';
import { InvitationMembershipQueue } from './invitation-membership.js';
import { PeerborneDocument } from './peerborne-document.js';
import { encodeSyncRequest } from './sync-request.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
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

const turn = () => new Promise<void>((resolve) => setImmediate(resolve));
const frame = (value = 3) => new Uint8Array([1, 2, value]);
type Receive = (message: {
  detail: { topic: string; data: Uint8Array };
}) => void;
type Validate = (
  peer: object,
  message: { data: Uint8Array },
) => Promise<string>;

function documentFixture(
  documentPath: string,
  decrypt: (
    _key: Uint8Array,
    _nonce: Uint8Array,
    data: Uint8Array,
  ) => Promise<Uint8Array | undefined>,
) {
  const topicValidators = new Map<string, Validate>();
  const topic = '/topic';
  const queue = new InvitationMembershipQueue();
  const sync = jest.fn(async () => true);
  const deserialize = jest.fn((data: Uint8Array) => ({
    documentId: documentPath,
    signatureContext: 'ordinary-sync-v1',
    changeId: String(data[0]),
    signature: 'AQ==',
  }));
  const pubsub = {
    addEventListener: jest.fn<(_event: string, handler: Receive) => void>(),
    removeEventListener: jest.fn(),
    subscribe: jest.fn(),
    unsubscribe: jest.fn(),
    topicValidators,
  };
  const document = Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath,
    _invitationBootstrapReady: true,
    load: async () => true,
    _hashes: new Set(),
    _computeTopic: () => topic,
    _keychainProvider: { keyIDLength: 1 },
    _authProvider: { nonceBytes: 1 },
    _decryptBlock: decrypt,
    _syncUnlocked: sync,
    _isSigningEnabled: () => true,
    _verifyWriterSignature: async () => true,
    _mutationQueue: queue,
    _syncMessageSerializer: {
      deserializeSyncMessage: deserialize,
      serializeSyncMessage: () => new Uint8Array([1]),
    },
    swarm: {
      config: { enableTopicValidators: true },
      registerDocument: jest.fn(),
      unregisterDocument: jest.fn(),
      heliaNode: { libp2p: { services: { pubsub } } },
    },
  }) as PeerborneDocument<unknown, unknown, unknown, unknown, unknown, unknown>;
  return {
    document,
    queue,
    sync,
    deserialize,
    currentReceive: () => pubsub.addEventListener.mock.lastCall![1],
    deliver: (data = frame()) =>
      pubsub.addEventListener.mock.lastCall![1]({ detail: { topic, data } }),
    validator: () => topicValidators.get(topic)!,
  };
}

test('the active receive paths share document and aggregate limits until work actually settles', async () => {
  const pending: PromiseWithResolvers<Uint8Array | undefined>[] = [];
  const decrypt = jest.fn(() => {
    const completion = Promise.withResolvers<Uint8Array | undefined>();
    pending.push(completion);
    return completion.promise;
  });
  const fixtures = Array.from({ length: 5 }, (_, index) =>
    documentFixture(`/document-${index}`, decrypt),
  );
  const validators: Promise<string>[] = [];
  const target = fixtures[4];
  try {
    await Promise.all(fixtures.map(({ document }) => document.open()));
    for (const fixture of fixtures.slice(0, 4)) {
      const validate = fixture.validator();
      for (let index = 0; index < DEFAULT_DOCUMENT_OPERATION_COUNT; index++) {
        if (index % 2 === 0) fixture.deliver();
        else validators.push(validate({}, { data: frame() }));
      }
      await expect(validate({}, { data: frame() })).resolves.toBe('ignore');
    }
    const charged = 4 * DEFAULT_DOCUMENT_OPERATION_COUNT;
    expect(decrypt).toHaveBeenCalledTimes(charged);
    await expect(target.validator()({}, { data: frame() })).resolves.toBe(
      'ignore',
    );
    await fixtures[0].document.close();
    target.deliver();
    expect(decrypt).toHaveBeenCalledTimes(charged);

    pending[0].resolve(new Uint8Array([3]));
    await turn();
    expect(fixtures[0].deserialize).not.toHaveBeenCalled();
    // The freed shared credit goes to the target's latest skipped frame.
    expect(decrypt).toHaveBeenCalledTimes(charged + 1);
    pending.at(-1)!.resolve(new Uint8Array([3]));
    for (let index = 0; index < 5; index++) await turn();
    expect(target.sync).toHaveBeenCalledTimes(1);
    const fresh = target.validator()({}, { data: frame() });
    expect(decrypt).toHaveBeenCalledTimes(charged + 2);
    pending.at(-1)!.resolve(new Uint8Array([3]));
    await expect(fresh).resolves.toBe('accept');
  } finally {
    for (let index = 0; index < pending.length; index++) {
      pending[index].resolve(undefined);
      await turn();
    }
    await Promise.all(validators);
    await turn();
    await Promise.all(fixtures.map(({ document }) => document.close()));
  }
});

test('a validated burst that exceeds the document limit still applies its final frame', async () => {
  const decrypt = jest.fn(
    async (_key: Uint8Array, _nonce: Uint8Array, data: Uint8Array) => data,
  );
  const fixture = documentFixture('/document', decrypt);
  const unblock = Promise.withResolvers<void>();
  const queued = fixture.queue.run(() => unblock.promise);
  const burst = DEFAULT_DOCUMENT_OPERATION_COUNT + 14;
  try {
    await fixture.document.open();
    const validate = fixture.validator();
    const results = Array.from({ length: burst }, (_, index) =>
      validate({}, { data: frame(index + 1) }),
    );
    await turn();
    expect(decrypt).toHaveBeenCalledTimes(DEFAULT_DOCUMENT_OPERATION_COUNT);
    unblock.resolve();
    const outcomes = await Promise.all(results);
    expect(outcomes.filter((outcome) => outcome === 'accept')).toHaveLength(
      DEFAULT_DOCUMENT_OPERATION_COUNT,
    );
    for (let index = 0; index < 10; index++) await turn();
    expect(decrypt).toHaveBeenCalledTimes(DEFAULT_DOCUMENT_OPERATION_COUNT + 1);
    expect(fixture.sync).toHaveBeenCalledTimes(1);
    expect(fixture.sync).toHaveBeenCalledWith(
      expect.objectContaining({ changeId: String(burst) }),
      true,
      'ordinary-sync-v1',
      undefined,
      false,
      undefined,
      {
        assertStillActive: expect.any(Function),
        prefetchedBlocks: expect.any(Map),
        fetchMissingBlocks: false,
      },
    );
  } finally {
    unblock.resolve();
    await queued;
    await fixture.document.close();
  }
});

test('closing discards a skipped frame before it can be retried', async () => {
  const decrypt = jest.fn(
    async (_key: Uint8Array, _nonce: Uint8Array, data: Uint8Array) => data,
  );
  const fixture = documentFixture('/document', decrypt);
  const unblock = Promise.withResolvers<void>();
  const queued = fixture.queue.run(() => unblock.promise);
  try {
    await fixture.document.open();
    const validate = fixture.validator();
    const results = Array.from(
      { length: DEFAULT_DOCUMENT_OPERATION_COUNT + 1 },
      (_, index) => validate({}, { data: frame(index + 1) }),
    );
    await turn();
    await fixture.document.close();
    unblock.resolve();
    await Promise.all(results);
    for (let index = 0; index < 10; index++) await turn();
    expect(decrypt).toHaveBeenCalledTimes(DEFAULT_DOCUMENT_OPERATION_COUNT);
    expect(fixture.sync).not.toHaveBeenCalled();
  } finally {
    unblock.resolve();
    await queued;
    await fixture.document.close();
  }
});

test('closing and reopening skips old queued receive work and applies fresh frames', async () => {
  const decrypt = jest.fn(
    async (_key: Uint8Array, _nonce: Uint8Array, data: Uint8Array) => data,
  );
  const fixture = documentFixture('/document', decrypt);
  const unblock = Promise.withResolvers<void>();
  const queued = fixture.queue.run(() => unblock.promise);
  try {
    await fixture.document.open();
    const oldReceive = fixture.currentReceive();
    const oldValidate = fixture.validator();
    await expect(fixture.document.open()).rejects.toThrow(
      'Document is already open',
    );
    expect(fixture.currentReceive()).toBe(oldReceive);
    expect(fixture.validator()).toBe(oldValidate);
    fixture.deliver(frame(3));
    const validation = oldValidate({}, { data: frame(4) });
    await turn();
    expect(fixture.deserialize).toHaveBeenCalledTimes(2);
    await fixture.document.close();
    await fixture.document.open();
    oldReceive({ detail: { topic: '/topic', data: frame(5) } });
    await expect(oldValidate({}, { data: frame(6) })).resolves.toBe('ignore');
    expect(decrypt).toHaveBeenCalledTimes(2);
    fixture.deliver(frame(7));
    unblock.resolve();
    await expect(validation).resolves.toBe('ignore');
    await turn();
    expect(fixture.sync).toHaveBeenCalledTimes(1);
    expect(fixture.sync).toHaveBeenCalledWith(
      expect.objectContaining({ changeId: '7' }),
      true,
      'ordinary-sync-v1',
      undefined,
      false,
      undefined,
      {
        assertStillActive: expect.any(Function),
        prefetchedBlocks: expect.any(Map),
        fetchMissingBlocks: false,
      },
    );
  } finally {
    unblock.resolve();
    await queued;
    await fixture.document.close();
  }
});

test('a closing subscriber stops an authenticated frame whose verification is still running', async () => {
  const fixture = documentFixture(
    '/document',
    async (_key, _nonce, data) => data,
  );
  const started = Promise.withResolvers<void>();
  const verification = Promise.withResolvers<boolean>();
  const verify = jest
    .fn(async () => true)
    .mockImplementationOnce(() => {
      started.resolve();
      return verification.promise;
    });
  const applyChanges = jest.fn(async (_changeId: string) => {});
  Object.assign(fixture.document, {
    _syncUnlocked: Object.getPrototypeOf(fixture.document)._syncUnlocked,
    _verifyWriterSignature: verify,
    _collectACLFromTree: (changes: unknown) => ({ changes, aclEntries: [] }),
    _syncDocumentChanges: applyChanges,
  });
  fixture.deserialize.mockImplementation((data) => ({
    documentId: '/document',
    signatureContext: 'ordinary-sync-v1',
    changeId: String(data[0]),
    signature: 'AQ==',
    changes: { kind: 'document', change: data[0] },
  }));
  try {
    await fixture.document.open();
    fixture.deliver(frame(3));
    await started.promise;
    await fixture.document.close();
    await fixture.document.open();
    fixture.deliver(frame(7));
    verification.resolve(true);
    await turn();
    expect(verify).toHaveBeenCalledTimes(2);
    expect(applyChanges).toHaveBeenCalledTimes(1);
    expect(applyChanges.mock.calls[0]![0]).toBe('7');
  } finally {
    verification.resolve(true);
    await fixture.document.close();
  }
});

test('a direct sync frame is applied like a GossipSub frame but never as a sync request', async () => {
  const decrypt = jest.fn(
    async (_key: Uint8Array, _nonce: Uint8Array, data: Uint8Array) => data,
  );
  const fixture = documentFixture('/document', decrypt);
  const handleSyncRequest = jest.fn(async () => {});
  Object.assign(fixture.document, { _handleSyncRequest: handleSyncRequest });
  const request = encodeSyncRequest({
    documentId: '/document',
    requester: 'member',
    requestId: '00'.repeat(16),
    issuedAtMs: Date.now(),
    knownTips: ['tip'],
    knownSnapshots: [],
    peer: 'memberPeer',
    signature: 'AQ==',
  });
  const requestFrame = new Uint8Array([1, 2, ...request]);
  const active = { isActive: () => true } as never;
  try {
    await fixture.document.open();
    await fixture.document.handleSyncFrameData(requestFrame, active);
    await fixture.document.handleSyncFrameData(frame(8), {
      isActive: () => false,
    } as never);
    await fixture.document.handleSyncFrameData(new Uint8Array(0), active);
    for (let index = 0; index < 5; index++) await turn();
    expect(handleSyncRequest).not.toHaveBeenCalled();
    expect(fixture.deserialize).not.toHaveBeenCalled();
    expect(fixture.sync).not.toHaveBeenCalled();

    fixture.deliver(requestFrame);
    for (let index = 0; index < 5; index++) await turn();
    expect(handleSyncRequest).toHaveBeenCalledTimes(1);

    await fixture.document.handleSyncFrameData(frame(9), active);
    for (let index = 0; index < 5; index++) await turn();
    expect(fixture.sync).toHaveBeenCalledTimes(1);
    expect(fixture.sync).toHaveBeenCalledWith(
      expect.objectContaining({ changeId: '9' }),
      true,
      'ordinary-sync-v1',
      undefined,
      false,
      undefined,
      {
        assertStillActive: expect.any(Function),
        prefetchedBlocks: expect.any(Map),
        fetchMissingBlocks: false,
      },
    );

    await fixture.document.close();
    await fixture.document.handleSyncFrameData(frame(10), active);
    for (let index = 0; index < 5; index++) await turn();
    expect(decrypt).toHaveBeenCalledTimes(3);
  } finally {
    await fixture.document.close();
  }
});
